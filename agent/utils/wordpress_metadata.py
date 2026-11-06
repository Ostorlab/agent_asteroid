"""Bounded public WordPress identity and advertised distribution metadata.

A readme Stable tag is not the installed plugin PHP Version. These helpers never
establish activation, deployed code, patch status, or exploitability.
"""

from __future__ import annotations

import re
import typing
import uuid
from urllib import parse

import requests

from agent import definitions
from agent.exploits import defensive_http
from agent.utils import defensive_metadata
from agent.utils import inventory_definitions as inventory_types

_ASCII_SPACE = " \t\r\n\v\f"
_VERSION = re.compile(
    rf"{inventory_types.VERSION_COMPONENT}(?:\.{inventory_types.VERSION_COMPONENT}){{0,3}}"
)
_DOCUMENT_HTML = re.compile(
    r"<\s*(?:!doctype|/?(?:html|head|body)(?:\s|>))", re.IGNORECASE
)

# Standard readme fields plus plugin/WooCommerce/BuddyPress fields observed in
# the verified vendor readmes. Any prose, heading or unknown field ends the
# initial metadata block; later Stable tags remain ambiguous and are rejected.
_METADATA_FIELDS = frozenset(
    {
        "contributors",
        "tags",
        "donate link",
        "requires at least",
        "tested up to",
        "requires php",
        "stable tag",
        "license",
        "license uri",
        "plugin name",
        "plugin uri",
        "plugin link",
        "author uri",
        "author",
        "wc requires at least",
        "wc tested up to",
        "buddypress",
        "version",
    }
)


def parse_release(value: object) -> tuple[int, ...] | None:
    """Compare one to four canonical numeric components by padding, never truncating."""
    if isinstance(value, str) is False:
        return None
    text = typing.cast(str, value)
    if _VERSION.fullmatch(text) is None:
        return None
    parts = tuple(int(part) for part in text.split("."))
    return parts + (0,) * (4 - len(parts))


def parse_readme(content: bytes, headings: tuple[str, ...]) -> str | None:
    """Read a single Stable tag from the exact plugin's initial metadata header."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeError:
        return None
    if (
        _DOCUMENT_HTML.search(text) is not None
        or any(ord(char) < 32 and char not in "\t\r\n" for char in text) is True
    ):
        return None
    lines = [
        line.strip(_ASCII_SPACE)
        for line in text.splitlines()
        if line.strip(_ASCII_SPACE) != ""
    ]
    if len(lines) == 0:
        return None
    heading = re.fullmatch(r"===[ \t]+(.+?)[ \t]+===", lines[0])
    if heading is None or heading.group(1) not in headings:
        return None
    if any(line.startswith("===") for line in lines[1:]) is True:
        return None
    stable_tags: list[str] = []
    explicit_versions: list[str] = []
    in_header = True
    for line in lines[1:]:
        if re.match(r"stable[ \t]+tag\b", line, re.IGNORECASE) is not None:
            match = re.fullmatch(
                r"Stable[ \t]+tag[ \t]*:[ \t]*(.*)", line, re.IGNORECASE
            )
            if in_header is False or match is None:
                return None
            stable_tags.append(match.group(1))
        if (
            in_header is True
            and re.match(r"version\b", line, re.IGNORECASE) is not None
        ):
            match = re.fullmatch(r"Version[ \t]*:[ \t]*(.*)", line, re.IGNORECASE)
            if match is None:
                return None
            explicit_versions.append(match.group(1))
        name, separator, _ = line.partition(":")
        field = re.sub(r"[ \t]+", " ", name.strip(_ASCII_SPACE).casefold())
        if separator != ":" or field not in _METADATA_FIELDS:
            in_header = False
    if len(stable_tags) != 1 or len(explicit_versions) > 1:
        return None
    release = parse_release(stable_tags[0])
    if release is None:
        return None
    if len(explicit_versions) == 1 and parse_release(explicit_versions[0]) != release:
        return None
    return stable_tags[0]


def _canonical_path(path: str) -> str | None:
    """Limit base paths to literal, unambiguous directory segments."""
    if re.fullmatch(r"(?:/[A-Za-z0-9_.~-]+)*/?", path) is None:
        return None
    if any(part in (".", "..") for part in path.split("/")) is True:
        return None
    return path.rstrip("/")


def _same_origin_path(value: object, target: definitions.Target) -> str | None:
    if isinstance(value, str) is False:
        return None
    text = typing.cast(str, value)
    if any(ord(char) <= 32 for char in text) is True:
        return None
    try:
        url = parse.urlsplit(text)
        origin = parse.urlsplit(target.origin)
        port = (
            url.port if url.port is not None else (443 if url.scheme == "https" else 80)
        )
        if (
            url.scheme != origin.scheme
            or url.hostname != origin.hostname
            or port != target.port
            or url.username is not None
            or url.password is not None
            or url.query != ""
            or url.fragment != ""
        ):
            return None
    except ValueError:
        return None
    return _canonical_path(url.path)


def _index_base(
    record: dict[str, object], target: definitions.Target, home_base: str
) -> str | None:
    namespaces = record.get("namespaces")
    routes = record.get("routes")
    if isinstance(namespaces, list) is False or isinstance(routes, dict) is False:
        return None
    if "wp/v2" not in typing.cast(list[object], namespaces):
        return None
    route_map = typing.cast(dict[str, object], routes)
    if _same_origin_path(record.get("home"), target) != home_base:
        return None
    root = route_map.get("/")
    namespace = route_map.get("/wp/v2")
    if isinstance(root, dict) is False or isinstance(namespace, dict) is False:
        return None
    if typing.cast(dict[str, object], namespace).get("namespace") != "wp/v2":
        return None
    links = typing.cast(dict[str, object], root).get("_links")
    if isinstance(links, dict) is False:
        return None
    self_links = typing.cast(dict[str, object], links).get("self")
    if isinstance(self_links, list) is False:
        return None
    self_list = typing.cast(list[object], self_links)
    if len(self_list) != 1 or isinstance(self_list[0], dict) is False:
        return None
    href = typing.cast(dict[str, object], self_list[0]).get("href")
    if _same_origin_path(href, target) != home_base + "/wp-json":
        return None
    # WordPress's REST index url is siteurl, while home determines the REST root.
    return _same_origin_path(record.get("url"), target)


def read_installation_base(
    session: requests.Session, target: definitions.Target
) -> str | None:
    """Bind a real REST index to its home and same-origin WordPress core directory."""
    if target.scheme not in ("http", "https"):
        return None
    bases = [""]
    candidate = _canonical_path(target.path.split("?", 1)[0].split("#", 1)[0])
    if candidate not in (None, ""):
        bases.insert(0, candidate)
    for base in bases:
        record = defensive_metadata.read_json(session, target, base + "/wp-json/")
        if record is not None:
            site_base = _index_base(record, target, base)
            if site_base is not None:
                return site_base
    return None


def _missing_static_path(
    session: requests.Session, target: definitions.Target, directory: str
) -> bool:
    """Require a negative static-path control; redirects and failed reads are inconclusive."""
    path = f"{directory}/asteroid-{uuid.uuid4().hex}.txt"
    try:
        with defensive_http.send_anonymous(
            session,
            "GET",
            target.origin + path,
            timeout=defensive_metadata.TIMEOUT_SECONDS,
        ) as response:
            return response.status_code in (404, 410) and len(response.history) == 0
    except requests.exceptions.RequestException:
        return False


def read_advertised_release(
    session: requests.Session,
    target: definitions.Target,
    readme_path: str,
    headings: tuple[str, ...],
) -> tuple[str, str] | None:
    """Read only the selected static readme after independently corroborating WordPress."""
    base = read_installation_base(session, target)
    if base is None:
        return None
    path = base + readme_path
    content = defensive_metadata.read_bytes(session, target, path)
    if content is None:
        return None
    release = parse_readme(content, headings)
    if (
        release is None
        or _missing_static_path(session, target, path.rsplit("/", 1)[0]) is False
    ):
        return None
    return release, path
