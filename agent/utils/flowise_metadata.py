"""Read corroborated installed Flowise server metadata without authentication."""

from __future__ import annotations

import html.parser
import re
import typing
import uuid

from agent import definitions
from agent.utils import defensive_metadata

VERSION_PATH = "/api/v1/version"
_RELEASE = re.compile(r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}")
_TITLE = "Flowise - Build AI Agents, Visually"


class _ProductParser(html.parser.HTMLParser):
    """Require unique upstream product markers, not an arbitrary version JSON."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.titles = 0
        self.title_open = False
        self.title: list[str] = []
        self.sites: list[str | None] = []
        self.invalid = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self.titles += 1
            self.title_open = True
        if tag == "meta" and ("property", "og:site_name") in attrs:
            attributes = dict(attrs)
            if len(attributes) != len(attrs):
                self.invalid = True
            self.sites.append(attributes.get("content"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.title_open = False

    def handle_data(self, data: str) -> None:
        if self.title_open is True:
            self.title.append(data)


def _matches_product(content: bytes) -> bool:
    try:
        parser = _ProductParser()
        parser.feed(content.decode("utf-8"))
        parser.close()
        return (
            parser.invalid is False
            and parser.titles == 1
            and parser.title_open is False
            and "".join(parser.title) == _TITLE
            and parser.sites == ["flowiseai.com"]
        )
    except (UnicodeError, ValueError, RecursionError):
        return False


def read_release(
    session: definitions.HttpSession, target: definitions.Target
) -> str | None:
    """Read server package version, editor identity and a source-backed SPA control."""
    record = defensive_metadata.read_json(session, target, VERSION_PATH)
    if record is None or set(record) != {"version"}:
        return None
    raw_label = record["version"]
    if isinstance(raw_label, str) is False:
        return None
    label = typing.cast(str, raw_label)
    if _RELEASE.fullmatch(label) is None:
        return None
    homepage = defensive_metadata.read_bytes(session, target, "/")
    if homepage is None or _matches_product(homepage) is False:
        return None
    # Flowise whitelists the version prefix; unmatched routes serve the same
    # static UI index. A wildcard version JSON must never satisfy this control.
    control = defensive_metadata.read_bytes(
        session, target, f"{VERSION_PATH}/asteroid-metadata-{uuid.uuid4().hex}"
    )
    if control != homepage:
        return None
    return label
