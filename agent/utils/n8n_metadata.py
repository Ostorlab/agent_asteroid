"""Shared read-only n8n installed-release metadata contract.

Extracted unchanged from CVE-2026-21858. See docs/cve-2026-21858.md and
docs/cve-2026-21877.md for pinned sources and coverage limitations.
"""

from __future__ import annotations

import base64
import binascii
import html.parser
import json
import re
import typing
import uuid

import requests
from packaging import version

from agent import definitions
from agent.exploits import defensive_http
from agent.utils import defensive_metadata

SETTINGS_PATH = "/rest/settings"
RELEASE_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}")


class _EditorParser(html.parser.HTMLParser):
    """Read actual editor markers and optional modern configuration tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_count = 0
        self.title_open = False
        self.noscript_open = False
        self.title: list[str] = []
        self.noscript: list[str] = []
        self.config: dict[str, str] = {}
        self.invalid = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self.title_count += 1
            self.title_open = True
        elif tag == "noscript":
            self.noscript_open = True
        elif tag == "meta":
            names = [value for key, value in attrs if key == "name"]
            for name in ("n8n:config:sentry", "n8n:config:rest-endpoint"):
                if name not in names:
                    continue
                attributes = dict(attrs)
                content = attributes.get("content")
                if (
                    len(attributes) != len(attrs)
                    or name in self.config
                    or content is None
                ):
                    self.invalid = True
                else:
                    self.config[name] = content

    def handle_data(self, data: str) -> None:
        if self.title_open is True:
            self.title.append(data)
        if self.noscript_open is True:
            self.noscript.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.title_open = False
        elif tag == "noscript":
            self.noscript_open = False


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate configuration fields, including identical duplicates."""
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise ValueError("Duplicate editor configuration key")
        record[key] = value
    return record


def _editor_matches(content: bytes, label: str) -> bool:
    """Corroborate the installed product and reject conflicting HTML metadata."""
    try:
        parser = _EditorParser()
        parser.feed(content.decode("utf-8"))
        parser.close()
        if (
            parser.invalid is True
            or parser.title_count != 1
            or parser.title_open is True
            or parser.noscript_open is True
            or "".join(parser.title) != "n8n.io - Workflow Automation"
            or "n8n Editor-UI doesn't work properly without JavaScript enabled."
            not in " ".join("".join(parser.noscript).split())
        ):
            return False
        rest_endpoint = parser.config.get("n8n:config:rest-endpoint")
        if (
            rest_endpoint is not None
            and base64.b64decode(rest_endpoint, validate=True) != b"rest"
        ):
            return False
        sentry = parser.config.get("n8n:config:sentry")
        if sentry is not None:
            record = json.loads(
                base64.b64decode(sentry, validate=True),
                object_pairs_hook=_unique_object,
            )
            if (
                isinstance(record, dict) is False
                or record.get("release") != f"n8n@{label}"
            ):
                return False
        return True
    except (ValueError, UnicodeError, binascii.Error, RecursionError):
        return False


def _installed_label(record: dict[str, object] | None) -> str | None:
    """Accept only canonical installed versions, never update-channel data."""
    if record is None:
        return None
    settings = record.get("data")
    if isinstance(settings, dict) is True:
        settings_record = typing.cast(dict[str, object], settings)
        match settings_record.get("versionCli"):
            case str(label) if (
                RELEASE_PATTERN.fullmatch(label) is not None
                and settings_record.get("settingsMode", "public") == "public"
            ):
                return label
    return None


def _missing_route(
    session: definitions.HttpSession, target: definitions.Target
) -> bool:
    """Require an explicit absent-route status; unread control bodies are closed."""
    try:
        with defensive_http.send_anonymous(
            session,
            "GET",
            f"{target.origin}/rest/asteroid-metadata-{uuid.uuid4().hex}",
            timeout=defensive_metadata.TIMEOUT_SECONDS,
        ) as response:
            return response.status_code in (404, 410) and len(response.history) == 0
    except requests.exceptions.RequestException:
        return False


def read_release(
    session: definitions.HttpSession, target: definitions.Target
) -> version.Version | None:
    """Read anonymous root metadata only; custom paths and ambiguous routes are unknown."""
    record = defensive_metadata.read_json(session, target, SETTINGS_PATH)
    label = _installed_label(record)
    if label is None:
        return None
    homepage = defensive_metadata.read_bytes(session, target, "/")
    if homepage is None or _editor_matches(homepage, label) is False:
        return None
    if _missing_route(session, target) is False:
        return None
    return version.Version(label)
