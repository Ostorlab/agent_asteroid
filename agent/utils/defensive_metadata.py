"""Bounded anonymous metadata reads shared by defensive HTTP detectors."""

from __future__ import annotations

import json
import typing

import requests

from agent import definitions
from agent.exploits import defensive_http

MAX_RESPONSE_BYTES = 256 * 1024
TIMEOUT_SECONDS = 5


def read_bytes(
    session: requests.Session, target: definitions.Target, path: str
) -> bytes | None:
    """Read one same-origin metadata resource without credentials or redirects."""
    if target.scheme not in ("http", "https"):
        return None
    try:
        with defensive_http.send_anonymous(
            session, "GET", f"{target.origin}{path}", timeout=TIMEOUT_SECONDS
        ) as response:
            if response.status_code != 200 or len(response.history) != 0:
                return None
            content = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                    return None
                content.extend(chunk)
            return bytes(content)
    except requests.exceptions.RequestException:
        return None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject contradictory duplicate fields at every JSON nesting level."""
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise ValueError("Duplicate metadata key")
        record[key] = value
    return record


def read_json(
    session: requests.Session, target: definitions.Target, path: str
) -> dict[str, object] | None:
    """Decode bounded JSON metadata, treating malformed responses as inconclusive."""
    content = read_bytes(session, target, path)
    if content is None:
        return None
    try:
        record: object = json.loads(content, object_pairs_hook=_unique_object)
        if isinstance(record, dict) is True:
            return typing.cast(dict[str, object], record)
    except (ValueError, UnicodeError, RecursionError):
        return None
    return None
