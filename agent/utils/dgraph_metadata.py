"""Read local Dgraph Alpha build metadata with bounded anonymous GETs."""

from __future__ import annotations

import json
import re
import typing
import uuid

import requests

from agent import definitions
from agent.exploits import defensive_http
from agent.utils import defensive_metadata

_RELEASE = re.compile(r"v(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}")
_ROOT_BANNER = (
    b"Dgraph browser is available for running separately using the dgraph-ratel binary"
)
_REQUIRED = {"instance", "address", "status", "group", "version", "lastEcho"}
_OPTIONAL = {"uptime", "ongoing", "indexing", "ee_features", "max_assigned"}


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise ValueError("Duplicate metadata key")
        record[key] = value
    return record


def _parse_health(content: bytes) -> str | None:
    try:
        value: object = json.loads(content, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if isinstance(value, list) is False:
        return None
    nodes = typing.cast(list[object], value)
    if len(nodes) != 1:
        return None
    node = nodes[0]
    if isinstance(node, dict) is False:
        return None
    record = typing.cast(dict[str, object], node)
    if (
        _REQUIRED.issubset(record) is False
        or set(record).issubset(_REQUIRED | _OPTIONAL) is False
    ):
        return None
    if record["instance"] != "alpha" or record["status"] != "healthy":
        return None
    if (
        any(
            isinstance(record[key], str) is False
            for key in ("address", "group", "version")
        )
        is True
    ):
        return None
    address = typing.cast(str, record["address"])
    group = typing.cast(str, record["group"])
    release = typing.cast(str, record["version"])
    if (
        len(address) == 0
        or re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", group) is None
        or _RELEASE.fullmatch(release) is None
    ):
        return None
    for key in ("lastEcho", "uptime", "max_assigned"):
        number = record.get(key, 0)
        if type(number) is not int or number < 0:
            return None
    for key in ("ongoing", "indexing", "ee_features"):
        entries = record.get(key, [])
        if isinstance(entries, list) is False:
            return None
        if (
            any(
                isinstance(entry, str) is False
                for entry in typing.cast(list[object], entries)
            )
            is True
        ):
            return None
    return release[1:]


def read_release(
    session: definitions.HttpSession, target: definitions.Target
) -> str | None:
    """Require local Alpha health, the source banner and an absent-route control."""
    content = defensive_metadata.read_bytes(
        session, target, "/health", accept="application/json"
    )
    if content is None:
        return None
    release = _parse_health(content)
    if release is None:
        return None
    if defensive_metadata.read_bytes(session, target, "/") != _ROOT_BANNER:
        return None
    try:
        with defensive_http.send_anonymous(
            session,
            "GET",
            f"{target.origin}/asteroid-metadata-{uuid.uuid4().hex}",
            timeout=defensive_metadata.TIMEOUT_SECONDS,
        ) as response:
            if response.status_code != 404 or len(response.history) != 0:
                return None
    except requests.exceptions.RequestException:
        return None
    return release
