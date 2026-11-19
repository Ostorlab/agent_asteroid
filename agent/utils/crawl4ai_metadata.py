"""Read installed Crawl4AI package metadata from the Docker API."""

from __future__ import annotations

import hashlib
import math
import re
import typing
import uuid

import requests

from agent import definitions
from agent.exploits import defensive_http
from agent.utils import defensive_metadata

_RELEASE = re.compile(r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}")
_LOGO_SHA256 = "50dafdc7defc6da27ae873dca7d48aef7187888506f4748c8e0022f9886b4c42"


def read_release(
    session: definitions.HttpSession, target: definitions.Target
) -> str | None:
    """Require the package health schema, public product logo and 404 control."""
    record = defensive_metadata.read_json(session, target, "/health")
    if record is None or set(record) != {"status", "timestamp", "version"}:
        return None
    if record["status"] != "ok":
        return None
    timestamp = record["timestamp"]
    if type(timestamp) not in (int, float):
        return None
    timestamp = typing.cast(int | float, timestamp)
    if timestamp <= 0 or timestamp >= 253402300800 or math.isfinite(timestamp) is False:
        return None
    release = record["version"]
    if isinstance(release, str) is False:
        return None
    release = typing.cast(str, release)
    if _RELEASE.fullmatch(release) is None:
        return None
    # Older Docker servers returned a stale hard-coded health version.
    if tuple(int(part) for part in release.split(".")) < (0, 8, 5):
        return None
    logo = defensive_metadata.read_bytes(
        session, target, "/static/assets/crawl4ai-logo.png"
    )
    if logo is None or hashlib.sha256(logo).hexdigest() != _LOGO_SHA256:
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
