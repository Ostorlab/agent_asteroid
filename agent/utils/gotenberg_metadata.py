"""Read Gotenberg's compiled backend release with bounded anonymous GETs."""

from __future__ import annotations

import re
import uuid

import requests

from agent import definitions
from agent.exploits import defensive_http
from agent.utils import defensive_metadata

_RELEASE = re.compile(rb"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}")
_ROOT = (
    "Hey, Gotenberg has no UI, it's an API. Head to the "
    '<a href="https://gotenberg.dev">documentation</a> to learn how to interact with it 🚀'
).encode()


def read_release(
    session: definitions.HttpSession, target: definitions.Target
) -> str | None:
    """Require the source-defined version, product banner and an absent route."""
    version = defensive_metadata.read_bytes(session, target, "/version")
    if version is None or _RELEASE.fullmatch(version) is None:
        return None
    if defensive_metadata.read_bytes(session, target, "/") != _ROOT:
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
    return version.decode("ascii")
