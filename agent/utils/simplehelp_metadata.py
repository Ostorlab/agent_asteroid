"""Vendor-documented installed SimpleHelp release metadata, without authentication."""

from __future__ import annotations

import datetime
import re
import uuid

import requests

from agent import definitions
from agent.exploits import defensive_http
from agent.utils import defensive_metadata

_VERSION_PAGE = re.compile(
    r"SH Version:[ \t]+SSuite-(?P<major>[1-9][0-9]{0,3})-(?P<minor>0|[1-9][0-9]{0,3})-"
    r"(?P<timestamp>[0-9]{8}-[0-9]{6})\r?\n"
    r"Visual Version:[ \t]+(?P<release>(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3}))"
    r"[ \t]*(?:\r?\n)?"
)


def read_release(
    session: definitions.HttpSession, target: definitions.Target
) -> str | None:
    content = defensive_metadata.read_bytes(
        session, target, "/allversions", accept="text/plain"
    )
    if content is None:
        return None
    try:
        match = _VERSION_PAGE.fullmatch(content.decode("ascii"))
    except UnicodeError:
        return None
    if match is None:
        return None
    try:
        datetime.datetime.strptime(match.group("timestamp"), "%Y%m%d-%H%M%S").replace(
            tzinfo=datetime.timezone.utc
        )
    except ValueError:
        return None
    release = match.group("release")
    if release.split(".")[:2] != [match.group("major"), match.group("minor")]:
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
