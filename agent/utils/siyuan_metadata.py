"""Read SiYuan compiled kernel metadata using bounded anonymous GETs."""

from __future__ import annotations

import hashlib
import re
import typing
import uuid

import requests

from agent import definitions
from agent.exploits import defensive_http
from agent.utils import defensive_metadata

_RELEASE = re.compile(r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}")
_ICON_SHA256 = "0238c5609523c7dff538c2a61ad1e05b9fda08e228235aad72bf2bdbc6f356a7"


def read_release(
    session: definitions.HttpSession, target: definitions.Target
) -> str | None:
    """Require compiled kernel version, public icon identity and absent-route control."""
    record = defensive_metadata.read_json(session, target, "/api/system/version")
    if record is None or set(record) != {"code", "msg", "data"}:
        return None
    if type(record["code"]) is not int or record["code"] != 0 or record["msg"] != "":
        return None
    release = record["data"]
    if isinstance(release, str) is False:
        return None
    release = typing.cast(str, release)
    if _RELEASE.fullmatch(release) is None:
        return None
    icon = defensive_metadata.read_bytes(session, target, "/favicon.ico")
    if icon is None or hashlib.sha256(icon).hexdigest() != _ICON_SHA256:
        return None
    try:
        with defensive_http.send_anonymous(
            session,
            "GET",
            f"{target.origin}/api/system/asteroid-metadata-{uuid.uuid4().hex}",
            timeout=defensive_metadata.TIMEOUT_SECONDS,
        ) as response:
            if response.status_code != 404 or len(response.history) != 0:
                return None
    except requests.exceptions.RequestException:
        return None
    return release
