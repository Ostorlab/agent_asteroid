"""Bounded anonymous installed-JAR metadata for Stirling-PDF detectors."""

from __future__ import annotations

import re
import typing
import uuid

import requests

from agent import definitions
from agent.exploits import defensive_http
from agent.utils import defensive_metadata

METADATA_PATH = "/v1/api-docs"
MAX_SCHEMA_BYTES = 2 * 1024 * 1024
_RELEASE = re.compile(r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}")
_DESCRIPTION = (
    "API documentation for all Server-Side processing.\n"
    "Please note some functionality might be UI only and missing from here."
)


def read_release(
    session: definitions.HttpSession,
    target: definitions.Target,
    *,
    operation_path: str = "/api/v1/convert/html/pdf",
    schema_versions: tuple[str, ...] = ("3.0.1", "3.1.0"),
) -> str | None:
    """Read installed JAR metadata and corroborate a declared POST operation."""
    schema = defensive_metadata.read_json(
        session, target, METADATA_PATH, max_response_bytes=MAX_SCHEMA_BYTES
    )
    if schema is None or schema.get("openapi") not in schema_versions:
        return None
    info = schema.get("info")
    paths = schema.get("paths")
    if isinstance(info, dict) is False or isinstance(paths, dict) is False:
        return None
    info = typing.cast(dict[str, object], info)
    paths = typing.cast(dict[str, object], paths)
    if (
        info.get("title") != "Stirling PDF API"
        or info.get("description") != _DESCRIPTION
    ):
        return None
    raw_release = info.get("version")
    if isinstance(raw_release, str) is False:
        return None
    release = typing.cast(str, raw_release)
    # Upstream substitutes 1.0.0 when the running JAR manifest version is absent.
    if _RELEASE.fullmatch(release) is None or release in ("0.0.0", "1.0.0"):
        return None
    conversion = paths.get(operation_path)
    if isinstance(conversion, dict) is False:
        return None
    conversion = typing.cast(dict[str, object], conversion)
    if isinstance(conversion.get("post"), dict) is False:
        return None
    try:
        with defensive_http.send_anonymous(
            session,
            "GET",
            f"{target.origin}/api/v1/asteroid-metadata-{uuid.uuid4().hex}",
            timeout=defensive_metadata.TIMEOUT_SECONDS,
        ) as response:
            if response.status_code != 404 or len(response.history) != 0:
                return None
    except requests.exceptions.RequestException:
        return None
    return release
