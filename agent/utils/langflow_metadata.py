"""Corroborate installed Langflow package metadata with its generated OpenAPI."""

from __future__ import annotations

import re
import typing

from agent import definitions
from agent.utils import defensive_metadata

VERSION_PATH = "/api/v1/version"
SCHEMA_PATH = "/openapi.json"
MAX_SCHEMA_BYTES = 2 * 1024 * 1024
_RELEASE = re.compile(r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}")


def read_release(
    session: definitions.HttpSession, target: definitions.Target
) -> str | None:
    """Require agreeing canonical backend versions in distinct response shapes."""
    installed = defensive_metadata.read_json(session, target, VERSION_PATH)
    if installed is None or set(installed) not in (
        {"version", "package"},
        {"version", "package", "main_version"},
    ):
        return None
    raw_release = installed["version"]
    if installed["package"] != "Langflow" or isinstance(raw_release, str) is False:
        return None
    release = typing.cast(str, raw_release)
    if _RELEASE.fullmatch(release) is None or release == "0.0.0":
        return None
    if "main_version" in installed and installed["main_version"] != release:
        return None
    schema = defensive_metadata.read_json(
        session, target, SCHEMA_PATH, max_response_bytes=MAX_SCHEMA_BYTES
    )
    if schema is None or schema.get("openapi") not in (
        "3.0.2",
        "3.0.3",
        "3.1.0",
        "3.1.1",
    ):
        return None
    info = schema.get("info")
    paths = schema.get("paths")
    if isinstance(info, dict) is False or isinstance(paths, dict) is False:
        return None
    info = typing.cast(dict[str, object], info)
    paths = typing.cast(dict[str, object], paths)
    version_route = paths.get(VERSION_PATH)
    if (
        info.get("title") != "Langflow"
        or info.get("version") != release
        or isinstance(version_route, dict) is False
    ):
        return None
    version_route = typing.cast(dict[str, object], version_route)
    if isinstance(version_route.get("get"), dict) is False:
        return None
    return release
