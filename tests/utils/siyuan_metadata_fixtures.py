"""Shared source-backed SiYuan responses used by detector and reader tests."""

from __future__ import annotations

import json
import pathlib
import typing

import requests_mock as req_mock

from agent import definitions

ORIGIN = "https://siyuan.example:443"
TARGET = definitions.Target("https", "siyuan.example", 443, "/private?token=secret")
_FIXTURES = pathlib.Path(__file__).parents[1] / "exploits/fixtures/cve_2026_69084"
ICON = (_FIXTURES / "icon.png").read_bytes()
VERSION = (_FIXTURES / "version.json").read_bytes()


def serve(mock: req_mock.mocker.Mocker, version: bytes | str = VERSION) -> None:
    """Serve the kernel envelope, product icon and absent-route control."""
    mock.get(req_mock.ANY, status_code=404)
    content = (
        json.dumps({"code": 0, "msg": "", "data": version}).encode()
        if isinstance(version, str) is True
        else typing.cast(bytes, version)
    )
    mock.get(f"{ORIGIN}/api/system/version", content=content)
    mock.get(f"{ORIGIN}/favicon.ico", content=ICON)
