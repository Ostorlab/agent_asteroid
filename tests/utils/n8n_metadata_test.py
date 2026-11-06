"""The shared reader returns installed releases independently of CVE boundaries."""

from __future__ import annotations

import pathlib

import pytest
import requests_mock as req_mock
from packaging import version

from agent import definitions
from agent.utils import n8n_metadata


@pytest.mark.parametrize("status", [404, 410])
def testReadRelease_whenLegacySourceMetadataAndMissingControl_returnsInstalledRelease(
    requests_mock: req_mock.mocker.Mocker, status: int
) -> None:
    fixtures = (
        pathlib.Path(__file__).parents[1] / "exploits" / "fixtures" / "cve_2026_21877"
    )
    target = definitions.Target("https", "n8n.example", 443)
    requests_mock.get(req_mock.ANY, status_code=status)
    requests_mock.get(
        f"{target.origin}/rest/settings",
        text=(fixtures / "settings-0.123.0.json").read_text(),
    )
    requests_mock.get(
        f"{target.origin}/",
        text=(fixtures / "editor-index-0.123.0.html").read_text(),
    )
    with definitions.HttpSession() as session:
        assert n8n_metadata.read_release(session, target) == version.Version("0.123.0")
    assert len(requests_mock.request_history) == 3
