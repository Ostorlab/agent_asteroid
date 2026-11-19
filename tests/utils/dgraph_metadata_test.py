"""Direct Dgraph reader tests using the existing source-backed fixture."""

from __future__ import annotations

import pathlib

import pytest
import requests_mock as req_mock

from agent import definitions
from agent.utils import dgraph_metadata

FIXTURES = pathlib.Path(__file__).parents[1] / "exploits/fixtures/cve_2026_34976"
HEALTH = (FIXTURES / "health.json").read_text()
BANNER = (FIXTURES / "root.txt").read_text().removesuffix("\n")
ORIGIN = "https://dgraph.example:443"


@pytest.mark.parametrize(
    "release", ["v24.0.0", "v24.1.7", "v24.1.8", "v25.0.0", "v25.3.2", "v25.3.3"]
)
def testReadRelease_whenVendorFormatMatches_returnsLocalAlphaRelease(
    requests_mock: req_mock.mocker.Mocker, release: str
) -> None:
    requests_mock.get(req_mock.ANY, status_code=404)
    requests_mock.get(f"{ORIGIN}/health", text=HEALTH.replace("v25.3.0", release))
    requests_mock.get(f"{ORIGIN}/", text=BANNER)
    target = definitions.Target("https", "dgraph.example", 443)
    assert (
        dgraph_metadata.read_release(definitions.HttpSession(), target) == release[1:]
    )
    assert requests_mock.call_count == 3
