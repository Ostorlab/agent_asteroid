"""Validate Crawl4AI metadata without calling the crawler or eval paths."""

from __future__ import annotations

import json
import pathlib

import pytest
import requests
import requests_mock as req_mock

from agent import definitions
from agent.utils import crawl4ai_metadata as metadata
from agent.utils import defensive_metadata

ORIGIN = "https://crawl4ai.example:443"
TARGET = definitions.Target("https", "crawl4ai.example", 443, "/private?token=secret")
FIXTURES = pathlib.Path(__file__).parent / "fixtures/crawl4ai_metadata"
LOGO = (FIXTURES / "logo.png").read_bytes()
HEALTH = (FIXTURES / "health.json").read_bytes()


def _serve(mock: req_mock.mocker.Mocker, body: bytes = HEALTH) -> None:
    mock.get(req_mock.ANY, status_code=404)
    mock.get(f"{ORIGIN}/health", content=body)
    mock.get(f"{ORIGIN}/static/assets/crawl4ai-logo.png", content=LOGO)


@pytest.mark.parametrize("release", ["0.8.5", "0.8.6", "0.8.7", "0.9.0"])
def testCrawl4AIMetadata_whenSourceFormatMatches_returnsPackageRelease(
    requests_mock: req_mock.mocker.Mocker, release: str
) -> None:
    _serve(requests_mock, HEALTH.replace(b"0.8.6", release.encode()))
    assert metadata.read_release(definitions.HttpSession(), TARGET) == release
    assert requests_mock.call_count == 3


@pytest.mark.parametrize(
    "release",
    [
        "0.8.4",
        "0.5.1-d1",
        "v0.8.6",
        "0.08.6",
        "0.8.6+fork",
        "0.8.6-dev",
        "0.8.6rc1",
        "0.8.6\n",
        "",
        "0.8." + "1" * 5000,
    ],
)
def testCrawl4AIMetadata_whenReleaseUnsupported_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, release: str
) -> None:
    body = json.loads(HEALTH)
    body["version"] = release
    _serve(requests_mock, json.dumps(body).encode())
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "error"),
        ("status", True),
        ("timestamp", True),
        ("timestamp", "1770000000"),
        ("timestamp", 0),
        ("timestamp", -1),
        ("timestamp", 253402300800),
        ("timestamp", 10**500),
        ("version", 0.86),
        ("version", None),
        ("latest_version", "0.8.6"),
    ],
)
def testCrawl4AIMetadata_whenEnvelopeUnsupported_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, field: str, value: object
) -> None:
    body = json.loads(HEALTH)
    body[field] = value
    _serve(requests_mock, json.dumps(body).encode())
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"{}",
        b"[]",
        b"null",
        b"Crawl4AI 0.8.6",
        b'{"status":"ok","timestamp":NaN,"version":"0.8.6"}',
        b'{"status":"ok","timestamp":1,"version":"0.8.6","version":"0.8.7"}',
        HEALTH + HEALTH,
    ],
)
def testCrawl4AIMetadata_whenJSONInvalid_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, body: bytes
) -> None:
    _serve(requests_mock, body)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize("field", ["status", "timestamp", "version"])
def testCrawl4AIMetadata_whenFieldMissing_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, field: str
) -> None:
    body = json.loads(HEALTH)
    del body[field]
    _serve(requests_mock, json.dumps(body).encode())
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize("path", ["/health", "/static/assets/crawl4ai-logo.png"])
@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 500])
def testCrawl4AIMetadata_whenUnavailable_doesNotFollowRedirects(
    requests_mock: req_mock.mocker.Mocker, path: str, status: int
) -> None:
    _serve(requests_mock)
    requests_mock.get(
        f"{ORIGIN}{path}",
        status_code=status,
        headers={"Location": "https://unrelated.example/"},
    )
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == (1 if path == "/health" else 2)


@pytest.mark.parametrize("path", ["/health", "/static/assets/crawl4ai-logo.png"])
def testCrawl4AIMetadata_whenResponseOversized_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, path: str
) -> None:
    _serve(requests_mock)
    requests_mock.get(
        f"{ORIGIN}{path}", content=b" " * (defensive_metadata.MAX_RESPONSE_BYTES + 1)
    )
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize("body", [b"", b"Crawl4AI", LOGO + b"fork"])
def testCrawl4AIMetadata_whenIdentityDiffers_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, body: bytes
) -> None:
    _serve(requests_mock)
    requests_mock.get(f"{ORIGIN}/static/assets/crawl4ai-logo.png", content=body)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize("status", [200, 301, 302, 401, 403, 500])
def testCrawl4AIMetadata_whenControlUnexpected_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, status: int
) -> None:
    requests_mock.get(req_mock.ANY, status_code=status)
    requests_mock.get(f"{ORIGIN}/health", content=HEALTH)
    requests_mock.get(f"{ORIGIN}/static/assets/crawl4ai-logo.png", content=LOGO)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize(
    "path", ["/health", "/static/assets/crawl4ai-logo.png", "control"]
)
def testCrawl4AIMetadata_whenTransportFails_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, path: str
) -> None:
    if path == "control":
        requests_mock.get(req_mock.ANY, exc=requests.exceptions.Timeout)
        requests_mock.get(f"{ORIGIN}/health", content=HEALTH)
        requests_mock.get(f"{ORIGIN}/static/assets/crawl4ai-logo.png", content=LOGO)
    else:
        _serve(requests_mock)
        requests_mock.get(f"{ORIGIN}{path}", exc=requests.exceptions.ConnectionError)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
