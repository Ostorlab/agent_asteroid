"""Source-backed public-path tests for the Flowise installed-release reader."""

from __future__ import annotations

import json
import pathlib

import pytest
import requests
import requests_mock as req_mock

from agent import definitions
from agent.utils import defensive_metadata as metadata_limits
from agent.utils import flowise_metadata

ORIGIN = "https://flowise.example:443"
TARGET = definitions.Target("https", "flowise.example", 443, "/ignored?secret=private")
FIXTURES = (
    pathlib.Path(__file__).parents[1] / "exploits" / "fixtures" / "cve_2025_59528"
)
HOMEPAGE = (FIXTURES / "editor-index.html").read_text()
VERSION = (FIXTURES / "version-3.0.5.json").read_text()


def _serve(
    mock: req_mock.mocker.Mocker,
    body: str = VERSION,
    homepage: str = HOMEPAGE,
) -> None:
    mock.get(req_mock.ANY, text=homepage)
    mock.get(f"{ORIGIN}/", text=homepage)
    mock.get(f"{ORIGIN}/api/v1/version", text=body)


@pytest.mark.parametrize("label", ["3.0.5", "3.0.6"])
def testReadRelease_whenSourceBackedMetadata_returnsServerRelease(
    requests_mock: req_mock.mocker.Mocker, label: str
) -> None:
    _serve(requests_mock, VERSION.replace("3.0.5", label))
    with definitions.HttpSession() as session:
        assert flowise_metadata.read_release(session, TARGET) == label


@pytest.mark.parametrize(
    "body",
    [
        "{}",
        "[]",
        "{",
        '{"version":null}',
        '{"version":true}',
        '{"version":305}',
        '{"version":"3.0.5","version":"3.0.5"}',
        '{"version":"3.0.5","latest":"3.0.6"}',
        '{"latestVersion":"3.0.5"}',
        '{"data":{"version":"3.0.5"}}',
    ],
)
def testReadRelease_whenVersionShapeInvalid_returnsNone(
    requests_mock: req_mock.mocker.Mocker, body: str
) -> None:
    _serve(requests_mock, body)
    with definitions.HttpSession() as session:
        assert flowise_metadata.read_release(session, TARGET) is None


@pytest.mark.parametrize(
    "label",
    [
        "",
        "3.0",
        "v3.0.5",
        "03.0.5",
        "3.00.5",
        "3.0.05",
        "3.0.5.0",
        "3.0.5-rc.1",
        "3.0.5+fork",
        "3.0.5-dev",
        "3.0.5\n",
        " 3.0.5",
    ],
)
def testReadRelease_whenVersionNoncanonical_returnsNone(
    requests_mock: req_mock.mocker.Mocker, label: str
) -> None:
    _serve(requests_mock, json.dumps({"version": label}))
    with definitions.HttpSession() as session:
        assert flowise_metadata.read_release(session, TARGET) is None


@pytest.mark.parametrize(
    "homepage",
    [
        "",
        "<title>Flowise - Build AI Agents, Visually</title>",
        HOMEPAGE.replace("Flowise - Build AI Agents, Visually", "Fork UI"),
        HOMEPAGE.replace('content="flowiseai.com"', 'content="other.example"'),
        HOMEPAGE + HOMEPAGE,
        HOMEPAGE.replace(
            'property="og:site_name"', 'property="og:site_name" property="other"'
        ),
    ],
)
def testReadRelease_whenProductIdentityMissingOrAmbiguous_returnsNone(
    requests_mock: req_mock.mocker.Mocker, homepage: str
) -> None:
    _serve(requests_mock, homepage=homepage)
    with definitions.HttpSession() as session:
        assert flowise_metadata.read_release(session, TARGET) is None


@pytest.mark.parametrize("path", ["/", "/api/v1/version"])
@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 500])
def testReadRelease_whenMetadataFailsOrRedirects_returnsNoneWithoutFollowing(
    requests_mock: req_mock.mocker.Mocker, path: str, status: int
) -> None:
    _serve(requests_mock)
    requests_mock.get(
        f"{ORIGIN}{path}",
        status_code=status,
        headers={"Location": "https://external.example/"},
    )
    with definitions.HttpSession() as session:
        assert flowise_metadata.read_release(session, TARGET) is None
    assert all(
        request.hostname == "flowise.example"
        for request in requests_mock.request_history
    )


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.Timeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.ChunkedEncodingError,
    ],
)
def testReadRelease_whenTransportFails_returnsNone(
    requests_mock: req_mock.mocker.Mocker,
    error: type[requests.exceptions.RequestException],
) -> None:
    _serve(requests_mock)
    requests_mock.get(f"{ORIGIN}/api/v1/version", exc=error)
    with definitions.HttpSession() as session:
        assert flowise_metadata.read_release(session, TARGET) is None


@pytest.mark.parametrize("path", ["/", "/api/v1/version"])
def testReadRelease_whenBodyOversized_returnsNone(
    requests_mock: req_mock.mocker.Mocker, path: str
) -> None:
    _serve(requests_mock)
    requests_mock.get(
        f"{ORIGIN}{path}", content=b" " * (metadata_limits.MAX_RESPONSE_BYTES + 1)
    )
    with definitions.HttpSession() as session:
        assert flowise_metadata.read_release(session, TARGET) is None


@pytest.mark.parametrize("control", ['{"version":"3.0.5"}', "", "other HTML"])
def testReadRelease_whenControlDoesNotMatchSourceFallback_returnsNone(
    requests_mock: req_mock.mocker.Mocker, control: str
) -> None:
    requests_mock.get(req_mock.ANY, text=control)
    requests_mock.get(f"{ORIGIN}/", text=HOMEPAGE)
    requests_mock.get(f"{ORIGIN}/api/v1/version", json={"version": "3.0.5"})
    with definitions.HttpSession() as session:
        assert flowise_metadata.read_release(session, TARGET) is None


def testReadRelease_whenSessionContainsSecrets_sendsOnlyAnonymousSameOriginGETs(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    _serve(requests_mock)
    with definitions.HttpSession() as session:
        session.auth = ("private", "private")
        session.headers.update(
            {"Authorization": "Bearer private", "X-Api-Key": "private"}
        )
        session.cookies.set("session", "private")
        assert flowise_metadata.read_release(session, TARGET) == "3.0.5"
    assert len(requests_mock.request_history) == 3
    for request in requests_mock.request_history:
        assert request.method == "GET"
        assert request.body is None
        assert request.hostname == "flowise.example"
        assert "private" not in request.url
        assert "Authorization" not in request.headers
        assert "Cookie" not in request.headers
        assert "X-Api-Key" not in request.headers


def testReadRelease_whenSchemeUnsupported_sendsNothing(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    with definitions.HttpSession() as session:
        assert (
            flowise_metadata.read_release(
                session, definitions.Target("ssh", "flowise.example", 22)
            )
            is None
        )
    assert requests_mock.call_count == 0
