"""Source-reconstructed Gotenberg backend version transport and identity tests."""

from __future__ import annotations

import pathlib

import pytest
import requests
import requests_mock as req_mock

from agent import definitions
from agent.utils import defensive_metadata
from agent.utils import gotenberg_metadata as metadata

ORIGIN = "https://gotenberg.example:443"
TARGET = definitions.Target("https", "gotenberg.example", 443, "/private?token=secret")
FIXTURES = pathlib.Path(__file__).parent / "fixtures/gotenberg_metadata"
ROOT = (FIXTURES / "root.html").read_bytes()
VERSION = (FIXTURES / "version.txt").read_bytes()


def _serve(mock: req_mock.mocker.Mocker, version: bytes = VERSION) -> None:
    mock.get(req_mock.ANY, status_code=404)
    mock.get(f"{ORIGIN}/version", content=version)
    mock.get(f"{ORIGIN}/", content=ROOT)


@pytest.mark.parametrize("release", [b"8.20.0", b"8.30.1", b"8.31.0", b"8.32.0"])
def testGotenbergMetadata_whenSourceFormatMatches_returnsBackendRelease(
    requests_mock: req_mock.mocker.Mocker, release: bytes
) -> None:
    _serve(requests_mock, release)
    assert metadata.read_release(definitions.HttpSession(), TARGET) == release.decode()
    assert requests_mock.call_count == 3


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"snapshot",
        b"v8.30.1",
        b"8.30.1\n",
        b"8.30.1 ",
        b"8.30.1+fork",
        b"8.30.1-rc1",
        b"8.030.1",
        b"8.30.1-dev",
        b'{"version":"8.30.1"}',
        b"8.30.1 8.31.0",
        b"\xff",
        b"8.30." + b"1" * 5000,
    ],
)
def testGotenbergMetadata_whenReleaseAmbiguous_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, body: bytes
) -> None:
    _serve(requests_mock, body)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == 1


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"8.30.1",
        b"<title>Gotenberg</title>",
        b"<script>" + ROOT + b"</script>",
        ROOT + b"fork",
        ROOT + ROOT,
        b"\xff",
    ],
)
def testGotenbergMetadata_whenIdentityUnrelated_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, body: bytes
) -> None:
    _serve(requests_mock)
    requests_mock.get(f"{ORIGIN}/", content=body)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == 2


@pytest.mark.parametrize("path", ["/version", "/"])
@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 500])
def testGotenbergMetadata_whenMetadataUnavailable_doesNotFollowRedirects(
    requests_mock: req_mock.mocker.Mocker, path: str, status: int
) -> None:
    _serve(requests_mock)
    requests_mock.get(
        f"{ORIGIN}{path}",
        status_code=status,
        headers={"Location": "https://other.example/"},
    )
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == (1 if path == "/version" else 2)


@pytest.mark.parametrize("status", [200, 301, 302, 401, 403, 500])
def testGotenbergMetadata_whenControlUnexpected_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, status: int
) -> None:
    requests_mock.get(req_mock.ANY, status_code=status, content=ROOT)
    requests_mock.get(f"{ORIGIN}/version", content=VERSION)
    requests_mock.get(f"{ORIGIN}/", content=ROOT)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == 3


@pytest.mark.parametrize("path", ["/version", "/", "control"])
def testGotenbergMetadata_whenTransportFails_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, path: str
) -> None:
    if path == "control":
        requests_mock.get(req_mock.ANY, exc=requests.exceptions.Timeout)
        requests_mock.get(f"{ORIGIN}/version", content=VERSION)
        requests_mock.get(f"{ORIGIN}/", content=ROOT)
    else:
        _serve(requests_mock)
        requests_mock.get(f"{ORIGIN}{path}", exc=requests.exceptions.ConnectionError)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize("path", ["/version", "/"])
def testGotenbergMetadata_whenResponseOversized_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, path: str
) -> None:
    _serve(requests_mock)
    requests_mock.get(
        f"{ORIGIN}{path}", content=ROOT + b" " * defensive_metadata.MAX_RESPONSE_BYTES
    )
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


def testGotenbergMetadata_whenSessionHasCredentials_sendsOnlyAnonymousReads(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    _serve(requests_mock)
    session = definitions.HttpSession()
    session.auth = ("user", "password")
    session.cookies.set("session", "secret")
    session.headers.update({"Authorization": "Bearer secret", "X-API-Key": "secret"})
    session.params = {"token": "secret"}
    assert metadata.read_release(session, TARGET) == "8.30.1"
    assert requests_mock.call_count == 3
    for request in requests_mock.request_history:
        assert request.method == "GET"
        assert request.body is None
        assert request.url.startswith(ORIGIN + "/")
        assert "?" not in request.url
        assert "/forms/" not in request.url
        assert "/debug" not in request.url
        assert "Authorization" not in request.headers
        assert "Cookie" not in request.headers
        assert "X-API-Key" not in request.headers
    assert requests_mock.request_history[-1].path.startswith("/asteroid-metadata-")


def testGotenbergMetadata_whenTargetUnsupported_makesNoRequests(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    assert (
        metadata.read_release(
            definitions.HttpSession(), definitions.Target("ftp", "host", 21)
        )
        is None
    )
    assert requests_mock.call_count == 0
