"""Source-backed SiYuan metadata, boundary, transport and selection tests."""

from __future__ import annotations

import json
import pathlib
import typing

import pytest
import requests
import requests_mock as req_mock

from agent import definitions
from agent.utils import defensive_metadata
from agent.utils import siyuan_metadata as metadata

ORIGIN = "https://siyuan.example:443"
TARGET = definitions.Target("https", "siyuan.example", 443, "/private?token=secret")
FIXTURES = pathlib.Path(__file__).parents[1] / "exploits/fixtures/cve_2026_69084"
ROOT = (FIXTURES / "icon.png").read_bytes()
VERSION = (FIXTURES / "version.json").read_bytes()


def _serve(mock: req_mock.mocker.Mocker, version: bytes | str = VERSION) -> None:
    mock.get(req_mock.ANY, status_code=404)
    mock.get(
        f"{ORIGIN}/api/system/version",
        content=(
            json.dumps({"code": 0, "msg": "", "data": version}).encode()
            if isinstance(version, str) is True
            else typing.cast(bytes, version)
        ),
    )
    mock.get(f"{ORIGIN}/favicon.ico", content=ROOT)


@pytest.mark.parametrize("release", [b"3.7.0", b"3.7.2", b"3.7.3", b"3.8.0"])
def testReadRelease_whenSourceFormatMatches_returnsBackendRelease(
    requests_mock: req_mock.mocker.Mocker, release: bytes
) -> None:
    _serve(requests_mock, release.decode())
    assert metadata.read_release(definitions.HttpSession(), TARGET) == release.decode()
    assert requests_mock.call_count == 3


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"snapshot",
        b"v3.7.2",
        b"3.7.2\n",
        b"3.7.2 ",
        b"3.7.2+fork",
        b"3.7.2-rc1",
        b"3.07.2",
        b"3.7.2-dev",
        b'{"version":"3.7.0"}',
        b"3.7.2 3.7.3",
        b"\xff",
        b"3.7." + b"1" * 5000,
    ],
)
def testReadRelease_whenReleaseAmbiguous_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, body: bytes
) -> None:
    _serve(requests_mock, body)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == 1


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"3.7.0",
        b"<title>SiYuan</title>",
        b"<script>" + ROOT + b"</script>",
        ROOT + b"fork",
        ROOT + ROOT,
        b"\xff",
    ],
)
def testReadRelease_whenIdentityUnrelated_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, body: bytes
) -> None:
    _serve(requests_mock)
    requests_mock.get(f"{ORIGIN}/favicon.ico", content=body)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == 2


@pytest.mark.parametrize("path", ["/api/system/version", "/favicon.ico"])
@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 500])
def testReadRelease_whenMetadataUnavailable_doesNotFollowRedirects(
    requests_mock: req_mock.mocker.Mocker, path: str, status: int
) -> None:
    _serve(requests_mock)
    requests_mock.get(
        f"{ORIGIN}{path}",
        status_code=status,
        headers={"Location": "https://other.example/"},
    )
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == (1 if path == "/api/system/version" else 2)


@pytest.mark.parametrize("status", [200, 301, 302, 401, 403, 500])
def testReadRelease_whenControlUnexpected_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, status: int
) -> None:
    requests_mock.get(req_mock.ANY, status_code=status, content=ROOT)
    requests_mock.get(f"{ORIGIN}/api/system/version", content=VERSION)
    requests_mock.get(f"{ORIGIN}/favicon.ico", content=ROOT)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == 3


@pytest.mark.parametrize("path", ["/api/system/version", "/favicon.ico", "control"])
def testReadRelease_whenTransportFails_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, path: str
) -> None:
    if path == "control":
        requests_mock.get(req_mock.ANY, exc=requests.exceptions.Timeout)
        requests_mock.get(f"{ORIGIN}/api/system/version", content=VERSION)
        requests_mock.get(f"{ORIGIN}/favicon.ico", content=ROOT)
    else:
        _serve(requests_mock)
        requests_mock.get(f"{ORIGIN}{path}", exc=requests.exceptions.ConnectionError)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize("path", ["/api/system/version", "/favicon.ico"])
def testReadRelease_whenResponseOversized_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, path: str
) -> None:
    _serve(requests_mock)
    requests_mock.get(
        f"{ORIGIN}{path}", content=ROOT + b" " * defensive_metadata.MAX_RESPONSE_BYTES
    )
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


def testReadRelease_whenSessionHasCredentials_sendsOnlyAnonymousReads(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    _serve(requests_mock)
    session = definitions.HttpSession()
    session.auth = ("user", "password")
    session.cookies.set("session", "secret")
    session.headers.update({"Authorization": "Bearer secret", "X-API-Key": "secret"})
    session.params = {"token": "secret"}
    assert metadata.read_release(session, TARGET) == "3.7.2"
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
    assert requests_mock.request_history[-1].path.startswith(
        "/api/system/asteroid-metadata-"
    )


def testReadRelease_whenTargetUnsupported_makesNoRequests(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    assert (
        metadata.read_release(
            definitions.HttpSession(), definitions.Target("ftp", "host", 21)
        )
        is None
    )
    assert requests_mock.call_count == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("code", True),
        ("code", 0.0),
        ("code", -1),
        ("msg", "denied"),
        ("msg", None),
        ("data", 372),
        ("data", None),
        ("data", {"version": "3.7.2"}),
        ("latest_version", "3.7.2"),
    ],
)
def testReadRelease_whenEnvelopeUnrelated_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, field: str, value: object
) -> None:
    body = json.loads(VERSION)
    body[field] = value
    _serve(requests_mock, json.dumps(body).encode())
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b"[]",
        b"null",
        VERSION.replace(b'"data":', b'"data":"3.7.3","data":'),
        VERSION.replace(b'"code":', b'"code":-1,"code":'),
        b'{"result":' + VERSION + b"}",
        VERSION + VERSION,
    ],
)
def testReadRelease_whenJSONConflicting_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, body: bytes
) -> None:
    _serve(requests_mock, body)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == 1


@pytest.mark.parametrize("field", ["code", "msg", "data"])
def testReadRelease_whenFieldMissing_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, field: str
) -> None:
    body = json.loads(VERSION)
    del body[field]
    _serve(requests_mock, json.dumps(body).encode())
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None


@pytest.mark.parametrize(
    "release",
    [
        "3.7.2-rc1",
        "3.7.2+fork",
        "3.7.2-dev",
        "3.07.2",
        "v3.7.2",
        "3.7.2\n",
        "3.7." + "1" * 5000,
    ],
)
def testReadRelease_whenReleaseFieldUnsupported_returnsInconclusive(
    requests_mock: req_mock.mocker.Mocker, release: str
) -> None:
    _serve(requests_mock, release)
    assert metadata.read_release(definitions.HttpSession(), TARGET) is None
    assert requests_mock.call_count == 1
