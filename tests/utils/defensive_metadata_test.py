"""Shared metadata transport conformance across defensive HTTP detectors."""

from __future__ import annotations

import io
import json
import pathlib
from unittest import mock

import pytest
import requests
import requests_mock as req_mock

from agent import definitions as agent_definitions
from agent.exploits import cve_2023_49105 as owncloud_detector
from agent.exploits import cve_2026_49869 as kestra_detector
from agent.exploits import cve_2026_59822 as litellm_mcp_detector
from agent.exploits import cve_2026_96652 as plex_detector
from agent.exploits import cve_2026_110447 as collabora_detector
from agent.exploits import cve_2026_114612 as litellm_detector
from agent.exploits import cve_2026_115547 as okta_detector
from agent.exploits import kiloview_2026_10 as kiloview_detector
from agent.utils import defensive_metadata

ORIGIN = "https://metadata.example:443"
TARGET = agent_definitions.Target(
    "https", "metadata.example", 443, "/ignored?secret=value"
)


def testReadJson_whenAcceptProvided_requestsJsonWithoutSessionHeaders(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    requests_mock.get(f"{ORIGIN}/identity", json={"size": 0})
    session = requests.Session()
    session.headers["Accept"] = "text/xml"
    session.headers["Authorization"] = "Bearer private"
    result = defensive_metadata.read_json(
        session, TARGET, "/identity", accept="application/json"
    )
    assert result == {"size": 0}
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.headers["Accept"] == "application/json"
    assert "Authorization" not in requests_mock.last_request.headers


def testReadJson_whenAcceptOmitted_preservesAnonymousDefault(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    requests_mock.get(f"{ORIGIN}/version", json={"version": "1.0.0"})
    assert defensive_metadata.read_json(requests.Session(), TARGET, "/version") == {
        "version": "1.0.0"
    }
    assert requests_mock.last_request is not None
    assert "Accept" not in requests_mock.last_request.headers


def _schema(release: object = "1.103.0") -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "info": {"title": "LiteLLM API", "version": release},
        "paths": {"/health/readiness": {"get": {}}, "/key/generate": {"post": {}}},
    }


def _xml(release: str = "26.4.302", app_name: str = "richdocumentscode") -> str:
    return f"<info><id>{app_name}</id><version>{release}</version></info>"


def _kiloview(
    release: object = "1.21.0008", product: object = "E3", oem: object = "kiloview"
) -> dict[str, object]:
    return {
        "result": "ok",
        "data": {
            "version": {
                "softwareVersion": release,
                "product": product,
                "oem": oem,
                "serialNumber": "private-serial",
            }
        },
    }


def _footer(release: str = "2026.10.1") -> str:
    return f"<html><h1>Okta Access Gateway</h1><footer>Copyright © 2026 Okta, Inc. Version {release} OS Version: 9.4</footer></html>"


NEW_JSON_CASES = [
    (
        litellm_mcp_detector.CVE202659822Exploit,
        "/openapi.json",
        json.dumps(_schema("1.83.9")),
    ),
    (
        kestra_detector.CVE202649869Exploit,
        "/api/v1/configs",
        json.dumps(
            {
                "version": "1.3.20",
                "edition": "OSS",
                "isTaskRunEnabled": True,
                "isBasicAuthInitialized": True,
                "systemNamespace": "private-namespace",
                "pluginsHash": 42,
                "uuid": "private-instance",
            }
        ),
    ),
    (
        plex_detector.CVE202696652Exploit,
        "/identity",
        json.dumps(
            {
                "MediaContainer": {
                    "size": 0,
                    "claimed": True,
                    "machineIdentifier": "private-machine",
                    "version": "1.43.3.10860-abcdef",
                }
            }
        ),
    ),
    (
        owncloud_detector.CVE202349105Exploit,
        "/status.php",
        json.dumps(
            {
                "installed": True,
                "maintenance": False,
                "needsDbUpgrade": False,
                "version": "10.13.0.4",
                "versionstring": "10.13.0",
                "product": "ownCloud",
                "productname": "ownCloud",
                "hostname": "private-hostname",
            }
        ),
    ),
]


CASES = [
    (litellm_detector.CVE2026114612Exploit, "/openapi.json", json.dumps(_schema())),
    (
        collabora_detector.CVE2026110447Exploit,
        "/apps/richdocumentscode/appinfo/info.xml",
        _xml(),
    ),
    (
        kiloview_detector.Kiloview202610Exploit,
        "/api/systemctrl/system/getSystemInfo",
        json.dumps(_kiloview()),
    ),
    (okta_detector.CVE2026115547Exploit, "/", _footer()),
] + NEW_JSON_CASES


@pytest.mark.parametrize("factory,path,body", CASES)
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 401, 403, 404, 500])
def testCriticalHTTP_whenErrorOrRedirect_reportsNothing(
    requests_mock: req_mock.mocker.Mocker,
    factory: type[agent_definitions.Exploit],
    path: str,
    body: str,
    status: int,
) -> None:
    requests_mock.get(
        req_mock.ANY,
        text=body,
        status_code=status,
        headers={
            "Location": "https://external.example/",
            "WWW-Authenticate": 'Basic realm="private"',
        },
    )
    detector = factory()
    assert detector.accept(TARGET) is False
    assert detector.check(TARGET) == []
    assert all(
        request.hostname == "metadata.example"
        for request in requests_mock.request_history
    )


@pytest.mark.parametrize("factory,path,body", CASES)
def testCriticalHTTP_whenSessionHasSecrets_sendsOnlyAnonymousReads(
    requests_mock: req_mock.mocker.Mocker,
    factory: type[agent_definitions.Exploit],
    path: str,
    body: str,
) -> None:
    requests_mock.get(req_mock.ANY, status_code=404)
    requests_mock.get(f"{ORIGIN}{path}", text=body)
    detector = factory()
    detector.session.auth = ("private-username", "private-password")
    detector.session.headers.update(
        {"Authorization": "Bearer private", "X-Api-Key": "private"}
    )
    detector.session.cookies.set("session", "private")
    findings = detector.check(TARGET)
    assert len(findings) == 1
    for secret in ("secret=value", "private"):
        assert secret not in repr(findings)
    for request in requests_mock.request_history:
        assert request.method == "GET"
        assert request.body is None
        assert "secret=value" not in request.url
        assert "Authorization" not in request.headers
        assert "X-Api-Key" not in request.headers
        assert "Cookie" not in request.headers


@pytest.mark.parametrize("factory,path,body", CASES)
def testCriticalHTTP_whenUnsupportedScheme_sendsNothing(
    requests_mock: req_mock.mocker.Mocker,
    factory: type[agent_definitions.Exploit],
    path: str,
    body: str,
) -> None:
    detector = factory()
    target = agent_definitions.Target("ssh", "metadata.example", 22)
    assert detector.accept(target) is False
    assert detector.check(target) == []
    assert requests_mock.call_count == 0


@pytest.mark.parametrize("factory,path,body", CASES)
def testCriticalHTTP_whenResponseExceedsCap_closesWithoutFinding(
    factory: type[agent_definitions.Exploit], path: str, body: str
) -> None:
    assert defensive_metadata.MAX_RESPONSE_BYTES == 262144
    response_cap = (
        8 * 1024 * 1024
        if factory is litellm_mcp_detector.CVE202659822Exploit
        else 262144
    )
    detector = factory()
    response = mock.MagicMock(spec=requests.Response)
    response.status_code = 200
    response.history = []
    response.__enter__.return_value = response
    response.iter_content.side_effect = lambda **kwargs: iter(
        [b" " * response_cap, body.encode()]
    )
    with mock.patch.object(
        detector.session.get_adapter(ORIGIN), "send", return_value=response
    ):
        assert detector.check(TARGET) == []
    assert response.__exit__.call_count >= 1


@pytest.mark.parametrize("factory,path,body", CASES)
@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.ChunkedEncodingError,
    ],
)
def testCriticalHTTP_whenConnectionFails_reportsNothing(
    requests_mock: req_mock.mocker.Mocker,
    factory: type[agent_definitions.Exploit],
    path: str,
    body: str,
    error: type[requests.exceptions.RequestException],
) -> None:
    requests_mock.get(req_mock.ANY, exc=error)
    detector = factory()
    assert detector.accept(TARGET) is False
    assert detector.check(TARGET) == []


@pytest.mark.parametrize("factory,path,body", NEW_JSON_CASES)
def testWebMetadata_whenNetrcAvailable_sendsNoAmbientCredentials(
    requests_mock: req_mock.Mocker,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    factory: type[agent_definitions.Exploit],
    path: str,
    body: str,
) -> None:
    netrc = tmp_path / "credentials.netrc"
    netrc.write_text(
        "machine metadata.example login netrc-user password private-netrc\n"
    )
    monkeypatch.setenv("NETRC", str(netrc))
    requests_mock.get(f"{ORIGIN}{path}", text=body)
    detector = factory()
    detector.session.trust_env = True
    assert detector.accept(TARGET) is True
    assert len(detector.check(TARGET)) == 1
    assert requests_mock.call_count == 2
    for request in requests_mock.request_history:
        assert "Authorization" not in request.headers
        assert "Cookie" not in request.headers
        assert request.url == f"{ORIGIN}{path}"
        assert request.method == "GET"
        assert request.body is None


@pytest.mark.parametrize("factory,path,body", NEW_JSON_CASES)
@pytest.mark.parametrize("malformed", [b"{", b"[]", b"null", b"\xff", b'{"version":'])
def testWebMetadata_whenJsonMalformed_reportsNothing(
    requests_mock: req_mock.Mocker,
    factory: type[agent_definitions.Exploit],
    path: str,
    body: str,
    malformed: bytes,
) -> None:
    requests_mock.get(f"{ORIGIN}{path}", content=malformed)
    detector = factory()
    assert detector.accept(TARGET) is False
    assert detector.check(TARGET) == []


@pytest.mark.parametrize("factory,path,body", NEW_JSON_CASES)
def testWebMetadata_whenVersionKeyDuplicated_rejectsConflictingEvidence(
    requests_mock: req_mock.Mocker,
    factory: type[agent_definitions.Exploit],
    path: str,
    body: str,
) -> None:
    conflicting = body.replace('"version":', '"version":"99.0.0","version":', 1)
    requests_mock.get(f"{ORIGIN}{path}", text=conflicting)
    detector = factory()
    assert detector.accept(TARGET) is False
    assert detector.check(TARGET) == []


@pytest.mark.parametrize("factory,path,body", NEW_JSON_CASES)
def testWebMetadata_whenReadingBody_usesBoundedStreamingAndClosesResponse(
    factory: type[agent_definitions.Exploit], path: str, body: str
) -> None:
    detector = factory()
    response = requests.Response()
    response.status_code = 200
    response.raw = io.BytesIO(body.encode())
    with (
        mock.patch.object(
            detector.session.get_adapter(ORIGIN), "send", return_value=response
        ) as send,
        mock.patch.object(response, "close", wraps=response.close) as close,
    ):
        assert len(detector.check(TARGET)) == 1
    assert send.call_count == 1
    assert send.call_args.kwargs["timeout"] == 5
    assert send.call_args.kwargs["stream"] is True
    assert send.call_args.kwargs["cert"] is None
    close.assert_called_once()
