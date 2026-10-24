"""Shared metadata transport conformance across the four HTTP detectors."""

from __future__ import annotations

import json
from unittest import mock

import pytest
import requests
import requests_mock as req_mock

from agent import definitions as agent_definitions
from agent.exploits import cve_2026_110447 as collabora_detector
from agent.exploits import cve_2026_114612 as litellm_detector
from agent.exploits import cve_2026_115547 as okta_detector
from agent.exploits import kiloview_2026_10 as kiloview_detector
from agent.utils import defensive_metadata

ORIGIN = "https://metadata.example:443"
TARGET = agent_definitions.Target(
    "https", "metadata.example", 443, "/ignored?secret=value"
)


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
]


@pytest.mark.parametrize("factory,path,body", CASES)
@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 500])
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
        headers={"Location": "https://external.example/"},
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
    detector.session.auth = ("username", "password")
    detector.session.headers.update(
        {"Authorization": "Bearer private", "X-Api-Key": "private"}
    )
    detector.session.cookies.set("session", "private")
    assert len(detector.check(TARGET)) == 1
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
    detector = factory()
    response = mock.MagicMock(spec=requests.Response)
    response.status_code = 200
    response.history = []
    response.__enter__.return_value = response
    response.iter_content.side_effect = lambda **kwargs: iter(
        [b" " * 262144, body.encode()]
    )
    with mock.patch.object(
        detector.session.get_adapter(ORIGIN), "send", return_value=response
    ):
        assert detector.check(TARGET) == []
    assert response.__exit__.call_count >= 1


@pytest.mark.parametrize("factory,path,body", CASES)
def testCriticalHTTP_whenConnectionFails_reportsNothing(
    requests_mock: req_mock.mocker.Mocker,
    factory: type[agent_definitions.Exploit],
    path: str,
    body: str,
) -> None:
    requests_mock.get(req_mock.ANY, exc=requests.exceptions.ConnectionError)
    assert factory().check(TARGET) == []
