"""Source-backed legacy/modern metadata and defensive transport checks."""

from __future__ import annotations

import pathlib

import pytest
import requests
import requests_mock as req_mock

from agent import definitions
from agent.utils import defensive_metadata as metadata_limits
from agent.utils import langflow_metadata

ORIGIN = "https://langflow.example:443"
TARGET = definitions.Target("https", "langflow.example", 443, "/ignored?secret=true")
FIXTURES = pathlib.Path(__file__).parents[1] / "exploits" / "fixtures" / "cve_2026_7873"
VERSION = (FIXTURES / "version-1.10.0.json").read_text()
SCHEMA = (FIXTURES / "openapi-1.10.0.json").read_text()


def _serve(
    mock: req_mock.mocker.Mocker, version: str = VERSION, schema: str = SCHEMA
) -> None:
    mock.get(f"{ORIGIN}/api/v1/version", text=version)
    mock.get(f"{ORIGIN}/openapi.json", text=schema)


@pytest.mark.parametrize("release", ["1.0.0", "1.10.0"])
def testReadRelease_whenSourceBackedLegacyOrModern_returnsPackageRelease(
    requests_mock: req_mock.mocker.Mocker, release: str
) -> None:
    _serve(
        requests_mock,
        (FIXTURES / f"version-{release}.json").read_text(),
        SCHEMA.replace("1.10.0", release),
    )
    with definitions.HttpSession() as session:
        assert langflow_metadata.read_release(session, TARGET) == release


@pytest.mark.parametrize(
    "body",
    [
        "{}",
        "[]",
        "invalid",
        SCHEMA,
        VERSION.replace('"Langflow"', '"Langflow Base"'),
        VERSION.replace('"Langflow"', '"Langflow Nightly"'),
        VERSION.replace('"Langflow"', '"Other"'),
        VERSION.replace('"version":"1.10.0"', '"version":null'),
        VERSION.replace('"version":"1.10.0"', '"version":1100'),
        VERSION.replace('"version":"1.10.0"', '"version":true'),
        VERSION.replace('"version":"1.10.0"', '"version":"1.10.0","version":"1.10.1"'),
        VERSION.replace('"main_version":"1.10.0"', '"main_version":"1.10.1"'),
        VERSION.replace('"main_version":"1.10.0"', '"latest":"1.10.0"'),
        VERSION.replace("1.10.0", "1.10.0rc1"),
        VERSION.replace("1.10.0", "1.10.0.dev1"),
        VERSION.replace("1.10.0", "1.10.0+fork"),
        VERSION.replace("1.10.0", "01.10.0"),
        VERSION.replace("1.10.0", "1.10"),
        VERSION.replace("1.10.0", "0.0.0"),
        VERSION.replace("1.10.0", "1.10.0\\n"),
    ],
)
def testReadRelease_whenInstalledEvidenceInvalid_returnsNone(
    requests_mock: req_mock.mocker.Mocker, body: str
) -> None:
    _serve(requests_mock, body)
    with definitions.HttpSession() as session:
        assert langflow_metadata.read_release(session, TARGET) is None


@pytest.mark.parametrize(
    "schema",
    [
        "{}",
        "[]",
        "invalid",
        VERSION,
        SCHEMA.replace('"Langflow"', '"FastAPI"'),
        SCHEMA.replace('"1.10.0"', '"1.10.1"'),
        SCHEMA.replace('"1.10.0"', '"1.10.0+fork"'),
        SCHEMA.replace(
            '"version": "1.10.0"', '"version": "1.10.0", "version": "1.10.1"'
        ),
        SCHEMA.replace('"3.1.0"', '"unsupported"'),
        SCHEMA.replace('"paths"', '"other"'),
        SCHEMA.replace('"/api/v1/version"', '"/other"'),
        SCHEMA.replace('"get"', '"post"'),
    ],
)
def testReadRelease_whenSchemaConflictsOrWildcard_returnsNone(
    requests_mock: req_mock.mocker.Mocker, schema: str
) -> None:
    _serve(requests_mock, schema=schema)
    with definitions.HttpSession() as session:
        assert langflow_metadata.read_release(session, TARGET) is None


@pytest.mark.parametrize("path", ["/api/v1/version", "/openapi.json"])
@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 500])
def testReadRelease_whenResourceUnavailable_rejectsWithoutRedirects(
    requests_mock: req_mock.mocker.Mocker, path: str, status: int
) -> None:
    _serve(requests_mock)
    requests_mock.get(
        f"{ORIGIN}{path}",
        status_code=status,
        headers={"Location": "https://other.example/"},
    )
    with definitions.HttpSession() as session:
        assert langflow_metadata.read_release(session, TARGET) is None
    assert all(
        request.url.startswith(ORIGIN) for request in requests_mock.request_history
    )


@pytest.mark.parametrize("path", ["/api/v1/version", "/openapi.json"])
def testReadRelease_whenTransportFails_returnsNone(
    requests_mock: req_mock.mocker.Mocker, path: str
) -> None:
    _serve(requests_mock)
    requests_mock.get(f"{ORIGIN}{path}", exc=requests.exceptions.Timeout)
    with definitions.HttpSession() as session:
        assert langflow_metadata.read_release(session, TARGET) is None


@pytest.mark.parametrize("schema", [False, True])
def testReadRelease_whenBodyOversized_returnsNone(
    requests_mock: req_mock.mocker.Mocker, schema: bool
) -> None:
    _serve(requests_mock)
    if schema is True:
        requests_mock.get(
            f"{ORIGIN}/openapi.json",
            text=SCHEMA + " " * langflow_metadata.MAX_SCHEMA_BYTES,
        )
    else:
        requests_mock.get(
            f"{ORIGIN}/api/v1/version",
            text=VERSION + " " * metadata_limits.MAX_RESPONSE_BYTES,
        )
    with definitions.HttpSession() as session:
        assert langflow_metadata.read_release(session, TARGET) is None


def testReadRelease_whenSessionHasCredentials_isolatesRequests(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    _serve(requests_mock)
    with definitions.HttpSession() as session:
        session.auth = ("user", "password")
        session.headers.update(
            {"Authorization": "Bearer secret", "X-Api-Key": "secret"}
        )
        session.cookies.set("session", "secret")
        session.params = {"private": "secret"}
        assert langflow_metadata.read_release(session, TARGET) == "1.10.0"
    assert requests_mock.call_count == 2
    for request in requests_mock.request_history:
        assert request.method == "GET"
        assert request.url in (f"{ORIGIN}/api/v1/version", f"{ORIGIN}/openapi.json")
        assert request.body is None
        assert "Authorization" not in request.headers
        assert "Cookie" not in request.headers
        assert "X-Api-Key" not in request.headers


def testReadRelease_whenUnsupportedScheme_makesNoRequest(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    with definitions.HttpSession() as session:
        assert (
            langflow_metadata.read_release(
                session, definitions.Target("ftp", "host", 21)
            )
            is None
        )
    assert requests_mock.call_count == 0
