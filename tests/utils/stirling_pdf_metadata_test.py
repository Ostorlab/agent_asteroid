"""Shared installed-JAR reader defaults and per-feature metadata contracts."""

import json
import pathlib

import pytest
import requests_mock as req_mock

from agent import definitions
from agent.utils import stirling_pdf_metadata

ORIGIN = "https://stirling.example:443"
TARGET = definitions.Target("https", "stirling.example", 443)
FIXTURES = pathlib.Path(__file__).parents[1] / "exploits" / "fixtures"


@pytest.mark.parametrize(
    "schema_version,expected", [("3.0.1", True), ("3.1.0", True), ("3.0.3", False)]
)
def testReadRelease_whenLegacyDefaultSchema_preservesExistingContract(
    requests_mock: req_mock.mocker.Mocker, schema_version: str, expected: bool
) -> None:
    record = json.loads(
        (FIXTURES / "cve_2025_55150" / "openapi-1.0.2.json").read_text()
    )
    record["openapi"] = schema_version
    requests_mock.get(req_mock.ANY, status_code=404)
    requests_mock.get(f"{ORIGIN}/v1/api-docs", json=record)
    release = stirling_pdf_metadata.read_release(definitions.HttpSession(), TARGET)
    assert release == ("1.0.2" if expected is True else None)


@pytest.mark.parametrize(
    "operation", ["/api/v1/convert/html/pdf", "/api/v1/database/import-database"]
)
@pytest.mark.parametrize("schema_version", ["3.0.1", "3.0.3", "3.1.0"])
def testReadRelease_whenFeatureAndSchemaDiffer_enforcesRequestedContract(
    requests_mock: req_mock.mocker.Mocker, operation: str, schema_version: str
) -> None:
    record = json.loads(
        (FIXTURES / "cve_2026_85714" / "openapi-2.13.1.json").read_text()
    )
    record["openapi"] = schema_version
    requests_mock.get(req_mock.ANY, status_code=404)
    requests_mock.get(f"{ORIGIN}/v1/api-docs", json=record)
    release = stirling_pdf_metadata.read_release(
        definitions.HttpSession(),
        TARGET,
        operation_path=operation,
        schema_versions=("3.0.3",),
    )
    expected = (
        operation == "/api/v1/database/import-database" and schema_version == "3.0.3"
    )
    assert release == ("2.13.1" if expected is True else None)
    assert all(request.method == "GET" for request in requests_mock.request_history)
