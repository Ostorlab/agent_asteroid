"""Tests for normalized owner-inventory assessments; never contact targets."""

from __future__ import annotations

import json
import pathlib

import pytest

from agent.assessments import critical_2026_10


@pytest.mark.parametrize(
    ("record", "cve"),
    [
        (
            {
                "product": "VeloCloud Orchestrator",
                "version": version,
                "deployment": "on-premises",
            },
            "CVE-2026-114625",
        )
        for version in ("5.2.3.17", "6.1.3.9", "6.4.2.11")
    ]
    + [
        (
            {"product": product, "version": version, "deployment": "self-managed"},
            "CVE-2026-110264",
        )
        for product in ("GitLab CE", "GitLab EE")
        for version in (
            "7.0.0",
            "18.11.12",
            "19.0.9",
            "19.1.8",
            "19.2.8",
            "19.3.5",
            "19.4.2",
            "19.5.0",
        )
    ]
    + [
        (
            {
                "product": "PHP",
                "version": version,
                "session_upload_progress_enabled": True,
                "configured_serialize_handler": handler,
                "runtime_serialize_handler_before_session_start": "php",
            },
            "CVE-2026-115560",
        )
        for version in ("8.2.35", "8.3.36", "8.4.27", "8.5.12")
        for handler in ("php_binary", "php_serialize")
    ]
    + [
        (
            {
                "product": "Envoy",
                "version": version,
                "brotli_decompressor_enabled": True,
            },
            "CVE-2026-111497",
        )
        for version in ("1.39.2", "1.38.5", "1.37.7", "1.36.11")
    ],
)
def testAssessRecord_whenVerifiedAffectedEvidence_returnsPotentialExposure(
    record: dict[str, object], cve: str
) -> None:
    result = critical_2026_10.assess_record(record)
    assert result.status == "potential_exposure"
    assert result.cve_ids == (cve,)
    assert "unconfirmed" in result.reason
    assert result.recommendation != ""


@pytest.mark.parametrize(
    "record",
    [
        {
            "product": "VeloCloud Orchestrator",
            "version": version,
            "deployment": "on-premises",
        }
        for version in ("5.2.3.18", "6.1.3.10", "6.4.2.12")
    ]
    + [
        {"product": "GitLab CE", "version": version, "deployment": "self-managed"}
        for version in (
            "18.11.13",
            "19.0.10",
            "19.1.9",
            "19.2.9",
            "19.3.6",
            "19.4.3",
            "19.5.1",
            "19.6.0",
        )
    ]
    + [
        {"product": "Envoy", "version": version, "brotli_decompressor_enabled": True}
        for version in ("1.40.0", "1.39.3", "1.38.6", "1.37.8", "1.36.12")
    ],
)
def testAssessRecord_whenVendorFixedRelease_returnsNotMatched(
    record: dict[str, object],
) -> None:
    assert critical_2026_10.assess_record(record).status == "not_matched"


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"product": "Linux", "version": "7.3.0"},
        {"product": "VeloCloud Orchestrator", "version": "6.4.2.11"},
        {
            "product": "VeloCloud Orchestrator",
            "version": "6.3.0.0",
            "deployment": "on-premises",
        },
        {
            "product": "VeloCloud Orchestrator",
            "version": "6.4.2.11-hotfix",
            "deployment": "on-premises",
        },
        {
            "product": "GitLab CE",
            "version": "19.4.2-ee.0",
            "deployment": "self-managed",
        },
        {"product": "GitLab EE", "version": "19.4.2-ce", "deployment": "self-managed"},
        {"product": "GitLab CE", "version": "19.4.2"},
        {"product": "GitLab CE", "version": "6.9.0", "deployment": "self-managed"},
        {"product": "GitLab CE", "version": "019.4.2", "deployment": "self-managed"},
        {"product": "Envoy", "version": "1.39.2"},
        {
            "product": "Envoy",
            "version": "1.39.2",
            "brotli_decompressor_enabled": "true",
        },
        {"product": "Envoy", "version": "1.39.2", "brotli_decompressor_enabled": 1},
        {"product": "Envoy", "version": "1.39.1", "brotli_decompressor_enabled": True},
        {
            "product": "Envoy",
            "version": "1.39.2-custom",
            "brotli_decompressor_enabled": True,
        },
        {
            "product": "PHP",
            "version": "8.4.27",
            "session_upload_progress_enabled": True,
        },
        {
            "product": "PHP",
            "version": "8.4.26",
            "session_upload_progress_enabled": True,
            "configured_serialize_handler": "php_binary",
            "runtime_serialize_handler_before_session_start": "php",
        },
        {
            "product": "PHP",
            "version": "8.4.28",
            "session_upload_progress_enabled": True,
            "configured_serialize_handler": "php_binary",
            "runtime_serialize_handler_before_session_start": "php",
        },
    ],
)
def testAssessRecord_whenIncompleteOrAmbiguous_returnsInconclusive(
    record: dict[str, object],
) -> None:
    assert critical_2026_10.assess_record(record).status == "inconclusive"


@pytest.mark.parametrize("product", ["GitLab CE", "GitLab EE"])
def testAssessRecord_whenMatchingGitLabEditionSuffix_matchesVersion(
    product: str,
) -> None:
    suffix = "ce" if product == "GitLab CE" else "ee"
    result = critical_2026_10.assess_record(
        {
            "product": product,
            "version": f"19.4.2-{suffix}.0",
            "deployment": "self-managed",
        }
    )
    assert result.status == "potential_exposure"


@pytest.mark.parametrize(
    "record",
    [
        {
            "product": "VeloCloud Orchestrator",
            "version": "6.4.2.11",
            "deployment": deployment,
        }
        for deployment in ("hosted", "dedicated")
    ]
    + [
        {"product": "GitLab CE", "version": "19.4.2", "deployment": "managed"},
        {"product": "Envoy", "version": "1.39.2", "brotli_decompressor_enabled": False},
        {
            "product": "PHP",
            "version": "8.4.27",
            "session_upload_progress_enabled": False,
            "configured_serialize_handler": "php_binary",
            "runtime_serialize_handler_before_session_start": "php",
        },
        {
            "product": "PHP",
            "version": "8.4.27",
            "session_upload_progress_enabled": True,
            "configured_serialize_handler": "php",
            "runtime_serialize_handler_before_session_start": "php",
        },
    ],
)
def testAssessRecord_whenRequiredPathAbsent_returnsNotMatched(
    record: dict[str, object],
) -> None:
    assert critical_2026_10.assess_record(record).status == "not_matched"


def testAssessmentCLI_whenValidInventory_emitsOnlyWhitelistedFields(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "Envoy",
                    "version": "1.39.2",
                    "brotli_decompressor_enabled": True,
                    "api_key": "secret-do-not-echo",
                }
            ]
        )
    )
    assert critical_2026_10.main([str(path)]) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert set(data[0]) == {"cve_ids", "status", "reason", "recommendation"}
    assert data[0]["status"] == "potential_exposure"
    assert "secret-do-not-echo" not in output.out + output.err


@pytest.mark.parametrize(
    "content",
    [
        "{}",
        "[1]",
        "[null]",
        '[{"product":"Envoy","product":"PHP"}]',
        "[] trailing",
        "[]" + " " * (1024 * 1024),
    ],
)
def testAssessmentCLI_whenInvalidInventory_returnsTwoWithoutEcho(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    path = tmp_path / "inventory.json"
    path.write_text(content)
    assert critical_2026_10.main([str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Invalid inventory file.\n"


def testAssessmentCLI_whenMissingFile_returnsTwo(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert critical_2026_10.main([str(tmp_path / "absent")]) == 2
    assert capsys.readouterr().err == "Invalid inventory file.\n"


@pytest.mark.parametrize("version", [None, False, 1942, [], {}])
def testAssessRecord_whenVersionHasWrongType_returnsInconclusive(
    version: object,
) -> None:
    assert (
        critical_2026_10.assess_record(
            {"product": "GitLab CE", "version": version, "deployment": "self-managed"}
        ).status
        == "inconclusive"
    )
