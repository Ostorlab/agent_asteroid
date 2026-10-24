"""Offline assessment tests for cve_2026_114625."""

from __future__ import annotations

import pytest

from agent.assessments import cve_2026_114625


@pytest.mark.parametrize(
    ("record", "cve"),
    [
        (
            {
                "deployment": "on-premises",
                "product": "VeloCloud Orchestrator",
                "version": "5.2.3.17",
            },
            "CVE-2026-114625",
        ),
        (
            {
                "deployment": "on-premises",
                "product": "VeloCloud Orchestrator",
                "version": "6.1.3.9",
            },
            "CVE-2026-114625",
        ),
        (
            {
                "deployment": "on-premises",
                "product": "VeloCloud Orchestrator",
                "version": "6.4.2.11",
            },
            "CVE-2026-114625",
        ),
    ],
)
def testAssessRecord_whenVerifiedAffectedEvidence_returnsPotentialExposure(
    record: dict[str, object], cve: str
) -> None:
    result = cve_2026_114625.assess_record(record)
    assert result.status == "potential_exposure"
    assert result.cve_ids == (cve,)
    assert "unconfirmed" in result.reason
    assert result.recommendation != ""


@pytest.mark.parametrize(
    "record",
    [
        {
            "deployment": "on-premises",
            "product": "VeloCloud Orchestrator",
            "version": "5.2.3.18",
        },
        {
            "deployment": "on-premises",
            "product": "VeloCloud Orchestrator",
            "version": "6.1.3.10",
        },
        {
            "deployment": "on-premises",
            "product": "VeloCloud Orchestrator",
            "version": "6.4.2.12",
        },
    ],
)
def testAssessRecord_whenVendorFixedRelease_returnsNotMatched(
    record: dict[str, object],
) -> None:
    assert cve_2026_114625.assess_record(record).status == "not_matched"


@pytest.mark.parametrize(
    "record",
    [
        {"product": "VeloCloud Orchestrator", "version": "6.4.2.11"},
        {
            "deployment": "on-premises",
            "product": "VeloCloud Orchestrator",
            "version": "6.3.0.0",
        },
        {
            "deployment": "on-premises",
            "product": "VeloCloud Orchestrator",
            "version": "6.4.2.11-hotfix",
        },
    ],
)
def testAssessRecord_whenIncompleteOrAmbiguous_returnsInconclusive(
    record: dict[str, object],
) -> None:
    assert cve_2026_114625.assess_record(record).status == "inconclusive"


@pytest.mark.parametrize(
    "record",
    [
        {
            "deployment": "hosted",
            "product": "VeloCloud Orchestrator",
            "version": "6.4.2.11",
        },
        {
            "deployment": "dedicated",
            "product": "VeloCloud Orchestrator",
            "version": "6.4.2.11",
        },
    ],
)
def testAssessRecord_whenRequiredPathAbsent_returnsNotMatched(
    record: dict[str, object],
) -> None:
    assert cve_2026_114625.assess_record(record).status == "not_matched"


@pytest.mark.parametrize("product", [None, "Unrelated Product", [], True])
def testAssessRecord_whenProductIdentityDoesNotMatch_returnsInconclusive(
    product: object,
) -> None:
    result = cve_2026_114625.assess_record(
        {
            "product": product,
            "version": "19.4.2",
            "deployment": "self-managed",
            "brotli_decompressor_enabled": True,
            "session_upload_progress_enabled": True,
            "configured_serialize_handler": "php_binary",
            "runtime_serialize_handler_before_session_start": "php",
        }
    )
    assert result.status == "inconclusive"
    assert result.cve_ids == ()
