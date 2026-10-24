"""Offline assessment tests for cve_2026_111497."""

from __future__ import annotations

import pytest

from agent.assessments import cve_2026_111497


@pytest.mark.parametrize(
    ("record", "cve"),
    [
        (
            {
                "brotli_decompressor_enabled": True,
                "product": "Envoy",
                "version": "1.39.2",
            },
            "CVE-2026-111497",
        ),
        (
            {
                "brotli_decompressor_enabled": True,
                "product": "Envoy",
                "version": "1.38.5",
            },
            "CVE-2026-111497",
        ),
        (
            {
                "brotli_decompressor_enabled": True,
                "product": "Envoy",
                "version": "1.37.7",
            },
            "CVE-2026-111497",
        ),
        (
            {
                "brotli_decompressor_enabled": True,
                "product": "Envoy",
                "version": "1.36.11",
            },
            "CVE-2026-111497",
        ),
    ],
)
def testAssessRecord_whenVerifiedAffectedEvidence_returnsPotentialExposure(
    record: dict[str, object], cve: str
) -> None:
    result = cve_2026_111497.assess_record(record)
    assert result.status == "potential_exposure"
    assert result.cve_ids == (cve,)
    assert "unconfirmed" in result.reason
    assert result.recommendation != ""


@pytest.mark.parametrize(
    "record",
    [
        {"brotli_decompressor_enabled": True, "product": "Envoy", "version": "1.40.0"},
        {"brotli_decompressor_enabled": True, "product": "Envoy", "version": "1.39.3"},
        {"brotli_decompressor_enabled": True, "product": "Envoy", "version": "1.38.6"},
        {"brotli_decompressor_enabled": True, "product": "Envoy", "version": "1.37.8"},
        {"brotli_decompressor_enabled": True, "product": "Envoy", "version": "1.36.12"},
    ],
)
def testAssessRecord_whenVendorFixedRelease_returnsNotMatched(
    record: dict[str, object],
) -> None:
    assert cve_2026_111497.assess_record(record).status == "not_matched"


@pytest.mark.parametrize(
    "record",
    [
        {"product": "Envoy", "version": "1.39.2"},
        {
            "brotli_decompressor_enabled": "true",
            "product": "Envoy",
            "version": "1.39.2",
        },
        {"brotli_decompressor_enabled": 1, "product": "Envoy", "version": "1.39.2"},
        {"brotli_decompressor_enabled": True, "product": "Envoy", "version": "1.39.1"},
        {
            "brotli_decompressor_enabled": True,
            "product": "Envoy",
            "version": "1.39.2-custom",
        },
    ],
)
def testAssessRecord_whenIncompleteOrAmbiguous_returnsInconclusive(
    record: dict[str, object],
) -> None:
    assert cve_2026_111497.assess_record(record).status == "inconclusive"


@pytest.mark.parametrize(
    "record",
    [{"brotli_decompressor_enabled": False, "product": "Envoy", "version": "1.39.2"}],
)
def testAssessRecord_whenRequiredPathAbsent_returnsNotMatched(
    record: dict[str, object],
) -> None:
    assert cve_2026_111497.assess_record(record).status == "not_matched"


@pytest.mark.parametrize("product", [None, "Unrelated Product", [], True])
def testAssessRecord_whenProductIdentityDoesNotMatch_returnsInconclusive(
    product: object,
) -> None:
    result = cve_2026_111497.assess_record(
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
