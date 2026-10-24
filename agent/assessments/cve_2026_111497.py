"""Offline owner-inventory assessment for CVE-2026-111497.

Applicability source (verified 2026-10-24):
https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr
Evidence must describe the same running target and effective configuration.
The assessor does not contact targets or independently verify supplied evidence.
"""

from __future__ import annotations

from agent.assessments import definitions

CVE_ID = "CVE-2026-111497"
PRODUCTS = ("Envoy",)
ADVISORY_URL = (
    "https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr"
)
RECOMMENDATION = "Upgrade Envoy to 1.40.0, 1.39.3, 1.38.6, 1.37.8, or 1.36.12 or later within its branch. Verify the deployed binary and effective Brotli decompressor configuration using trusted owner administration evidence."

_ENVOY_AFFECTED = {(1, 39, 2), (1, 38, 5), (1, 37, 7), (1, 36, 11)}

_ENVOY_FIXED = {
    (1, 39): (1, 39, 3),
    (1, 38): (1, 38, 6),
    (1, 37): (1, 37, 8),
    (1, 36): (1, 36, 12),
}


def _assess_evidence(record: dict[str, object]) -> tuple[definitions.Status, str]:
    release = definitions.parse_release(record.get("version"), 3)
    if release is None:
        return (
            "inconclusive",
            "A canonical Envoy release is required; custom builds need owner verification.",
        )
    enabled = record.get("brotli_decompressor_enabled")
    if type(enabled) is not bool:
        return (
            "inconclusive",
            "Effective Brotli decompressor configuration must be explicitly verified.",
        )
    if enabled is False:
        return (
            "not_matched",
            "The Brotli decompressor prerequisite is absent in the supplied effective configuration.",
        )
    fixed = _ENVOY_FIXED.get((release[0], release[1]))
    if release >= (1, 40, 0) or (fixed is not None and release >= fixed):
        return (
            "not_matched",
            "The supplied Envoy release is at or beyond a vendor-fixed point.",
        )
    if release in _ENVOY_AFFECTED:
        return (
            "potential_exposure",
            "Owner-supplied Envoy release and Brotli decompressor configuration match the advisory; exploitability unconfirmed.",
        )
    return (
        "inconclusive",
        "This Envoy release is not one of the four explicitly identified affected releases.",
    )


def assess_record(record: dict[str, object]) -> definitions.Assessment:
    """Assess normalized evidence for this CVE only, without target I/O."""
    if record.get("product") not in PRODUCTS:
        return definitions.Assessment(
            (),
            "inconclusive",
            "Unsupported or missing product identity.",
            "Verify the product and consult its vendor advisory.",
        )
    status, reason = _assess_evidence(record)
    return definitions.Assessment((CVE_ID,), status, reason, RECOMMENDATION)
