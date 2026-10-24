"""Assess normalized owner inventory without contacting or executing target code.

Usage: python -m agent.assessments.critical_2026_10 inventory.json
The input is an array of records in Asteroid's normalized evidence schema, NOT
a vendor API response. Callers must collect trustworthy release, deployment,
and effective configuration evidence for the same running target. This module
does not independently authenticate that evidence or verify backported fixes.
Only whitelisted assessment fields are emitted; supplied records are never echoed.

Primary applicability sources (verified 2026-10-24):
https://www.arista.com/en/support/advisories-notices/security-advisory/24838-security-advisory-0199
https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/
https://www.php.net/archive/2026.php#2026-10-23-1
https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import re
import sys
import typing

MAX_INVENTORY_BYTES = 1024 * 1024
type Status = typing.Literal["potential_exposure", "not_matched", "inconclusive"]
_CVE_IDS = {
    "VeloCloud Orchestrator": ("CVE-2026-114625",),
    "GitLab CE": ("CVE-2026-110264",),
    "GitLab EE": ("CVE-2026-110264",),
    "PHP": ("CVE-2026-115560",),
    "Envoy": ("CVE-2026-111497",),
}
_RECOMMENDATIONS = {
    "VeloCloud Orchestrator": (
        "Upgrade on-premises VCO to 5.2.3.18, 6.1.3.10, or 6.4.2.12 or later "
        "within its branch. Restrict management access and review the vendor's "
        "compromise indicators. Verify backports and effective installed release."
    ),
    "GitLab": (
        "Upgrade self-managed GitLab to 18.11.13, 19.0.10, 19.1.9, 19.2.9, "
        "19.3.6, 19.4.3, 19.5.1 or a newer supported release. Verify owner "
        "inventory and consult GitLab's exploitation detection guidance."
    ),
    "PHP": (
        "Set session.upload_progress.enabled=0 in server configuration applied "
        "before request parsing and restart every PHP worker. Retain this "
        "mitigation until the vendor's next regular fix; do not rely on ini_set() "
        "or FPM .user.ini. The October 21 patches fix the original PHP2Shell pair "
        "but do not address CVE-2026-115560."
    ),
    "Envoy": (
        "Upgrade Envoy to 1.40.0, 1.39.3, 1.38.6, 1.37.8, or 1.36.12 or later "
        "within its branch. Verify the deployed binary and effective Brotli "
        "decompressor configuration using trusted owner administration evidence."
    ),
}
_VCO_FIXED = {
    (5, 2): (5, 2, 3, 18),
    (6, 1): (6, 1, 3, 10),
    (6, 4): (6, 4, 2, 12),
}
_GITLAB_FIXED = {
    (18, 11): (18, 11, 13),
    (19, 0): (19, 0, 10),
    (19, 1): (19, 1, 9),
    (19, 2): (19, 2, 9),
    (19, 3): (19, 3, 6),
    (19, 4): (19, 4, 3),
    (19, 5): (19, 5, 1),
}
_ENVOY_AFFECTED = {(1, 39, 2), (1, 38, 5), (1, 37, 7), (1, 36, 11)}
_ENVOY_FIXED = {
    (1, 39): (1, 39, 3),
    (1, 38): (1, 38, 6),
    (1, 37): (1, 37, 8),
    (1, 36): (1, 36, 12),
}
_PHP_VERIFIED = {(8, 2, 35), (8, 3, 36), (8, 4, 27), (8, 5, 12)}
_COMPONENT = r"(?:0|[1-9][0-9]{0,3})"


@dataclasses.dataclass(frozen=True, slots=True)
class Assessment:
    """A bounded conclusion about supplied evidence, not an exploit verdict."""

    cve_ids: tuple[str, ...]
    status: Status
    reason: str
    recommendation: str


def _parse_release(value: object, components: int) -> tuple[int, ...] | None:
    """Accept only canonical numeric releases; custom builds need manual review."""
    if isinstance(value, str) is False:
        return None
    text = typing.cast(str, value)
    if (
        re.fullmatch(rf"{_COMPONENT}(?:\.{_COMPONENT}){{{components - 1}}}", text)
        is None
    ):
        return None
    return tuple(int(part) for part in text.split("."))


def _assess_vco(record: dict[str, object]) -> tuple[Status, str]:
    release = _parse_release(record.get("version"), 4)
    if release is None:
        return "inconclusive", "A canonical four-component VCO release is required."
    deployment = record.get("deployment")
    if deployment in ("hosted", "dedicated"):
        return (
            "not_matched",
            "Arista reports hosted and dedicated VCO were already patched.",
        )
    if deployment != "on-premises":
        return "inconclusive", "Verified on-premises deployment evidence is required."
    fixed = _VCO_FIXED.get((release[0], release[1]))
    if fixed is None:
        return (
            "inconclusive",
            "This VCO branch is outside the vendor's assessed release matrix.",
        )
    if release >= fixed:
        return (
            "not_matched",
            "The supplied VCO release is at or beyond its branch's fixed point.",
        )
    return (
        "potential_exposure",
        "Owner-supplied VCO release matches an affected branch; backports and exploitability unconfirmed.",
    )


def _assess_gitlab(record: dict[str, object]) -> tuple[Status, str]:
    raw_version = record.get("version")
    if isinstance(raw_version, str) is False:
        return "inconclusive", "A canonical GitLab release and edition are required."
    version_text = typing.cast(str, raw_version)
    match = re.fullmatch(
        rf"({_COMPONENT}\.{_COMPONENT}\.{_COMPONENT})(?:-(ce|ee)(?:\.0)?)?",
        version_text,
    )
    if match is None:
        return (
            "inconclusive",
            "The GitLab release is incomplete or has an unverified build suffix.",
        )
    edition = match.group(2)
    expected_edition = "ce" if record.get("product") == "GitLab CE" else "ee"
    if edition is not None and edition != expected_edition:
        return (
            "inconclusive",
            "The supplied GitLab edition and version suffix conflict.",
        )
    release = tuple(int(part) for part in match.group(1).split("."))
    deployment = record.get("deployment")
    if deployment in ("managed", "gitlab.com", "dedicated"):
        return (
            "not_matched",
            "GitLab reports its managed infrastructure already includes the fix.",
        )
    if deployment != "self-managed":
        return (
            "inconclusive",
            "Verified self-managed GitLab deployment evidence is required.",
        )
    if release < (7, 0, 0):
        return "inconclusive", "This release predates the vendor's affected range."
    fixed = _GITLAB_FIXED.get((release[0], release[1]))
    if (fixed is not None and release >= fixed) or release >= (19, 6, 0):
        return (
            "not_matched",
            "The supplied GitLab release is at or beyond a vendor-fixed point.",
        )
    if release < (18, 11, 13) or fixed is not None:
        return (
            "potential_exposure",
            "Owner-supplied self-managed GitLab release matches the advisory; backports and exploitability unconfirmed.",
        )
    return (
        "inconclusive",
        "The supplied GitLab branch is outside the verified release matrix.",
    )


def _assess_php(record: dict[str, object]) -> tuple[Status, str]:
    release = _parse_release(record.get("version"), 3)
    if release not in _PHP_VERIFIED:
        return (
            "inconclusive",
            "PHP has not published complete affected bounds for this issue; only the four October 21 point releases are assessed here.",
        )
    enabled = record.get("session_upload_progress_enabled")
    configured = record.get("configured_serialize_handler")
    runtime = record.get("runtime_serialize_handler_before_session_start")
    if (
        type(enabled) is not bool
        or configured not in ("php", "php_binary", "php_serialize")
        or runtime not in ("php", "php_binary", "php_serialize")
    ):
        return (
            "inconclusive",
            "Effective upload-progress configuration and the handler transition before session_start must be supplied explicitly.",
        )
    if enabled is False or configured == "php" or runtime != "php":
        return (
            "not_matched",
            "The specific upload-progress and serialize-handler transition described by PHP is absent; other vulnerability paths are not assessed.",
        )
    return (
        "potential_exposure",
        "Owner-supplied PHP configuration matches the narrow CVE-2026-115560 path; exploitability unconfirmed.",
    )


def _assess_envoy(record: dict[str, object]) -> tuple[Status, str]:
    release = _parse_release(record.get("version"), 3)
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


def assess_record(record: dict[str, object]) -> Assessment:
    """Assess one normalized trusted-inventory record with explicit prerequisites."""
    product = record.get("product")
    if isinstance(product, str) is False or product not in _CVE_IDS:
        return Assessment(
            (),
            "inconclusive",
            "Unsupported or missing product identity.",
            "Verify the product and consult its vendor advisory.",
        )
    if product == "VeloCloud Orchestrator":
        status, reason = _assess_vco(record)
    elif product in ("GitLab CE", "GitLab EE"):
        status, reason = _assess_gitlab(record)
    elif product == "PHP":
        status, reason = _assess_php(record)
    else:
        status, reason = _assess_envoy(record)
    recommendation_key = "GitLab" if product in ("GitLab CE", "GitLab EE") else product
    return Assessment(
        _CVE_IDS[product], status, reason, _RECOMMENDATIONS[recommendation_key]
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inventory field")
        result[key] = value
    return result


def _reject_constant(value: str) -> typing.NoReturn:
    raise ValueError("Non-standard JSON constant")


def main(argv: list[str] | None = None) -> int:
    """Read bounded JSON inventory and emit sanitized assessments, with no target I/O."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        with args.inventory.open("rb") as inventory_file:
            content = inventory_file.read(MAX_INVENTORY_BYTES + 1)
        if len(content) > MAX_INVENTORY_BYTES:
            raise ValueError("Inventory too large")
        records = json.loads(
            content, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
        if isinstance(records, list) is False or any(
            isinstance(record, dict) is False for record in records
        ):
            raise ValueError("Inventory must be an array of records")
        assessments = [dataclasses.asdict(assess_record(record)) for record in records]
    except (OSError, ValueError, UnicodeError, RecursionError):
        print("Invalid inventory file.", file=sys.stderr)
        return 2
    print(json.dumps(assessments))
    return 0


if __name__ == "__main__":
    sys.exit(main())
