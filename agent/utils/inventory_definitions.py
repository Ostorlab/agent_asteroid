"""Shared result types and canonical release parsing for offline assessments."""

from __future__ import annotations

import dataclasses
import re
import typing

type Status = typing.Literal["potential_exposure", "not_matched", "inconclusive"]

VERSION_COMPONENT = r"(?:0|[1-9][0-9]{0,3})"

_GITLAB_RELEASE_RE = re.compile(
    rf"({VERSION_COMPONENT}\.{VERSION_COMPONENT}\.{VERSION_COMPONENT})"
    r"(?:-(ce|ee)(?:\.0)?)?"
)

_GITLAB_MANAGED_DEPLOYMENTS = ("managed", "gitlab.com", "dedicated")


@dataclasses.dataclass(frozen=True, slots=True)
class Assessment:
    """A bounded conclusion about supplied evidence, not an exploit verdict."""

    cve_ids: tuple[str, ...]
    status: Status
    reason: str
    recommendation: str


@dataclasses.dataclass(frozen=True, slots=True)
class GitLabEvidence:
    """Canonical GitLab evidence: the release tuple and edition suffix."""

    release: tuple[int, int, int]
    edition: str | None


def parse_release(value: object, components: int) -> tuple[int, ...] | None:
    """Accept only canonical numeric releases; custom builds need manual review."""
    if isinstance(value, str) is False:
        return None
    text = typing.cast(str, value)
    if (
        re.fullmatch(
            rf"{VERSION_COMPONENT}(?:\.{VERSION_COMPONENT}){{{components - 1}}}", text
        )
        is None
    ):
        return None
    return tuple(int(part) for part in text.split("."))


def parse_gitlab_version(
    record: dict[str, object],
) -> GitLabEvidence | tuple[Status, str]:
    """Parse the canonical GitLab release and edition of an inventory record.

    Returns the parsed evidence, or the terminal ``(status, reason)`` pair the
    GitLab assessors emit when the version is missing, is not a canonical
    release, carries an unverified build suffix, or its edition suffix
    conflicts with the record's product. Every GitLab CVE assessor must stay
    in lockstep on this grammar and these verdicts.
    """
    raw_version = record.get("version")
    if isinstance(raw_version, str) is False:
        return "inconclusive", "A canonical GitLab release and edition are required."
    match = _GITLAB_RELEASE_RE.fullmatch(typing.cast(str, raw_version))
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
    major, minor, patch = (int(part) for part in match.group(1).split("."))
    return GitLabEvidence((major, minor, patch), edition)


def classify_gitlab_deployment(
    record: dict[str, object],
) -> tuple[Status, str] | None:
    """Classify the deployment evidence shared by every GitLab CVE assessor.

    Returns ``None`` for a self-managed deployment — the only deployment an
    offline assessor can range-check, so the caller proceeds to its CVE's
    fixed-point table — or the terminal ``(status, reason)`` pair for the
    vendor-managed deployments GitLab reports as already patched, and for
    deployment evidence that is not verifiable.
    """
    deployment = record.get("deployment")
    if deployment in _GITLAB_MANAGED_DEPLOYMENTS:
        return (
            "not_matched",
            "GitLab reports its managed infrastructure already includes the fix.",
        )
    if deployment != "self-managed":
        return (
            "inconclusive",
            "Verified self-managed GitLab deployment evidence is required.",
        )
    return None


# Absolute Secure Access releases are two components (major.minor), and the
# vendor's own advisories write both padded and unpadded minors (13.08 and
# 14.61), so each component accepts leading zeros and is compared numerically.
_ABSOLUTE_RELEASE_RE = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})")


def assess_absolute_release(
    record: dict[str, object],
    lower: tuple[int, int] | None,
    upper: tuple[int, int],
    impact_label: str,
) -> tuple[Status, str]:
    """Range-check a Secure Access server release against one CVE's boundary.

    Every advisory of the 14.61 release family states its impact as one
    half-open range of two-component releases (verified 2026-11-03 against
    the vendor's 14.61 release advisory and each CVE's own archive page,
    https://www.absolute.com/platform/security-information/vulnerability-archive/):
    ``lower`` inclusive to ``upper`` exclusive, with ``lower=None`` for the
    advisories that say "all versions through 14.60". The vendor states
    Secure Access SaaS customers are not impacted, so a ``saas`` deployment
    is not matched; anything other than verified ``on-premises`` deployment
    evidence stays inconclusive. A non-canonical or missing release also
    stays inconclusive — the assessor does not order custom builds.
    """
    raw_version = record.get("version")
    if isinstance(raw_version, str) is False:
        return "inconclusive", "A canonical Secure Access server release is required."
    match = _ABSOLUTE_RELEASE_RE.fullmatch(typing.cast(str, raw_version))
    if match is None:
        return (
            "inconclusive",
            (
                "The Secure Access release is incomplete, non-canonical, or "
                "carries an unverified suffix; custom builds need manual review."
            ),
        )
    deployment = record.get("deployment")
    if deployment == "saas":
        return (
            "not_matched",
            "The vendor states Secure Access SaaS customers are not impacted.",
        )
    if deployment != "on-premises":
        return (
            "inconclusive",
            "Verified on-premises Secure Access deployment evidence is required.",
        )
    release = (int(match.group(1)), int(match.group(2)))
    if release >= upper:
        return (
            "not_matched",
            (
                "The supplied Secure Access release is at or beyond the "
                f"vendor's fixed release ({upper[0]}.{upper[1]})."
            ),
        )
    if lower is not None and release < lower:
        return (
            "not_matched",
            (
                "The advisory lists no release before "
                f"{lower[0]}.{lower[1]} as impacted; this CVE's range is "
                f"{impact_label}."
            ),
        )
    return (
        "potential_exposure",
        (
            "Owner-supplied Secure Access release matches the advisory "
            f"({impact_label}); backports and exploitability unconfirmed."
        ),
    )
