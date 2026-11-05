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


def parse_patch_number(value: object) -> int | None:
    """Parse an explicitly installed patch/take (0 means none), bounded to 9999."""
    if isinstance(value, bool) is True or isinstance(value, int) is False:
        return None
    number = typing.cast(int, value)
    if 0 <= number <= 9999:
        return number
    return None


@dataclasses.dataclass(frozen=True, slots=True)
class BeyondTrustPatch:
    """Normalized patch evidence tied to the same running product and release."""

    name: str
    install_status: str
    applicability_verified: bool


def parse_beyondtrust_patches(
    record: dict[str, object],
) -> tuple[BeyondTrustPatch, ...] | None:
    """Validate complete owner patch inventory; no CVE applicability is inferred.

    None means missing, malformed, mixed-node, or conflicting evidence. An empty
    tuple means the owner explicitly inventoried no patches. CVE assessors must
    still check each exact package name and its published application interval.
    """
    entries = record.get("installed_patches")
    if isinstance(entries, list) is False:
        return None
    patches: list[BeyondTrustPatch] = []
    names: set[str] = set()
    for raw_entry in typing.cast(list[object], entries):
        if isinstance(raw_entry, dict) is False:
            return None
        entry = typing.cast(dict[str, object], raw_entry)
        raw_name = entry.get("name")
        raw_status = entry.get("install_status")
        applicability = entry.get("applicability_verified")
        if isinstance(raw_name, str) is False or isinstance(raw_status, str) is False:
            return None
        name = typing.cast(str, raw_name)
        status = typing.cast(str, raw_status)
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) is None
            or name in names
            or entry.get("product")
            not in (
                "BeyondTrust Remote Support",
                "BeyondTrust Privileged Remote Access",
            )
            or entry.get("product") != record.get("product")
            or parse_release(entry.get("application_version"), 3) is None
            or entry.get("application_version") != record.get("version")
            or status not in ("installed", "downloaded", "scheduled", "failed")
            or isinstance(applicability, bool) is False
        ):
            return None
        names.add(name)
        patches.append(BeyondTrustPatch(name, status, typing.cast(bool, applicability)))
    return tuple(patches)
