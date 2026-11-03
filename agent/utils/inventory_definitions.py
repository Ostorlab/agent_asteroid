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


def assess_gitlab_release(
    record: dict[str, object],
    fixed_table: typing.Mapping[tuple[int, int], tuple[int, int, int]],
    affected_summary: str,
    older_note: str = "",
) -> tuple[Status, str]:
    """Range-check a self-managed GitLab release against one CVE's fixed points.

    Shared skeleton of the regular-expression advisory family
    (CVE-2026-89078, -93577 and -97229): each module supplies its per-branch
    fixed table and its advisory's affected-range sentence, so the version
    grammar, the edition-conflict and deployment verdicts, and the boundary
    messages cannot drift between family members. ``older_note`` appends to
    the pre-range verdict (CVE-2026-97229 points at the sibling CVEs that
    cover some of the older releases). CVE-2026-110264 keeps its own range
    logic: its advisory covers releases back to 7.0.0 on different branches,
    which is CVE-specific rather than family-shared.
    """
    parsed = parse_gitlab_version(record)
    if isinstance(parsed, tuple):
        return parsed
    deployment = classify_gitlab_deployment(record)
    if deployment is not None:
        return deployment
    release = parsed.release
    newest_branch = max(fixed_table)
    fixed = fixed_table.get((release[0], release[1]))
    if fixed is None:
        if (release[0], release[1]) > newest_branch:
            return (
                "not_matched",
                (
                    "The advisory lists no release beyond "
                    f"{newest_branch[0]}.{newest_branch[1]} as impacted."
                ),
            )
        return (
            "not_matched",
            (
                "The advisory lists no release before 19.2 as impacted; older "
                f"releases fall outside this CVE's range{older_note}."
            ),
        )
    if release >= fixed:
        return (
            "not_matched",
            (
                "The supplied GitLab release is at or beyond its branch's "
                f"fixed point ({fixed[0]}.{fixed[1]}.{fixed[2]})."
            ),
        )
    return (
        "potential_exposure",
        (
            "Owner-supplied self-managed GitLab release matches the advisory "
            f"({affected_summary}); backports and exploitability unconfirmed."
        ),
    )


_CWP_RELEASE_RE = re.compile(
    rf"({VERSION_COMPONENT}\.{VERSION_COMPONENT})"
    rf"(?:\.{VERSION_COMPONENT})?"
)


def assess_cwp_release(
    record: dict[str, object],
    fixed: tuple[int, int, int],
    fixed_label: str,
) -> tuple[Status, str]:
    """Range-check a CWP ``webpanel_version`` against one CVE's fixed point.

    Every CWP CVE advisory states its impact as ``webpanel_version before
    <fixed>`` with no lower bound (VulnCheck advisories CVE-2026-73696,
    -77880, -73697, -104080, -77881, all fetched 2026-11-03), so any release
    below the fixed point matches and any release at or beyond it does not.
    Canonical releases are two or three numeric components (the vendor's own
    scheme: 1.12, 1.16, 1.30, 1.30.1); a two-component release is normalized
    to ``.0``. Non-canonical or missing evidence stays inconclusive — the
    assessor does not order custom builds.
    """
    raw_version = record.get("version")
    if isinstance(raw_version, str) is False:
        return "inconclusive", "A canonical webpanel_version release is required."
    match = _CWP_RELEASE_RE.fullmatch(typing.cast(str, raw_version))
    if match is None:
        return (
            "inconclusive",
            (
                "The webpanel_version is incomplete, non-canonical, or carries "
                "an unverified suffix; custom builds need manual review."
            ),
        )
    parts = tuple(int(part) for part in typing.cast(str, raw_version).split("."))
    release = (parts[0], parts[1], parts[2] if len(parts) == 3 else 0)
    if release >= fixed:
        return (
            "not_matched",
            (
                f"The supplied webpanel_version ({raw_version}) is at or "
                f"beyond this advisory's fixed point ({fixed_label})."
            ),
        )
    return (
        "potential_exposure",
        (
            "Owner-supplied webpanel_version matches the advisory "
            f"(webpanel_version before {fixed_label}); backports and "
            "exploitability unconfirmed."
        ),
    )
