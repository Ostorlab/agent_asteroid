"""Shared GitLab evidence-parsing tests for inventory_definitions."""

from __future__ import annotations

import pytest

from agent.utils import inventory_definitions


def testParseGitlabVersion_whenCanonicalWithEdition_returnsReleaseAndEdition() -> None:
    parsed = inventory_definitions.parse_gitlab_version(
        {"product": "GitLab EE", "version": "19.4.1-ee"}
    )
    assert isinstance(parsed, inventory_definitions.GitLabEvidence)
    assert parsed.release == (19, 4, 1)
    assert parsed.edition == "ee"


def testParseGitlabVersion_whenBareRelease_returnsReleaseWithoutEdition() -> None:
    parsed = inventory_definitions.parse_gitlab_version(
        {"product": "GitLab CE", "version": "19.2.8"}
    )
    assert isinstance(parsed, inventory_definitions.GitLabEvidence)
    assert parsed.release == (19, 2, 8)
    assert parsed.edition is None


def testParseGitlabVersion_whenZeroPaddedEditionSuffix_stillParses() -> None:
    parsed = inventory_definitions.parse_gitlab_version(
        {"product": "GitLab CE", "version": "19.4.2-ce.0"}
    )
    assert isinstance(parsed, inventory_definitions.GitLabEvidence)
    assert parsed.release == (19, 4, 2)
    assert parsed.edition == "ce"


@pytest.mark.parametrize(
    "record",
    [
        {"product": "GitLab EE", "version": "19.4.1-ce"},
        {"product": "GitLab CE", "version": "19.4.1-ee"},
    ],
)
def testParseGitlabVersion_whenEditionSuffixConflicts_returnsInconclusive(
    record: dict[str, object],
) -> None:
    parsed = inventory_definitions.parse_gitlab_version(record)
    assert parsed == (
        "inconclusive",
        "The supplied GitLab edition and version suffix conflict.",
    )


@pytest.mark.parametrize(
    "version",
    [None, "", "19.4", "19.4.1.2", "19.4.1-unknown", "19.4.1-rc1", "v19.4.1"],
)
def testParseGitlabVersion_whenNonCanonical_returnsInconclusive(
    version: object,
) -> None:
    parsed = inventory_definitions.parse_gitlab_version(
        {"product": "GitLab CE", "version": version}
    )
    if version is None:
        assert parsed == (
            "inconclusive",
            "A canonical GitLab release and edition are required.",
        )
    else:
        assert parsed == (
            "inconclusive",
            "The GitLab release is incomplete or has an unverified build suffix.",
        )


@pytest.mark.parametrize("deployment", ["managed", "gitlab.com", "dedicated"])
def testClassifyGitlabDeployment_whenVendorManaged_returnsNotMatched(
    deployment: str,
) -> None:
    assert inventory_definitions.classify_gitlab_deployment(
        {"deployment": deployment}
    ) == (
        "not_matched",
        "GitLab reports its managed infrastructure already includes the fix.",
    )


@pytest.mark.parametrize("deployment", [None, "", "unknown", "cloud"])
def testClassifyGitlabDeployment_whenNotSelfManaged_returnsInconclusive(
    deployment: object,
) -> None:
    assert inventory_definitions.classify_gitlab_deployment(
        {"deployment": deployment}
    ) == (
        "inconclusive",
        "Verified self-managed GitLab deployment evidence is required.",
    )


def testClassifyGitlabDeployment_whenSelfManaged_returnsNone() -> None:
    assert (
        inventory_definitions.classify_gitlab_deployment({"deployment": "self-managed"})
        is None
    )


_FAMILY_TABLE = {
    (19, 2): (19, 2, 7),
    (19, 3): (19, 3, 3),
    (19, 4): (19, 4, 1),
}


def testAssessGitlabRelease_whenAffectedSelfManagedRelease_returnsExposure() -> None:
    status, reason = inventory_definitions.assess_gitlab_release(
        {"product": "GitLab EE", "version": "19.4.0", "deployment": "self-managed"},
        _FAMILY_TABLE,
        "19.2 before 19.2.7, 19.3 before 19.3.3, 19.4 before 19.4.1",
    )
    assert status == "potential_exposure"
    assert "19.4 before 19.4.1" in reason
    assert "unconfirmed" in reason


def testAssessGitlabRelease_whenAtOrBeyondFixed_returnsNotMatched() -> None:
    status, reason = inventory_definitions.assess_gitlab_release(
        {"product": "GitLab EE", "version": "19.4.1", "deployment": "self-managed"},
        _FAMILY_TABLE,
        "19.2 before 19.2.7, 19.3 before 19.3.3, 19.4 before 19.4.1",
    )
    assert status == "not_matched"
    assert "fixed point (19.4.1)" in reason


def testAssessGitlabRelease_whenBeyondNewestBranch_returnsNotMatched() -> None:
    status, reason = inventory_definitions.assess_gitlab_release(
        {"product": "GitLab EE", "version": "19.5.0", "deployment": "self-managed"},
        _FAMILY_TABLE,
        "19.2 before 19.2.7, 19.3 before 19.3.3, 19.4 before 19.4.1",
    )
    assert status == "not_matched"
    assert "no release beyond 19.4" in reason


@pytest.mark.parametrize("version", ["19.1.9", "18.11.12"])
def testAssessGitlabRelease_whenBelowFamilyRange_returnsNotMatchedWithNote(
    version: str,
) -> None:
    """Older releases fall outside the family range; the older_note (used by
    CVE-2026-97229 to point at the sibling CVEs) is appended verbatim."""
    status, reason = inventory_definitions.assess_gitlab_release(
        {"product": "GitLab EE", "version": version, "deployment": "self-managed"},
        _FAMILY_TABLE,
        "19.2 before 19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2",
        older_note=" (the sibling regular-expression CVEs cover some of them)",
    )
    assert status == "not_matched"
    assert "outside this CVE's range (the sibling" in reason


def testAssessGitlabRelease_delegatesGrammarAndDeployment() -> None:
    """The shared skeleton forwards the grammar and deployment verdicts of
    the parse/classify helpers, so family members cannot drift on them."""
    assert inventory_definitions.assess_gitlab_release(
        {"product": "GitLab EE", "version": "19.4.0.1", "deployment": "self-managed"},
        _FAMILY_TABLE,
        "19.4 before 19.4.1",
    ) == (
        "inconclusive",
        "The GitLab release is incomplete or has an unverified build suffix.",
    )
    assert inventory_definitions.assess_gitlab_release(
        {"product": "GitLab EE", "deployment": "self-managed"},
        _FAMILY_TABLE,
        "19.4 before 19.4.1",
    ) == (
        "inconclusive",
        "A canonical GitLab release and edition are required.",
    )
    assert inventory_definitions.assess_gitlab_release(
        {"product": "GitLab EE", "version": "19.4.0"},
        _FAMILY_TABLE,
        "19.4 before 19.4.1",
    ) == (
        "inconclusive",
        "Verified self-managed GitLab deployment evidence is required.",
    )
