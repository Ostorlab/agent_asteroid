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


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, 0),
        (9999, 9999),
        (True, None),
        (False, None),
        (-1, None),
        (10000, None),
        ("1", None),
        (1.0, None),
        (None, None),
        ([], None),
    ],
)
def testParsePatchNumber_whenNormalizedOrInvalid_returnsBoundedInteger(
    value: object, expected: int | None
) -> None:
    assert inventory_definitions.parse_patch_number(value) == expected


def testParseBeyondtrustPatches_whenComplete_returnsInstalledEvidence() -> None:
    result = inventory_definitions.parse_beyondtrust_patches(
        {
            "product": "BeyondTrust Remote Support",
            "version": "24.3.1",
            "installed_patches": [
                {
                    "name": "BT24-10-ONPREM1",
                    "product": "BeyondTrust Remote Support",
                    "application_version": "24.3.1",
                    "install_status": "installed",
                    "applicability_verified": True,
                }
            ],
        }
    )
    assert result is not None
    assert len(result) == 1
    assert result[0].name == "BT24-10-ONPREM1"
    assert result[0].install_status == "installed"
    assert result[0].applicability_verified is True


@pytest.mark.parametrize(
    ("patches", "expected"),
    [([], ()), (None, None), ([{}], None), (["BT26-05-RS"], None)],
)
def testParseBeyondtrustPatches_whenEmptyOrMalformed_distinguishesUnknownInventory(
    patches: object, expected: object
) -> None:
    assert (
        inventory_definitions.parse_beyondtrust_patches(
            {
                "product": "BeyondTrust Remote Support",
                "version": "24.3.1",
                "installed_patches": patches,
            }
        )
        == expected
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("15.5.5-014", (15, 5, 5, 14)),
        ("16.0.4-302", (16, 0, 4, 302)),
        ("16.5.0-780", (16, 5, 0, 780)),
        ("15.5.5-14", None),
        ("15.5.5-0014", None),
        ("15.5.5-014-custom", None),
        ("015.5.5-014", None),
        (True, None),
        ([], None),
    ],
)
def testParseAsyncosRelease_whenVendorGrammar_preservesBuild(
    value: object, expected: tuple[int, ...] | None
) -> None:
    assert inventory_definitions.parse_asyncos_release(value) == expected
