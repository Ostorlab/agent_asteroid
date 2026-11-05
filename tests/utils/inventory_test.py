"""Offline assessment tests for inventory."""

from __future__ import annotations

import json
import pathlib
import typing

import pytest

from agent.utils import inventory


@pytest.mark.parametrize("record", [{}, {"product": "Linux", "version": "7.3.0"}])
def testAssessRecords_whenIncompleteOrAmbiguous_returnsInconclusive(
    record: dict[str, object],
) -> None:
    results = inventory.assess_records(record)
    assert len(results) == 1
    assert results[0].status == "inconclusive"
    assert results[0].cve_ids == ()


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
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert set(data[0]) == {"cve_ids", "status", "reason", "recommendation"}
    assert data[0]["status"] == "potential_exposure"
    assert "secret-do-not-echo" not in output.out + output.err


def testAssessmentCLI_whenGitLabRecord_assessesEachRegexpCveSeparately(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A GitLab record is assessed for every CVE with its own boundaries.

    19.4.2 is the fixed point for CVE-2026-97229 but still affected by
    CVE-2026-110264, whose fix is 19.4.3; both verdicts must be emitted.
    """
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "GitLab CE",
                    "version": "19.4.2",
                    "deployment": "self-managed",
                }
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    by_cve = {tuple(entry["cve_ids"]): entry["status"] for entry in data}
    assert by_cve[("CVE-2026-97229",)] == "not_matched"
    assert by_cve[("CVE-2026-110264",)] == "potential_exposure"


def testAssessmentCLI_whenGitLabRecordAffectedByBoth_reportsBothExposures(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """19.4.1 self-managed EE: still exposed for the two later-family CVEs
    (97229 fixed 19.4.2, 110264 fixed 19.4.3) and clean for the two CVEs whose
    fix shipped in this very release (89078 and 93577, fixed 19.4.1)."""
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "GitLab EE",
                    "version": "19.4.1-ee",
                    "deployment": "self-managed",
                }
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert {(entry["cve_ids"][0], entry["status"]) for entry in data} == {
        ("CVE-2026-97229", "potential_exposure"),
        ("CVE-2026-110264", "potential_exposure"),
        ("CVE-2026-89078", "not_matched"),
        ("CVE-2026-93577", "not_matched"),
    }


def testAssessmentCLI_whenMissingFile_returnsTwo(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert inventory.main([str(tmp_path / "absent")]) == 2
    assert capsys.readouterr().err == "Invalid inventory file.\n"


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
    assert inventory.main([str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Invalid inventory file.\n"


def testAssessmentCLI_whenGitLabRecordEmitsAllFourRegexpFamilyVerdicts(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One GitLab record is assessed against the whole regexp family.

    19.4.0 is fixed for none of the four (all report potential exposure);
    19.4.1 is exactly the fixed point of CVE-2026-89078 and CVE-2026-93577
    (the 19.4.1 release) but still affected by CVE-2026-97229 (fixed 19.4.2)
    and CVE-2026-110264 (fixed 19.4.3); 19.4.3 is fixed for all four.
    """
    expected = {
        "19.4.0": {
            ("CVE-2026-89078",): "potential_exposure",
            ("CVE-2026-93577",): "potential_exposure",
            ("CVE-2026-97229",): "potential_exposure",
            ("CVE-2026-110264",): "potential_exposure",
        },
        "19.4.1": {
            ("CVE-2026-89078",): "not_matched",
            ("CVE-2026-93577",): "not_matched",
            ("CVE-2026-97229",): "potential_exposure",
            ("CVE-2026-110264",): "potential_exposure",
        },
        "19.4.3": {
            ("CVE-2026-89078",): "not_matched",
            ("CVE-2026-93577",): "not_matched",
            ("CVE-2026-97229",): "not_matched",
            ("CVE-2026-110264",): "not_matched",
        },
    }
    for version, per_cve in expected.items():
        path = tmp_path / f"inventory_{version}.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "product": "GitLab CE",
                        "version": version,
                        "deployment": "self-managed",
                    }
                ]
            )
        )
        assert inventory.main([str(path)]) == 0
        output = capsys.readouterr()
        data = json.loads(output.out)
        by_cve = {tuple(entry["cve_ids"]): entry["status"] for entry in data}
        assert by_cve == per_cve


def testAssessmentCLI_whenGitLabCeAndEeRecords_emitIdenticalVerdictSets(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Registration parity asserted through the public CLI behavior.

    The CE and EE dispatch entries describe the same software, so the same
    record content assessed under each product key must emit the identical
    verdict set: an assessor registered for only one key would surface as a
    different number or content of assessments. Replaces the previous
    private ``_ASSESSORS`` identity check, which reached into the module's
    registry rather than its published behavior.

    19.4.1 exercises every family member: not matched for the two CVEs whose
    fix shipped in this very release (89078/93577, fixed 19.4.1), still a
    potential exposure for the two later ones (97229 fixed 19.4.2, 110264
    fixed 19.4.3).
    """

    def assess_as(product: str) -> list[dict[str, typing.Any]]:
        path = tmp_path / f"inventory-{product.replace(' ', '-')}.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "product": product,
                        "version": "19.4.1",
                        "deployment": "self-managed",
                    }
                ]
            )
        )
        assert inventory.main([str(path)]) == 0
        verdicts: list[dict[str, typing.Any]] = json.loads(capsys.readouterr().out)
        return verdicts

    ce_verdicts = assess_as("GitLab CE")
    ee_verdicts = assess_as("GitLab EE")

    assert ce_verdicts == ee_verdicts
    assert {(entry["cve_ids"][0], entry["status"]) for entry in ce_verdicts} == {
        ("CVE-2026-97229", "potential_exposure"),
        ("CVE-2026-110264", "potential_exposure"),
        ("CVE-2026-89078", "not_matched"),
        ("CVE-2026-93577", "not_matched"),
    }


@pytest.mark.parametrize(
    ("product", "expected"),
    [
        ("Cisco ISE", {"CVE-2026-76460"}),
        ("Cisco Catalyst SD-WAN Manager", {"CVE-2026-76504"}),
        ("FortiMail", {"CVE-2026-104286"}),
        ("Check Point Quantum Security Gateway", {"CVE-2026-85102"}),
        ("F5 BIG-IP APM", {"CVE-2026-94127"}),
        ("MikroTik RouterOS", {"CVE-2026-86060", "CVE-2026-67279"}),
        ("WatchGuard Fireware OS", {"CVE-2025-9242"}),
        ("NetScaler ADC", {"CVE-2026-19490"}),
        ("Cisco Secure Email Gateway", {"CVE-2026-76461", "CVE-2026-76519"}),
        ("Check Point Spark Firewall", {"CVE-2026-85102"}),
        ("NetScaler Gateway", {"CVE-2026-19490"}),
        ("Cisco ISE-PIC", {"CVE-2026-76460"}),
        ("AhsayCBS", {"CVE-2026-105133", "CVE-2026-105134"}),
        ("Check Point Quantum Security Management", {"CVE-2026-93616"}),
        ("BeyondTrust Remote Support", {"CVE-2024-12356", "CVE-2026-102764"}),
        ("BeyondTrust Privileged Remote Access", {"CVE-2024-12356"}),
        ("Avada Builder", {"CVE-2026-8713"}),
        ("VeloCloud Orchestrator", {"CVE-2026-114625", "CVE-2026-93952"}),
        ("Envoy", {"CVE-2026-111497"}),
        ("PHP", {"CVE-2026-115560"}),
        (
            "GitLab CE",
            {"CVE-2026-89078", "CVE-2026-93577", "CVE-2026-97229", "CVE-2026-110264"},
        ),
        (
            "GitLab EE",
            {"CVE-2026-89078", "CVE-2026-93577", "CVE-2026-97229", "CVE-2026-110264"},
        ),
    ],
)
def testAssessRecords_whenSupportedProduct_dispatchesAllIndependentCves(
    product: str, expected: set[str]
) -> None:
    results = inventory.assess_records({"product": product})
    assert {cve for result in results for cve in result.cve_ids} == expected


def testAssessmentCLI_whenWebInventory_emitsIndependentSanitizedVerdictsOffline(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_network(*args: object, **kwargs: object) -> typing.NoReturn:
        raise AssertionError("Inventory attempted network I/O")

    monkeypatch.setattr("socket.socket.connect", reject_network)
    monkeypatch.setattr("socket.socket.connect_ex", reject_network)
    monkeypatch.setattr("socket.getaddrinfo", reject_network)
    path = tmp_path / "web-inventory.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "Cisco ISE",
                    "version": "3.4",
                    "patch": 6,
                    "api_key": "secret-do-not-echo",
                },
                {
                    "product": "AhsayCBS",
                    "version": "10.3.4.0",
                    "replication_capability_available": True,
                    "receiver_enabled": False,
                },
                {
                    "product": "Check Point Quantum Security Management",
                    "version": "R82",
                    "role": "security-management-server",
                    "deployment": "customer-managed",
                    "jumbo_hotfix_take": 126,
                    "security_hotfixes": [],
                    "livepatch_take": 30,
                },
                {
                    "product": "BeyondTrust Remote Support",
                    "version": "24.3.1",
                    "deployment": "self-hosted",
                    "installed_patches": [
                        {
                            "name": "BT24-10-ONPREM1",
                            "product": "BeyondTrust Remote Support",
                            "application_version": "24.3.1",
                            "install_status": "installed",
                            "applicability_verified": True,
                        }
                    ],
                },
                {"product": "Cisco ISE", "version": "secret-do-not-echo", "patch": 6},
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    assert "secret-do-not-echo" not in output.out + output.err
    data = json.loads(output.out)
    assert {(row["cve_ids"][0], row["status"]) for row in data} == {
        ("CVE-2026-76460", "potential_exposure"),
        ("CVE-2026-76460", "inconclusive"),
        ("CVE-2026-105133", "potential_exposure"),
        ("CVE-2026-105134", "potential_exposure"),
        ("CVE-2026-93616", "potential_exposure"),
        ("CVE-2024-12356", "not_matched"),
        ("CVE-2026-102764", "potential_exposure"),
    }
    assert all(
        set(row) == {"cve_ids", "status", "reason", "recommendation"} for row in data
    )


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        (
            "cisco-ise-inventory.json",
            [
                ("CVE-2026-76460", "potential_exposure"),
                ("CVE-2026-76460", "not_matched"),
            ],
        ),
        (
            "ahsaycbs-inventory.json",
            [
                ("CVE-2026-105133", "potential_exposure"),
                ("CVE-2026-105134", "potential_exposure"),
                ("CVE-2026-105133", "not_matched"),
                ("CVE-2026-105134", "not_matched"),
            ],
        ),
        (
            "checkpoint-management-inventory.json",
            [
                ("CVE-2026-93616", "potential_exposure"),
                ("CVE-2026-93616", "inconclusive"),
                ("CVE-2026-93616", "not_matched"),
                ("CVE-2026-93616", "not_matched"),
            ],
        ),
        (
            "beyondtrust-inventory.json",
            [
                ("CVE-2024-12356", "not_matched"),
                ("CVE-2026-102764", "potential_exposure"),
                ("CVE-2024-12356", "not_matched"),
                ("CVE-2026-102764", "not_matched"),
                ("CVE-2024-12356", "not_matched"),
                ("CVE-2024-12356", "not_matched"),
                ("CVE-2026-102764", "inconclusive"),
                ("CVE-2024-12356", "not_matched"),
                ("CVE-2026-102764", "not_matched"),
            ],
        ),
    ],
)
def testAssessmentCLI_whenDocumentedExamples_returnsDocumentedVerdicts(
    filename: str, expected: list[tuple[str, str]], capsys: pytest.CaptureFixture[str]
) -> None:
    path = pathlib.Path(__file__).resolve().parents[2] / "docs" / "examples" / filename
    assert inventory.main([str(path)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [(row["cve_ids"][0], row["status"]) for row in data] == expected


@pytest.mark.parametrize(
    ("version", "patch_name", "cve"),
    [
        ("21.3.1", "BT24-10-ONPREM1", "CVE-2024-12356"),
        ("24.3.0", "BT26-05-RS", "CVE-2026-102764"),
        ("26.3.1", "BT26-05-RS", "CVE-2026-102764"),
    ],
)
def testAssessRecords_whenSaasContradictsPatchApplicability_returnsInconclusive(
    version: str, patch_name: str, cve: str
) -> None:
    results = inventory.assess_records(
        {
            "product": "BeyondTrust Remote Support",
            "version": version,
            "deployment": "beyondtrust-saas",
            "service_identity_verified": True,
            "installed_patches": [
                {
                    "name": patch_name,
                    "product": "BeyondTrust Remote Support",
                    "application_version": version,
                    "install_status": "installed",
                    "applicability_verified": True,
                }
            ],
        }
    )
    assert {result.cve_ids[0]: result.status for result in results}[
        cve
    ] == "inconclusive"


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        (
            "sdwan-manager-inventory.json",
            [
                ("CVE-2026-76504", "potential_exposure"),
                ("CVE-2026-76504", "not_matched"),
                ("CVE-2026-76504", "inconclusive"),
            ],
        ),
        (
            "fortimail-inventory.json",
            [
                ("CVE-2026-104286", "potential_exposure"),
                ("CVE-2026-104286", "not_matched"),
                ("CVE-2026-104286", "not_matched"),
            ],
        ),
        (
            "secure-email-inventory.json",
            [
                ("CVE-2026-76461", "potential_exposure"),
                ("CVE-2026-76519", "not_matched"),
                ("CVE-2026-76461", "not_matched"),
                ("CVE-2026-76519", "potential_exposure"),
                ("CVE-2026-76461", "not_matched"),
                ("CVE-2026-76519", "not_matched"),
            ],
        ),
        (
            "checkpoint-vpn-inventory.json",
            [
                ("CVE-2026-85102", "potential_exposure"),
                ("CVE-2026-85102", "not_matched"),
                ("CVE-2026-85102", "potential_exposure"),
                ("CVE-2026-85102", "not_matched"),
            ],
        ),
        (
            "f5-apm-inventory.json",
            [
                ("CVE-2026-94127", "potential_exposure"),
                ("CVE-2026-94127", "not_matched"),
                ("CVE-2026-94127", "inconclusive"),
            ],
        ),
        (
            "routeros-inventory.json",
            [
                ("CVE-2026-67279", "potential_exposure"),
                ("CVE-2026-86060", "potential_exposure"),
                ("CVE-2026-67279", "not_matched"),
                ("CVE-2026-86060", "not_matched"),
            ],
        ),
        (
            "fireware-inventory.json",
            [
                ("CVE-2025-9242", "potential_exposure"),
                ("CVE-2025-9242", "not_matched"),
                ("CVE-2025-9242", "inconclusive"),
            ],
        ),
        (
            "netscaler-inventory.json",
            [
                ("CVE-2026-19490", "potential_exposure"),
                ("CVE-2026-19490", "not_matched"),
                ("CVE-2026-19490", "potential_exposure"),
                ("CVE-2026-19490", "not_matched"),
            ],
        ),
        (
            "vco-inventory.json",
            [
                ("CVE-2026-114625", "potential_exposure"),
                ("CVE-2026-93952", "not_matched"),
                ("CVE-2026-114625", "potential_exposure"),
                ("CVE-2026-93952", "potential_exposure"),
                ("CVE-2026-114625", "not_matched"),
                ("CVE-2026-93952", "inconclusive"),
            ],
        ),
    ],
)
def testAssessmentCLI_whenApplianceExamples_reportsIndependentVerdictsOffline(
    filename: str,
    expected: list[tuple[str, str]],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_external_io(*args: object, **kwargs: object) -> typing.NoReturn:
        raise AssertionError("Offline inventory attempted target I/O or commands")

    monkeypatch.setattr("socket.socket.connect", reject_external_io)
    monkeypatch.setattr("socket.socket.connect_ex", reject_external_io)
    monkeypatch.setattr("socket.getaddrinfo", reject_external_io)
    monkeypatch.setattr("subprocess.Popen", reject_external_io)
    path = pathlib.Path(__file__).resolve().parents[2] / "docs" / "examples" / filename
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    rows = json.loads(output.out)
    assert [(cve, row["status"]) for row in rows for cve in row["cve_ids"]] == expected
    assert all(
        set(row) == {"cve_ids", "status", "reason", "recommendation"} for row in rows
    )
    assert output.err == ""


@pytest.mark.parametrize(
    "field", ["version", "build", "engineering_hotfix", "livepatch_take"]
)
def testAssessmentCLI_whenDuplicateApplianceEvidence_rejectsBeforeDispatch(
    field: str, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '[{"product":"WatchGuard Fireware OS","'
        + field
        + '":"secret-first","'
        + field
        + '":"secret-second"}]'
    )
    assert inventory.main([str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Invalid inventory file.\n"


def testAssessmentCLI_whenMalformedApplianceEvidence_neverEchoesSecrets(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "malformed.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "F5 BIG-IP APM",
                    "version": "secret-release",
                    "engineering_hotfix": "secret-hotfix",
                    "api_key": "secret-token",
                }
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    assert "secret" not in output.out + output.err
    assert json.loads(output.out)[0]["status"] == "inconclusive"
