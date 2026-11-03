"""Offline assessment tests for inventory."""

from __future__ import annotations

import json
import pathlib

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
                [{"product": "GitLab CE", "version": version, "deployment": "self-managed"}]
            )
        )
        assert inventory.main([str(path)]) == 0
        output = capsys.readouterr()
        data = json.loads(output.out)
        by_cve = {tuple(entry["cve_ids"]): entry["status"] for entry in data}
        assert by_cve == per_cve
