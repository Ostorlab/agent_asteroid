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


_GITLAB_REGEXP_CVES = {
    ("CVE-2026-89078",),
    ("CVE-2026-93577",),
    ("CVE-2026-97229",),
    ("CVE-2026-110264",),
}


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
    data = [
        entry
        for entry in json.loads(output.out)
        if tuple(entry["cve_ids"]) in _GITLAB_REGEXP_CVES
    ]
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
        by_cve = {
            tuple(entry["cve_ids"]): entry["status"]
            for entry in data
            if tuple(entry["cve_ids"]) in _GITLAB_REGEXP_CVES
        }
        assert by_cve == per_cve


def testAssessmentCLI_whenGitLabCeAndEeRecords_emitIdenticalVerdictSets(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Assert CE/EE parity for the four regexp-family CVEs through the CLI.

    Other GitLab CVEs can have edition-specific feature prerequisites. Keep
    exact family membership and verdict parity without constraining unrelated
    assessments. At 19.4.1 the two earlier fixes apply and two later ones do not.
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
        return [
            entry
            for entry in verdicts
            if tuple(entry["cve_ids"]) in _GITLAB_REGEXP_CVES
        ]

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
    "product,version,cve",
    [
        ("org.apache.logging.log4j:log4j-core", "2.14.1", "CVE-2021-44228"),
        ("org.springframework:spring-webmvc", "5.3.17", "CVE-2022-22965"),
        ("org.springframework:spring-webflux", "5.3.17", "CVE-2022-22965"),
        ("org.apache.commons:commons-text", "1.9", "CVE-2022-42889"),
    ],
)
def testAssessmentCLI_whenJavaLibraryRecord_emitsSanitizedOfflineVerdict(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    product: str,
    version: str,
    cve: str,
) -> None:
    record: dict[str, object] = {
        "product": product,
        "version": version,
        "api_key": "SECRET_SENTINEL",
        "host": "never-contact.example",
    }
    original = dict(record)
    results = inventory.assess_records(record)
    assert len(results) == 1
    assert results[0].cve_ids == (cve,)
    assert results[0].status == "potential_exposure"
    assert record == original
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps([record]))
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    rows = json.loads(output.out)
    assert rows[0]["cve_ids"] == [cve]
    assert rows[0]["status"] == "potential_exposure"
    assert set(rows[0]) == {"cve_ids", "status", "reason", "recommendation"}
    assert "SECRET_SENTINEL" not in output.out + output.err
    assert "never-contact.example" not in output.out + output.err


@pytest.mark.parametrize("engine", ["ruby", "jruby"])
def testAssessmentCLI_whenRubyInventory_emitsAdvisoryIdsWithoutSecrets(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str], engine: str
) -> None:
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "Ruby",
                    "version": "4.0.8",
                    "ruby_engine": engine,
                    "api_key": "secret-do-not-echo",
                }
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert len(data) == 3
    assert all(
        set(entry) == {"cve_ids", "advisory_ids", "status", "reason", "recommendation"}
        for entry in data
    )
    assert all(entry["cve_ids"] == [] for entry in data)
    assert [entry["advisory_ids"] for entry in data] == [
        ["GHSA-gfj3-8wj9-qx8p"],
        ["GHSA-22mf-ggw7-pxfx"],
        ["GHSA-qm4g-8pfh-6996"],
    ]
    assert [entry["status"] for entry in data] == (
        ["not_matched", "not_matched", "potential_exposure"]
        if engine == "ruby"
        else ["inconclusive"] * 3
    )
    assert "secret-do-not-echo" not in output.out + output.err


def testAssessmentCLI_whenMalformedRubyEvidence_doesNotEchoSecret(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "Ruby",
                    "version": "secret-do-not-echo",
                    "ruby_engine": "ruby",
                    "verified_fixed_advisories": ["secret-do-not-echo"],
                }
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    assert all(entry["status"] == "inconclusive" for entry in json.loads(output.out))
    assert "secret-do-not-echo" not in output.out + output.err


@pytest.mark.parametrize(
    "product",
    [
        "OpenJDK",
        "Oracle Java SE",
        "Oracle GraalVM for JDK",
        "Oracle GraalVM Enterprise Edition",
    ],
)
def testAssessRecords_whenJavaProduct_dispatchesJava4Shell(product: str) -> None:
    version = (
        "21.3.20.0.3" if product == "Oracle GraalVM Enterprise Edition" else "17.0.21"
    )
    results = inventory.assess_records({"product": product, "version": version})
    assert len(results) == 1
    assert results[0].cve_ids == ("CVE-2026-114938",)
    assert results[0].status == "potential_exposure"


def testAssessmentCLI_whenJavaInventory_emitsBoundedVerdictWithoutEvidenceEcho(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "java.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "Oracle Java SE",
                    "version": "8u511b33-perf",
                    "secret": "do-not-echo",
                }
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    result = json.loads(output.out)[0]
    assert result["cve_ids"] == ["CVE-2026-114938"]
    assert result["status"] == "potential_exposure"
    assert "do-not-echo" not in output.out + output.err
