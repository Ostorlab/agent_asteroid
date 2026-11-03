"""Offline assessment tests for inventory."""

from __future__ import annotations

import json
import pathlib

import pytest

from agent.utils import inventory


@pytest.mark.parametrize("record", [{}, {"product": "Linux", "version": "7.3.0"}])
def testAssessRecord_whenIncompleteOrAmbiguous_returnsInconclusive(
    record: dict[str, object],
) -> None:
    assert inventory.assess_record(record).status == "inconclusive"


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


@pytest.mark.parametrize(
    ("product", "version"),
    [
        ("Cisco ASA", "9.16.4.103"),
        ("Cisco FTD", "7.2.6"),
    ],
)
def testAssessmentCLI_whenCiscoRecord_dispatchesBothProductKeys(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    product: str,
    version: str,
) -> None:
    """The dispatcher routes both Cisco product keys to the assessor.

    A misspelled or mis-keyed ``_ASSESSORS`` entry (a trailing space, a typo)
    would silently route these records to the generic "Unsupported or missing
    product identity." path while the assessor module's own tests keep
    passing, so both product keys are locked through the public CLI.
    9.16.4.103 sits one patch below the 9.16 catch-all fixed point
    (9.16.4.104) and 7.2.6 below the FTD 7.2 first fixed release (7.2.13);
    with both configuration prerequisites supplied they are potential
    exposures. The verdict vocabulary and recommendation content stay pinned
    in the assessor's own shape tests; this test pins the dispatch."""
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": product,
                    "version": version,
                    "webvpn_enabled": True,
                    "secondary_authentication_configured": True,
                }
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert len(data) == 1
    assert data[0]["cve_ids"] == ["CVE-2026-76418"]
    assert data[0]["status"] == "potential_exposure"


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
