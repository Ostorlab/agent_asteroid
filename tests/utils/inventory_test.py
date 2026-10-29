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


def testAssessmentCLI_whenMissingFile_returnsTwo(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert inventory.main([str(tmp_path / "absent")]) == 2
    assert capsys.readouterr().err == "Invalid inventory file.\n"


def testAssessmentCLI_whenPostizRecords_emitsDistinctCveResults(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "postiz.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "Postiz",
                    "cve_id": cve_id,
                    "version": "2.25.2",
                    "deployment": "self-hosted",
                    "authenticated_user_access": True,
                    "post_validation_access": True,
                    "validation_channel_available": True,
                    "team_invitation_access": True,
                    "JWT_SECRET": "do-not-echo",
                }
                for cve_id in ("CVE-2026-115931", "CVE-2026-115932", "CVE-2026-115933")
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    results = json.loads(output.out)
    assert [(result["cve_ids"], result["status"]) for result in results] == [
        (["CVE-2026-115931"], "not_matched"),
        (["CVE-2026-115932"], "potential_exposure"),
        (["CVE-2026-115933"], "potential_exposure"),
    ]
    assert all(
        set(result) == {"cve_ids", "status", "reason", "recommendation"}
        for result in results
    )
    assert "do-not-echo" not in output.out + output.err


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
