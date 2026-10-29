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


def testAssessmentCLI_whenMlflowInventoryProvided_dispatchesAndSanitizes(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "mlflow.json"
    path.write_text(
        json.dumps(
            [
                {
                    "product": "MLflow",
                    "version": "3.14.0",
                    "deployment": "tracking-server",
                    "fix_applied": False,
                    "authentication": "disabled",
                    "caller_can_create_experiments": True,
                    "caller_can_create_runs": True,
                    "caller_can_upload_artifacts": True,
                    "caller_can_invoke_scorers": True,
                    "scorer_package": "mlflow.genai.scorers.trulens",
                    "scorer_package_writable": True,
                    "artifact_uploads_reach_scorer_package": True,
                    "api_key": "secret-do-not-echo",
                },
                {"product": "MLflow", "version": "3.14.0"},
            ]
        )
    )
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert data[0]["cve_ids"] == ["CVE-2026-116692"]
    assert data[0]["status"] == "potential_exposure"
    assert data[1]["status"] == "inconclusive"
    assert set(data[0]) == {"cve_ids", "status", "reason", "recommendation"}
    assert "secret-do-not-echo" not in output.out + output.err
