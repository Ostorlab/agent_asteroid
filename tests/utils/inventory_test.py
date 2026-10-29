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


def testAssessmentCLI_whenKsmbdAdvisoriesDiffer_preservesIndependentResults(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    common: dict[str, object] = {
        "product": "KSMBD",
        "ksmbd_running": True,
        "running_build_id": "lab-artifact",
        "reviewed_build_id": "lab-artifact",
        "code_evidence_source": "source_review",
        "code_evidence": "private-review-reference",
        "tcp_smb_reachable": True,
        "guest_share_accessible": True,
        "smb_direct_enabled": True,
        "rdma_transport_reachable": True,
        "writable_share_accessible": True,
    }
    records = [
        {**common, "advisory_id": "ZDI-CAN-33774", "code_status": "fixed"},
        {**common, "advisory_id": "ZDI-CAN-33549", "code_status": "affected"},
    ]
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(records))
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    results = json.loads(output.out)
    assert [result["status"] for result in results] == [
        "not_matched",
        "potential_exposure",
    ]
    assert [result["cve_ids"] for result in results] == [
        ["ZDI-CAN-33774"],
        ["ZDI-CAN-33549"],
    ]
    assert "private-review-reference" not in output.out + output.err
