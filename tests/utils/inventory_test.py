"""Offline assessment tests for inventory."""

from __future__ import annotations

import json
import pathlib

import pytest

from agent.utils import inventory


@pytest.fixture
def laravel_record() -> dict[str, object]:
    """Owner evidence for one legacy Laravel guard path."""
    return {
        "product": "Laravel",
        "version": "12.67.0",
        "guard_driver": "token",
        "entry_point": "user",
        "token_guard_rejects_non_string": False,
        "user_provider": "eloquent",
        "provider_preserves_numeric_token": True,
        "database_driver": "mysql",
        "token_storage_is_text": True,
        "non_string_token_reaches_guard": True,
        "guard_hash": False,
    }


def testAssessRecord_whenLaravelPrerequisitesVerified_returnsPotentialExposure(
    laravel_record: dict[str, object],
) -> None:
    result = inventory.assess_record(laravel_record)
    assert result.status == "potential_exposure"
    assert result.cve_ids == ("CVE-2026-114509",)
    assert "unconfirmed" in result.reason


def testAssessmentCLI_whenLaravelInventory_emitsScopedSanitizedResults(
    laravel_record: dict[str, object],
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "laravel.json"
    laravel_record["api_token"] = "private-token-must-not-appear"
    records = [
        laravel_record,
        {
            **laravel_record,
            "version": "12.68.0",
            "token_guard_rejects_non_string": True,
        },
        {"product": "Laravel", "version": "12.67.0"},
        {**laravel_record, "guard_driver": "sanctum"},
    ]
    path.write_text(json.dumps(records))
    assert inventory.main([str(path)]) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert [item["status"] for item in data] == [
        "potential_exposure",
        "not_matched",
        "inconclusive",
        "not_matched",
    ]
    assert all(item["cve_ids"] == ["CVE-2026-114509"] for item in data)
    assert all(
        set(item) == {"cve_ids", "status", "reason", "recommendation"} for item in data
    )
    assert "private-token-must-not-appear" not in output.out + output.err


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
