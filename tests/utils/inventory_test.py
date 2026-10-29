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


@pytest.mark.parametrize(
    ("product", "version", "prerequisites"),
    [
        (
            "Node.js",
            "26.12.0",
            {"official_build": True, "untrusted_brotli_input": True},
        ),
        ("Bun", "1.4.3", {"official_build": True, "untrusted_brotli_input": True}),
        (
            "Brotli (PyPI)",
            "1.2.0",
            {"official_build": True, "untrusted_brotli_input": True},
        ),
        (
            "brotlicffi (PyPI)",
            "1.2.0.2",
            {"official_build": True, "untrusted_brotli_input": True},
        ),
        (".NET", "10.0.13", {"official_build": True, "untrusted_brotli_input": True}),
        ("Istio", "1.31.1", {"brotli_decompressor_enabled": True}),
    ],
)
def testAssessRecord_whenNode2ShellProduct_dispatchesAssessment(
    product: str, version: str, prerequisites: dict[str, object]
) -> None:
    record: dict[str, object] = {
        "product": product,
        "version": version,
        **prerequisites,
    }
    result = inventory.assess_record(record)
    assert result.status == "potential_exposure"
    assert result.cve_ids == ("CVE-2026-111497",)
