"""Unit tests for the generic detection rules under detection_rules/.

The tests validate the Semgrep/Opengrep rule files against the vulnerable and safe
fixtures under ``detection_rules/python/examples/``. They are skipped automatically
when neither ``semgrep`` nor ``opengrep`` is available on PATH, so they do not affect
CI on runners without the tool installed.
"""

import json
import pathlib
import shutil
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_RULE = (
    _REPO_ROOT / "detection_rules" / "python" / "django_tenant_scoped_orm_lookup.yml"
)
_EXAMPLES = _REPO_ROOT / "detection_rules" / "python" / "examples"


def _scanner() -> str | None:
    """Return the first available scanner binary, or None."""
    for candidate in ("semgrep", "opengrep"):
        path = shutil.which(candidate)
        if path is not None:
            return path
    return None


def _run_scanner(scanner: str) -> dict[str, list[dict[str, object]]]:
    """Run the scanner against the examples and return findings grouped by file."""
    result = subprocess.run(
        [
            scanner,
            "scan",
            "--quiet",
            "--config",
            str(_RULE),
            "--json",
            str(_EXAMPLES),
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    payload = json.loads(result.stdout.decode("utf-8"))
    by_file: dict[str, list[dict[str, object]]] = {}
    for finding in payload.get("results", []):
        path = str(pathlib.Path(str(finding["path"])).name)
        by_file.setdefault(path, []).append(finding)
    return by_file


@pytest.mark.skipif(_scanner() is None, reason="semgrep/opengrep not installed")
def test_rule_flags_vulnerable_dict_lookup_without_organisation() -> None:
    """The id-only filter dict must be flagged as a cross-tenant IDOR."""
    scanner = _scanner()
    assert scanner is not None
    findings = _run_scanner(scanner)
    vulnerable = findings.get("vulnerable_dict_lookup.py", [])
    assert len(vulnerable) == 1
    assert "missing-organisation-key" in str(vulnerable[0]["check_id"])


@pytest.mark.skipif(_scanner() is None, reason="semgrep/opengrep not installed")
def test_rule_flags_inline_lookup_without_organisation() -> None:
    """The inline id-only lookup must be flagged."""
    scanner = _scanner()
    assert scanner is not None
    findings = _run_scanner(scanner)
    inline = findings.get("inline_lookups.py", [])
    assert len(inline) == 1
    assert "inline-missing-organisation" in str(inline[0]["check_id"])


@pytest.mark.skipif(_scanner() is None, reason="semgrep/opengrep not installed")
def test_rule_does_not_flag_protected_lookups() -> None:
    """Lookups that include the organisation scope must not be flagged."""
    scanner = _scanner()
    assert scanner is not None
    findings = _run_scanner(scanner)
    assert findings.get("safe_dict_lookup.py", []) == []
