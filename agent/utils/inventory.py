"""Assess normalized owner inventory without contacting or executing target code.

Usage: python -m agent.utils.inventory inventory.json
The input is an array of records in Asteroid's normalized evidence schema, NOT
a vendor API response. Callers must collect trustworthy release, deployment,
and effective configuration evidence for the same running target. This module
does not independently authenticate that evidence or verify backported fixes.
Only whitelisted assessment fields are emitted; supplied records are never echoed.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import sys
import typing

from agent.exploits import cve_2026_109618 as php_oom_assessment
from agent.exploits import cve_2026_109619 as php_stale_assessment
from agent.exploits import cve_2026_110264 as gitlab_assessment
from agent.exploits import cve_2026_111497 as envoy_assessment
from agent.exploits import cve_2026_114625 as vco_assessment
from agent.exploits import cve_2026_115560 as php_assessment
from agent.utils import inventory_definitions

MAX_INVENTORY_BYTES = 1024 * 1024
_ASSESSORS = {
    "VeloCloud Orchestrator": vco_assessment.assess_record,
    "GitLab CE": gitlab_assessment.assess_record,
    "GitLab EE": gitlab_assessment.assess_record,
    "PHP": php_assessment.assess_record,
    "Envoy": envoy_assessment.assess_record,
}


_PHP_ASSESSORS = {
    "CVE-2026-109618": php_oom_assessment.assess_record,
    "CVE-2026-109619": php_stale_assessment.assess_record,
    "CVE-2026-115560": php_assessment.assess_record,
}


def assess_record(record: dict[str, object]) -> inventory_definitions.Assessment:
    """Dispatch normalized owner evidence to the product's CVE assessment."""
    product = record.get("product")
    if isinstance(product, str) is False or product not in _ASSESSORS:
        return inventory_definitions.Assessment(
            (),
            "inconclusive",
            "Unsupported or missing product identity.",
            "Verify the product and consult its vendor advisory.",
        )
    if product == "PHP" and "cve_id" in record:
        cve_id = record["cve_id"]
        if isinstance(cve_id, str) is False or cve_id not in _PHP_ASSESSORS:
            return inventory_definitions.Assessment(
                (),
                "inconclusive",
                "Unsupported PHP CVE selection.",
                "Select a supported PHP cve_id and supply owner-verified evidence.",
            )
        return _PHP_ASSESSORS[cve_id](record)
    return _ASSESSORS[product](record)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inventory field")
        result[key] = value
    return result


def _reject_constant(value: str) -> typing.NoReturn:
    raise ValueError("Non-standard JSON constant")


def main(argv: list[str] | None = None) -> int:
    """Read bounded JSON inventory and emit sanitized assessments, with no target I/O."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        with args.inventory.open("rb") as inventory_file:
            content = inventory_file.read(MAX_INVENTORY_BYTES + 1)
        if len(content) > MAX_INVENTORY_BYTES:
            raise ValueError("Inventory too large")
        records = json.loads(
            content, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
        if isinstance(records, list) is False or any(
            isinstance(record, dict) is False for record in records
        ):
            raise ValueError("Inventory must be an array of records")
        assessments = [dataclasses.asdict(assess_record(record)) for record in records]
    except (OSError, ValueError, UnicodeError, RecursionError):
        print("Invalid inventory file.", file=sys.stderr)
        return 2
    print(json.dumps(assessments))
    return 0


if __name__ == "__main__":
    sys.exit(main())
