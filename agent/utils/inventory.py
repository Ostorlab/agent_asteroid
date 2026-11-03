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
from collections.abc import Callable

from agent.exploits import cve_2026_89078 as gitlab_regexp_parser_assessment
from agent.exploits import cve_2026_93577 as gitlab_regexp_compiler_assessment
from agent.exploits import cve_2026_97229 as gitlab_cicd_assessment
from agent.exploits import cve_2026_97718 as absolute_csrf_assessment
from agent.exploits import cve_2026_110264 as gitlab_regexp_assessment
from agent.exploits import cve_2026_111497 as envoy_assessment
from agent.exploits import cve_2026_114364 as syncope_assessment
from agent.exploits import cve_2026_114625 as vco_assessment
from agent.exploits import cve_2026_115560 as php_assessment
from agent.exploits import (
    cve_2026_116766 as absolute_input_handling_assessment,
)
from agent.exploits import (
    cve_2026_116767 as absolute_dos_767_assessment,
)
from agent.exploits import (
    cve_2026_116768 as absolute_dos_768_assessment,
)
from agent.exploits import (
    cve_2026_116769 as absolute_auth_bypass_assessment,
)
from agent.utils import inventory_definitions

MAX_INVENTORY_BYTES = 1024 * 1024
# One product can carry several CVE assessors when their advisories disagree on
# boundaries; each keeps its own assessment and its own verdict.
_Assessor = Callable[[dict[str, object]], inventory_definitions.Assessment]
# One tuple of assessors shared by both GitLab product keys, so the CE and EE
# registrations can never drift apart when the next family CVE is added.
_GITLAB_ASSESSORS: tuple[_Assessor, ...] = (
    gitlab_regexp_parser_assessment.assess_record,
    gitlab_regexp_compiler_assessment.assess_record,
    gitlab_cicd_assessment.assess_record,
    gitlab_regexp_assessment.assess_record,
)
# One tuple of assessors shared by every Secure Access product key (the
# vendor's former name NetMotion Mobility included), so the registrations
# can never drift apart when the next family CVE is added.
_ABSOLUTE_SA_ASSESSORS: tuple[_Assessor, ...] = (
    absolute_auth_bypass_assessment.assess_record,
    absolute_csrf_assessment.assess_record,
    absolute_input_handling_assessment.assess_record,
    absolute_dos_767_assessment.assess_record,
    absolute_dos_768_assessment.assess_record,
)
_ASSESSORS: dict[str, tuple[_Assessor, ...]] = {
    "VeloCloud Orchestrator": (vco_assessment.assess_record,),
    "GitLab CE": _GITLAB_ASSESSORS,
    "GitLab EE": _GITLAB_ASSESSORS,
    "PHP": (php_assessment.assess_record,),
    "Envoy": (envoy_assessment.assess_record,),
    "Absolute Secure Access": _ABSOLUTE_SA_ASSESSORS,
    "Secure Access": _ABSOLUTE_SA_ASSESSORS,
    "NetMotion Mobility": _ABSOLUTE_SA_ASSESSORS,
    "Apache Syncope": (syncope_assessment.assess_record,),
    "Syncope": (syncope_assessment.assess_record,),
}


def assess_records(record: dict[str, object]) -> list[inventory_definitions.Assessment]:
    """Dispatch normalized owner evidence to the product's CVE assessments."""
    product = record.get("product")
    if isinstance(product, str) is False or product not in _ASSESSORS:
        return [
            inventory_definitions.Assessment(
                (),
                "inconclusive",
                "Unsupported or missing product identity.",
                "Verify the product and consult its vendor advisory.",
            )
        ]
    return [assess(record) for assess in _ASSESSORS[product]]


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
        assessments = [
            dataclasses.asdict(assessment)
            for record in records
            for assessment in assess_records(record)
        ]
    except (OSError, ValueError, UnicodeError, RecursionError):
        print("Invalid inventory file.", file=sys.stderr)
        return 2
    print(json.dumps(assessments))
    return 0


if __name__ == "__main__":
    sys.exit(main())
