"""Shared result types and canonical release parsing for offline assessments."""

from __future__ import annotations

import dataclasses
import re
import typing

type Status = typing.Literal["potential_exposure", "not_matched", "inconclusive"]

VERSION_COMPONENT = r"(?:0|[1-9][0-9]{0,3})"


@dataclasses.dataclass(frozen=True, slots=True)
class Assessment:
    """A bounded conclusion about supplied evidence, not an exploit verdict."""

    cve_ids: tuple[str, ...]
    status: Status
    reason: str
    recommendation: str


def parse_release(value: object, components: int) -> tuple[int, ...] | None:
    """Accept only canonical numeric releases; custom builds need manual review."""
    if isinstance(value, str) is False:
        return None
    text = typing.cast(str, value)
    if (
        re.fullmatch(
            rf"{VERSION_COMPONENT}(?:\.{VERSION_COMPONENT}){{{components - 1}}}", text
        )
        is None
    ):
        return None
    return tuple(int(part) for part in text.split("."))
