"""Pytest fixtures for agent Asteroid"""
from typing import Type

import pytest

from agent import definitions


@pytest.fixture()
def exploit_instance() -> Type[definitions.Exploit]:
    class TestExploit(definitions.Exploit):
        """test class Exploit."""

        def accept(self, target: definitions.Target) -> bool:
            return False

        def check(self, target: definitions.Target) -> list[definitions.Vulnerability]:
            return []

    return TestExploit
