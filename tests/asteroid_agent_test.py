"""Unit tests for AsteroidAgent."""
from typing import Type, Generator

from ostorlab.agent.message import message as m

from agent import asteroid_agent
from agent import definitions


def testAsteroidAgent_whenExploitCheckDetectVulnz_EmitsVulnerabilityReport(
    exploit_instance_with_report: Generator[Type[definitions.Exploit], None, None],
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
    agent_mock: list[m.Message],
    scan_message_domain_name: m.Message,
) -> None:
    """Unit test for agent AsteroidAgent exploits check. case Exploit emits vulnerability report"""

    asteroid_agent_instance.process(scan_message_domain_name)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
