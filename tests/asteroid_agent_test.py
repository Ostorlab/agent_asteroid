"""Unit tests for AsteroidAgent."""
from typing import Type


from ostorlab.agent.message import message as m

from agent import asteroid_agent
from agent import definitions
from agent import exploits_registry


def testAsteroidAgent_whenExploitCheckDetectVulnz_EmitsVulnerabilityReport2(
    exploit_instance_with_report: Type[definitions.Exploit],
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
    agent_mock: list[m.Message],
    scan_message_domain_name: m.Message,
) -> None:
    """Unit test for agent AsteroidAgent exploits check. case Exploit emits vulnerability report"""

    asteroid_agent_instance.process(scan_message_domain_name)
    exploits_registry.ExploitsRegistry.registry["ExploitsRegistry"].pop("TestExploit")

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
