"""Unit tests for AsteroidAgent."""
from agent import asteroid_agent
from ostorlab.agent.message import message as m


def testAsteroidAgent_whenNoExploitYet_doesNotEmitsVulnerabilityReport(
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
    agent_mock: list[m.Message],
    scan_message_domain_name,
) -> None:
    """Unit test for agent AsteroidAgent exploits check."""

    asteroid_agent_instance.process(scan_message_domain_name)

    assert len(agent_mock) == 0
