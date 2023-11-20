"""Unit tests for AsteroidAgent."""
import datetime


from ostorlab.agent.message import message as m
import requests
from pytest_mock import plugin

from agent import asteroid_agent

seed: int = 0


def testAsteroidAgent_whenExploitCheckDetectVulnz_EmitsVulnerabilityReport(
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
    agent_mock: list[m.Message],
    scan_message_ipv4_for_cve_2023_27997: m.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for agent AsteroidAgent exploits check. case Exploit emits vulnerability report"""

    def side_effect(*args, **kwargs):  # type: ignore[no-untyped-def]
        global seed
        mock_response = mocker.Mock(spec=requests.Response)
        if seed % 2 == 0:
            elapsed = datetime.timedelta(microseconds=2500)
        else:
            elapsed = datetime.timedelta(microseconds=1)

        mock_response.elapsed = elapsed
        seed += 1
        return mock_response

    mocker.patch("requests.sessions.Session.post", side_effect=side_effect)

    asteroid_agent_instance.process(scan_message_ipv4_for_cve_2023_27997)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
