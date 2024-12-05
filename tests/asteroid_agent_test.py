"""Unit tests for AsteroidAgent."""

from typing import Any, Iterator, Type

import requests_mock
from ostorlab.agent.message import message as m
from pytest_mock import plugin
from requests_mock.adapter import ANY

from agent import asteroid_agent, definitions


def testAsteroidAgent_whenExploitCheckDetectVulnz_EmitsVulnerabilityReport(
    exploit_instance_with_report: Iterator[Type[definitions.Exploit]],
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
    agent_mock: list[m.Message],
    scan_message_domain_name: m.Message,
) -> None:
    """Unit test for agent AsteroidAgent exploits check. case Exploit emits vulnerability report"""

    asteroid_agent_instance.process(scan_message_domain_name)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"


def testAsteroidAgent_whenTooManyRedirects_doesNotCrash(
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
    agent_mock: list[m.Message],
    mocker: plugin.MockerFixture,
    requests_mock: requests_mock.Mocker,
) -> None:
    """Ensure that the agent does not crash when there are too many redirects."""

    def response_callback(request: Any, context: Any) -> str:
        context.headers = {"Location": request.url}
        context.status_code = 302
        return ""

    requests_mock.register_uri(
        ANY,
        ANY,
        text=response_callback,
    )

    mock_var_bind = mocker.MagicMock()
    mock_var_bind.__getitem__.return_value.prettyPrint.return_value = (
        "ArubaOS (MODEL: 7005), Version 8.5.0.0"
    )
    mock_iterator = mocker.MagicMock()
    mock_iterator.__next__.return_value = (None, None, None, [mock_var_bind])
    mocker.patch("pysnmp.hlapi.getCmd", return_value=mock_iterator)

    msg = m.Message(
        selector="v3.asset.link",
        data={"url": "https://example.com", "method": "GET"},
        raw=b"\n\x19https://example.com\x12\x03GET",
    )
    asteroid_agent_instance.process(msg)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
