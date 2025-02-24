"""Unit tests for AsteroidAgent."""

import ipaddress
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
    mocker: plugin.MockerFixture,
    requests_mock: requests_mock.Mocker,
) -> None:
    """Unit test for agent AsteroidAgent exploits check. case Exploit emits vulnerability report"""

    mock_var_bind = mocker.MagicMock()
    mock_var_bind.__getitem__.return_value.prettyPrint.return_value = (
        "ArubaOS (MODEL: 7005), Version 8.5.0.0"
    )
    mock_iterator = mocker.MagicMock()
    mock_iterator.__next__.return_value = (None, None, None, [mock_var_bind])
    mocker.patch("pysnmp.hlapi.getCmd", return_value=mock_iterator)

    requests_mock.register_uri(ANY, ANY, status_code=404, text="")

    asteroid_agent_instance.process(scan_message_domain_name)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["vulnerability_location"] is not None
    assert agent_mock[0].data["dna"] is not None


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
    assert agent_mock[0].data["vulnerability_location"] is not None
    assert agent_mock[0].data["dna"] is not None


def testAsteroidAgent_whenDomainReceivedTwice_onlyProcessesOnce(
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
    scan_message_domain_name: m.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a message is only processed once and marked as processed."""
    targets_preparer_mock = mocker.patch(
        "agent.asteroid_agent.targets_preparer.prepare_targets"
    )
    asteroid_agent_instance.process(scan_message_domain_name)

    asteroid_agent_instance.process(scan_message_domain_name)

    assert targets_preparer_mock.call_count == 1
    assert (
        asteroid_agent_instance.set_is_member(
            key=asteroid_agent.ASTEROID_AGENT_KEY, value="www.google.com"
        )
        is True
    )


def testAsteroidAgent_whenIPReceivedWithMaskTwice_onlyProcessesNetowrkOnce(
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
    scan_message_ipv4: m.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a message is only processed once and marked as processed."""
    targets_preparer_mock = mocker.patch(
        "agent.asteroid_agent.targets_preparer.prepare_targets"
    )
    asteroid_agent_instance.process(scan_message_ipv4)

    asteroid_agent_instance.process(scan_message_ipv4)

    assert targets_preparer_mock.call_count == 1
    addresses = ipaddress.ip_network("192.168.1.17/32", strict=False)
    assert (
        asteroid_agent_instance.ip_network_exists(
            key=asteroid_agent.ASTEROID_AGENT_KEY, ip_range=addresses
        )
        is True
    )


def testAsteroidAgent_whenIPReceivedWithNoMask_onlyProcessesIPOnce(
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
    scan_message_ipv4: m.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a message is only processed once and marked as processed."""
    scan_message_ipv4.data.pop("mask")
    targets_preparer_mock = mocker.patch(
        "agent.asteroid_agent.targets_preparer.prepare_targets"
    )
    asteroid_agent_instance.process(scan_message_ipv4)

    asteroid_agent_instance.process(scan_message_ipv4)

    assert targets_preparer_mock.call_count == 1
    assert (
        asteroid_agent_instance.set_is_member(
            key=asteroid_agent.ASTEROID_AGENT_KEY, value="192.168.1.17"
        )
        is True
    )


def testAsteroidAgent_whenRecivedTargetIsNotValid_logWarning(
    caplog: Any,
    asteroid_agent_instance: asteroid_agent.AsteroidAgent,
) -> None:
    """Test that a warning is logged when an invalid message is received."""
    msg = m.Message(
        selector="v3.asset.link",
        data={"x": "https://example.com", "method": "GET"},
        raw=b"\n\x19https://example.com\x12\x03GET",
    )

    asteroid_agent_instance.process(msg)

    assert "Invalid message format" in caplog.text
