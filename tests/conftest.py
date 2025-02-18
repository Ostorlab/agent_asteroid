"""Pytest fixtures for agent Asteroid"""

import pathlib
import random
from typing import Type, Generator

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions

from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.agent.kb import kb
from agent import asteroid_agent
from agent import exploits_registry
from agent import definitions


@pytest.fixture()
def scan_message_domain_name() -> message.Message:
    """Creates a message of type v3.asset.domain_name.service to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name.service"
    msg_data = {"schema": "https", "name": "www.google.com", "port": 443}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_link() -> message.Message:
    """Creates a message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {"url": "https://www.google.com", "method": "POST"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6() -> message.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "128",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv4() -> message.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "32", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv4_with_mask8() -> message.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "8", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6_with_mask64() -> message.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "64",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def asteroid_agent_instance(
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> asteroid_agent.AsteroidAgent:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/asteroid",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        return asteroid_agent.AsteroidAgent(definition, settings)


@pytest.fixture()
def exploit_instance_with_report() -> Generator[Type[definitions.Exploit], None, None]:
    @exploits_registry.register
    class TestExploit(definitions.Exploit):
        """test class Exploit."""

        def accept(self, target: definitions.Target) -> bool:
            return True

        def check(self, target: definitions.Target) -> list[definitions.Vulnerability]:
            return [
                definitions.Vulnerability(
                    technical_detail="test",
                    entry=kb.Entry(
                        title="test",
                        risk_rating="INFO",
                        short_description="test purposes",
                        description="test purposes",
                        recommendation="",
                        references={},
                        security_issue=False,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False,
                    ),
                    risk_rating=vuln_mixin.RiskRating.HIGH,
                )
            ]

    yield TestExploit
    exploits_registry.unregister(TestExploit)


@pytest.fixture
def scan_bad_url_message() -> message.Message:
    """Creates a bad message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {
        "url": "javascript: window.open('/index.html', '_blank', 'width=900, height=600, toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=no');",
        "method": "GET",
        "form_credential": {
            "login": "testlogin",
            "password": "testpassword",
            "url": "https://example.com//Login.aspx",
        },
        "parent": {
            "url": "https://example.com/index.html",
            "method": "GET",
        },
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_bad_message() -> message.Message:
    """Creates a bad message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {
        "method": "GET",
        "form_credential": {
            "login": "testlogin",
            "password": "testpassword",
            "url": "https://example.com//Login.aspx",
        },
        "parent": {
            "url": "https://example.com/index.html",
            "method": "GET",
        },
    }
    return message.Message.from_data(selector, data=msg_data)
