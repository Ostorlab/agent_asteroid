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
def asteroid_agent_instance() -> asteroid_agent.AsteroidAgent:
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


@pytest.fixture()
def secure_html_example_cve_2024_31461() -> str:
    return """<html data-theme="dark" style="color-scheme: dark;">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width">
  <title>Sign In</title>
  <meta name="next-head-count" content="3">
  <meta property="og:site_name" content="Plane | Simple, extensible, open-source project management tool.">
  <meta property="og:title" content="Plane | Simple, extensible, open-source project management tool.">
  <style type="text/css">
    .EmojiPickerReact button.epr-emoji {
      align-items: center;
      border-radius: 8px;
      box-sizing: border-box;
      display: flex;
      height: var(--epr-emoji-fullsize);
      justify-content: center;
      max-height: var(--epr-emoji-fullsize);
      max-width: var(--epr-emoji-fullsize);
      overflow: hidden;
      position: relative;
      width: var(--epr-emoji-fullsize)
    }
  </style>
</head>
</html>
"""


@pytest.fixture()
def insecure_html_example_cve_2024_31461() -> str:
    return """
<html data-theme="dark" style="color-scheme: dark;">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width">
  <title>Plane | Simple, extensible, open-source project management tool.</title>
  <meta property="og:site_name" content="Plane | Simple, extensible, open-source project management tool.">
  <meta property="og:title" content="Plane | Simple, extensible, open-source project management tool.">
  <meta property="og:url" content="https://app.plane.so/">
</head>

<body>
  <div id="__next">
    <script>!function () { try { var d = document.documentElement, n = 'data-theme', s = 'setAttribute'; var e = localStorage.getItem('theme'); if ('system' === e || (!e && true)) { var t = '(prefers-color-scheme: dark)', m = window.matchMedia(t); if (m.media !== t || m.matches) { d.style.colorScheme = 'dark'; d[s](n, 'dark') } else { d.style.colorScheme = 'light'; d[s](n, 'light') } } else if (e) { d[s](n, e || '') } if (e === 'light' || e === 'dark') d.style.colorScheme = e } catch (e) { } }()</script>
    <div class="pointer-events-none fixed top-5 right-5 z-50 h-full w-80 space-y-5 overflow-hidden"></div>
    <div class="pointer-events-none fixed top-5 right-5 z-50 h-full w-80 space-y-5 overflow-hidden"></div>
    <div class="h-screen w-full overflow-hidden bg-custom-background-100">
      <div
        class="hidden sm:block sm:fixed border-r-[0.5px] border-custom-border-200 h-screen w-[0.5px] top-0 left-20 lg:left-32">
      </div>
      <div
        class="fixed grid place-items-center bg-custom-background-100 sm:py-5 top-11 sm:top-12 left-7 sm:left-16 lg:left-28">
        <div class="grid place-items-center bg-custom-background-100">
          <div class="h-[30px] w-[30px]"><span
              style="box-sizing: border-box; display: inline-block; overflow: hidden; width: initial; height: initial; background: none; opacity: 1; border: 0px; margin: 0px; padding: 0px; position: relative; max-width: 100%;"><span
                style="box-sizing: border-box; display: block; width: initial; height: initial; background: none; opacity: 1; border: 0px; margin: 0px; padding: 0px; max-width: 100%;"><img
                  alt="" aria-hidden="true"
                  src="data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%27276%27%20height=%27276%27/%3e"
                  style="display: block; max-width: 100%; width: initial; height: initial; background: none; opacity: 1; border: 0px; margin: 0px; padding: 0px;"></span><img
                alt="Plane Logo"
                src="/_next/image?url=%2F_next%2Fstatic%2Fmedia%2Fblue-without-text.17aa0249.png&amp;w=640&amp;q=75"
                decoding="async" data-nimg="intrinsic"
                style="position: absolute; inset: 0px; box-sizing: border-box; padding: 0px; border: none; margin: auto; display: block; width: 0px; height: 0px; min-width: 100%; max-width: 100%; min-height: 100%; max-height: 100%;"
                srcset="/_next/image?url=%2F_next%2Fstatic%2Fmedia%2Fblue-without-text.17aa0249.png&amp;w=384&amp;q=75 1x, /_next/image?url=%2F_next%2Fstatic%2Fmedia%2Fblue-without-text.17aa0249.png&amp;w=640&amp;q=75 2x"></span>
          </div>
        </div>
      </div>
</body>

</html>
"""


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
