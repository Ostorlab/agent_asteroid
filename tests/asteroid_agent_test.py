"""Unit tests for Agent Asteroid: CVE-2025-22457"""

import json
from unittest import mock

import pathlib


from agent import definitions
from agent.exploits import cve_2025_22457
from agent import asteroid_agent

from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message
from ostorlab.utils import definitions as utils_definitions


def testAccept_whenHttpsAndVulnerableVersion_shouldReturnTrue() -> None:
    """Test accept method with valid conditions."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock requests.get to return a vulnerable version response
    mock_response = mock.Mock()
    mock_response.text = '<PARAM NAME="ProductVersion" VALUE="22.7R2.4"><PARAM NAME="ProductName" VALUE="Ivanti Connect Secure">'
    mock_response.status_code = 200

    # Only mock requests.get and let the real _grab_version_info run
    with mock.patch("requests.get", return_value=mock_response):
        assert exploit.accept(target) is True


def testAccept_whenHttp_shouldReturnFalse() -> None:
    """Test accept method with HTTP target."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("http", "localhost", 80)

    # Should return False for HTTP without even making a request
    assert exploit.accept(target) is False


def testCheck_whenTargetIsVulnerable_shouldReportVulnerability() -> None:
    """Test check method with vulnerable target."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock the accept method to return True
    with (
        mock.patch.object(exploit, "accept", return_value=True),
        mock.patch("agent.exploits.cve_2025_22457._check_crash", return_value=True),
    ):
        vulnerabilities = exploit.check(target)

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].entry.title == cve_2025_22457.VULNERABILITY_TITLE
        assert vulnerabilities[0].entry.risk_rating == cve_2025_22457.RISK_RATING
        assert vulnerabilities[0].vulnerability_location is not None
        assert vulnerabilities[0].dna is not None


def testCheck_whenVersionCheckFails_shouldNotReportVulnerability() -> None:
    """Test check method when version check fails."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock the accept method to return False (version check failure)
    with mock.patch.object(exploit, "accept", return_value=False):
        vulnerabilities = exploit.check(target)
        assert len(vulnerabilities) == 0


def testCheck_whenNoCrash_shouldNotReportVulnerability() -> None:
    """Test check method when target doesn't crash."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock the accept method to return True but _check_crash to return False
    with (
        mock.patch.object(exploit, "accept", return_value=True),
        mock.patch("agent.exploits.cve_2025_22457._check_crash", return_value=False),
    ):
        vulnerabilities = exploit.check(target)

        assert len(vulnerabilities) == 0


def testCheck_whenVersionNotVulnerable_shouldNotReportVulnerability() -> None:
    """Test check method when version is not vulnerable."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock requests.get to return a patched version response
    with mock.patch.object(exploit, "accept", return_value=False):
        vulnerabilities = exploit.check(target)
        assert len(vulnerabilities) == 0


def testAgent_whenCustomCVEPassed_shouldScanOnlyTheScope(
    agent_mock: list[message.Message],
) -> None:
    """Fixture of the Nmap Agent to be used for testing purposes."""
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/asteroid",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="custom_cve_list",
                    type="array",
                    value=json.dumps(
                        [
                            "CVE-2014-0780",
                            "CVE-2025-27364",
                        ]
                    ).encode(),
                )
            ],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = asteroid_agent.AsteroidAgent(definition, settings)

        assert len(agent.exploits) == 2
        found_cves: list[str] = []
        for exploit in agent.exploits:
            found_cves.extend(exploit.metadata.cve_ids)

        assert "CVE-2014-0780" in found_cves
        assert "CVE-2025-27364" in found_cves


def testAgent_whenCustomCVEsMatchCVEIDsInMetadatabutNotPluginName_shouldScanOnlyTheScope(
    agent_mock: list[message.Message],
) -> None:
    """Even if the plugin's name doesn’t match the CVEs passed, the agent should still include it in the scan if its metadata contains matching CVEs."""
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/asteroid",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="custom_cve_list",
                    type="array",
                    value=json.dumps(
                        [
                            "CVE-2014-0780",
                            "CVE-2025-27364",
                            "CVE-2025-48828",
                            "CVE-2018-10562",
                        ]
                    ).encode(),
                )
            ],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = asteroid_agent.AsteroidAgent(definition, settings)

        assert len(agent.exploits) == 4
        found_cves: list[str] = []
        for exploit in agent.exploits:
            found_cves.extend(exploit.metadata.cve_ids)

        assert "CVE-2014-0780" in found_cves
        assert "CVE-2025-27364" in found_cves
        assert "CVE-2025-48828" in found_cves
        assert "CVE-2018-10562" in found_cves


def testAgent_whenNoCustomCVEPassed_shouldSetAllExploits() -> None:
    """Ensure that when no custom CVE list is provided, the agent loads all available exploits."""
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/asteroid",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )
        agent = asteroid_agent.AsteroidAgent(definition, settings)

        assert len(agent.exploits) == 116
