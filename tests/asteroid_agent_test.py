"""Unit tests for Agent Asteroid: CVE-2025-22457"""

import json
import pathlib
from unittest import mock

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import definitions as utils_definitions

from agent import (
    asteroid_agent,
    definitions,
)
from agent import (
    exploits_registry as registry,
)
from agent.exploits import cve_2025_22457


@pytest.mark.parametrize(
    "cve,detector_name",
    [
        ("CVE-2026-102610", "CVE2026102610Exploit"),
        ("CVE-2026-59822", "CVE202659822Exploit"),
        ("CVE-2026-49869", "CVE202649869Exploit"),
        ("CVE-2026-96652", "CVE202696652Exploit"),
        ("CVE-2026-96654", "CVE202696652Exploit"),
        ("CVE-2026-96655", "CVE202696652Exploit"),
        ("CVE-2026-96656", "CVE202696652Exploit"),
        ("CVE-2023-49105", "CVE202349105Exploit"),
    ],
)
def testAgent_whenWebMetadataCveSelected_loadsItsRegisteredDetector(
    cve: str, detector_name: str
) -> None:
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
                value=json.dumps([cve]).encode(),
            )
        ],
        healthcheck_port=0,
        redis_url="redis://guest:guest@localhost:6379",
    )
    scanner = asteroid_agent.AsteroidAgent(definition, settings)
    assert len(scanner.exploits) == 1
    assert type(scanner.exploits[0]).__name__ == detector_name
    assert cve in scanner.exploits[0].metadata.cve_ids


def testAccept_whenHttpsAndVulnerableVersion_shouldReturnTrue() -> None:
    """Test accept method with valid conditions."""
    exploit = cve_2025_22457.CVE202522457Exploit()
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
    exploit = cve_2025_22457.CVE202522457Exploit()
    target = definitions.Target("http", "localhost", 80)

    # Should return False for HTTP without even making a request
    assert exploit.accept(target) is False


def testCheck_whenTargetIsVulnerable_shouldReportVulnerability() -> None:
    """Test check method with vulnerable target."""
    exploit = cve_2025_22457.CVE202522457Exploit()
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
    exploit = cve_2025_22457.CVE202522457Exploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock the accept method to return False (version check failure)
    with mock.patch.object(exploit, "accept", return_value=False):
        vulnerabilities = exploit.check(target)
        assert len(vulnerabilities) == 0


def testCheck_whenNoCrash_shouldNotReportVulnerability() -> None:
    """Test check method when target doesn't crash."""
    exploit = cve_2025_22457.CVE202522457Exploit()
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
    exploit = cve_2025_22457.CVE202522457Exploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock requests.get to return a patched version response
    with mock.patch.object(exploit, "accept", return_value=False):
        vulnerabilities = exploit.check(target)
        assert len(vulnerabilities) == 0


def testAgent_whenWordPressCveSelected_loadsExactlyOneProfile() -> None:
    """Each profile survives registration and the real custom_cve_list filter."""
    cves = (
        "CVE-2024-5333",
        "CVE-2023-3452",
        "CVE-2025-12536",
        "CVE-2026-2416",
        "CVE-2025-69411",
        "CVE-2025-13801",
        "CVE-2025-9209",
        "CVE-2025-12841",
        "CVE-2026-8181",
        "CVE-2025-13773",
        "CVE-2026-9290",
        "CVE-2026-1980",
        "CVE-2026-39468",
        "CVE-2019-14793",
        "CVE-2026-4060",
        "CVE-2026-49772",
        "CVE-2026-52715",
        "CVE-2026-9848",
        "CVE-2026-3296",
    )
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
    keys: set[str] = set()
    for cve in cves:
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/asteroid",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="custom_cve_list",
                    type="array",
                    value=json.dumps([cve]).encode(),
                )
            ],
            healthcheck_port=0,
            redis_url="redis://guest:guest@localhost:6379",
        )
        scanner = asteroid_agent.AsteroidAgent(definition, settings)
        assert len(scanner.exploits) == 1
        assert scanner.exploits[0].metadata.cve_ids == [cve]
        keys.add(scanner.exploits[0].__key__)
    assert len(keys) == len(cves)


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

        assert len(agent.exploits) >= 177
        assert len(agent.exploits) == len(registry.ExploitsRegistry.values())
        assert {exploit.__key__ for exploit in agent.exploits} == {
            registered.__key__ for registered in registry.ExploitsRegistry.values()
        }


def testAgent_whenMetabaseCVEsRequested_loadsSevenIndependentDetectors() -> None:
    """Each Metabase CVE must be selectable independently through the agent."""
    cve_ids = {
        "CVE-2026-27464",
        "CVE-2026-33725",
        "CVE-2026-59826",
        "CVE-2026-59827",
        "CVE-2026-72898",
        "CVE-2026-72899",
        "CVE-2026-72900",
    }
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
                value=json.dumps(sorted(cve_ids)).encode(),
            )
        ],
        healthcheck_port=0,
        redis_url="redis://guest:guest@localhost:6379",
    )
    agent = asteroid_agent.AsteroidAgent(definition, settings)

    assert len(agent.exploits) == 7
    assert {detector.metadata.reference for detector in agent.exploits} == cve_ids
    assert all(len(detector.metadata.cve_ids) == 1 for detector in agent.exploits)


def testAgent_whenGiteaCVEsRequested_loadsOnlyRegisteredRemoteDetectors() -> None:
    """The configuration-sensitive Docker advisory remains inventory-only."""
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
    requested = ["CVE-2026-59774", "CVE-2026-60004", "CVE-2026-27771", "CVE-2021-45328"]
    settings = runtime_definitions.AgentSettings(
        key="agent/ostorlab/asteroid",
        bus_url="NA",
        bus_exchange_topic="NA",
        args=[
            utils_definitions.Arg(
                name="custom_cve_list",
                type="array",
                value=json.dumps(requested + ["CVE-2026-20896"]).encode(),
            )
        ],
        healthcheck_port=0,
        redis_url="redis://guest:guest@localhost:6379",
    )
    agent = asteroid_agent.AsteroidAgent(definition, settings)
    assert len(agent.exploits) == 4
    assert {
        cve for detector in agent.exploits for cve in detector.metadata.cve_ids
    } == set(requested)


def testAgent_whenDefensiveCVEsRequested_loadsAllRequestedDetectors() -> None:
    """Ensure newly added 2025-2026 CVE detectors load via custom_cve_list."""
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
                        "CVE-2025-53770",
                        "CVE-2025-3248",
                        "CVE-2025-55182",
                        "CVE-2025-31324",
                    ]
                ).encode(),
            )
        ],
        healthcheck_port=0,
        redis_url="redis://guest:guest@localhost:6379",
    )

    agent = asteroid_agent.AsteroidAgent(definition, settings)

    assert len(agent.exploits) == 4
    assert {
        cve for detector in agent.exploits for cve in detector.metadata.cve_ids
    } == {
        "CVE-2025-53770",
        "CVE-2025-3248",
        "CVE-2025-55182",
        "CVE-2025-31324",
    }


def testAgent_whenN8nCVERequested_loadsOnlyRequestedDetector() -> None:
    """The n8n detector survives the actual custom_cve_list selection path."""
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
                value=json.dumps(["CVE-2026-21858"]).encode(),
            )
        ],
        healthcheck_port=0,
        redis_url="redis://guest:guest@localhost:6379",
    )
    agent = asteroid_agent.AsteroidAgent(definition, settings)

    assert [exploit.metadata.reference for exploit in agent.exploits] == [
        "CVE-2026-21858"
    ]
    assert agent.exploits[0].metadata.cve_ids == ["CVE-2026-21858"]
