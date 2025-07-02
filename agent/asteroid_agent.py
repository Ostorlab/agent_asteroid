"""Asteroid Agent is designed to identify known exploitable vulnerabilities in a remote system. The agent expects a
message of type `v3.asset.ip.[v4,v6]` or `v3.asset.[domain_name,link]`, and emits back messages of type
`v3.report.vulnerability` with a technical report."""

import ipaddress
import logging
from concurrent import futures
from typing import Any

from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import definitions
from agent import exploits
from agent import exploits_registry
from agent import targets_preparer

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)


def _check_target(
    exploit: definitions.Exploit, target: definitions.Target
) -> list[definitions.Vulnerability]:
    if exploit.accept(target) is False:
        return []

    logger.info("Checking %s ...", target.host)
    return exploit.check(target)


ASTEROID_AGENT_KEY = b"agent_asteroid_asset"


class AsteroidAgent(
    agent.Agent,
    vuln_mixin.AgentReportVulnMixin,
    persist_mixin.AgentPersistMixin,
):
    """Asteroid Agent is designed to identify known exploitable vulnerabilities in a remote system."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        """Initialize The Agent instance."""

        super().__init__(agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

        exploits.import_all()

        custom_cve_list: Any | None = self.args.get("custom_cve_list")

        self.exploits: list[definitions.Exploit] = []
        all_exploits = exploits_registry.ExploitsRegistry.values()
        logger.info(all_exploits)

        if custom_cve_list is not None and len(custom_cve_list) == 0:
            self.exploits = all_exploits
        else:
            for exploit in all_exploits:
                if (
                    custom_cve_list is not None
                    and exploit.__class__.__name__ in custom_cve_list
                ):
                    self.exploits.append(exploit)

    def _is_target_already_processed(self, message: m.Message) -> bool:
        """Checks if the target has already been processed before"""
        if message.data.get("url") is not None or message.data.get("name") is not None:
            unicity_check_key = f"{message.data.get('url') or message.data.get('name')}"
            return self.set_is_member(key=ASTEROID_AGENT_KEY, value=unicity_check_key)

        if message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                return self.ip_network_exists(
                    key=ASTEROID_AGENT_KEY, ip_range=addresses
                )
            return self.set_is_member(key=ASTEROID_AGENT_KEY, value=host)
        logger.warning(f"Invalid message format\nmessage: {message}")
        return True

    def _mark_target_as_processed(self, message: m.Message) -> None:
        """Mark the target as processed"""
        if message.data.get("url") is not None or message.data.get("name") is not None:
            unicity_check_key = f"{message.data.get('url') or message.data.get('name')}"
            self.set_add(ASTEROID_AGENT_KEY, unicity_check_key)
        elif message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                self.add_ip_network(key=ASTEROID_AGENT_KEY, ip_range=addresses)
            else:
                self.set_add(ASTEROID_AGENT_KEY, host)

    def process(self, message: m.Message) -> None:
        """Process messages of type `v3.asset.ip.[v4,v6]` or `v3.asset.[domain_name,link]` and performs a network
        scan. Once the scan is completed, it emits messages of type
        `v3.report.vulnerability` with the technical report.

        Args:
            message: message containing the asset to scan.
        """
        if self._is_target_already_processed(message) is True:
            return
        logger.info("Preparing targets ...")
        targets = targets_preparer.prepare_targets(message)
        with futures.ThreadPoolExecutor() as executor:
            targets_checks = [
                executor.submit(_check_target, exploit, target)
                for target in targets
                for exploit in self.exploits
            ]
            for target_vulnz in futures.as_completed(targets_checks):
                if len(target_vulnz.result()) == 0:
                    continue
                logger.info("Found %d vulnerabilities", len(target_vulnz.result()))
                for vulnerability in target_vulnz.result():
                    self.report_vulnerability(
                        entry=vulnerability.entry,
                        risk_rating=vulnerability.risk_rating,
                        vulnerability_location=vulnerability.vulnerability_location,
                        dna=vulnerability.dna,
                        technical_detail=vulnerability.technical_detail,
                    )

        self._mark_target_as_processed(message)


if __name__ == "__main__":
    logger.info("starting agent ...")
    AsteroidAgent.main()
