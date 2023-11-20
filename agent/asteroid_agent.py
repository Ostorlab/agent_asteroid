"""Asteroid Agent is designed to identify known exploitable vulnerabilities in a remote system. The agent expects a
message of type `v3.asset.ip.[v4,v6]` or `v3.asset.[domain_name,link]`, and emits back messages of type
`v3.report.vulnerability` with a technical report."""
import logging
from rich import logging as rich_logging
import concurrent.futures


from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message as m

from agent import utils
from agent import exploits_registry
from agent import definitions

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)


class AsteroidAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Asteroid Agent is designed to identify known exploitable vulnerabilities in a remote system."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        """Initialize The Agent instance."""

        super().__init__(agent_definition, agent_settings)
        self.exploits: list[
            definitions.Exploit
        ] = exploits_registry.ExploitsRegistry.values()

    def process(self, message: m.Message) -> None:
        """Process messages of type `v3.asset.ip.[v4,v6]` or `v3.asset.[domain_name,link]` and performs a network
        scan. Once the scan is completed, it emits messages of type
        `v3.report.vulnerability` with the technical report.

        Args:
            message: message containing the asset to scan.
        """
        targets = utils.prepare_targets(message)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for exploit in self.exploits:
                for target in targets:
                    exploit_vulnz = []
                    if exploit.accept(target) is False:
                        continue
                    exploit_vulnz.append(executor.submit(exploit.check, target))

            for target_vulnz in exploit_vulnz:
                for vulnerability in target_vulnz.result():
                    self.report_vulnerability(
                        entry=vulnerability.entry,
                        risk_rating=vulnerability.risk_rating,
                        vulnerability_location=vulnerability.vulnerability_location,
                        dna=vulnerability.dna,
                        technical_detail=vulnerability.technical_detail,
                    )


if __name__ == "__main__":
    logger.info("starting agent ...")
    AsteroidAgent.main()
