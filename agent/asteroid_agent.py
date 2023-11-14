"""Asteroid Agent is designed to identify known exploitable vulnerabilities in a remote system. The agent expects a
message of type `v3.asset.ip.[v4,v6]` or `v3.asset.[domain_name,link]`, and emits back messages of type
`v3.report.vulnerability` with a technical report."""
import logging
from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.message import message as m

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

    def process(self, message: m.Message) -> None:
        """Process messages of type `v3.asset.ip.[v4,v6]` or `v3.asset.[domain_name,link]` and performs a network
        scan. Once the scan is completed, it emits messages of type
        `v3.report.vulnerability` with the technical report.

        Args:
            message: message containing the asset to scan.
        """

        # TODO (benyissa): implement agent logic here.


if __name__ == "__main__":
    logger.info("starting agent ...")
    AsteroidAgent.main()
