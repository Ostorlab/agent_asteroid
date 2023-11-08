"""Sample agent implementation"""
import logging
from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent.message import message as m

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


class HellWorldAgent(agent.Agent):
    """Hello world agent."""

    def start(self) -> None:
        """TODO (author): add your description here."""
        logger.info("running start")

    def process(self, message: m.Message) -> None:
        """TODO (author): add your description here.

        Args:
            message:

        Returns:

        """
        # TODO (author): implement agent logic here.
        del message
        logger.info("processing message")
        self.emit("v3.healthcheck.ping", {"body": "Hello World!"})


if __name__ == "__main__":
    logger.info("starting agent ...")
    HellWorldAgent.main()
