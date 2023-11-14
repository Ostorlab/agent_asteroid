"""Ostorlab Agent for Detecting Known exploitable vulnerabilities on a Remote system"""
import logging
import dataclasses
import ipaddress
from urllib import parse
from rich import logging as rich_logging
from typing import List, Optional, cast

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
logger.setLevel("DEBUG")

SCHEME_TO_PORT = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "pop3": 110,
    "imap": 143,
    "irc": 6667,
    "mysql": 3306,
    "postgres": 5432,
    "redis": 6379,
    "mongodb": 27017,
    "ldap": 389,
    "sftp": 22,
    "vnc": 5900,
    "git": 9418,
}


@dataclasses.dataclass
class Target:
    name: str
    schema: Optional[str] = None
    port: Optional[int] = None


class AsteroidAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Asteroid agent."""


    def process(self, message: m.Message) -> None:
        """ add your description here.

        Args:
            message:

        Returns:

        """
        #  implement agent logic here.
        del message
        logger.info("processing message")
        self.emit("v3.healthcheck.ping", {"body": "Hello World!"})

    def _get_target_from_url(self, message: m.Message) -> Target | None:
        """Compute schema and port from a URL"""
        url = message.data["url"]
        parsed_url = parse.urlparse(url)
        if parsed_url.scheme not in SCHEME_TO_PORT:
            return None
        schema = parsed_url.scheme or self.args.get("schema")
        schema = cast(str, schema)
        domain_name = parse.urlparse(url).netloc
        port = 0
        if len(parsed_url.netloc.split(":")) > 1:
            domain_name = parsed_url.netloc.split(":")[0]
            if (
                len(parsed_url.netloc.split(":")) > 0
                and parsed_url.netloc.split(":")[-1] != ""
            ):
                port = int(parsed_url.netloc.split(":")[-1])
        args_port = self._get_port(message)
        port = port or SCHEME_TO_PORT.get(schema) or args_port
        target = Target(name=domain_name, schema=schema, port=port)
        return target

    def _get_port(self, message: m.Message) -> int:
        """Returns the port to be used for the target."""
        if message.data.get("port") is not None:
            return int(message.data["port"])
        else:
            return int(str(self.args.get("port")))

    def _get_schema(self, message: m.Message) -> str:
        """Returns the schema to be used for the target."""
        if message.data.get("schema") is not None:
            if str(message.data["schema"]) in [
                "https?",
                "ssl/https-alt?",
                "ssl/https-alt",
                "https-alt",
                "https-alt?",
            ]:
                return "https"
            elif str(message.data["schema"]) in ["http?", "http"]:
                return "http"
            else:
                return str(message.data["schema"])
        elif message.data.get("protocol") is not None:
            return str(message.data["protocol"])
        elif self.args.get("https") is True:
            return "https"
        else:
            return "http"

    def _prepare_targets(self, message: m.Message) -> List[str]:
        """Prepare targets based on type, if a domain name is provided, port and protocol are collected
        from the config."""
        if message.data.get("host") is not None:
            host = str(message.data.get("host"))
            if message.data.get("mask") is None:
                ip_network = ipaddress.ip_network(host)
            else:
                mask = message.data.get("mask")
                ip_network = ipaddress.ip_network(f"{host}/{mask}", strict=False)
            return [str(h) for h in ip_network.hosts()]

        elif (domain_name := message.data.get("name")) is not None:
            schema = self._get_schema(message)
            port = self._get_port(message)
            if schema == "https" and port not in [443, None]:
                url = f"https://{domain_name}:{port}"
            elif schema == "https":
                url = f"https://{domain_name}"
            elif port == 80:
                url = f"http://{domain_name}"
            elif port is None:
                url = f"{schema}://{domain_name}"
            else:
                url = f"{schema}://{domain_name}:{port}"

            return [url]

        elif (url_temp := message.data.get("url")) is not None:
            return [url_temp]
        else:
            return []


if __name__ == "__main__":
    logger.info("starting agent ...")
    AsteroidAgent.main()
