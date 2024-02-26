"""Agent Asteriod definitions"""
import abc
import dataclasses

from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin

from agent.exploits import common


@dataclasses.dataclass
class Target:
    """Target dataclass"""

    scheme: str
    host: str
    port: int
    path: str = "/"

    @property
    def url(self) -> str:
        host = common.prepare_host(self.host)
        return f"{self.scheme}://{host}:{self.port}{self.path}"

    @property
    def origin(self) -> str:
        host = common.prepare_host(self.host)
        return f"{self.scheme}://{host}:{self.port}"


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability entry with technical details, custom risk rating, DNA for unique identification and location."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: vuln_mixin.RiskRating
    dna: str | None = None
    vulnerability_location: vuln_mixin.VulnerabilityLocation | None = None


class Exploit(abc.ABC):
    """Base Exploit"""

    @abc.abstractmethod
    def accept(self, target: Target) -> bool:
        """Rule: heuristically detect if a specific target is valid.

        Args:
            target: Target to verify

        Returns:
            True if the target is valid; otherwise False.
        """
        pass

    @abc.abstractmethod
    def check(self, target: Target) -> list[Vulnerability]:
        """Rule to detect specific vulnerability on a specific target.

        Args:
            target: target to scan

        Returns:
            List of identified vulnerabilities.
        """
        pass

    @property
    def __key__(self) -> str:
        """Unique key for the class, mainly useful for registering the exploits."""
        return self.__class__.__name__
