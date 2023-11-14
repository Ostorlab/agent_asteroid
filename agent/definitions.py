"""Agent Asteriod definitions"""
import abc
import dataclasses

from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin


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
    def accept(self, target: str) -> bool:
        """Rule to detect specific vulnerability on a specific target.

        Args:
            target: Target to verify

        Returns:
            List of identified vulnerabilities.
        """
        pass

    @abc.abstractmethod
    def check(self, target: str) -> list[Vulnerability]:
        """Rule to detect specific vulnerability on a specific target.

        Args:
            target: target to scan

        Returns:
            List of identified vulnerabilities.
        """
        pass
