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


class BaseExploit(abc.ABC):
    """Base Exploit"""

    @property
    @abc.abstractmethod
    def vulnerability_title(self) -> str:
        """Vulnerability title"""
        pass

    @property
    @abc.abstractmethod
    def vulnerability_reference(self) -> str:
        """Vulnerability reference (ie. CVE)"""
        pass

    @property
    @abc.abstractmethod
    def vulnerability_description(self) -> str:
        """Vulnerability description"""
        pass

    def is_target_valid(self) -> bool:
        return False

    def check(self) -> list[Vulnerability] | None:
        """Rule to detect specific vulnerability on a specific target.

        Args:


        Returns:
            List of identified vulnerabilities.
        """
        return None
