"""Agent Asteroid definitions"""

import abc
import ssl
import dataclasses
from typing import Any

import requests
import cloudscraper
from packaging import version
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin

from agent.exploits import common

MAX_REDIRECTS = 2


@dataclasses.dataclass
class Target:
    """Target dataclass."""

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


@dataclasses.dataclass
class VulnerabilityMetadata:
    """Vulnerability metadata: title, description, risk"""

    title: str
    description: str
    reference: str
    risk_rating: str = "CRITICAL"
    recommendation: str = (
        "- Make sure to install the latest security patches from software vendor \n"
        "- Update to the latest software version"
    )
    short_description: str | None = None
    references: dict[str, str] = dataclasses.field(default_factory=dict)
    security_issue: bool = True
    privacy_issue: bool = False
    has_public_exploit: bool = True
    targeted_by_malware: bool = False
    targeted_by_ransomware: bool = False
    targeted_by_nation_state: bool = False

    def get_references(self) -> dict[str, str]:
        """Get complete references dict including default NVD reference."""
        refs = {
            "nvd.nist.gov": f"https://nvd.nist.gov/vuln/detail/{self.reference}",
        }
        if self.references is not None:
            refs.update(self.references)
        return refs


class SSLAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args: Any, **kwargs: dict[str, Any]) -> Any:
        """
        Initializes the pool manager for handling HTTPS connections.

        This method overrides the default implementation to customize the SSL context
        for HTTPS connections, specifically to disable SSL verification and hostname checking.

        Args:
            *args: Variable length argument list. Passed to the parent method.
            **kwargs: Keyword arguments. Passed to the parent method, after the override
            of the ssl_context parameter.

        Returns:
            PoolManager: An instance of PoolManager configured with the provided SSL context.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = context  # type:ignore[assignment]
        return super().init_poolmanager(*args, **kwargs)  # type:ignore[no-untyped-call]


class HttpSession(cloudscraper.CloudScraper):  # type:ignore[no-any-unimported,misc]
    """Wrapper for the requests session class."""

    def __init__(self) -> None:
        super().__init__()
        self.max_redirects = MAX_REDIRECTS
        self.verify = False
        self.mount("https://", SSLAdapter())


class Exploit(abc.ABC):
    """Base Exploit"""

    metadata: VulnerabilityMetadata = dataclasses.field(
        default_factory=VulnerabilityMetadata
    )

    def __init__(self) -> None:
        self.session = HttpSession()

    @abc.abstractmethod
    def accept(self, target: Target) -> bool:
        """Rule: heuristically detect if a specific target is valid.

        Args:
            target: Target to verify

        Returns:
            True if the target is valid; otherwise False.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def check(self, target: Target) -> list[Vulnerability]:
        """Rule to detect specific vulnerability on a specific target.

        Args:
            target: target to scan

        Returns:
            List of identified vulnerabilities.
        """
        raise NotImplementedError()

    @property
    def __key__(self) -> str:
        """Unique key for the class, mainly useful for registering the exploits."""
        return self.__class__.__name__

    def _create_vulnerability(
        self,
        target: Target,
    ) -> Vulnerability:
        """Creates a vulnerability instance with consistent metadata.

        Args:
            target: The target being checked

        Returns:
            Vulnerability instance with complete metadata
        """

        entry = kb.Entry(
            title=self.metadata.title,
            risk_rating=self.metadata.risk_rating,
            short_description=self.metadata.short_description
            or self.metadata.description,
            description=self.metadata.description,
            references=self.metadata.get_references(),
            recommendation=self.metadata.recommendation,
            security_issue=self.metadata.security_issue,
            privacy_issue=self.metadata.privacy_issue,
            has_public_exploit=self.metadata.has_public_exploit,
            targeted_by_malware=self.metadata.targeted_by_malware,
            targeted_by_ransomware=self.metadata.targeted_by_ransomware,
            targeted_by_nation_state=self.metadata.targeted_by_nation_state,
        )

        technical_detail = (
            f"{target.url} is vulnerable to {self.metadata.reference}, "
            f"{self.metadata.title}"
        )
        vulnerability_location = common.build_vuln_location(target.url)
        dna = common.compute_dna(
            vulnerability_title=self.metadata.title,
            vuln_location=vulnerability_location,
        )

        return Vulnerability(
            entry=entry,
            technical_detail=technical_detail,
            risk_rating=vuln_mixin.RiskRating[self.metadata.risk_rating.upper()],
            vulnerability_location=vulnerability_location,
            dna=dna,
        )


@dataclasses.dataclass
class Request:
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] | None = None
    data: bytes | None = None


@dataclasses.dataclass
class VulnRange:
    min: version.Version | None
    max: version.Version | None
