"""Agent Asteriod definitions"""

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
