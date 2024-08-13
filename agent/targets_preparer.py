"""Target Preparer Module for Asteroid Agent"""

from typing import Generator
from urllib.parse import urlparse
import logging

from ostorlab.agent.message import message as m
import ipaddress
from agent import definitions

logger = logging.getLogger(__name__)

IPV4_CIDR_LIMIT = 16
IPV6_CIDR_LIMIT = 112
DEFAULT_PORT = 443
DEFAULT_SCHEME = "https"
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


def _get_port(message: m.Message, scheme: str) -> int:
    """Returns the port to be used for the target."""
    if message.data.get("port") is None:
        return SCHEME_TO_PORT.get(scheme) or DEFAULT_PORT
    return int(message.data["port"])


def _get_scheme(message: m.Message) -> str:
    """Returns the schema to be used for the target."""
    protocol = message.data.get("protocol")
    if protocol is not None:
        return str(protocol)

    schema = message.data.get("schema")
    if schema is None:
        return DEFAULT_SCHEME
    if schema in [
        "https",
        "https?",
        "ssl/https-alt?",
        "ssl/https-alt",
        "https-alt",
        "https-alt?",
    ]:
        return "https"
    if schema in ["http?", "http"]:
        return "http"
    return str(schema)


def prepare_targets(message: m.Message) -> Generator[definitions.Target, None, None]:
    """Prepare targets based on type. If a domain name is provided, port and protocol are collected from the config.

    Args:
        message (m.Message): The input message containing information about the target.

    Yields:
        Target: A target containing host, port, and scheme information.
    """
    if (host := message.data.get("host")) is not None:
        scheme = _get_scheme(message)
        port = _get_port(message, scheme)
        mask = message.data.get("mask")
        if mask is None:
            hosts = ipaddress.ip_network(host)
        else:
            version = message.data.get("version")
            if version == 4 and int(mask) < IPV4_CIDR_LIMIT:
                raise ValueError(
                    f"Subnet mask below {IPV4_CIDR_LIMIT} is not supported."
                )
            if version == 6 and int(mask) < IPV6_CIDR_LIMIT:
                raise ValueError(
                    f"Subnet mask below {IPV6_CIDR_LIMIT} is not supported."
                )
            hosts = ipaddress.ip_network(f"{host}/{mask}", strict=False)
        yield from (
            definitions.Target(host=str(h), port=port, scheme=scheme) for h in hosts
        )
    elif (host := message.data.get("name")) is not None:
        scheme = _get_scheme(message)
        port = _get_port(message, scheme)
        yield definitions.Target(host=host, port=port, scheme=scheme)
    elif (url := message.data.get("url")) is not None:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port or _get_port(message, parsed_url.scheme)
        scheme = parsed_url.scheme or "https"
        if host is not None and port is not None and scheme is not None:
            yield (definitions.Target(host=host, port=port, scheme=scheme))
        else:
            logger.warning(
                "Incomplete target configuration: host, port, and scheme must all be provided."
                f"host: {host},\nport: {port}\nscheme: {scheme}"
            )
    else:
        logger.warning("Invalid message format" f"message: {message}")
