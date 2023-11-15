"""Utilities for Asteroid agent"""


from ostorlab.agent.message import message as m
from urllib import parse as urlparser

from agent import definitions

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


def _get_port(message: m.Message, scheme: str = None) -> int:
    """Returns the port to be used for the target."""
    if message.data.get("port") is None:
        return SCHEME_TO_PORT.get(scheme) or DEFAULT_PORT
    return int(message.data["port"])


def _get_schema(message: m.Message) -> str:
    """Returns the schema to be used for the target."""
    if message.data.get("schema") is None:
        return DEFAULT_SCHEME
    if str(message.data["schema"]) in [
        "https?",
        "ssl/https-alt?",
        "ssl/https-alt",
        "https-alt",
        "https-alt?",
    ]:
        return "https"
    else:
        return str(message.data["schema"])


def prepare_target(message: m.Message) -> definitions.Target:
    """Prepare targets based on type, if a domain name is provided, port and protocol are collected
    from the config."""
    if (host := message.data.get("host")) is not None:
        scheme = _get_schema(message)
        port = _get_port(message, scheme)
        return definitions.Target(host=host, port=port, scheme=scheme)
    elif (host := message.data.get("name")) is not None:
        scheme = _get_schema(message)
        port = _get_port(message, scheme)
        return definitions.Target(host=host, port=port, scheme=scheme)
    elif (url := message.data.get("url")) is not None:
        parsed_url = urlparser.urlparse(url)
        host = parsed_url.netloc
        scheme = parsed_url.scheme
        port = _get_port(message, scheme)
        return definitions.Target(host=host, port=port, scheme=scheme)
    else:
        raise NotImplementedError
