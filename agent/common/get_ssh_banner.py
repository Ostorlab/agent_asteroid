import socket
import logging

DEFAULT_TIMEOUT = 90
BANNER_SIZE = 1024

logger = logging.getLogger(__name__)


def get_ssh_banner(ip_address: str, port: int) -> str:
    """Retrieves the SSH banner from the specified IP address and port.

    Args:
        ip_address: The IP address of the target.
        port: The port of the target.

    Returns:
        The SSH banner as a string, or an empty string if retrieval fails.
    """
    try:
        with socket.create_connection(
            (ip_address, port), timeout=DEFAULT_TIMEOUT
        ) as sock:
            sock.settimeout(2)
            banner = sock.recv(BANNER_SIZE).decode(errors="ignore").strip()
            return banner
    except socket.timeout as error:
        logger.error("Timeout error retrieving SSH banner: %s", error)
    except socket.error as error:
        logger.error("Socket error retrieving SSH banner: %s", error)
    return ""
