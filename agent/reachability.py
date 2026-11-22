"""Reachability check of the targets, run once per target before any exploit is tried."""

import logging
import socket
from concurrent import futures

from agent import definitions

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT_SECONDS = 5
MAX_WORKERS = 32


def is_target_reachable(
    target: definitions.Target, timeout: float = CONNECT_TIMEOUT_SECONDS
) -> bool:
    """Check that a TCP connection can be opened on the target's host and port.

    Only the TCP connection is tested, TLS is deliberately not: legacy devices that only speak old TLS versions
    are valid targets and a modern handshake would wrongly drop them.

    Args:
        target: Target to probe.
        timeout: Connection timeout, in seconds.

    Returns:
        - True if the host accepts the connection, False if it doesn't resolve, refuses it or times out.
    """
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout):
            return True
    except OSError as e:
        logger.info("target %s:%s is unreachable: %s", target.host, target.port, e)
        return False


def filter_reachable_targets(
    targets: list[definitions.Target], timeout: float = CONNECT_TIMEOUT_SECONDS
) -> list[definitions.Target]:
    """Drop the targets that can't be connected to, the probes run in parallel.

    Args:
        targets: Targets about to be checked by the exploits.
        timeout: Timeout of each probe, in seconds.

    Returns:
        - The reachable targets, in their original order.
    """
    if len(targets) == 0:
        return targets
    with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(lambda t: is_target_reachable(t, timeout), targets))
    return [t for t, reachable in zip(targets, results) if reachable is True]
