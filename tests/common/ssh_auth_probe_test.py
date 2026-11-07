"""Unit tests for the CVE-2026-123158 SSH differential auth probe."""

import time
from collections.abc import Callable

import paramiko
import pytest

from agent.common import ssh_auth_probe

ATTACK_LEN = ssh_auth_probe.ATTACK_PASSWORD_LENGTH

Decider = Callable[[str, str, int], bool]


class _FakeTransport:
    """Scripts paramiko.Transport auth behaviour for one simulated connection."""

    def __init__(self, decide: Decider) -> None:
        self._decide = decide
        self._calls = 0
        self._authed = False
        self.banner_timeout: float | None = None

    def start_client(self, timeout: float | None = None) -> None:
        return None

    def auth_password(self, username: str, password: str) -> None:
        self._calls += 1
        if self._decide(username, password, self._calls) is True:
            self._authed = True
            return
        raise paramiko.AuthenticationException("auth failed")

    def is_authenticated(self) -> bool:
        return self._authed

    def close(self) -> None:
        return None


def _install(monkeypatch: pytest.MonkeyPatch, decide: Decider) -> None:
    # Patch the shared module objects that ssh_auth_probe imports and uses.
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        paramiko,
        "Transport",
        lambda _address: _FakeTransport(decide),
    )


def testConfirmPasswordBypass_whenBypassOnSecondAttempt_shouldBeVulnerable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An overlong password accepted on the 2nd same-connection attempt confirms."""

    def decide(username: str, password: str, call_index: int) -> bool:
        if username != "alpine":
            return False
        if len(password) < ATTACK_LEN:
            return False
        return call_index >= 2

    _install(monkeypatch, decide)

    result = ssh_auth_probe.confirm_password_bypass("host", 22)

    assert result.vulnerable is True
    assert result.username == "alpine"
    assert result.attempt == 2
    assert result.control_rejected is True


def testConfirmPasswordBypass_whenServerAcceptsAnything_shouldNotBeVulnerable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A server that also accepts the short control password is discarded."""
    _install(monkeypatch, lambda _user, _password, _call: True)

    result = ssh_auth_probe.confirm_password_bypass("host", 22)

    assert result.vulnerable is False


def testConfirmPasswordBypass_whenAllAuthFails_shouldNotBeVulnerable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A patched host rejects every attempt."""
    _install(monkeypatch, lambda _user, _password, _call: False)

    result = ssh_auth_probe.confirm_password_bypass("host", 22)

    assert result.vulnerable is False
