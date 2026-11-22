"""Unit tests for the reachability module."""

import socket

from pytest_mock import plugin

from agent import definitions, reachability


def _target(host: str, port: int = 443) -> definitions.Target:
    return definitions.Target(scheme="https", host=host, port=port)


def testIsTargetReachable_whenConnectionOpens_returnsTrue(
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("socket.create_connection")

    assert reachability.is_target_reachable(_target("example.com")) is True


def testIsTargetReachable_whenHostDoesNotResolve_returnsFalse(
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("socket.create_connection", side_effect=socket.gaierror)

    assert reachability.is_target_reachable(_target("nope.example.com")) is False


def testIsTargetReachable_whenConnectionTimesOut_returnsFalse(
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("socket.create_connection", side_effect=TimeoutError)

    assert reachability.is_target_reachable(_target("example.com")) is False


def testIsTargetReachable_whenConnectionRefused_returnsFalse(
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("socket.create_connection", side_effect=ConnectionRefusedError)

    assert reachability.is_target_reachable(_target("example.com")) is False


def testFilterReachableTargets_whenSomeTargetsUnreachable_keepsOnlyReachableOnes(
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch(
        "agent.reachability.is_target_reachable",
        side_effect=lambda target, timeout: "dead" not in target.host,
    )
    live = _target("live.example.com")
    dead = _target("dead.example.com")
    other_live = _target("other.example.com", port=80)

    targets = reachability.filter_reachable_targets([live, dead, other_live])

    assert targets == [live, other_live]


def testFilterReachableTargets_whenNoTargets_returnsEmptyList() -> None:
    assert reachability.filter_reachable_targets([]) == []
