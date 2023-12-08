"""Unit tests for target preparer"""
from ostorlab.agent.message import message
import pytest
from agent import targets_preparer


def testPrepareTargets_whenDomainAsset_returnResult(
    scan_message_domain_name: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_domain_name)

    for target in targets:
        assert target.host == "www.google.com"
        assert target.scheme == "https"
        assert target.port == 443


def testPrepareTargets_whenIPv4Asset_returnResult(
    scan_message_ipv4: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_ipv4)

    for target in targets:
        assert target.host == "192.168.1.17"
        assert target.scheme == "https"
        assert target.port == 443


def testPrepareTargets_whenIPv6Asset_returnResult(
    scan_message_ipv6: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_ipv6)

    for target in targets:
        assert target.host == "2001:db8:3333:4444:5555:6666:7777:8888"
        assert target.scheme == "https"
        assert target.port == 443


def testPrepareTargets_whenLinkAsset_returnResult(
    scan_message_link: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_link)

    for target in targets:
        assert target.host == "www.google.com"
        assert target.scheme == "https"
        assert target.port == 443


def testPrepareTargets_whenIPv4AssetReachCIDRLimit_raiseValueError(
    scan_message_ipv4_with_mask8: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_ipv4_with_mask8)

    with pytest.raises(ValueError, match="Subnet mask below 16 is not supported."):
        assert any(targets)


def testPrepareTargets_whenIPv6AssetReachCIDRLimit_raiseValueError(
    scan_message_ipv6_with_mask64: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_ipv6_with_mask64)

    with pytest.raises(ValueError, match="Subnet mask below 112 is not supported."):
        assert any(targets)
