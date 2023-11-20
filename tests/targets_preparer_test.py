"""Unit tests for target preparer"""
from ostorlab.agent.message import message

from agent import targets_preparer


def testPrepareTargets_whenDomainAsset_returnResult(
    scan_message_domain_name: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_domain_name)

    assert any(targets)
    for target in targets:
        assert target.host == "192.168.1.17"
        assert target.scheme == "https"
        assert target.port == 443


def testPrepareTargets_whenIPv4Asset_returnResult(
    scan_message_ipv4: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_ipv4)

    assert any(targets)
    for target in targets:
        assert target.host == "192.168.1.17"
        assert target.scheme == "https"
        assert target.port == 443


def testPrepareTargets_whenIPv6Asset_returnResult(
    scan_message_ipv6: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_ipv6)

    assert any(targets)
    for target in targets:
        assert target.host == "2001:db8:3333:4444:5555:6666:7777:8888"
        assert target.scheme == "https"
        assert target.port == 443


def testPrepareTargets_whenLinkAsset_returnResult(
    scan_message_link: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_link)

    assert any(targets)
    for target in targets:
        assert target.host == "www.google.com"
        assert target.scheme == "https"
        assert target.port == 443
