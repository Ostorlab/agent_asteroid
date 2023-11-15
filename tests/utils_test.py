"""Unit tests for asteroid agent utilities"""
from ostorlab.agent.message import message

from agent import utils


def testPrepareTarget_whenDomainAsset_returnResult(
    scan_message_domain_name: message.Message,
) -> None:
    target = utils.prepare_target(scan_message_domain_name)

    assert target.host == "www.google.com"
    assert target.scheme == "https"
    assert target.port == 443


def testPrepareTarget_whenIPv4Asset_returnResult(
    scan_message_ipv4: message.Message,
) -> None:
    target = utils.prepare_target(scan_message_ipv4)

    assert target.host == "192.168.1.17"
    assert target.scheme == "https"
    assert target.port == 443


def testPrepareTarget_whenIPv6Asset_returnResult(
    scan_message_ipv6: message.Message,
) -> None:
    target = utils.prepare_target(scan_message_ipv6)

    assert target.host == "2001:db8:3333:4444:5555:6666:7777:8888"
    assert target.scheme == "https"
    assert target.port == 443


def testPrepareTarget_whenLinkAsset_returnResult(
    scan_message_link: message.Message,
) -> None:
    target = utils.prepare_target(scan_message_link)

    assert target.host == "www.google.com"
    assert target.scheme == "https"
    assert target.port == 443
