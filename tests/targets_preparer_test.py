"""Unit tests for target preparer"""

import pytest
from ostorlab.agent.message import message

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


def testPrepareTargets_whenApiSchemaAsset_returnResult(
    scan_message_api_schema: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_message_api_schema)

    for target in targets:
        assert target.host == "api.example.com"
        assert target.scheme == "https"
        assert target.port == 443


def testPrepareTargets_whenNmapHttpPortService_derivesHttpScheme(
    scan_message_nmap_http_port: message.Message,
) -> None:
    targets = list(targets_preparer.prepare_targets(scan_message_nmap_http_port))

    assert len(targets) == 1
    assert targets[0].host == "10.0.0.5"
    assert targets[0].scheme == "http"
    assert targets[0].port == 8080
    assert targets[0].url == "http://10.0.0.5:8080/"


def testPrepareTargets_whenNmapHttpServiceOnPort443_derivesHttpsScheme(
    scan_message_nmap_https_port: message.Message,
) -> None:
    targets = list(targets_preparer.prepare_targets(scan_message_nmap_https_port))

    assert len(targets) == 1
    assert targets[0].host == "10.0.0.5"
    assert targets[0].scheme == "https"
    assert targets[0].port == 443
    assert targets[0].url == "https://10.0.0.5:443/"


def testPrepareTargets_whenNmapHttpsAltPortService_derivesHttpsScheme(
    scan_message_nmap_https_alt_port: message.Message,
) -> None:
    targets = list(targets_preparer.prepare_targets(scan_message_nmap_https_alt_port))

    assert len(targets) == 1
    assert targets[0].host == "10.0.0.5"
    assert targets[0].scheme == "https"
    assert targets[0].port == 8443


def testPrepareTargets_whenNmapEmptyService_keepsTransportValue(
    scan_message_nmap_empty_service_port: message.Message,
) -> None:
    targets = list(
        targets_preparer.prepare_targets(scan_message_nmap_empty_service_port)
    )

    assert len(targets) == 1
    assert targets[0].host == "10.0.0.5"
    assert targets[0].scheme == "tcp"
    assert targets[0].port == 9999


def testPrepareTargets_whenNmapSshPortService_keepsTransportValue(
    scan_message_nmap_ssh_port: message.Message,
) -> None:
    targets = list(targets_preparer.prepare_targets(scan_message_nmap_ssh_port))

    assert len(targets) == 1
    assert targets[0].host == "10.0.0.5"
    assert targets[0].scheme == "tcp"
    assert targets[0].port == 22


def testPrepareTargets_whenNmapSmbPortService_keepsTransportValue(
    scan_message_nmap_smb_port: message.Message,
) -> None:
    targets = list(targets_preparer.prepare_targets(scan_message_nmap_smb_port))

    assert len(targets) == 1
    assert targets[0].host == "10.0.0.5"
    assert targets[0].scheme == "tcp"
    assert targets[0].port == 445


def testPrepareTargets_whenNmapUdpSnmpPortService_keepsUdpTransportValue(
    scan_message_nmap_snmp_port: message.Message,
) -> None:
    targets = list(targets_preparer.prepare_targets(scan_message_nmap_snmp_port))

    assert len(targets) == 1
    assert targets[0].host == "10.0.0.5"
    assert targets[0].scheme == "udp"
    assert targets[0].port == 161


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


def testPrepareTargets_whenUrlCantBeParsed_returnEmptyTargets(
    scan_bad_url_message: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_bad_url_message)

    assert any(targets) is False


def testPrepareTargets_whenInvalidMessage_returnEmptyTargets(
    scan_bad_message: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_bad_message)

    assert any(targets) is False


def testPrepareTargets_whenBadApiSchemaMessage_returnEmptyTargets(
    scan_bad_api_schema_message: message.Message,
) -> None:
    targets = targets_preparer.prepare_targets(scan_bad_api_schema_message)

    assert any(targets) is False
