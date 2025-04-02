import pytest
from unittest.mock import patch
from agent.definitions import Target
from agent.exploits.cve_2017_3066 import (
    CVE20173066Exploit,
    VULNERABILITY_TITLE,
    VULNERABILITY_REFERENCE,
    VULNERABILITY_DESCRIPTION,
    RISK_RATING,
    CF_INDICATOR,
    AMF_MESSAGE_SECURE,
)


@pytest.fixture
def exploit():
    return CVE20173066Exploit()


@pytest.fixture
def vulnerable_target():
    return Target(origin="http://vulnerable.example.com:8500")


@pytest.fixture
def secure_target():
    return Target(origin="http://secure.example.com:8500")


def test_exploit_metadata(exploit):
    """Test that the exploit has correct metadata"""
    assert exploit.metadata.title == VULNERABILITY_TITLE
    assert exploit.metadata.reference == VULNERABILITY_REFERENCE
    assert exploit.metadata.description == VULNERABILITY_DESCRIPTION
    assert exploit.metadata.risk_rating == RISK_RATING


def test_accept_vulnerable_target(exploit, vulnerable_target):
    """Test that the exploit accepts a vulnerable target"""
    with patch("agent.exploits.cve_2017_3066.WebExploit._send_request") as mock_request:
        mock_request.return_value.status_code = 200
        mock_request.return_value.text = CF_INDICATOR
        assert exploit.accept(vulnerable_target) is True


def test_accept_secure_target(exploit, secure_target):
    """Test that the exploit rejects a secure target"""
    with patch("agent.exploits.cve_2017_3066.WebExploit._send_request") as mock_request:
        mock_request.return_value.status_code = 200
        mock_request.return_value.text = AMF_MESSAGE_SECURE
        assert exploit.accept(secure_target) is False


def test_accept_wrong_port(exploit):
    """Test that the exploit rejects targets on wrong ports"""
    target = Target(origin="http://example.com:8080")
    assert exploit.accept(target) is False


def test_accept_no_coldfusion(exploit, vulnerable_target):
    """Test that the exploit rejects targets without ColdFusion"""
    with patch("agent.exploits.cve_2017_3066.WebExploit._send_request") as mock_request:
        mock_request.return_value.status_code = 404
        assert exploit.accept(vulnerable_target) is False


def test_create_vulnerability(exploit, vulnerable_target):
    """Test vulnerability creation"""
    vuln = exploit.create_vulnerability(vulnerable_target)
    assert vuln.target == vulnerable_target
    assert vuln.title == VULNERABILITY_TITLE
    assert vuln.reference == VULNERABILITY_REFERENCE
    assert vuln.description == VULNERABILITY_DESCRIPTION
    assert vuln.risk_rating == RISK_RATING
