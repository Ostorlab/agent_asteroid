"""Unit tests for Agent Asteroid: CVE-2025-22457"""

from unittest import mock


from agent import definitions
from agent.exploits import cve_2025_22457


def testAccept_whenHttpsAndVulnerableVersion_shouldReturnTrue() -> None:
    """Test accept method with valid conditions."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock requests.get to return a vulnerable version response
    mock_response = mock.Mock()
    mock_response.text = '<PARAM NAME="ProductVersion" VALUE="22.7R2.4"><PARAM NAME="ProductName" VALUE="Ivanti Connect Secure">'
    mock_response.status_code = 200

    # Only mock requests.get and let the real _grab_version_info run
    with mock.patch("requests.get", return_value=mock_response):
        assert exploit.accept(target) is True


def testAccept_whenHttp_shouldReturnFalse() -> None:
    """Test accept method with HTTP target."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("http", "localhost", 80)

    # Should return False for HTTP without even making a request
    assert exploit.accept(target) is False


def testCheck_whenTargetIsVulnerable_shouldReportVulnerability() -> None:
    """Test check method with vulnerable target."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock the accept method to return True
    with (
        mock.patch.object(exploit, "accept", return_value=True),
        mock.patch("agent.exploits.cve_2025_22457._check_crash", return_value=True),
    ):
        vulnerabilities = exploit.check(target)

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].entry.title == cve_2025_22457.VULNERABILITY_TITLE
        assert vulnerabilities[0].entry.risk_rating == cve_2025_22457.RISK_RATING
        assert vulnerabilities[0].vulnerability_location is not None
        assert vulnerabilities[0].dna is not None


def testCheck_whenVersionCheckFails_shouldNotReportVulnerability() -> None:
    """Test check method when version check fails."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock the accept method to return False (version check failure)
    with mock.patch.object(exploit, "accept", return_value=False):
        vulnerabilities = exploit.check(target)
        assert len(vulnerabilities) == 0


def testCheck_whenNoCrash_shouldNotReportVulnerability() -> None:
    """Test check method when target doesn't crash."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock the accept method to return True but _check_crash to return False
    with (
        mock.patch.object(exploit, "accept", return_value=True),
        mock.patch("agent.exploits.cve_2025_22457._check_crash", return_value=False),
    ):
        vulnerabilities = exploit.check(target)

        assert len(vulnerabilities) == 0


def testCheck_whenVersionNotVulnerable_shouldNotReportVulnerability() -> None:
    """Test check method when version is not vulnerable."""
    exploit = cve_2025_22457.IvantiConnectSecureExploit()
    target = definitions.Target("https", "localhost", 443)

    # Mock requests.get to return a patched version response
    with mock.patch.object(exploit, "accept", return_value=False):
        vulnerabilities = exploit.check(target)
        assert len(vulnerabilities) == 0
