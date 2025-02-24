"""Unit tests for definitions module."""

from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin

from agent import definitions


def testCreateVulnerability_whenBasicMetadata_createsCorrectVulnerability() -> None:
    """Test creation of vulnerability with basic metadata."""
    class TestExploit(definitions.Exploit):
        """Test exploit class."""
        metadata = definitions.VulnerabilityMetadata(
            title="Test Vulnerability",
            description="Test Description",
            reference="CVE-2024-1234",
            risk_rating="HIGH",
        )

        def accept(self, target: definitions.Target) -> bool:
            return True

        def check(self, target: definitions.Target) -> list[definitions.Vulnerability]:
            return []

    target = definitions.Target(scheme="https", host="example.com", port=443)
    exploit = TestExploit()
    vulnerability = exploit.create_vulnerability(target)

    assert vulnerability.entry.title == "Test Vulnerability"
    assert vulnerability.entry.risk_rating == "HIGH"
    assert vulnerability.entry.description == "Test Description"
    assert vulnerability.entry.references == {
        "nvd.nist.gov": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    }
    assert vulnerability.entry.recommendation == (
        "- Make sure to install the latest security patches from software vendor \n"
        "- Update to the latest software version"
    )
    assert vulnerability.technical_detail == (
        "https://example.com:443/ is vulnerable to CVE-2024-1234, Test Vulnerability"
    )
    assert vulnerability.risk_rating == agent_report_vulnerability_mixin.RiskRating.HIGH


def testCreateVulnerability_whenCustomReferences_includesAllReferences() -> None:
    """Test creation of vulnerability with custom references."""
    class TestExploit(definitions.Exploit):
        """Test exploit class."""
        metadata = definitions.VulnerabilityMetadata(
            title="Test Vulnerability",
            description="Test Description",
            reference="CVE-2024-1234",
            risk_rating="HIGH",
            references={"extra-ref": "https://example.com/ref"}
        )

        def accept(self, target: definitions.Target) -> bool:
            return True

        def check(self, target: definitions.Target) -> list[definitions.Vulnerability]:
            return []

    target = definitions.Target(scheme="https", host="example.com", port=443)
    exploit = TestExploit()
    vulnerability = exploit.create_vulnerability(target)

    assert vulnerability.entry.references == {
        "nvd.nist.gov": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "extra-ref": "https://example.com/ref"
    }

def testCreateVulnerability_whenAllMetadataFields_setsAllFields() -> None:
    """Test creation of vulnerability with all metadata fields."""
    class TestExploit(definitions.Exploit):
        """Test exploit class."""
        metadata = definitions.VulnerabilityMetadata(
            title="Test Vulnerability",
            description="Test Description",
            short_description="Short Description",
            reference="CVE-2024-1234",
            risk_rating="CRITICAL",
            recommendation="Custom Recommendation",
            security_issue=True,
            privacy_issue=True,
            has_public_exploit=True,
            targeted_by_malware=True,
            targeted_by_ransomware=True,
            targeted_by_nation_state=True,
        )

        def accept(self, target: definitions.Target) -> bool:
            return True

        def check(self, target: definitions.Target) -> list[definitions.Vulnerability]:
            return []

    target = definitions.Target(scheme="https", host="example.com", port=443)
    exploit = TestExploit()
    vulnerability = exploit.create_vulnerability(target)

    assert vulnerability.entry.title == "Test Vulnerability"
    assert vulnerability.entry.risk_rating == "CRITICAL"
    assert vulnerability.entry.description == "Test Description"
    assert vulnerability.entry.short_description == "Short Description"
    assert vulnerability.entry.recommendation == "Custom Recommendation"
    assert vulnerability.entry.references == {
        "nvd.nist.gov": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    }
    assert vulnerability.entry.security_issue is True
    assert vulnerability.entry.privacy_issue is True
    assert vulnerability.entry.has_public_exploit is True
    assert vulnerability.entry.targeted_by_malware is True
    assert vulnerability.entry.targeted_by_ransomware is True
    assert vulnerability.entry.targeted_by_nation_state is True
