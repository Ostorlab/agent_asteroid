"""Unit tests for CVE-2019-7193"""
import requests_mock as req_mock
from agent.exploits import cve_2019_7193
from agent import definitions


def testCVE20197193_whenVulnerable_reportFinding(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    """Unit test for CVE-2019-7193, case when target is vulnerable"""
    target = definitions.Target(scheme="https", host="127.0.0.1", port=443)
    exploit_instance = cve_2019_7193.CVE20197193Exploit()
    requests_mock.post(
        "https://127.0.0.1:443/photo/p/api/album.php",
        content=b"<output>xyz</output>",
    )
    requests_mock.get(
        "https://127.0.0.1:443/photo/slideshow.php?album=xyz",
        content=b"encodeURIComponent('abc')",
    )
    requests_mock.post(
        "https://127.0.0.1:443/photo/p/api/video.php",
        content=b"admin:x:0:0:administrator,,,:/share/homes/admin:/bin/sh"
        b"guest:x:65534:65534:guest:/share/homes/guest:/bin/sh"
        b"httpdusr:x:99:0:Apache httpd user:/tmp:/bin/sh"
        b"[sshd]:x:110:65534:SSHD Privilege Separation:/var/empty:/bin/sh",
    )

    vulnerabilities = exploit_instance.check(target)
    vulnerability = vulnerabilities[0]

    assert (
        vulnerability.entry.title == "QNAP QTS Improper Input Validation Vulnerability"
    )
    assert (
        vulnerability.technical_detail
        == "https://127.0.0.1:443 is vulnerable to CVE-2019-7193, "
        "QNAP QTS Improper Input Validation Vulnerability"
    )
    assert vulnerability.risk_rating.name == "CRITICAL"


def testCVE20197193_whenSafe_reportFinding(
    requests_mock: req_mock.mocker.Mocker,
) -> None:
    """Unit test for CVE-2019-7193, case when target is vulnerable"""
    target = definitions.Target(scheme="https", host="127.0.0.1", port=443)
    exploit_instance = cve_2019_7193.CVE20197193Exploit()
    requests_mock.post(
        "https://127.0.0.1:443/photo/p/api/album.php",
        content=b"Invalid Request",
    )

    vulnerabilities = exploit_instance.check(target)

    assert len(vulnerabilities) == 0
