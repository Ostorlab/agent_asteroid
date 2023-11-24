"""Unit tests for CVE-2018-7841"""
import datetime
import random

import requests
from pytest_mock import plugin

from agent import definitions
from agent.exploits import cve_2018_7841


def testCVE20187841_whenVulnerable_reportFinding(mocker: plugin.MockerFixture) -> None:
    """Unit test for CVE-2018-7841, case when target is vulnerable."""

    delays = [60, 50, 40, 30]

    def side_effect(*args, **kwargs):  # type: ignore[no-untyped-def]
        mock_response = mocker.Mock(spec=requests.Response)
        elapsed = datetime.timedelta(seconds=delays.pop())

        mock_response.elapsed = elapsed
        return mock_response

    mocker.patch("requests.sessions.Session.post", side_effect=side_effect)

    target = definitions.Target(scheme="https", host="127.0.0.1", port=443)
    exploit_instance = cve_2018_7841.CVE20187841Exploit()

    vulnerabilities = exploit_instance.check(target)
    vulnerability = vulnerabilities[0]

    assert (
        vulnerability.entry.title
        == "Schneider Electric U.motion Builder SQL Injection Vulnerability"
    )
    assert vulnerability.technical_detail == (
        "https://127.0.0.1:443 is vulnerable to CVE-2018-7841, Schneider Electric "
        "U.motion Builder SQL Injection Vulnerability"
    )
    assert vulnerability.risk_rating.name == "CRITICAL"


def testCVE20187841_whenSafe_reportNothing(mocker: plugin.MockerFixture) -> None:
    """Unit test for CVE-2018-7841, case when target is safe."""

    def side_effect(*args, **kwargs):  # type: ignore[no-untyped-def]
        mock_response = mocker.Mock(spec=requests.Response)
        elapsed = datetime.timedelta(seconds=random.randint(30, 90))
        mock_response.elapsed = elapsed
        return mock_response

    mocker.patch("requests.sessions.Session.post", side_effect=side_effect)
    target = definitions.Target(scheme="https", host="127.0.0.1", port=443)
    exploit_instance = cve_2018_7841.CVE20187841Exploit()

    vulnerabilities = exploit_instance.check(target)

    assert len(vulnerabilities) == 0
