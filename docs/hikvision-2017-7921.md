# Hikvision IP camera CVE-2017-7921 authentication bypass

**CVE-2017-7921** is an improper-authentication flaw in many Hikvision DS-2CD
series IP cameras. Appending a hardcoded `auth` parameter grants access to
protected endpoints without credentials (CWE-287), disclosing device
configuration and enabling privilege escalation.

```text
GET /system/deviceInfo?auth=YWRtaW46MTEK
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2017-7921> (published 2017-05-06, CWE-287, CVSS 3.1 9.8).
- ICS-CERT advisory ICSA-17-124-01: <https://www.cisa.gov/news-events/ics-advisories/icsa-17-124-01>.
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2017-7921>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2017-7921>.

## Affected and fixed versions
Multiple DS-2CD/DS-2DF/DS-2CD63xx firmware builds between V5.2.0 (2014) and the
V5.4.x fixes of 2016; see the ICS-CERT advisory for the exact build ranges.

## How the detection confirms it
One anonymous `GET` of `/system/deviceInfo?auth=...`. A finding needs HTTP 200,
an `application/xml` content type and the `<firmwareVersion>` element. Only
device metadata is read; the request is bounded, sends no real credential or
cookie and follows no redirect.

## Remediation
Upgrade the camera firmware to a build that fixes CVE-2017-7921, keep cameras off
the public internet and on a management VLAN, and rotate device and stream
credentials. The issue is in the CISA KEV catalog.
