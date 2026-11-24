# PerkinElmer ProcessPlus CVE-2024-6911 path traversal

PerkinElmer ProcessPlus through 1.11.6507.0 exposes an unauthenticated log-download endpoint whose `filename` parameter traverses outside the log directory (CWE-22).

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-6911> (published 2024-07-22 by the CyberDanube CNA, CVSS 3.1 7.5).
- Advisory: <https://seclists.org/fulldisclosure/2024/Jul/13>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-6911>.

## How the detection confirms it
A ProcessPlus UI fingerprint, then a `GET` reading `win.ini` through the log-download traversal (needs the `[fonts]`/`extensions`/`bit app support` markers). Only a non-secret Windows file is read; requests are bounded.

## Remediation
Apply the vendor update and keep the interface off the public network.
