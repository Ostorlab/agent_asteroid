# WordPress CVE-2026-63030 pre-auth batch route confusion

WordPress core 6.9.0-6.9.4 and 7.0.0-7.0.1 are affected by a pre-authentication route confusion in the REST `/batch/v1` endpoint (CWE-863).

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-63030> (published 2026-07-17 by the WPScan CNA, CVSS 3.1 9.8).
- GitHub advisory GHSA-ff9f-jf42-662q: <https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-63030>.

## Affected and fixed versions
WordPress core **6.9.0-6.9.4** and **7.0.0-7.0.1**; fixed in 6.9.5 / 7.0.2.

## How the detection confirms it
The check fingerprints WordPress, then sends a bounded anonymous batch
request. A finding requires HTTP 207 and at least one of the expected
validation markers. The request creates no posts or blocks.

## Remediation
Upgrade WordPress core to 6.9.5 / 7.0.2 or later.
