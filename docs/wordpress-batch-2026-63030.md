# WordPress CVE-2026-63030 pre-auth batch route confusion

WordPress core 6.9.0-6.9.4 and 7.0.0-7.0.1 are affected by a pre-authentication route confusion in the REST `/batch/v1` endpoint (CWE-863).

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-63030> (published 2026-07-17 by the WPScan CNA, CVSS 3.1 9.8).
- GitHub advisory GHSA-ff9f-jf42-662q: <https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-63030>.

## Affected and fixed versions
WordPress core **6.9.0-6.9.4** and **7.0.0-7.0.1**; fixed in 6.9.5 / 7.0.2.

## How the detection confirms it
A WordPress fingerprint, then an anonymous `POST /?rest_route=/batch/v1` with a benign batch (needs HTTP 207 and the `parse_path_failed` / `block_cannot_read` / `rest_batch_not_allowed` markers). No post or block is created; requests are bounded.

## Remediation
Upgrade WordPress core to 6.9.5 / 7.0.2 or later.
