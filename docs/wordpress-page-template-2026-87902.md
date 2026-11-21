# WordPress CVE-2026-87902 page-template local file inclusion

WordPress core page-template resolution (`get_page_template()`) can be coerced into including a core file outside the active theme via a crafted `pagename` traversal (CWE-22).

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-87902> (published 2026-09-22 by the HackerOne CNA, CVSS 3.1 8.1).
- GitHub advisory GHSA-7hp8-65ch-5whp: <https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-87902>.

## How the detection confirms it
The check locates a published page and tests whether WordPress renders a core
template from outside the active theme. It reads only non-sensitive templates
and bounds its requests.

## Remediation
Upgrade WordPress core to **7.1.2** or later. If you maintain an older
branch, use the backported release listed in the
[WordPress security release notes](https://wordpress.org/documentation/wordpress-version/version-7-1-2/).
