# WordPress CVE-2026-87902 page-template local file inclusion

WordPress core page-template resolution (`get_page_template()`) can be coerced into including a core file outside the active theme via a crafted `pagename` traversal (CWE-22).

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-87902> (published 2026-09-22 by the HackerOne CNA, CVSS 3.1 8.1).
- GitHub advisory GHSA-7hp8-65ch-5whp: <https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-87902>.

## How the detection confirms it
Resolves a published page id (REST API or home page), then requests the `pagename` traversal payloads (needs a rendered core template outside the theme: the footer or OPML markers). Only non-sensitive core templates are read; requests are bounded.

## Remediation
Upgrade WordPress core to the fixed release in GHSA-7hp8-65ch-5whp.
