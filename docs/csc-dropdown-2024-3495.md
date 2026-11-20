# WordPress Country State City Dropdown CF7 CVE-2024-3495 SQL injection

The Country State City Dropdown CF7 plugin for WordPress up to 2.7.2 does not
escape the `sid` parameter of the `tc_csca_get_cities` AJAX action (CWE-89),
allowing unauthenticated SQL injection.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-3495> (published 2024-05-22 by the Wordfence CNA, CWE-89, CVSS 3.1 9.8).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-3495>.

## Affected and fixed versions
Country State City Dropdown CF7 **<= 2.7.2**; update to a later release.

## How the detection confirms it, safely
It reads the public AJAX nonce from the site home page, then sends a UNION payload
that makes the database compute `md5(N)` for a random `N`. A finding needs the
expected hash in the response. Because `N` is random and its hash is never sent, a
server that echoes the request cannot match — the database must have executed the
SQL. Only a hash is computed: no rows are read and no data changes; the request is
bounded.

## Remediation
Update the plugin to a version after 2.7.2 or remove it. Review the database for
tampering and rotate WordPress secrets.
