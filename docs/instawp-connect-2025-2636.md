# InstaWP Connect CVE-2025-2636 local file inclusion

The InstaWP Connect plugin for WordPress up to 0.1.0.85 is vulnerable to local
file inclusion via the `instawp-database-manager` parameter (CWE-22), letting an
unauthenticated attacker include database-manager templates and read sensitive
data such as the `wp_users` table.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-2636> (published 2025-04-11 by the Wordfence CNA, CWE-22, CVSS 3.1 8.1).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-2636>.

## Affected and fixed versions
InstaWP Connect **<= 0.1.0.85**; update to a later release.

## How the detection confirms it
One anonymous `GET` of the database-manager path reading `wp_users`. A finding
needs HTTP 200 and the table markers (`instawp-wrap`, `user_pass</th>`,
`user_email</th>`). Only the table listing is read; the request is bounded.

## Remediation
Update InstaWP Connect to a version after 0.1.0.85 or remove it. Treat any data
the web user can read as disclosed.
