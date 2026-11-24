# CVE-2026-102782: OrdaSoft Simple Membership unauthenticated SQL injection

**CVE-2026-102782 is an unauthenticated SQL injection** in OrdaSoft Simple
Membership (`com_simplemembership`) for Joomla (CWE-89, CVSS 4.0 9.3).
`site/simplemembership.php` dispatches `task=checkLoginPass` without any
authentication or access control and concatenates the `login` request parameter
straight into a SQL query with no escaping or parameter binding.

**Affected:** OrdaSoft Simple Membership < 7.4.0

**Fixed:** OrdaSoft Simple Membership 7.4.0

**Severity:** CVSS 4.0 9.3 (Critical) —
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`

## How does the detector verify it?

This is an **active, non-destructive, unforgeable** check. It sends one
anonymous GET whose `login` parameter closes the string context and asks the
database to compute `MD5` of a **random integer chosen per probe**, reflected
through an error-based `EXTRACTVALUE` XPATH error:

```
GET /index.php?option=com_simplemembership&task=checkLoginPass&format=raw
    &login=' AND EXTRACTVALUE(1,CONCAT(0x7e,MD5(<random>)))-- -
# confirm the response contains MD5("<random>") (truncation-safe 20-hex prefix)
```

The injection rides the `checkLoginPass` **`SELECT` only** — no row is written,
created or deleted. Only the database could return the MD5 of a number that is
random per probe and never pre-computed in the request, so a match proves the
server executed the injected SQL. A server that merely echoes the parameter
cannot contain that digest. No credential or cookie is sent and redirects are
not followed.

**Limitation:** the check reads the digest from the SQL error the endpoint
surfaces in its response. A vulnerable server configured to suppress database
errors (no reflected XPATH error) produces no match and is not reported — a
conservative false negative, never a false positive. MySQL/MariaDB back ends
only; the `EXTRACTVALUE` error-based path does not apply to other databases.

## Remediation

Update OrdaSoft Simple Membership to version 7.4.0 or later. Restrict network
access to the Joomla site to trusted clients and keep database error reporting
disabled in production.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-102782> (published 2026-10-07,
  CWE-89, CVSS 4.0 9.3).
- Public PoC: <https://github.com/murrez/CVE-2026-102782>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-102782>.
