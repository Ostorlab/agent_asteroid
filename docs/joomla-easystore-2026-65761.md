# Joomla EasyStore CVE-2026-65761 search SQL injection

**CVE-2026-65761** is a SQL injection (CWE-89) in the Joomla EasyStore
extension 1.0.0 through 2.0.1. The `filter_sortby` order parameter of the
product search is concatenated into the SQL ORDER BY clause without
escaping, letting an unauthenticated attacker read the full database
including credentials and sessions.

**Affected:** Joomla EasyStore extension 1.0.0 through 2.0.1

**Fixed:** latest available version

**Severity:** CVSS 4.0 9.3 (Critical) — `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`

## How does the detector verify it?

This is an **active, non-destructive, unforgeable** check. The injection
rides the search's own `SELECT` — never an `INSERT`/`UPDATE` — with MySQL's
`EXTRACTVALUE` error-based trick:

```
GET /index.php?option=com_easystore&view=products&task=search&
    filter_sortby=created-ASC,EXTRACTVALUE(1,CONCAT(CHAR(126),
    SUBSTRING(MD5(<N>),1,28)))--+-
# N random per probe; confirm the XPATH error embeds MD5(N)[:28]
```

The expected digest fragment is computed locally from the random number and
never sent in the request, so only a database that actually evaluates the
injected subquery can reflect it in the MySQL XPATH syntax error text. No
row is read, written or changed — this is an error-based read, not a blind
write, and redirects are not followed.

## Remediation

Update the Joomla EasyStore extension to the latest version. Parameterize
the ORDER BY clause of the product search query.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-65761> (published
  2026-07-23, CWE-89, CVSS 4.0 9.3).
- Public disclosure:
  <https://mysites.guru/blog/easystore-security-disclosure/>.
- Vendor: <https://www.joomshaper.com/easystore>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-65761>.
