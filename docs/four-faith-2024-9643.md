# Four-Faith router CVE-2024-9643 hard-coded default credentials

**CVE-2024-9643** is a hard-coded, unchangeable default account in Four-Faith
F3x36 and related routers (CWE-798/CWE-489): the `ffadmin:ffadminff` web/API
credential cannot be changed, so anyone who knows it authenticates to the router.

```text
GET /Status_Router.asp
Authorization: Basic ZmZhZG1pbjpmZmFkbWluZmY=
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-9643> (published 2025-02-04, CWE-798/CWE-489, CVSS 3.1 9.8).
- VulnCheck advisory: <https://www.vulncheck.com/advisories/four-faith-authenticated-router-os-command-injection>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-9643>.

## Affected and fixed versions
Four-Faith F3x36 and related routers shipping the hard-coded account; apply the
vendor firmware update that removes it.

## How the detection confirms it
One `GET` of the router status page with the documented default Basic credential
(sent through the scanner session, since the anonymous transport cannot set an
`Authorization` header). A finding needs HTTP 200, the `httpd_four-faith` server
banner, and the status-page markers (`Four-Faith`, `Status`). Only the status
page is read with published default credentials; no state is changed and
redirects are not followed.

## Remediation
Apply the Four-Faith firmware update that removes the hard-coded account,
restrict the management interface to trusted networks, and never expose it to the
internet.
