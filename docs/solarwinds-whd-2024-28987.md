# SolarWinds Web Help Desk CVE-2024-28987 hardcoded credential

SolarWinds Web Help Desk ships a hardcoded `helpdeskIntegrationUser` account
(CWE-798), letting a remote unauthenticated attacker read and modify help desk
data over HTTP Basic auth.

```text
GET /helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets/   (Authorization: Basic ...)
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-28987> (published 2024-08-21, CWE-798, CVSS 3.1 9.1).
- SolarWinds advisory: <https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28987>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-28987>.

## Affected and fixed versions
Web Help Desk **12.8.3 Hotfix 1 and earlier**; fixed in **12.8.3 Hotfix 2**.

## How the detection confirms it
One request to the read-only tickets API using the documented hardcoded Basic
credential. A finding needs HTTP 200 and the `displayClient` and `shortDetail`
ticket fields in the body. Only a ticket list is read; nothing is changed and the
read is bounded.

The Basic `Authorization` header cannot be sent through the anonymous
`defensive_http` transport, so this detection uses the scanner session directly
with redirects disabled.

## Remediation
Upgrade Web Help Desk to 12.8.3 Hotfix 2 or later, which removes the hardcoded
account. Restrict access to Web Help Desk and rotate credentials that could
have appeared in tickets, including administrator and integration credentials.
