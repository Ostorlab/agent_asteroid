# NetScaler Console CVE-2024-6235 sensitive information disclosure

NetScaler Console (NetScaler ADM) exposes the internal
`/internal/v2/config/mps_secret/ADM_SESSIONID` endpoint without authentication
(CWE-287), disclosing the session secret.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-6235> (published 2024-07-10 by the Citrix CNA, CWE-287, CVSS 3.1 8.8).
- Citrix advisory CTX677998: <https://support.citrix.com/article/CTX677998>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-6235>.

## Affected and fixed versions
NetScaler Console before **14.1-25.53**; see CTX677998.

## How the detection confirms it
One anonymous `GET` of the internal endpoint. A finding needs HTTP 200 and the
`"mps_secret"` and `ADM_SESSIONID` fields in the body. The detection confirms the
field is present and does not retain the secret value; the request is bounded.

## Remediation
Upgrade NetScaler Console to 14.1-25.53 or later. Keep the Console off the public
internet, rotate the session secret, and review for unauthorized access.
