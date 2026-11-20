# JFrog Artifactory CVE-2026-82329 blank join-key authentication bypass

Affected JFrog Artifactory builds accept a node-registration JWT signed with the blank default join key (32 spaces) (CWE-287), so an unauthenticated attacker forges a valid join token and registers a node.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-82329> (published 2026-08-28 by the JFrog CNA, CWE-287, CVSS 3.1 9.8).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-82329>.

## How the detection confirms it
One anonymous `POST` of an HS256 JWT signed with the blank join key to `/access/api/v1/registry/join`. A finding needs HTTP 201 and a `token` in the response. An ephemeral node is registered only to confirm the bypass; the request is bounded.

The `User-Agent` header the endpoint requires cannot be sent through the anonymous `defensive_http` transport, so this detection uses the scanner session directly.

## Remediation
Upgrade Artifactory and set a strong, non-default join key. Review registered nodes for unauthorized entries.
