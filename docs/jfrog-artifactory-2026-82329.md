# JFrog Artifactory CVE-2026-82329 blank join-key authentication bypass

**CVE-2026-82329** is an authentication bypass in self-hosted JFrog Artifactory
that can give an unauthenticated attacker administrative access (CWE-287).

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-82329> (published 2026-08-28 by the JFrog CNA, CWE-287, CVSS 3.1 9.8).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-82329>.

## How the detection confirms it
One anonymous `POST` of an HS256 JWT signed with the blank join key to `/access/api/v1/registry/join`. A finding needs HTTP 201 and a `token` in the response. An ephemeral node is registered only to confirm the bypass; the request is bounded.

The `User-Agent` header the endpoint requires cannot be sent through the anonymous `defensive_http` transport, so this detection uses the scanner session directly.

## Remediation
Upgrade self-hosted Artifactory to the fixed version for your branch:
**7.111.21**, **7.117.28**, **7.125.20**, **7.133.29**, **7.146.38**, or
**7.161.20**. Consult the
[JFrog security advisory](https://docs.jfrog.com/releases/docs/jfrog-security-advisories)
for your release branch. Set a strong, non-default join key and review
registered nodes for unauthorized entries.
