# Versa Concerto CVE-2025-34026 Spring Boot Actuator authentication bypass

Versa Concerto is affected by an authentication bypass in its Spring Boot
Actuator endpoints (CWE-288): a `Connection: X-Real-Ip` request header makes the
front proxy drop the internal `X-Real-Ip` header, so the actuator treats the
request as internal and exposes it (including `heapdump`) without authentication.

```text
GET /portalapi/actuator    (Connection: X-Real-Ip)
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-34026> (published 2025-05-21 by the VulnCheck CNA, CWE-288, NVD CVSS 3.1 7.5).
- ProjectDiscovery write-up: <https://projectdiscovery.io/blog/versa-concerto-authentication-bypass-rce>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-34026>.

## Affected and fixed versions
Versa Concerto; apply the vendor patch referenced in the advisory (patched Feb
2025).

## How the detection confirms it
One `GET` of `/portalapi/actuator` with a `Connection: X-Real-Ip` header. A
finding needs HTTP 200, the `EECP-CSRF-TOKEN` response header and `heapdump` in
the actuator index. Only the index is read; the request is bounded and follows no
redirect.

The `Connection` header cannot be sent through the anonymous `defensive_http`
transport, so this detection uses the scanner session directly with redirects
disabled.

## Remediation
Apply the Versa Concerto patch for CVE-2025-34026, make the front proxy strip
client-supplied `X-Real-Ip` / hop-by-hop headers, and restrict access to the
actuator. Rotate secrets reachable from a heapdump.
