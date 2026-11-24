# Citrix NetScaler CVE-2023-4966 (Citrix Bleed) memory disclosure

**Citrix Bleed (CVE-2023-4966)** is a memory disclosure vulnerability in
NetScaler ADC or NetScaler Gateway configured as a Gateway or AAA virtual
server. The disclosed process memory can include valid session cookies.

```text
GET /oauth/idp/.well-known/openid-configuration   (Host: aaaa... ~24KB)
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-4966> (published 2023-10-10, CWE-119, Citrix CVSS 3.1 9.4).
- Citrix advisory CTX579459: <https://support.citrix.com/article/CTX579459>.
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-4966>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2023-4966>.

## Affected and fixed versions
NetScaler ADC/Gateway before 13.1-49.15, 14.1-8.50, 13.0-92.19, and the
FIPS/NDcPP fixes; see CTX579459.

## How the detection confirms it
One request to the OpenID configuration endpoint with an oversized `Host` header.
A finding needs HTTP 200 and both a leaked `NSC_AAAC=` session cookie and the
`{"issuer":` field in the body. The leaked memory is not kept; the read is
bounded and follows no redirect.

The oversized `Host` header cannot be sent through the anonymous `defensive_http`
transport, so this detection uses the scanner session directly with redirects
disabled.

## Remediation
Upgrade to the fixed builds in CTX579459. Because valid session tokens may have
leaked, terminate all active sessions after upgrading. The issue is actively
exploited and in the CISA KEV catalog.
