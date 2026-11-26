# FOSSBilling CVE-2026-27604 /api/system/* authorization bypass

**CVE-2026-27604** is an authorization bypass in FOSSBilling's API role
handling (CWE-200, CWE-306, CWE-862, CWE-863). Because the `system` role
resolves to the cron admin identity, an unauthenticated caller can invoke
privileged `/api/system/*` methods without a valid credential, session or
CSRF token.

**Affected:** FOSSBilling 0.5.4 up to (not including) 0.8.0

**Fixed:** 0.8.0

**Severity:** CVSS 4.0 10.0 (Critical) — `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

## How does the detector verify it?

```
GET /api/system/system/error_reporting_enabled
```

The probe calls the read-only `error_reporting_enabled` system getter and
requires HTTP 200 with a null `error` and a boolean `result` in the JSON
response. A control request for an unrelated system method must not return
that shape. No mutation is sent, no credential or cookie is used and
redirects are not followed.

## Remediation

Upgrade FOSSBilling to 0.8.0 or later. Until upgraded, block external access
to `/api/system/*` at the reverse proxy/WAF, restrict API access to trusted
source IPs and rotate admin/client API tokens.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-27604> (published
  2026-06-23, CWE-200/306/862/863, CVSS 4.0 10.0).
- FOSSBilling advisory:
  <https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-57mv-jm88-66jc>.
- FOSSBilling advisory (related):
  <https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-78x5-c8gw-8279>.
- VulnCheck write-up:
  <https://www.vulncheck.com/blog/fossbilling-auth-bypass-ssti-rce>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-27604>.
