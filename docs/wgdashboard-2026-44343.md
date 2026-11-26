# CVE-2026-44343: WGDashboard unauthenticated path traversal to file read

**CVE-2026-44343 is an unauthenticated path traversal** (CWE-20) in
WGDashboard < 4.3.2. The `/fileDownload` endpoint does not validate the
`file` parameter before resolving it on disk.

**Affected:** WGDashboard < 4.3.2

**Fixed:** 4.3.2

**Severity:** CVSS 3.1 9.8 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

## How does the detector verify it?

This is an **active, non-destructive** check:

```
GET /fileDownload?file=../../../../etc/passwd
# confirm: HTTP 200 and body contains "root:x:0:0:"
```

Only the world-readable `/etc/passwd` is read; no file is written and no
state is changed. No credential or cookie is sent and redirects are not
followed.

## Remediation

Update WGDashboard to version 4.3.2 or later. Restrict network access to the
dashboard until patched.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-44343> (published
  2026-05-12, CWE-20, CVSS 3.1 9.8).
- Security advisory GHSA-rrf5-q4fp-qvgm:
  <https://github.com/WGDashboard/WGDashboard/security/advisories/GHSA-rrf5-q4fp-qvgm>.
- Fix commit:
  <https://github.com/WGDashboard/WGDashboard/commit/b15bbce9bc5554ec379d558f032c730db47fcea2>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-44343>.
