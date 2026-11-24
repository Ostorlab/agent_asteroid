# CVE-2026-12227: Visual Composer unauthenticated local file inclusion

**CVE-2026-12227 is an unauthenticated local file inclusion** in the Visual
Composer Website Builder plugin for WordPress through 45.16.0 (CWE-98, CVSS 3.1
9.8). The `vcv-template` parameter is included without validating path
traversal, letting an unauthenticated attacker include and execute arbitrary
files on the server.

**Affected:** Visual Composer Website Builder for WordPress <= 45.16.0

**Fixed:** a plugin release past 45.16.0

**Severity:** CVSS 3.1 9.8 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

## How does the detector verify it?

This is an **active, non-destructive** check. It sends one bounded anonymous GET
that traverses to the world-readable `/etc/passwd` and confirms the account
listing is returned:

```
GET /?vcv-template-type=vc&vcv-template=../../../../../../../etc/passwd
# confirm the response body contains  root:...:0:0:
```

Only the world-readable `/etc/passwd` is read — **no file is written and no
command is run**. No credential or cookie is sent and redirects are not
followed.

**Limitation:** the check reads `/etc/passwd`, so it only confirms hosts where
that file exists and is readable (typical Linux). A Windows host, or one that
restricts the file, is a conservative false negative, never a false positive.

## Remediation

Update Visual Composer Website Builder past 45.16.0. Validate the `vcv-template`
parameter against an allow-list of known templates and reject path-traversal
sequences.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-12227> (published 2026-09-24,
  CWE-98, CVSS 3.1 9.8).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-12227>.
- Wordfence advisory:
  <https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/visualcomposer/visual-composer-website-builder-45160-unauthenticated-local-file-inclusion-via-vcv-template-parameter>.
- Public PoC: <https://github.com/murrez/CVE-2026-12227>.
