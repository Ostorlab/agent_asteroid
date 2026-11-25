# CVE-2026-93616: Check Point Management unauthenticated traversal to RCE

**CVE-2026-93616 is an unauthenticated directory traversal and arbitrary-file
upload** in Check Point Management Server (CWE-22, CVSS 3.1 9.8). The
`/cpmws/UpgradeSvcRemote` SOAP endpoint is reachable without authentication, and
a vulnerable build fails to validate the `targetVersion` field, allowing a
traversal and script upload that leads to remote code execution.

**Affected:** Check Point Security Management, Multi-Domain Security Management,
Log and SmartEvent servers — R82.20; R82.10 Jumbo Hotfix Take 44 or lower; R82
Take 126 or lower; R81.20 Take 166 or lower; R81.10 Take 190 or lower (EoS)

**Fixed:** R82.20 Security Hotfix; Jumbo Hotfix Take 10 (R82.20), 45 (R82.10),
127 (R82), 170 (R81.20) and 192 (R81.10) and later takes; no LivePatch addresses
this issue

**Severity:** CVSS 3.1 9.8 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

## How does the detector verify it?

This is an **active, non-destructive** behavioural check. It sends one anonymous
SOAP `loginAsApplicationReadOnlyPublicSession` whose `targetVersion` carries an
illegal `!` character and observes the server's handling of it:

```
POST /cpmws/UpgradeSvcRemote    Content-Type: text/xml; charset=utf-8  SOAPAction: ""
  ...<targetVersion>osprobe!</targetVersion>...
# vulnerable: HTTP 500 naming UpgradeSvcRemote.loginAsApplicationReadOnlyPublicSession
#   and NO "targetVersion contains illegal characters" rejection
```

A patched build validates `targetVersion` and returns
`targetVersion contains illegal characters`; a vulnerable build does not, which
is the missing validation that enables the traversal. The check **uploads no
file, writes no traversal path and changes no state** — it never performs the
upload, only observes that the input validation is absent. No credential or
cookie is sent and redirects are not followed.

**Limitation:** the check confirms the missing input validation (the
precondition for the traversal), not a completed file write, which would be
destructive. A build that faults differently yet is still vulnerable, or a
WAF-fronted host that rewrites the error, produces no match — a conservative
false negative, never a false positive.

## Remediation

Update Check Point Management Server to a fixed build per advisory sk1000171.
Restrict network access to the management service (TCP 19009) to trusted
administrative hosts.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-93616> (published 2026-09-22,
  CWE-22, CVSS 3.1 9.8).
- Check Point advisory: <https://support.checkpoint.com/results/sk/sk1000171>.
- Check Point blog: <https://blog.checkpoint.com/security/security-advisory-action-required-active-exploitation-of-cve-2026-85102-and-a-management-pre-authentication-vulnerability-cve-2026-93616/>.
- Public check: <https://github.com/BishopFox/CVE-2026-93616-check>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-93616>.
