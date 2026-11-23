# Progress ADC LoadMaster CVE-2026-8037 command injection

**CVE-2026-8037** lets an unauthenticated attacker run OS commands on a Progress
ADC LoadMaster appliance. The `/accessv2` API passes unsanitised group
parameters into a shell command, so an injected command executes with the
appliance's privileges (CWE-77).

```text
POST /accessv2
Content-Type: application/json

{"cmd": "getall", "apiuser": "''''", "apipass": "BBBBB",
 "g0": "AAAAAAAAAAAAAAAA'; cat /etc/passwd #", ... "g60": "...same..."}
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-8037> (published 2026-06-04, CWE-77, CVSS 3.1 9.6).
- Progress security bulletin: <https://community.progress.com/s/article/LoadMaster-Critical-Security-Bulletin-June-2026-CVE-2026-8037-CVE-2026-33691>.
- watchTowr Labs analysis: <https://labs.watchtowr.com/enterprise-tech-in-shell-out-progress-kemp-loadmaster-uninitialized-heap-to-pre-auth-rce-cve-2026-8037/>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-8037>.

## Affected and fixed versions
Progress ADC LoadMaster; apply the fix from the June 2026 critical security
bulletin (CVE-2026-8037 / CVE-2026-33691).

## How the detection confirms it
One anonymous `POST /accessv2` whose injected command is the benign, read-only
`cat /etc/passwd`. A finding needs HTTP 200, a `text/json` response, and the
`root:...:0:0:` account line in the body, with a random control path that does
not return it. Only the world-readable `/etc/passwd` is read; no file is
written, no credential or cookie is sent and redirects are not followed.

## Remediation
Apply the Progress LoadMaster update from the June 2026 critical security
bulletin. Restrict management and API access to trusted hosts, and treat any
file the appliance process can read as potentially disclosed.
