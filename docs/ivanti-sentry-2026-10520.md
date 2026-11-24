# CVE-2026-10520: Ivanti Sentry unauthenticated OS command injection

**CVE-2026-10520 is an unauthenticated OS command injection** in Ivanti Sentry
(CWE-78, CVSS 3.1 10.0). An unauthenticated MICS `handleMessage` endpoint runs
the `commandexec` system action, letting a remote attacker execute OS commands
as root.

**Affected:** Ivanti Sentry before R10.5.2, R10.6.2 and R10.7.1

**Fixed:** R10.5.2, R10.6.2, R10.7.1 or later

**Severity:** CVSS 3.1 10.0 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

## How does the detector verify it?

This is an **active, non-destructive, unforgeable** check. It runs the MICS
`commandexec` action with a benign `echo` of a random arithmetic expansion, and
confirms the computed product (never the literal `$((A*B))` expression) is
reflected:

```
POST /mics/api/v2/sentry/mics-config/handleMessage
  message=execute system /configuration/system/commandexec
          <commandexec><index>1</index>
          <reqandres>echo $((<A>*<B>))</reqandres></commandexec>
# confirm: body contains "Message handled successfully" AND the product A*B
```

`echo` changes nothing on the host; its standard output is the reflected
product this check reads. A POSIX shell expands `$((A*B))` to the product before
echo runs, so the product's presence proves a shell evaluated the arithmetic; a
server that merely reflects the request body would contain the literal
`$((A*B))` expression, not the product. No file is read or written, no
credential or cookie is sent and redirects are not followed.

**Limitation:** a vulnerable device whose `commandexec` does not invoke a shell
that supports `$(())` arithmetic is not reported (a conservative false negative,
never a false positive).

## Remediation

Upgrade Ivanti Sentry to R10.5.2, R10.6.2, R10.7.1 or later. Restrict network
access to the Sentry MICS interface to trusted clients.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-10520> (published 2026-06-09,
  CWE-78, CVSS 3.1 10.0).
- watchTowr PoC:
  <https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523/blob/main/README.md>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-10520>.
