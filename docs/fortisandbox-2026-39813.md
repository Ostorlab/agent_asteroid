# Fortinet FortiSandbox JRPC path-traversal authentication bypass CVE-2026-39813

**CVE-2026-39813** is a path traversal in the FortiSandbox JRPC API
`is_valid_session()` function (CWE-24). The caller-supplied session value is
passed to `os.path.join()` without validation, so a session of `../../tmp/`
resolves to `/tmp/` (which always exists with a recent mtime) and the session
check passes. This bypasses authentication for read-only JRPC methods such as
`sys/status` (version, hostname, serial number, resource usage).

```
POST /jsonrpc/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded

data={"id":1,"session":"../../tmp/","method":"get","params":[{"url":"sys/status"}],"ver":"2.0"}
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-39813> (published 2026-04-14, CWE-24, CVSS 3.1 9.8 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
- Fortinet PSIRT FG-IR-26-112: <https://fortiguard.fortinet.com/psirt/FG-IR-26-112>.
- Technical write-up: <https://rustlang.rs/posts/blog_cve_2026_39813_en/>.
- CSA advisory: <https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-038/>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-39813>.

## Affected and fixed versions
FortiSandbox **4.4.0 - 4.4.8** and **5.0.0 - 5.0.5**; fixed in **4.4.9** and
**5.0.6**. The patched `is_valid_session()` accepts only 32-character
hexadecimal session IDs.

## How the detection confirms it
The detection posts the published `../../tmp/` traversal session with the
read-only `sys/status` method to `/fortisandbox/jsonrpc/` and `/jsonrpc/`, and
reports only when the response is `application/json` and carries the
`"Serial-Number"`, `"status"` and `"result"` fields of the system status. Only
the read-only `sys/status` method is invoked; no credential or cookie is sent
and redirects are not followed.

## Remediation
Upgrade FortiSandbox to 4.4.9 or later, or 5.0.6 or later (FG-IR-26-112). If
an immediate upgrade is not possible, restrict access to the `/jsonrpc/`
endpoint and block JRPC requests containing path-traversal sequences.
