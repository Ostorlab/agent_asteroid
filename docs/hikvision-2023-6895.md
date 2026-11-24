# Hikvision Intercom ping.php command injection (CVE-2023-6895)

**CVE-2023-6895** is an OS command injection vulnerability (CWE-78) in the
Hikvision Intercom Broadcasting System 3.0.3. The `jsondata[ip]` parameter of
`/php/ping.php` is passed into a shell command, so an unauthenticated attacker
runs arbitrary commands on the device.

```text
POST /php/ping.php
Content-Type: application/x-www-form-urlencoded

jsondata[type]=99&jsondata[ip]=echo $((<A>*<B>))
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-6895> (published 2023-12-17, CWE-78, CVSS 3.1 6.3).
- VulDB entry 248254: <https://vuldb.com/?id.248254>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2023-6895>.

## Affected and fixed versions
Hikvision Intercom Broadcasting System **3.0.3_20201113_RELEASE** and earlier.
Fixed in **4.1.0**.

## How the detection confirms it
One anonymous `POST` injects `echo $((A*B))` with two random five-digit
integers. A finding needs HTTP 200 and the exact arithmetic product in the
response body, proving the parameter was evaluated by a shell. A server that
merely reflects the parameter (showing the literal expression rather than the
product) is rejected by a reflection guard. Only a benign arithmetic expansion
is evaluated; no file is written, read or deleted and no state changes.

## Remediation
Upgrade the Hikvision Intercom Broadcasting System to 4.1.0 or later and keep
the management interface off untrusted networks.
