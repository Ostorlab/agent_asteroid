# Adobe ColdFusion CVE-2024-20767 arbitrary file read

**CVE-2024-20767** is an improper access control issue (CWE-284) in Adobe
ColdFusion 2023.6, 2021.12 and earlier. An unauthenticated client can reach the
Performance Monitoring `/pms` logging module through a `..`/`..CFIDE`
path-traversal prefix and read arbitrary files via the `file_name` parameter.

```
GET /hax/..CFIDE/adminapi/_servermanager/servermanager.cfc?method=getHeartBeat
# -> WDDX packet exposes the server <var name='uuid'>
GET /hax/../pms?module=logging&file_name=../../.../etc/passwd&number_of_lines=1000
uuid: <extracted uuid>
# -> application/json body with /etc/passwd
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-20767> (published 2024-03-18, CWE-284, CVSS 3.1 7.4).
- Adobe advisory APSB24-14: <https://helpx.adobe.com/security/products/coldfusion/apsb24-14.html>.
- Public analysis: <https://jeva.cc/2973.html>.
- Public exploit: <https://github.com/Praison001/CVE-2024-20767-Adobe-ColdFusion>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-20767>.

## Affected and fixed versions
ColdFusion **2023 update 6 and earlier**, **2021 update 12 and earlier**; fixed
in **2023.7** / **2021.13**.

## How the detection confirms it
The reader reads the server `uuid` from the unauthenticated `getHeartBeat` WDDX
packet, replays it as the `uuid` header, and reads the world-readable
`/etc/passwd` through the `/pms` logging traversal. A finding requires the
`root:...:0:0:` account prefix in a JSON response. Each request restores its raw
`..` path so the traversal reaches the server intact. Only `/etc/passwd` is
read; nothing is written and redirects are not followed.

## Remediation
Update ColdFusion to 2023.7 / 2021.13 or later. Do not expose the administrator
or Performance Monitoring endpoints to untrusted clients.
