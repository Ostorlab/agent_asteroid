# Adobe ColdFusion CVE-2023-26347 access-control bypass

Adobe ColdFusion 2023.5 and earlier and 2021.11 and earlier let an
unauthenticated attacker reach administration CFM/CFC endpoints via a crafted
path prefix (CWE-284).

```text
GET /hax/..CFIDE/adminapi/administrator.cfc?method=getBuildNumber&_cfclient=true
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-26347> (published 2023-11-17, CWE-284, CVSS 3.1 7.5).
- Adobe advisory APSB23-52: <https://helpx.adobe.com/security/products/coldfusion/apsb23-52.html>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2023-26347>.

## Affected and fixed versions
ColdFusion **2023.5 and earlier** and **2021.11 and earlier**; fixed in
ColdFusion 2023 Update 6 / 2021 Update 12 (APSB23-52).

## How the detection confirms it
One anonymous `GET` calling the administrator CFC `getBuildNumber` method through
the path-prefix bypass. A finding needs HTTP 200 and a WDDX packet
(`wddxPacket version=` with a `<string>`). Only a read-only call is made; no
configuration changes.

## Remediation
Apply APSB23-52. Restrict access to the ColdFusion administrator and CFC
endpoints, and review logs for `/hax/..CFIDE` path prefixes.
