# Adobe ColdFusion CVE-2026-48313 FILEIO path traversal

Adobe ColdFusion 2025.9, 2023.20 and earlier are affected by a path traversal in the `ide.cfm` FILEIO action (CWE-22, scope changed) allowing unauthenticated arbitrary file read and limited write.

```text
POST /CFIDE/main/ide.cfm?ACTION=FILEIO    2:000011:/etc/passwd000004:READ
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-48313> (published 2026-06-30 by the Adobe PSIRT, CWE-22).
- Adobe advisory APSB26-68: <https://helpx.adobe.com/security/products/coldfusion/apsb26-68.html>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-48313>.

## Affected and fixed versions
ColdFusion **2025.9**, **2023.20** and earlier; fixed in APSB26-68.

## How the detection confirms it
One anonymous `POST` to the FILEIO action requesting `win.ini` or `/etc/passwd`. A finding needs the file signature (`[fonts]` or `root:x:0:0:`) in the response. Only a world-readable non-secret file is read; the request is bounded.

## Remediation
Apply APSB26-68 and restrict access to `/CFIDE/`.
