# SAP NetWeaver AS Java CVE-2017-12637 directory traversal

**CVE-2017-12637** is a directory traversal in SAP NetWeaver Application Server
Java 7.5. The scheduler endpoint
`scheduler/ui/js/ffffffffbca41eb4/UIUtilJavaScriptJS` reads arbitrary files via a
`..` in the query string (CWE-22), exploited in the wild in August 2017 (SAP
Security Note 2486657).

```text
GET /scheduler/ui/js/ffffffffbca41eb4/UIUtilJavaScriptJS?/..
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2017-12637> (published 2017-08-07, CWE-22, CVSS 3.1 7.5).
- SAP Security Note 2486657.
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2017-12637>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2017-12637>.

## Affected and fixed versions
SAP NetWeaver AS Java **7.5**; fixed by SAP Security Note 2486657.

## How the detection confirms it
One anonymous `GET` of the scheduler endpoint with `?/..`. A finding needs HTTP
200 and both `WEB-INF` and `META-INF` in the returned directory listing. Only a
deployment directory listing is read; the request is bounded, sends no credential
or cookie and follows no redirect.

## Remediation
Apply SAP Security Note 2486657 and keep NetWeaver AS Java patched. Restrict
access to the scheduler application. The issue is in the CISA KEV catalog.
