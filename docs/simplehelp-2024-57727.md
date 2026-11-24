# SimpleHelp CVE-2024-57727 unauthenticated path traversal

**CVE-2024-57727** is an unauthenticated path traversal in SimpleHelp remote
support software (CWE-22): a request that traverses out of the `toolbox-resource`
handler downloads arbitrary server files, including `serverconfig.xml` which
holds secrets and hashed user passwords.

```text
GET /toolbox-resource/../serverconfig.xml
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-57727> (published 2025-01-15, CWE-22, CVSS 3.1 7.5).
- Horizon3 disclosure: <https://www.horizon3.ai/attack-research/disclosures/critical-vulnerabilities-in-simplehelp-remote-support-software/>.
- Vendor advisory: <https://simple-help.com/kb---security-vulnerabilities-01-2025>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-57727>.

## Affected and fixed versions
SimpleHelp **5.5.7 and earlier**; fixed in 5.5.8.

## How the detection confirms it
One anonymous `GET` of `serverconfig.xml` through the traversal, sent with the
raw `..` segment preserved. A finding needs HTTP 200, an
`application/octet-stream` content type, and the config markers (`<SimpleSuite`,
`<HashPassword>`). Only that file is read; no credential or cookie is sent and
redirects are not followed.

## Remediation
Update SimpleHelp to 5.5.8 or later, rotate secrets and user passwords stored in
`serverconfig.xml`, and restrict the web interface to trusted networks.
