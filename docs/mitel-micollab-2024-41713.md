# Mitel MiCollab CVE-2024-41713 path traversal authentication bypass

Insufficient input validation in the Mitel MiCollab NuPoint (NPM) component lets
an unauthenticated attacker traverse out of the `/npm-pwg` context and reach
internal services (CWE-22).

```text
GET /npm-pwg/..;/axis2-AWC/services/listServices
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-41713> (published 2024-10-21, CWE-22, CVSS 3.1 9.1).
- Mitel advisory MISA-2024-0029: <https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-41713>.

## Affected and fixed versions
Mitel lists **9.8 SP1 FP2 (9.8.1.201)** and earlier as affected. The fix is
in **9.8 SP2 (9.8.2.12)**. See MISA-2024-0029 for backported patches.

## How the detection confirms it
One anonymous `GET` of the traversal path. A finding needs HTTP 200 and the Axis2
service listing (`Available services`, `Service Description`). Only a service
listing is read; the request is bounded and follows no redirect.

## Remediation
Apply the MiCollab update in MISA-2024-0029 and restrict access to the web
interface.
