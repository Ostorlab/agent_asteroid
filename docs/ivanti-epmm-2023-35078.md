# Ivanti EPMM CVE-2023-35078 authentication bypass

**CVE-2023-35078** is an unauthenticated API access vulnerability in Ivanti
Endpoint Manager Mobile (EPMM, formerly MobileIron Core) through 11.10 (CWE-287).
Administrative API paths such as `/mifs/aad/api/v2/admins/users` are reachable
without authentication, disclosing PII and enabling account creation and
configuration changes. It was exploited in the wild in July 2023 (KEV).

```text
GET /mifs/aad/api/v2/admins/users
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-35078> (published 2023-07-25, CWE-287, CVSS 3.1 9.8).
- Ivanti advisory: <https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability>.
- CISA alert: <https://www.cisa.gov/news-events/alerts/2023/07/24/ivanti-releases-security-updates-endpoint-manager-mobile-epmm-cve-2023-35078>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2023-35078>.

## Affected and fixed versions
Ivanti EPMM **<= 11.10**; fixed in **11.8.1.1, 11.9.1.1, 11.10.0.2** and later.

## How the detection confirms it
One anonymous `GET` of `/mifs/aad/api/v2/admins/users`. A finding needs HTTP 200,
an `application/json` body, and the user-listing markers (`results`, `userId`,
`name`), proving the admin API is reachable without authentication. Only the
listing is read; no credential or cookie is sent and redirects are not followed.

## Remediation
Apply the Ivanti EPMM security update, restrict management-interface exposure to
trusted networks, and review admin accounts and configuration for unauthorized
changes.
