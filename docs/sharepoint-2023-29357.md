# Microsoft SharePoint CVE-2023-29357 JWT authentication bypass

Microsoft SharePoint Server validates a JWT access token without verifying its
signature (CWE-303), so a token forged with the `none` algorithm impersonates a
privileged user and reaches SharePoint APIs.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-29357> (published 2023-06-14, CWE-303, Microsoft CVSS 3.1 9.8).
- MSRC update guide: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2023-29357>.

## Affected and fixed versions
SharePoint Server 2019 before 16.0.10399.20005 and Subscription Edition; see the
MSRC guide. Fixed in the June 2023 updates.

## How the detection confirms it
Two requests to `/_api/web/siteusers`: the first (unauthenticated) yields the
realm from the `WWW-Authenticate` header; the detection forges a `none`-algorithm
JWT for that realm and the second request confirms the API returns user records
(`LoginName`, `Email`, `IsSiteAdmin`). Only the siteusers list is read; nothing
is changed and the read is bounded.

The forged `Authorization` / `X-PROOF_TOKEN` headers cannot be sent through the
anonymous `defensive_http` transport, so this detection uses the scanner session
directly with redirects disabled.

## Remediation
Apply the Microsoft SharePoint security update for CVE-2023-29357 (June 2023 or
later) and enable AMSI. Restrict access to SharePoint, and because privilege
escalation is possible (and chainable to RCE with CVE-2023-24955), review for
unauthorized administrative actions.
