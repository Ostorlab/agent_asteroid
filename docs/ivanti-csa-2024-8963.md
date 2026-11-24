# Ivanti Cloud Services Appliance CVE-2024-8963 path traversal

Ivanti Cloud Services Appliance (CSA) before 4.6 Patch 519 contains a path
traversal (CWE-22) that lets an unauthenticated attacker reach restricted
functionality via `/client/index.php%3F.php/...`. The flaw has been exploited
in the wild, including alongside CVE-2024-8190.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-8963> (published 2024-09-19, CWE-22, CVSS 3.1 9.1).
- Ivanti advisory: <https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-CSA-4-6-Cloud-Services-Appliance-CVE-2024-8963>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-8963>.

## Affected and fixed versions
Ivanti CSA before **4.6 Patch 519** (4.6 is end of life; move to 5.0).

## How the detection confirms it
One anonymous `GET` of the traversal path. A finding needs HTTP 200 and the CSA
user-administration markers (`Ivanti Cloud Services Appliance`, `User name`,
`Set Password`). Only page markup is read; the request is bounded.

## Remediation
Upgrade Ivanti CSA to 4.6 Patch 519 or 5.0. Keep the management interface off the
internet and review the appliance for compromise.
