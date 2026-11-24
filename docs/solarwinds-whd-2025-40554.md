# SolarWinds Web Help Desk CVE-2025-40554 LoginPref authentication bypass

SolarWinds Web Help Desk 12.8.8 HF1 and earlier serves the protected authentication-settings admin page without authentication through a crafted WebObjects request.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-40554> (SolarWinds PSIRT).
- WHD 2026-1 release notes: <https://documentation.solarwinds.com/en/success_center/whd/content/release_notes/whd_2026-1_release_notes.htm>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-40554>.

## Affected and fixed versions
Web Help Desk **12.8.8 HF1 and earlier**; fixed in 2026.1.

## How the detection confirms it
A WHD fingerprint, then an anonymous `GET` of the LoginPref admin page (needs `externalAuthContainer`, `Authentication Settings`, `admin_pswd`). Only the admin page is read; requests are bounded.

## Remediation
Upgrade Web Help Desk to the 2026.1 fixed release and restrict the WebObjects endpoints.
