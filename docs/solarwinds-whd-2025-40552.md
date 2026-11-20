# SolarWinds Web Help Desk CVE-2025-40552 LookAndFeel authentication bypass

SolarWinds Web Help Desk serves the protected LookAndFeel admin page without authentication through a WebObjects request.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-40552> (published 2026-01-28 by the SolarWinds PSIRT, CVSS 3.1 9.8).
- WHD 2026-1 release notes: <https://documentation.solarwinds.com/en/success_center/whd/content/release_notes/whd_2026-1_release_notes.htm>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-40552>.

## How the detection confirms it
A WHD fingerprint, then an anonymous `POST` for the LookAndFeel page (needs the `Add File`/`saveOptions` admin markers). Only the admin page is read; requests are bounded.

## Remediation
Upgrade Web Help Desk to the 2026.1 fixed release and restrict the WebObjects endpoints.
