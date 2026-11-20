# SolarWinds Web Help Desk CVE-2025-40553 unauthenticated deserialization

SolarWinds Web Help Desk exposes an unauthenticated JSON-RPC sink that deserializes attacker-controlled gadget data.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-40553> (SolarWinds PSIRT).
- WHD 2026-1 release notes: <https://documentation.solarwinds.com/en/success_center/whd/content/release_notes/whd_2026-1_release_notes.htm>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-40553>.

## How the detection confirms it, safely
A WHD fingerprint and a reachable RPC page, then a benign `BasicDataSource` gadget whose `validationQuery` is a random marker. A finding needs a `getConnection`/`syntax error` response showing the gadget class, proving deserialization. Only a short-lived JDBC connection to a benign DSN is opened; no file is read and no persistent state changes.

## Remediation
Upgrade Web Help Desk to the 2026.1 fixed release and review the host for compromise.
