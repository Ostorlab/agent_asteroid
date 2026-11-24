# React Server Components CVE-2025-55184 denial of service / source exposure

React Server Components 19.0.0 to 19.2.1 (`react-server-dom-*` packages) are affected by a denial of service and source-code exposure via Server Functions.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-55184> (published 2025-12-11 by the Facebook/Meta CNA, CVSS 3.1 7.5).
- React advisory: <https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-55184>.

## Affected and fixed versions
react-server-dom-* **19.0.0 to 19.2.1**; fixed in 19.2.2.

## How the detection confirms it
Fingerprints a Next.js app, scans static JS chunks for a React version in the affected range, then sends a benign Server Function probe (needs the `Server action not found` 404). No Server Function is executed; requests are bounded.

The `Next-Action` header cannot be sent through the anonymous `defensive_http` transport, so the scanner session is used directly.

## Remediation
Upgrade react-server-dom-* / React to 19.2.2 or later.
