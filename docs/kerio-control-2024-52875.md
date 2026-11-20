# GFI Kerio Control CVE-2024-52875 CRLF injection

GFI Kerio Control 9.2.5 through 9.4.5 reflects the base64-decoded `dest`
parameter of several `/nonauth/*.cs` endpoints into the `Location` header without
stripping CR/LF (CWE-113), allowing HTTP response splitting and reflected XSS
(1-click RCE when chained).

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-52875> (published 2025-01-31, CWE-113, CVSS 3.1 8.8).
- Karma(In)Security write-up: <https://karmainsecurity.com/hacking-kerio-control-via-cve-2024-52875>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-52875>.

## Affected and fixed versions
Kerio Control **9.2.5 through 9.4.5**; fixed in 9.4.5 Patch 2.

## How the detection confirms it
Anonymous `GET` requests to the `/nonauth/*.cs` endpoints with the public
proof-of-concept `dest` values. A finding needs either the injected `Crlf`
response header or the reflected `<script>` in a 302 HTML response. No state is
changed; requests are bounded and redirects are not followed.

## Remediation
Upgrade Kerio Control to 9.4.5 Patch 2 or later and restrict access to the
`/nonauth/` endpoints.
