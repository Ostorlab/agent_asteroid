# mojoPortal CVE-2025-28367 directory traversal

**CVE-2025-28367** is a directory traversal (CWE-284) in mojoPortal through
2.9.0.1. The `imagehandler` action of the BetterImageGallery API does not
validate its `path` parameter, so an unauthenticated request can read
`Web.Config` and obtain the MachineKey.

**Affected:** mojoPortal through 2.9.0.1.
**Fixed:** 2.9.0.2.
**Severity:** CVSS 3.1 6.5 (Medium) — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N

## How does the detector verify it?

```
GET /api/BetterImageGallery/imagehandler?path=../../../Web.Config
```

The check passes only on HTTP 200 with both `<machineKey` and `<system.web>`
in the body, which a normal image response never contains. It sends one
anonymous GET (no cookie or credential), does not follow redirects, bounds the
response read and reads a single file. Nothing is written or changed.

**Limitation:** a patched or hardened host, or one that serves the handler
under another route, is not reported.

## Remediation
Upgrade mojoPortal to 2.9.0.2 or later and rotate the MachineKey.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-28367> (published 2025-04-21, CWE-284, CVSS 3.1 6.5).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-28367>.
- Advisory: <https://www.0xlanks.me/blog/cve-2025-28367-advisory/>.
- Project: <https://github.com/i7MEDIA/mojoportal>.
