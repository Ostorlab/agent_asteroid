# ShareFile Storage Zones Controller CVE-2026-2699 admin page authentication bypass

**CVE-2026-2699** lets an unauthenticated client reach the configuration pages
of a customer-managed Progress ShareFile Storage Zones Controller (SZC). The
admin page answers an anonymous visitor with a redirect to the login page but
keeps running, so the same response carries the rendered admin page
(CWE-284, CWE-698 Execution After Redirect).

```text
GET /ConfigService/Admin.aspx

HTTP/1.1 302 Found
Location: /ConfigService/Login.aspx?callerpage=Admin
Content-Length: 22448        <- full admin page after the "Object moved" stub
```

The cause is `Response.Redirect(url, false)`, which does not end the request.
From the admin page an attacker can change the zone configuration; watchTowr
chains this with CVE-2026-2701 to pre-auth remote code execution.

## Which advisory and references confirm the vulnerability?

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-2699> (published
  2026-04-02T14:16Z by the Progress CNA, CWE-284 and CWE-698, CVSS 3.1 9.8
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
- Progress advisory:
  <https://docs.sharefile.com/en-us/storage-zones-controller/5-0/security-vulnerability-feb26>.
- watchTowr Labs write-up (2026-04-02):
  <https://labs.watchtowr.com/youre-not-supposed-to-sharefile-with-everyone-progress-sharefile-pre-auth-rce-chain-cve-2026-2699-cve-2026-2701/>.
- watchTowr detection script:
  <https://github.com/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-2699>.

## Affected and fixed versions

The CNA marks versions through **5.12.3** as affected; NVD's CPE range is
5.0.0 up to, not including, **5.12.4**. watchTowr reports 5.12.4 was released
to 5.x customers on 2026-03-10 as the fix.

## How the detection confirms it

One anonymous `GET /ConfigService/Admin.aspx`, no redirect followed:

1. **Attribution** — the answer must be a 302 whose `Location` path is
   `/ConfigService/Login.aspx` with `callerpage=Admin` (relative or absolute,
   any case). Patched and unpatched controllers both send this redirect.
2. **Evidence** — the redirect body must be larger than 10,000 bytes, the
   threshold of watchTowr's detection script. A fixed controller sends only
   the short "Object moved" stub.

The body is counted and thrown away; the read stops at 10,001 bytes or after
10 seconds. No credential, cookie or request body is sent and no state
changes. The same response serves `accept` and `check`, so the target gets a
single request.

## Remediation

Upgrade the Storage Zones Controller to 5.12.4 or later. Until then, block
external access to `/ConfigService/` so only administrators on a management
network reach it. Review the zone settings and passphrase, and check IIS logs
for anonymous requests to `/ConfigService/Admin.aspx` and other
`/ConfigService/` pages.
