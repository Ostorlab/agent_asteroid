# WordPress Swim Team CVE-2015-5471 arbitrary file read

**CVE-2015-5471** is an absolute path traversal in the WP-SwimTeam plugin
1.44.10777 for WordPress. `include/user/download.php` returns any file named in
the `file` parameter (CWE-22), so an unauthenticated attacker reads files such
as `/etc/passwd`.

```text
GET /wp-content/plugins/wp-swimteam/include/user/download.php?file=/etc/passwd&filename=/etc/passwd&contenttype=text/html&transient=1&abspath=/usr/share/wordpress
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2015-5471> (published 2016-01-12, CWE-22, CVSS 3.0 5.3).
- WPScan: <https://wpscan.com/vulnerability/8071>.
- Vendor fix topic: <https://wordpress.org/support/topic/security-vulnerability-6>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2015-5471>.

## Affected and fixed versions
WP-SwimTeam **1.44.10777**; fixed in the 1.45 line.

## How the detection confirms it
One anonymous `GET` of `download.php` for `/etc/passwd`. A finding needs HTTP 200
and the `root:...:0:0:` account line. Only that world-readable file is read; the
request is bounded, sends no credential or cookie and follows no redirect.

## Remediation
Update or remove the WP-SwimTeam plugin. Restrict direct access to its
`download.php`, and treat any file the web user can read as disclosed.
