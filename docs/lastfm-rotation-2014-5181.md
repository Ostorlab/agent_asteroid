# Last.fm Rotation CVE-2014-5181 local file inclusion

The Last.fm Rotation 1.0 WordPress plugin exposes `lastfm-proxy.php`, whose `snode` parameter reads arbitrary files (CWE-22).

```text
GET /wp-content/plugins/lastfm-rotation/lastfm-proxy.php?snode=/etc/passwd
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2014-5181> (published 2014-08-06, CWE-22).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2014-5181>.

## How the detection confirms it
A home-page fingerprint for the plugin, then a `GET` reading `/etc/passwd` through the proxy (needs the `root:...:0:0:` line). Only a world-readable file is read; requests are bounded.

## Remediation
Remove the unmaintained plugin and restrict access to its PHP files.
