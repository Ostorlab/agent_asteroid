# jqueryFileTree CVE-2017-1000170 directory traversal

**CVE-2017-1000170** is a directory traversal in the jqueryFileTree 2.1.5 PHP
connector (here bundled by the WordPress Delightful Downloads plugin). The
connector lists any directory named in the `dir` POST parameter (CWE-22), so an
unauthenticated attacker enumerates directories such as `/etc`.

```text
POST /wp-content/plugins/delightful-downloads/assets/vendor/jqueryFileTree/connectors/jqueryFileTree.php
dir=%2Fetc%2F&onlyFiles=true
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2017-1000170> (published 2017-11-17, CWE-22, CVSS 3.1 7.5).
- Upstream issue / fix: <https://github.com/jqueryfiletree/jqueryfiletree/issues/66>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2017-1000170>.

## Affected and fixed versions
jqueryFileTree **2.1.5 and older**.

## How the detection confirms it
One anonymous `POST` listing `/etc`. A finding needs HTTP 200 and the connector's
`passwd` list entry markers. Only a directory listing is read -- no file content;
the request is bounded, sends no credential or cookie and follows no redirect.

## Remediation
Update jqueryFileTree and the plugin that bundles it, or remove the connector.
Do not expose the connector to untrusted clients and confine the directories it
may list.
