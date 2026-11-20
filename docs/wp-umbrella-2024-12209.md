# WP Umbrella CVE-2024-12209 local file inclusion

The WP Umbrella plugin for WordPress (<= 2.17.0) is affected by an unauthenticated local file inclusion via the `filename` parameter of the `umbrella-restore` action (CWE-22).

```text
GET /?umbrella-restore=1&filename=../../../../../../etc/passwd
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-12209> (published 2024-12-08 by the Wordfence CNA, CVSS 3.1 9.8).
- Wordfence advisory: <https://www.wordfence.com/threat-intel/vulnerabilities/id/c74ce3e8-cab9-4cc6-a1ad-1e51f7268474>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-12209>.

## Affected and fixed versions
WP Umbrella **<= 2.17.0**.

## How the detection confirms it
A home-page fingerprint for the plugin, then a `GET` reading `/etc/passwd` through the `umbrella-restore` filename traversal. Only a world-readable file is read; requests are bounded.

## Remediation
Update the plugin past 2.17.0 or remove it.
