# Meteobridge CVE-2025-4008 template.cgi command injection

**CVE-2025-4008** is an unauthenticated OS command injection in the Meteobridge
weather-station web interface at or below version 6.1 (CWE-306 / CWE-77): the
`templatefile` parameter of `/public/template.cgi` is passed into a shell context
without sanitisation, so an attacker runs arbitrary commands as root.

```text
GET /public/template.cgi?templatefile=$((a*b))
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-4008> (published 2025-05-21, CWE-306 / CWE-77, CVSS 3.1 8.8).
- ONEKEY advisory: <https://www.onekey.com/resource/security-advisory-remote-command-execution-on-smartbedded-meteobridge-cve-2025-4008>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-4008>.

## Affected and fixed versions
Meteobridge **<= 6.1**. Fixed in **6.2**.

## How the detection confirms it
One anonymous `GET` injects a random `$((a*b))` arithmetic expansion whose product
is never placed on the wire. A finding needs HTTP 200 and an error page
(`Error: template file ...`) reporting the evaluated product, proving the shell
executed the injected expansion. Only a benign arithmetic result is echoed; no
state is changed and redirects are not followed.

## Remediation
Upgrade Meteobridge to 6.2 or later and restrict network access to the device web
interface.
