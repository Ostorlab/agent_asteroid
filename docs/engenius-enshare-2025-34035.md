# EnGenius EnShare CVE-2025-34035 usbinteract.cgi root command injection

**CVE-2025-34035** is an unauthenticated OS command injection in EnGenius EnShare
IoT Gigabit Cloud Service 1.4.11 and earlier (CWE-78): the `path` POST field of
`usbinteract.cgi` is passed into a shell command without sanitisation, so an
attacker runs arbitrary commands as root.

```text
POST /web/cgi-bin/usbinteract.cgi
action=7&path="|echo ${IFS}$((a*b))||"
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-34035> (published 2025-06-24, CWE-78, CVSS 3.1 9.8).
- ZeroScience advisory ZSL-2017-5413: <https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5413.php>.
- Exploit-DB 42114: <https://www.exploit-db.com/exploits/42114>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-34035>.

## Affected and fixed versions
EnGenius EnShare Cloud Service **1.4.11 and earlier**. Fixed in **1.4.12**.

## How the detection confirms it
One anonymous `POST` (tried on both known CGI paths) injects a random `$((a*b))`
arithmetic expansion whose product is never placed on the wire. A finding needs
HTTP 200, the broken-CGI `Content-type: text/html` body marker and the evaluated
product, proving the CGI executed the injected command. Only a benign arithmetic
result is echoed; no state is changed and redirects are not followed.

## Remediation
Upgrade EnShare Cloud Service to 1.4.12 or later and restrict network access to
the device web interface.
