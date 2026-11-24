# CVE-2025-6389: Sneeit Framework unauthenticated RCE via call_user_func

**CVE-2025-6389 is an unauthenticated remote code execution** in the Sneeit
Framework WordPress plugin (CWE-94, CVSS 3.1 9.8). The
`sneeit_articles_pagination` AJAX action passes the attacker-controlled
`callback` and `args` straight into `call_user_func()`, so an unauthenticated
request runs any PHP function on any arguments.

**Affected:** Sneeit Framework plugin for WordPress <= 8.3

**Fixed:** a release beyond 8.3 that stops passing user input into
`call_user_func()`

**Severity:** CVSS 3.1 9.8 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

## How does the detector verify it?

This is an **active, non-destructive, unforgeable** check. It calls the
read-only builtin `var_dump` on a single random marker and confirms `var_dump`'s
exact typed output is reflected:

```
POST /wp-admin/admin-ajax.php    Content-Type: application/x-www-form-urlencoded
  action=sneeit_articles_pagination&callback=var_dump&args=["<marker>"]
# <marker> random per probe; confirm response contains:  string(<len>) "<marker>"
```

`var_dump` only reads and prints its argument — **no OS command is run and no
file is read**. A server that merely echoes the marker cannot reproduce
`var_dump`'s `array(1) { [0]=> string(<len>) "<marker>" }` structure, so a match
proves the server invoked `var_dump` through `call_user_func`. No credential or
cookie is sent and redirects are not followed.

**Limitation:** the check relies on the `callback`/`args` reaching
`call_user_func` (the default, unauthenticated path). A deployment that blocks
`admin-ajax.php` at a WAF, or that disables `var_dump` output, produces no match
and is not reported — a conservative false negative, never a false positive.

## Remediation

Update the Sneeit Framework plugin beyond version 8.3. Restrict network access
to `wp-admin/admin-ajax.php` and remove the plugin if it is not required.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-6389> (published 2025-11-25,
  CWE-94, CVSS 3.1 9.8).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-6389>.
- WPScan advisory: <https://wpscan.com/vulnerability/CVE-2025-6389>.
- Public exploit: <https://github.com/Nxploited/CVE-2025-6389>.
