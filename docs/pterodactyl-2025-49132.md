# Pterodactyl Panel CVE-2025-49132 locale LFI configuration disclosure

Pterodactyl Panel before 1.11.11 allows an unauthenticated attacker to read arbitrary configuration via a path traversal in the locale translation endpoint (CWE-94). The disclosed `APP_KEY` enables remote code execution.

```text
GET /locales/locale.json?locale=..%2F..%2Fconfig&namespace=app
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-49132> (published 2025-06-20 by the GitHub CNA, CWE-94, CVSS 3.1 10.0).
- Fix commit: <https://github.com/pterodactyl/panel/commit/24c82b0e335fb5d7a844226b08abf9f176e592f0>.
- Release v1.11.11: <https://github.com/pterodactyl/panel/releases/tag/v1.11.11>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-49132>.

## Affected and fixed versions
Pterodactyl Panel before **1.11.11**.

## How the detection confirms it
One anonymous `GET` reading the app config through the locale traversal. A finding needs HTTP 200 and the config markers (`{"app":{"version":`, `"key":"base64{{`). Only configuration is read; the request is bounded.

## Remediation
Upgrade to Pterodactyl Panel 1.11.11 or later, rotate the `APP_KEY` and derived secrets, and review for compromise.
