# Gravity SMTP CVE-2026-4020 unauthenticated System Report exposure

**CVE-2026-4020** is an unauthenticated information exposure in the
[Gravity SMTP](https://www.gravityforms.com/gravity-smtp/) WordPress plugin by
RocketGenius. All versions up to and including **2.1.4** register this REST
route with a `permission_callback` that always returns true (CWE-200):

```text
GET /wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings
```

The `page=gravitysmtp-settings` parameter makes the plugin's
`register_connector_data()` fill its connector data, so the endpoint returns
about 365 KB of JSON with the full System Report: PHP version and extensions,
web server and database versions, document root, WordPress configuration,
active plugins and theme, database table names, and any API keys or tokens
configured in the plugin.

## Which advisory and references confirm the vulnerability?

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-4020> (published
  2026-03-31T02:15Z by the Wordfence CNA, CWE-200, CVSS 3.1 7.5
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`).
- Wordfence advisory:
  <https://www.wordfence.com/threat-intel/vulnerabilities/id/12a296db-ecc0-409b-8718-0c208504053a>.
- Vendor changelog: <https://docs.gravitysmtp.com/gravity-smtp-changelog/>
  (2.1.5, 2026-03-25: "Added security enhancements").
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-4020>.

## Affected and fixed versions

The CNA marks all versions through **2.1.4** as affected. The next release,
**2.1.5** (2026-03-25), is the first after 2.1.4 and its changelog entry is a
security fix. Gravity SMTP is a commercial plugin not hosted on WordPress.org,
so no public source diff of the fix was checked.

## How the detection confirms it

The detection is read-only and makes two anonymous `GET` requests:

1. **Attribution** — `GET /wp-json/gravitysmtp/v1` is the REST namespace index
   WordPress builds for every registered namespace. The site is accepted only
   when the JSON answer has `"namespace": "gravitysmtp/v1"` and a `routes`
   object. The read is capped at 256 KB.
2. **Evidence** — `GET /wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings`.
   A finding needs HTTP 200, a JSON content type, no redirect, and the
   `gravitysmtp_admin_config`, `system_report_clipboard` and `feature_flags`
   keys in the body. The body is streamed and dropped as soon as all three
   key names are seen; only a short sliding window is held in memory, and the
   read stops after 1 MB or 10 seconds.

No part of the System Report is stored or put in the finding. No credential,
cookie or request body is sent, no redirect is followed and no state changes.
Sites on plain permalinks, where the REST API lives only under
`?rest_route=`, are not probed.

## Remediation

Update Gravity SMTP to 2.1.5 or later. Until then, block anonymous requests to
`/wp-json/gravitysmtp/v1/tests/` at the web server or WAF, or deactivate the
plugin. The System Report includes the plugin's mail-provider API keys and
tokens, so rotate them and review access logs for requests to
`/wp-json/gravitysmtp/v1/tests/mock-data`.
