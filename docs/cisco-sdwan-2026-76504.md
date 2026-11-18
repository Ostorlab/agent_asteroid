# Cisco Catalyst SD-WAN Manager URI-encoding authentication bypass (CVE-2026-76504)

CVE-2026-76504 lets an unauthenticated client bypass Cisco Catalyst SD-WAN
Manager's login restriction by percent-encoding a character in
`/j_security_check`. This detector reports a bypass only when the encoded
login creates a session that reads an XSRF token and a valid protected server
document with HTTP 200, while anonymous and plain-login controls are denied.
It confirms administrative access only for an exactly recognized role.

## Advisory facts

- Cisco advisory [`cisco-sa-sdwan-webauth-xr8beuuU`](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU), first published
  2026-09-30, revised 2026-10-02.
- CWE-177 (improper handling of URL encoding); CVSS 3.1 9.8
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
- Cisco reports active exploitation and CISA added the CVE to its
  [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-76504) on
  2026-09-30.
- [First fixed releases by train](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU#fs): 20.9.10.1 (20.9), 20.12.8.2 (20.12), 20.15.6.1 (20.15),
  20.18.4.1 (20.18), 26.1.2.1 (26.1), 26.2.1 (26.2). Releases earlier than
  20.9 have no fix and must migrate.
- Cisco's indicators of compromise show `POST /%6a_security_check` returning
  HTTP 200 and a `viptela-reserved-*` account in the vManage server log.

## Root cause and remote observable

The authentication rule that restricts the `/j_security_check` login endpoint
compares the raw request URI, while the login handler resolves the
percent-decoded path. Encoding one character of the login path (for example
`%6a` for `j`) skips the rule and reaches the login handler, which maps the
request to a reserved administrative service account. Cisco says any one
encoded character works.

Cisco's own `CiscoDevNet/vmanage-client` documents the session flow this
detector relies on:

- `POST /j_security_check` with form fields `j_username` and `j_password`.
  A successful login returns an empty body and a `JSESSIONID`; a failed login
  returns the login HTML page.
- `GET /dataservice/client/token` returns the session XSRF token.
- `GET /dataservice/client/server` returns the session `user`, `roles` and
  `platformVersion` under `data`.

## Detection contract

The detector first attributes a Cisco Catalyst SD-WAN Manager from the
anonymous `GET /dataservice/client/about` document (the shared reader also
used by the CVE-2026-20127 exposure check). It then performs, in order:

1. `GET /dataservice/client/server` without a session; it must be refused
   with 401/403 (or redirected to a login page). An open endpoint invalidates
   the check because the evidence cannot be attributed to the bypass.
2. `POST /j_security_check` with a random synthetic `j_username` and a random
   password. Its session must still be refused by the protected endpoint.
3. `POST /%6a_security_check` with the same synthetic form. It must return
   HTTP 200, no redirect, and a `JSESSIONID`.
4. `GET /dataservice/client/token` with the encoded session; it must return
   HTTP 200 and a token-shaped body.
5. `GET /dataservice/client/server` with the encoded session and the token in
   `X-XSRF-TOKEN`; it must return HTTP 200 and a valid session document. The
   finding says administrative access was confirmed only when `data.roles`
   contains an exactly recognized administrative role after case and
   whitespace normalization. Unknown roles do not independently confirm
   administrative privileges.

The request path is restored after `requests` preparation because `requests`
normalises percent-encoded unreserved characters (`%6a` becomes `j`). Without
restoring the path, step 3's encoded request would become a duplicate of
step 2's plain `/j_security_check` login control. A direct loopback test
asserts that the wire target is the encoded path.

No credential is guessed: the username is `ostorlab-scan-<random>` and the
password is random. The token and cookie values are never stored in the
finding, the token is used only for the single role read, and no appliance
configuration or application data is changed.

## Validation

The reproducible artifact is
`artifacts/asteroid/2026-11-18-cisco-sdwan-auth-bypass/` in the shared memory
repository. It contains the loopback fixture server, an independent stdlib
oracle, a separate detector client, and the per-case results.

| Case | Fixture | Oracle | Detector |
| --- | --- | --- | --- |
| `vulnerable` | Manager 20.15.5, encoded path issues an admin session | vulnerable | finding, admin role |
| `variant` | Manager with no release, 401 plain login, JSON-string token, `super-admin` | vulnerable | finding, admin role |
| `non_admin_role` | encoded path issues a `viewer` session | vulnerable | finding, non-admin claim |
| `fixed` | Manager 20.18.4.1, encoded path refused | benign | no finding |
| `fixed_affected_label` | Manager advertises 20.15.5 but encoded path refused | benign | no finding |
| `lookalike_jboss` | non-Manager JBoss login page | benign | no finding |
| `open_endpoint` | protected endpoint answers anonymously | benign | no finding |
| `bad_token` | encoded session exists but token body is HTML | benign | no finding |
| `server_refused` | encoded session reads a token but the protected server document refuses it | benign | no finding |

Result: **TP 3 / TN 6 / FP 0 / FN 0 / inconclusive 0** (9 cases). The
fixtures are synthetic, built from the Cisco advisory and the public
`vmanage-client` session flow; no real vManage image was available in this
environment. The fixture results validate the detector's request sequence,
path preservation, session controls and reporting, not a production
false-positive rate.

## Limits

- A reverse proxy that decodes the path before vManage sees it prevents the
  observation (the bypass is mitigated by that proxy).
- SAML-only login, a removed or relocated login endpoint, or a deployment
  where the token route is not available causes a false negative.
- The advertised release may be stale, partially upgraded, or belong to a
  different component; an affected label alone is never reported.
- A session document without a role list reports the confirmed
  unauthenticated session without independently confirming the admin level.
- No real vManage was available, so the detector is validated against the
  documented exchange rather than against a vendor image. A positive on an
  authorised real appliance should be reviewed before remediation claims.

## Companion fingerprint

`Ostorlab/agent_whatweb` gains
`plugins/cisco_catalyst_sdwan_manager.rb`, matching the vManage landing
document title and the `Cisco SD-WAN Manager` / `Cisco vManage` / `vManage`
markers. It fingerprints both vulnerable and fixed fixtures and rejects
JBoss, Cisco IOS, a generic SD-WAN orchestrator, a vSmart controller page and a
generic page. The release is served by `/dataservice/client/about`, which
WhatWeb does not fetch at default aggression, so version extraction is a
recorded gap.

## Remediation and coverage

Upgrade to the first fixed release for the installed train in
[Cisco's fixed-software guidance](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU#fs);
releases earlier than 20.9 must migrate to a fixed train. Restrict management
access to trusted hosts while planning the upgrade and review Cisco's
indicators of compromise if compromise is suspected.

See the [detector source](../agent/exploits/cve_2026_76504.py), its
[README coverage row](../README.md#coverage), and the
[WhatWeb companion fingerprint (#174)](https://github.com/Ostorlab/agent_whatweb/pull/174)
for the implementation and product-inventory integration.
