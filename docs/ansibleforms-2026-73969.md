# AnsibleForms CVE-2026-73969 public fallback JWT secret

**CVE-2026-73969** is an authentication bypass in AnsibleForms
(`ansibleforms/ansibleforms`), a self-hosted web application that turns
Ansible automation into self-service forms. The Express backend signs and
verifies session JWTs with `process.env.ACCESS_TOKEN_SECRET`. When the variable
is unset it falls back to a literal that is published in the repository:

```text
j6fz%Q9S2YJC?x|u
```

`server/src/auth/auth_jwt.js` accepts every token whose HS256 signature
verifies and whose payload carries `access: true`; it never reloads the user
from the database. `server/src/lib/middleware.js` and the controllers then
authorize on the payload's `roles` and `options`. A deployment that did not set
a deployment-specific secret therefore accepts an attacker-minted token for any
identity, including an administrator with the settings, designer, log and
backup options (CWE-287, CWE-798, CWE-1188; CVSS 3.1 9.8
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

## Which releases are affected?

The fallback is present **before 6.2.1**. Release 6.2.1 (commit `a9b4979`,
pull request #473) replaces it with a 64-byte random secret generated at
startup when the environment variable is missing, so tokens do not survive a
restart. The vulnerability is also conditional on deployment: setting a strong
`ACCESS_TOKEN_SECRET` removes it at any release, and that is the fixed state for
older versions.

AnsibleForms changed its API between 6.1 and 6.2. The detector supports both
generations:

| Release family | Version document | Profile / group routes |
| --- | --- | --- |
| 6.2.x | `GET /api/v2/version` (`{version, server}`) | `/api/v2/profile`, `/api/v2/group` |
| 6.1.x and earlier | `GET /api/v1/version` (`{status, message, data}`) | `/api/v1/profile`, `/api/v1/group` |

Both generations expose the anonymous `GET /api/v2/schema` report, which names
the `AnsibleForms` schema and corroborates the product.

## Sources

- GitHub advisory GHSA-g27f-cjvv-42rf:
  <https://github.com/ansibleforms/ansibleforms/security/advisories/GHSA-g27f-cjvv-42rf>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-73969> (published
  2026-11-18T21:18Z).
- Fix commit:
  <https://github.com/ansibleforms/ansibleforms/commit/a9b4979165c4730b2abe1dbcfd053b4d3f9a5594>
- Fix pull request:
  <https://github.com/ansibleforms/ansibleforms/pull/473>
- Fixed release:
  <https://github.com/ansibleforms/ansibleforms/releases/tag/6.2.1>
- Vulnerable configuration at 6.2.0: `server/config/auth.config.js`.
- Vulnerable verification at 6.2.0: `server/src/auth/auth_jwt.js`.
- Vulnerable authorization at 6.2.0: `server/src/lib/middleware.js`.

## How does the detector confirm the bypass?

1. Read the anonymous version document (v2 first, v1 as a fallback) and the
   anonymous `/api/v2/schema` report. Require a semver release and the exact
   `Schema 'AnsibleForms' is present` marker, and require the release to be
   below 6.2.1. A release at or above 6.2.1 is not probed.
2. Mint two short-lived HS256 tokens for the same fabricated administrator
   identity (`username: <random non-existent value>`, `roles: [public, admin]`,
   `options.showSettings: true`): one signed with the public fallback secret
   and one signed with an unrelated secret.
3. Require `GET <profile>` without a token and with the wrong-secret token to
   answer `401`. A service that accepts any token, or that disabled
   authentication, does not have this bug and is not reported.
4. Require `GET <profile>` with the fallback token to answer `200` and echo the
   fabricated username, the `admin` role entry and the `showSettings` option. This
   shows the token verified without a database lookup.
5. Require `GET <group>?name=<random>` without a token to answer `401`, but
   with the fallback token to reach the handler's missing-group outcome — a
   `404` JSON `No such group found` on v2, or a `200` JSON
   `{"status":"error","message":"no such group found"}` on v1. This shows the
   `showSettings` option claim was honored by the authorization middleware.

The token probe sends five GETs, three of them carrying a locally minted bearer
token for a non-existent identity; product attribution adds the anonymous
version and schema reads (two GETs on 6.2.x, three on 6.1.x where the v2
version route answers 404 first). It reads no user, form, log, credential or
settings record: the only bodies inspected are the forged token's own echoed
claims and a lookup for a group name that cannot exist. No real credentials are
used and no state is changed. The finding confirms the authentication bypass but
leaves administrative actions unexercised.

## What does the detector miss?

- A deployment with a strong, deployment-specific `ACCESS_TOKEN_SECRET` is not
  vulnerable and is not reported, even on an affected release. A clean scan
  therefore does not prove the release is patched.
- A reverse proxy that blocks the version, schema, profile or group route
  prevents the evidence.
- A fork that removes the `/api/v2/schema` marker or changes the JWT shapes
  fails attribution.
- A deployment that mounts the app under a path prefix is not probed.
- A service that accepts any bearer token, or that answers the group lookup
  with an unexpected body, is deliberately not reported; those are different
  authentication failures.
- Network errors, timeouts, redirects, oversized documents and non-JSON
  responses are inconclusive.

## How was the detector validated?

Real upstream release tarballs from GitHub were installed with `server/package.json`
on Node.js 22.23.4 against a local MariaDB 11.8 database, each on its own
loopback port:

| Release | Tarball SHA-256 | Secret | Result |
| --- | --- | --- | --- |
| 6.2.0 | `315a6667d8da33f47831d8825efa0953d08d6132276e0bdcffb16d1971bd90ab` | unset (fallback) | TP |
| 6.1.0 | `156825d9d4e0951c6d86e758991bc280df659d954faa816d0bcb331afc92f6c0` | unset (fallback) | TP |
| 6.2.0 | `315a6667d8da33f47831d8825efa0953d08d6132276e0bdcffb16d1971bd90ab` | deployment-specific | TN |
| 6.2.1 | `afbcae30ba0575a9002f56879c6dbcedbd464656304ccf2bc8ac8c9e6bfafc57` | unset (random at startup) | TN |

Three benign lookalikes implemented with the Python standard library served the
same version and schema documents with a different security-relevant
behavior: one accepted any bearer token, one validated the fallback token but
returned a success envelope for the group lookup, and one rejected every token.
All three are TN.

An independent `http.client` oracle, sharing no code with the detector, minted
its own tokens and reproduced each ground-truth verdict. A separate adapter
imported the registered Asteroid detector and called `accept`/`check` with only
target scheme, host and port.

`run_cases.py`-equivalent matrix: **TP 2 / TN 5 / FP 0 / FN 0 / inconclusive 0**.

| Case | Kind | Oracle | Detector |
| --- | --- | --- | --- |
| 6.2.0, fallback secret | vulnerable | vulnerable | 1 finding |
| 6.1.0, fallback secret (v1 API) | variant | vulnerable | 1 finding |
| 6.2.0, deployment secret | fixed | not vulnerable | no finding |
| 6.2.1, random startup secret | fixed | not vulnerable | no finding |
| Lookalike accepting any token | benign | not vulnerable | no finding |
| Lookalike with a success group handler | benign | not vulnerable | no finding |
| Lookalike rejecting every token | benign | not vulnerable | no finding |

`TP` = true positive; `TN` = true negative. These are curated fixtures, not a
production false-positive rate.

## How do I run the check?

```shell
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2026-73969"]' link --url https://ansibleforms.example.org
```

Only the five token-probe GETs and the anonymous version/schema reads described
in [How does the detector confirm the bypass?](#how-does-the-detector-confirm-the-bypass)
are sent.

If the check reports a finding, upgrade to 6.2.1 or later, or set a strong
`ACCESS_TOKEN_SECRET` (for example `openssl rand -hex 32`) and restart the
backend. Because a token signed with the public fallback could already have been
used, review authentication and job logs for actions that do not belong to a
real account and rotate any credentials the application can reach. See the
[README coverage table](../README.md#detected-cves) for the rest of the Asteroid
checks.
