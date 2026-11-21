# CVE-2026-77338: Sprout Track public fallback JWT secret authentication bypass

**[CVE-2026-77338](https://nvd.nist.gov/vuln/detail/CVE-2026-77338) is a full
authentication bypass** in Sprout Track before 1.3.5 (CWE-798, CVSS 4.0 9.3).
`app/api/utils/auth.ts` signed and verified access tokens with
`process.env.JWT_SECRET` or, when the variable was unset, the literal
`baby-tracker-jwt-secret` published in the repository. The stock setup did not
generate a unique value. The token verifier copied `isSysAdmin`, `role` and the
identity fields straight from the payload without reloading the user from the
database, and the auth-context wrapper gave a system-administrator token the
family context named by the request. Anyone who knows the literal can mint a
system-administrator token, which the advisory maps to family, child activity,
account and email data access.

**Affected:** Sprout Track before 1.3.5
([GHSA-x6rw-w9f5-5hw2](https://github.com/Oak-and-Sprout/sprout-track/security/advisories/GHSA-x6rw-w9f5-5hw2))

**Fixed:** Sprout Track 1.3.5
([fix commit 2b05592](https://github.com/Oak-and-Sprout/sprout-track/commit/2b05592b089009d5a3b86b0769dcf3407a689c6a),
[PR #200](https://github.com/Oak-and-Sprout/sprout-track/pull/200)). The fix
removes the fallback, fails closed when `JWT_SECRET` is unset, and the upgrade
generates a unique key.

**Severity:** CVSS 4.0 9.3 (Critical) —
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

A deployment with a strong, deployment-specific `JWT_SECRET` is not affected,
even before 1.3.5.

## How does the detector verify the bypass?

1. `GET /api/changelog` is anonymous and returns the project changelog. Its
   first `## vX.Y.Z` heading is the running release, and the document must
   begin with `# Sprout Track Changelog`. Only a release below 1.3.5 is
   probed.
2. Four anonymous `GET /api/family/setup-status?familyId=...` requests use a
   family id that cannot exist:
   - without a token — 401 `Authentication required`;
   - with the fabricated system-administrator claims signed by an unrelated
     secret — 401 `Authentication required`, so the service validates
     signatures rather than accepting any token;
   - with the public fallback secret and an ordinary user identity — 403
     `No family context available`, so the token is accepted but does not carry
     administrator rights;
   - with the public fallback secret and `isSysAdmin: true` — 404
     `Family not found`, so the token verified as a system administrator and
     reached the family lookup. A real family is never read.

The check reads only the public changelog and the error envelope of a lookup
for a non-existent family. It never requests a real family, caretaker,
activity, account, credential or configuration record and changes no state.

## What does a positive finding claim?

The finding confirms that a token signed with the published fallback literal
is accepted as a system administrator. It does not claim that any family,
child, account or email record was read, and it does not perform an
administrative action. The advisory's data-access impact is the consequence of
the confirmed authentication bypass.

## What does the detector miss?

- A deployment that does not expose `/api/changelog` (a customized build or a
  proxy that blocks the route) is not attributed and is not reported.
- A deployment mounted under a path prefix is not probed; the check uses the
  origin's standard paths.
- A 1.3.5 or later deployment is never considered, even if an operator
  explicitly set `JWT_SECRET` to the old public literal; that configuration is
  outside the advisory's affected range.
- Network errors, timeouts, redirects, oversized bodies and malformed JSON are
  inconclusive and produce no finding; a missing finding is not proof that the
  bypass is absent.

## How do I run the check?

```sh
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2026-77338"]' ip 10.0.0.10
```

The equivalent manual differential on the same origin is:

```sh
curl -i 'http://10.0.0.10:3000/api/changelog'
curl -i 'http://10.0.0.10:3000/api/family/setup-status?familyId=missing'
# then repeat the last request with each locally minted bearer token
```

| Request | Vulnerable 1.3.4 / 1.2.4 | Fixed 1.3.5 |
| --- | --- | --- |
| `GET /api/changelog` | `200`, first heading `v1.3.4` / `v1.2.4` | `200`, first heading `v1.3.5` |
| setup-status, no token | `401 Authentication required` | `401 Authentication required` |
| setup-status, wrong-secret sysadmin token | `401 Authentication required` | `401 Authentication required` |
| setup-status, fallback-secret user token | `403 No family context available` | `401 Authentication required` |
| setup-status, fallback-secret sysadmin token | `404 Family not found` | `401 Authentication required` |

A vulnerable deployment with a unique `JWT_SECRET` answers 401 to both
fallback-secret requests while still exposing the vulnerable release in the
changelog.

## How do I fix CVE-2026-77338?

Upgrade Sprout Track to 1.3.5 or later. On an older deployment, set a strong,
deployment-specific `JWT_SECRET` (for example `openssl rand -hex 32`) in the
environment and restart the service; the 1.3.5 upgrade generates one
automatically.

Because tokens signed with the public fallback are accepted as system
administrators, treat every session and every administrator action recorded
before the secret was changed as potentially forged. Review the application and
reverse-proxy logs, and rotate the system PIN and other secrets reachable
through the administrator interface. Restrict the web port to trusted networks
or a reverse proxy.

## How was the detector validated?

Real Sprout Track release tags were built with Node.js 22 and served on
loopback with a migrated SQLite database and synthetic configuration. An
independent stdlib `http.client` oracle that never imports the detector
reproduced the token differential, and the registered detector ran from a
separate client process:

| Fixture | Release | Oracle | Detector | Result |
| --- | --- | --- | --- | --- |
| Sprout Track, no `JWT_SECRET` | 1.3.4 | vulnerable | 1 finding | TP |
| Sprout Track, no `JWT_SECRET` | 1.2.4 | vulnerable | 1 finding | TP |
| Sprout Track, fixed | 1.3.5 | fixed | no finding | TN |
| Sprout Track with a unique `JWT_SECRET` | 1.3.4 | fixed | no finding | TN |
| catch-all lookalike (same changelog, no route semantics) | N/A | not exploitable | no finding | TN |
| other-product lookalike | N/A | not Sprout Track | no finding | TN |

N/A indicates a Python standard-library fixture with no source distribution.

**TP 2 / TN 4 / FP 0 / FN 0 / inconclusive 0** (6 cases). These are curated
fixture results, not a production false-positive rate.

The companion WhatWeb plugin was validated with WhatWeb 0.6.4 at default
aggression: it identified 1.2.4, 1.3.4 and 1.3.5 and did not match an unrelated
dashboard, a title-only page or a description-only page. The release is not in
the landing response, so version extraction is a recorded fingerprint gap.
