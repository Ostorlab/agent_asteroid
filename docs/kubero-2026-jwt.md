# Kubero CVE-2026-125370 public fallback JWT secret

**CVE-2026-125370** is an authentication bypass in Kubero
(`kubero-dev/kubero`), a self-hosted platform for deploying applications on
Kubernetes. The NestJS backend signs and verifies session JWTs with
`process.env.JWT_SECRET`. When the variable is unset it falls back to a literal
that is published in the repository:

```text
DO NOT USE THIS VALUE. INSTEAD, CREATE A COMPLEX SECRET AND KEEP IT SAFE OUTSIDE OF THE SOURCE CODE.
```

`JwtStrategy.validate` copies `role`, `userGroups` and `permissions` from the
verified payload without a database or session lookup, and `PermissionsGuard`
authorizes on the `permissions` claim. A deployment that did not set a
deployment-specific secret therefore accepts an attacker-minted HS256 token for
any identity and any permission (CWE-321; CVSS 4.0 9.3
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`).

The fallback is present in **3.0.0 through 3.1.1** and on `main` when this
check was written (10 November 2026). The vulnerability is conditional on the
deployment: setting `JWT_SECRET` removes it. No fixed upstream release had been
published at that date.

## Sources

- Upstream report kubero-dev/kubero#786:
  <https://github.com/kubero-dev/kubero/issues/786>
- VulnCheck advisory:
  <https://www.vulncheck.com/advisories/kubero-3.0.0-through-3.1.1-authentication-bypass-via-hardcoded-jwt-secret>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-125370> (published
  2026-11-10, CWE-321, CVSS 4.0 9.3).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-125370>.
- Vulnerable strategy at v3.1.1:
  `server/src/auth/strategies/jwt.strategy.ts` (`secretOrKey` fallback and
  `validate`).
- Vulnerable signing module at v3.1.1:
  `server/src/auth/auth.module.ts` (`JwtModule.register` fallback).

## How does the detector verify the bypass?

1. Read the anonymous `GET /api/docs-json` and require the OpenAPI document to
   carry the exact title `Kubero` and the description prefix
   `Kubero is a web-based tool deploy applications on a Kubernetes clusters.`
   (verbatim from upstream, grammar included — keep byte-identical to the
   detector constant). This attributes the product without a version banner.
2. Mint a short-lived HS256 token whose claims name a non-existent probe
   identity and request no permissions, then call `GET /api/auth/session` with
   it. The session endpoint is guarded only by the JWT strategy and exposes
   `isAuthenticated` plus version/feature flags, not user data.
3. Require HTTP `200` and `isAuthenticated: true`. This is the fallback-secret
   acceptance signal.
4. Send the same claims signed with an unrelated secret. A `401` is required:
   a service that accepts any bearer token, or one that disabled
   authentication, does not have this bug and is not reported.
5. Call `GET /api/roles` with the fallback token carrying no permission and
   require `403`, then with the same token carrying `user:read` and require
   `200` with a JSON role list. This shows the permission guard trusts the
   token's claim, so arbitrary administrative permissions can be asserted.

All five requests are GETs. Only the `GET /api/docs-json` attribution is
anonymous; the other four carry a locally minted `Authorization: Bearer` token
for a fabricated identity. No real credentials are used and no state is
changed. The RBAC role listing is the only extra payload returned; it is
inspected for a JSON array shape and is never reported. No user records, API
tokens or application data are read. A deployment with `JWT_SECRET` set answers
`401` to the fallback token and is not reported.

## What does the detector miss?

- A deployment with a strong, deployment-specific `JWT_SECRET` is not
  vulnerable and is not reported. This is the fixed state for the conditional
  weakness; a missing finding therefore does not prove a patched release.
- A reverse proxy that blocks `/api/auth/session`, `/api/roles` or
  `/api/docs-json` prevents the evidence, even if the backend is vulnerable.
- A fork that changes the OpenAPI title or description prefix fails product
  attribution.
- The check is behavioural and does not parse a release version, so a future
  release that still accepts the fallback literal is reported, while a
  backport that rejects it is not.
- No fixed release existed on the validation date. Applying a vendor fix later
  should make the fallback token fail; re-validate after upgrading.

## How was the detector validated?

- Real upstream tags installed from `server/package.json` on Node.js 22.23.4
  with SQLite, each on its own loopback port: v3.1.1 (vulnerable), v3.1.0
  (vulnerable variant) and v3.1.1 with a random deployment `JWT_SECRET`
  (fixed).
- Four benign lookalikes implemented with the Python standard library served
  the Kubero OpenAPI document with different authentication behaviour:
  accept-any, roles-without-guard, reject-all and a different product title.
- An independent stdlib oracle — sharing no code with the detector — read each
  real release's `jwt.strategy.ts` for the fallback literal and exercised the
  service with its own tokens.
- A separate adapter imported the registered Asteroid detector and called
  `accept`/`check` with only target scheme/host/port.

`run_cases.py`: **2 true positives / 5 true negatives / 0 false positives /
0 false negatives / 0 inconclusive**.

| Case | Kind | Result |
| --- | --- | --- |
| Kubero v3.1.1, no `JWT_SECRET` | vulnerable | TP |
| Kubero v3.1.0, no `JWT_SECRET` | variant | TP |
| Kubero v3.1.1 with a deployment `JWT_SECRET` | fixed | TN |
| Lookalike accepting any bearer token | benign | TN |
| Lookalike with an unguarded `/api/roles` | benign | TN |
| Lookalike serving another product's OpenAPI document | benign | TN |
| Lookalike rejecting every token | benign | TN |

`TP` = true positive; `TN` = true negative. These are curated fixtures, not a
production false-positive rate.

## Run the detector

```shell
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2026-125370"]' link --url https://kubero.example.org
```

Only the five GETs described in
[How does the detector verify the bypass?](#how-does-the-detector-verify-the-bypass)
are sent. See the [README coverage table](../README.md#detected-cves) for the
rest of the Asteroid checks.
