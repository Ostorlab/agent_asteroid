# HarnessRouter CVE-2026-125331 console internal-key relay bypass

**CVE-2026-125331 is an authorization bypass** in HarnessRouter, a unified API
for running agent harnesses. Its Next.js console proxies `/api/harness/*` to a
FastAPI gateway. In a console that is not in self-hosted mode the proxy attaches
the gateway's internal trust key to every request that carries an
`Authorization` header, before anything validates the bearer. The gateway's
service-only routes trust that key and take the organization from the URL.

**Affected:** HarnessRouter before 0.31.8
**Fixed:** 0.31.8 (commit `28609ec`)
**Severity:** CVSS 3.1 9.1 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`, CWE-862, CWE-863

The service-only routes are `GET|PUT /v1/orgs/{org}/connections/{name}`,
`PUT /v1/orgs/{org}/policy/{backend}` and `/internal/*`. A remote caller with a
made-up bearer therefore reaches them for any organization. The advisory's
demonstrated impact is rewriting another organization's provider connection to
an attacker-controlled endpoint, so later prompts are disclosed and
attacker-controlled responses can influence tasks.

Version 0.31.8 refuses a service-only request that also carries an
`Authorization` header and stops forwarding `/internal/*` through a
multi-tenant console. A default self-hosted install is not reachable this way:
its proxy attaches the key only for a valid console session.

## How does the detector verify the relay?

1. `GET /api/harness/v1/uhp` must return HarnessRouter's own anonymous UHP
   discovery document: `object` is `uhp.discovery`, `protocol` is `uhp`, a
   `versions` list contains `default_version`, and `implementation.name` is
   exactly `HarnessRouter Community Edition`. This attributes the product from
   the console proxy itself, not from a banner.
2. `GET /api/harness/v1/orgs/<random>/connections/<random>` without a bearer
   must answer `401`. This proves the console route is present and gated.
3. The same request with a locally fabricated bearer must reach the gateway's
   own handler: HTTP `404`, a JSON body whose `detail` is exactly
   `connection not found` and whose `error.code` is `not_found`, plus a
   `UHP-Version` response header. A fixed build answers `401`; a generic proxy
   `404`, a lookalike body without the gateway's header, or a vulnerable build
   that reports version 0.31.8 or later is not reported.

The random organization and connection names do not exist, so the check never
reads an existing connection or any `/internal/*` payload. It sends three
anonymous GETs: no real credential is used, no `PUT`/`POST` is sent, and no
state is changed. The connection rewrite and prompt disclosure are not
attempted.

## What is the finding?

The finding confirms that the console relayed a fabricated bearer to an
internal-only route and that the gateway accepted it for an organization taken
from the URL. It does **not** claim that a provider connection was read or
rewritten, or that prompts were disclosed: those require a `PUT` or a known
connection and are not performed. The finding recommends updating to 0.31.8 and
reviewing provider connections for unauthorized endpoints.

## What does the detector miss?

- A self-hosted console, or a console whose internal key is unset, does not
  attach the key to a bearer-only request and is not reported.
- A deployment that fronts the console with an additional authentication layer
  or blocks `/api/harness/*` is not reported.
- A console mounted under a path prefix is not probed; the check reads the
  origin's root paths.
- A build that reports 0.31.8 or later is not reported as this CVE even if a
  fork reintroduced the relay; that would be a regression, not this advisory.
- Network errors, timeouts, truncated responses and unsupported schemes are
  inconclusive and produce no finding; a missing finding is not proof that the
  relay is absent.

## How to reproduce and remediate

Attribute the product and check the gate:

```sh
curl -i 'http://<target>/api/harness/v1/uhp'
curl -i 'http://<target>/api/harness/v1/orgs/probe/connections/probe'
curl -i -H 'Authorization: Bearer probe' \
  'http://<target>/api/harness/v1/orgs/probe/connections/probe'
```

A `401` without a bearer and a `404` with the gateway's
`{"detail":"connection not found"}` envelope (and a `UHP-Version` header) with a
fabricated bearer confirms the relay. A fixed build answers `401` to the
fabricated-bearer request instead of the gateway's `404` envelope; the `401` to
the no-bearer request is identical in both.

Upgrade to HarnessRouter 0.31.8 or later. Until then, restrict the console to
trusted users or networks, keep the gateway off the public network, and review
provider connections and routing policy for unauthorized endpoints. Rotate any
provider credential whose connection was rewritten. For the agent-side summary,
run `oxo vulnz describe -v CVE-2026-125331`.

## Sources

- GitHub advisory GHSA-p6cq-54cg-8mpv:
  <https://github.com/HarnessRouter/harnessrouter/security/advisories/GHSA-p6cq-54cg-8mpv>
  (published 2026-11-10, critical 9.1, CWE-862/CWE-863).
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-125331> (published
  2026-11-10T19:21Z).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-125331>.
- Fix commit:
  <https://github.com/HarnessRouter/harnessrouter/commit/28609ec65ed671112d7e5418926bbd3cb3b25c00>
  (`_internal_only` refuses a relayed bearer; the console stops forwarding
  `/internal/*` outside a self-hosted box).
- Fix pull request:
  <https://github.com/HarnessRouter/harnessrouter/pull/418>.
- Fixed release:
  <https://github.com/HarnessRouter/harnessrouter/releases/tag/v0.31.8>.
