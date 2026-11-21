# CVE-2026-63189: Dialoqbase unauthenticated view-route file read

**[CVE-2026-63189](https://nvd.nist.gov/vuln/detail/CVE-2026-63189) is an
unauthenticated arbitrary file read** in Dialoqbase's `GET /api/v1/view/*`
route (CWE-22, CVSS 3.1 9.8). Through 1.11.4
`server/src/routes/api/v1/view/root.ts` joined the caller-controlled wildcard
onto a fixed parent chain with `join(__dirname, "../../../../../" + filePath)`
and read the result with no normalization or containment. The route is
registered without authentication.

The advisory reads `.env` or `/proc/self/environ` to obtain `DB_SECRET_KEY`,
the `@fastify/jwt` signing key, and then forges an administrator token that
takes over the application.

**Affected:** Dialoqbase through 1.11.4 ([GHSA-2448-c4f7-4crm](https://github.com/n4ze3m/dialoqbase/security/advisories/GHSA-2448-c4f7-4crm))

**Fixed:** Dialoqbase 1.11.5 ([fix commit c9d128c](https://github.com/n4ze3m/dialoqbase/commit/c9d128c58997d91d9786b54a0fd626206ce0f4f9), [PR #317](https://github.com/n4ze3m/dialoqbase/pull/317)).
The fixed route resolves every request against `process.cwd()/uploads` and
answers 404 for a path that resolves outside it.

**Severity:** CVSS 3.1 9.8 (Critical) —
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

The published production image copies the compiled `dist` tree into `/app`, so
the route's five-parent base is `/`; a source-tree build keeps the `server/`
prefix and bases there. Both layouts expose files outside the intended uploads
directory.

## How does the detector verify the traversal?

1. `GET /` must return the Dialoqbase single-page landing document with an
   exact `<title>Dialoqbase</title>` element.
2. `GET /docs/static/index.html` must return the server-rendered Swagger UI
   document whose title is `Dialoqbase API Docs`. The title is set in the
   server's `app.ts` and is present in an unmodified release.
3. `GET /api/v1/view/app/prisma/schema.prisma` (production image base `/`) or
   `GET /api/v1/view/prisma/schema.prisma` (source-tree base `server/`) must
   answer HTTP 200 with the application's own non-sensitive Prisma schema: the
   `provider = "postgresql"` datasource and the `Bot`, `BotSource` and
   `BotDocument` models.
4. The same base naming a missing file must answer HTTP 404, so a catch-all
   server that returns a body for every path is not reported.

The check reads only the product's own Prisma schema. It never requests an
upload, a user row, a token, `.env`, `/proc/self/environ` or any other
credential or configuration value, and it changes no state. A fixed 1.11.5
server answers 404 to both schema paths.

## What does a positive finding claim?

The finding confirms the unauthenticated file read: the view route returned the
application's own schema from outside the uploads directory while the same base
naming a missing file returned 404. It does not claim that `DB_SECRET_KEY` or
any other secret was read, nor that an administrator token was forged; those
parts of the advisory's impact were deliberately not exercised.

## What does the detector miss?

- A deployment that serves a custom landing title or a custom Swagger UI title
  is not attributed, so its view route is not probed.
- A deployment mounted under a path prefix is not probed; the check uses the
  origin's standard paths.
- A reverse proxy that blocks `/api/v1/view/` or normalizes the probe path
  prevents the schema read even when the backend is vulnerable, so no finding
  is reported.
- A repackaged build that omits `prisma/schema.prisma`, or a deployment whose
  layout differs from both supported layouts, has no benign oracle and is not
  reported. This is a coverage limitation, not a clean negative.
- Network errors, timeouts, redirects, oversized bodies and malformed responses
  are inconclusive and produce no finding; a missing finding is not proof that
  the traversal is absent.

## How do I run the check?

```sh
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2026-63189"]' ip 10.0.0.10
```

The equivalent manual differential on the same origin is:

```sh
curl -i 'http://<target>:3000/'
curl -i 'http://<target>:3000/docs/static/index.html'
curl -i 'http://<target>:3000/api/v1/view/app/prisma/schema.prisma'
curl -i 'http://<target>:3000/api/v1/view/app/prisma/__asteroid_missing__'
```

| Request | Vulnerable 1.11.4 | Fixed 1.11.5 |
| --- | --- | --- |
| `/` | `200` Dialoqbase landing | `200` Dialoqbase landing |
| `/docs/static/index.html` | `200` Dialoqbase API Docs | `200` Dialoqbase API Docs |
| `/api/v1/view/app/prisma/schema.prisma` | `200` Prisma schema | `404` Not Found |
| `/api/v1/view/app/prisma/__asteroid_missing__` | `404` Not Found | `404` Not Found |

For a source-tree build, substitute `/api/v1/view/prisma/schema.prisma` and
`/api/v1/view/prisma/__asteroid_missing__`. Run the four commands against the
same origin and compare the status codes with the table above.

## How do I fix CVE-2026-63189?

1. Upgrade Dialoqbase to 1.11.5 or later and restart the server.
2. Rotate `DB_SECRET_KEY` on every deployment that ran an affected release,
   because it is the `@fastify/jwt` signing key and may have been read through
   the view route.
3. Rotate any stored third-party integration credential reachable by the
   application.
4. If an upgrade cannot be applied immediately, block `/api/v1/view/` at the
   reverse proxy and restrict the HTTP endpoint to trusted clients.
5. Review access logs for `/api/v1/view/` requests targeting `.env`,
   `/proc/self/environ`, `prisma/schema.prisma` or other direct relative paths
   while the deployment was exposed.

## How was the detector validated?

Real production images (`n4z3m/dialoqbase:v1.11.3`, `v1.11.4`, `v1.11.5`) were
run on loopback with a local PostgreSQL/pgvector and Redis, migrations applied,
synthetic secrets and no application data. A source-tree layout was reproduced
by placing the same real `dist` tree under `server/dist` with `server/prisma`,
which exercises the second schema path. An independent stdlib `http.client`
oracle that never imports the detector, and the registered detector run from a
separate client process, were used:

| Fixture | Layout | Oracle | Detector | Result |
| --- | --- | --- | --- | --- |
| Dialoqbase 1.11.3 production image | `dist` at `/app` | vulnerable | 1 finding | TP |
| Dialoqbase 1.11.4 production image | `dist` at `/app` | vulnerable | 1 finding | TP |
| Dialoqbase 1.11.4 | `server/dist` + `server/prisma` | vulnerable | 1 finding | TP |
| Dialoqbase 1.11.5 production image | `dist` at `/app` | fixed | no finding | TN |
| Dialoqbase 1.11.5 | `server/dist` + `server/prisma` | fixed | no finding | TN |
| catch-all lookalike (schema read and missing path both 200) | stdlib | not exploitable | no finding | TN |
| wrong-body lookalike (JSON at the schema path, 404 control) | stdlib | not exploitable | no finding | TN |
| title-only lookalike (Dialoqbase landing, no docs title) | stdlib | not attributed | no finding | TN |
| other-product lookalike | stdlib | not Dialoqbase | no finding | TN |

**TP 3 / TN 6 / FP 0 / FN 0 / inconclusive 0** (9 cases). These are curated
fixture results, not a production false-positive rate.

## Companion WhatWeb fingerprint

The companion fingerprint is a WhatWeb plugin in `Ostorlab/agent_whatweb`
([PR #185](https://github.com/Ostorlab/agent_whatweb/pull/185)),
`plugins/dialoqbase.rb`, validated with WhatWeb 0.6.4. The 1.11.3, 1.11.4 and
fixed 1.11.5 production landings are identified as **Dialoqbase**; a custom
page with the title but no SPA root container, a page with the root container
and another title, and an unrelated product are not matched. The release is not
present in the landing response, so the plugin extracts no version; component
matching cannot resolve the patch level from the landing document, which is
recorded as a gap.

## Sources

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-63189> (published
  2026-11-18; CWE-22; CVSS 3.1 9.8).
- GitHub advisory GHSA-2448-c4f7-4crm:
  <https://github.com/n4ze3m/dialoqbase/security/advisories/GHSA-2448-c4f7-4crm>.
- Fix commit `c9d128c58997d91d9786b54a0fd626206ce0f4f9`:
  <https://github.com/n4ze3m/dialoqbase/commit/c9d128c58997d91d9786b54a0fd626206ce0f4f9>.
- Fixed release: <https://github.com/n4ze3m/dialoqbase/releases/tag/v1.11.5>.

## Generic coverage

The reusable pattern — an unauthenticated static/file-serving route that joins
a caller-controlled path to a server-side directory without normalization or
containment, observed with a product-owned file outside that directory as the
benign oracle — is a candidate for a generic path-traversal detection rule.
This CVE module does not claim generic static-route coverage.
