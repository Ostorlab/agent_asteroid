# Chartbrew CVE-2026-86005 unauthenticated BullMQ dashboard

**CVE-2026-86005** is a missing-authentication exposure in Chartbrew
(`chartbrew/chartbrew`), a self-hosted dashboard and reporting application.
When Redis and BullMQ are enabled, `server/setUpQueues.js` mounts the Bull
Board administration UI at `/apps/queues`. The only middleware in front of the
Bull Board router sets a Content-Security-Policy header; no authentication or
authorization check runs.

Through **5.2.2** the dashboard is reachable by anyone who can reach the
backend. It exposes the internal queue listing and, depending on the installed
Bull Board version and queue state, job payloads and logs and job retry,
delete or creation controls (CWE-306; CVSS 4.0 9.3
`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`).

The fix in **5.2.3** adds `server/middlewares/bullBoardAuth.js` (commit
`91873ce`) and mounts it before the router. The route now answers `401` with a
Basic Auth challenge, or `503` when `CB_BULLMQ_USERNAME`/`CB_BULLMQ_PASSWORD`
are not configured, and fails closed.

Checked 9 November 2026. Baseline `dbfec93` on `main`.

## Sources

- GitHub security advisory GHSA-w8g3-j8rf-qc5j:
  <https://github.com/chartbrew/chartbrew/security/advisories/GHSA-w8g3-j8rf-qc5j>
  (published 2026-09-06; vulnerable `5.2.2`, patched `5.2.3`).
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-86005> (published
  2026-11-06; CWE-306, CVSS 4.0 9.3).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-86005>.
- Vulnerable mount at v5.2.2: `server/setUpQueues.js` (`app.use("/apps/queues", ...)`).
- Fix commit `91873ce25d2b76d7bb6de7c61f372d03d56cc4aa`; release
  <https://github.com/chartbrew/chartbrew/releases/tag/v5.2.3>.

The same unauthenticated mount is present in the earlier v5.0.0 and v4.0.0
tags, so the fix boundary is the release that adds the auth middleware rather
than a version string the detector has to parse.

## How does the detector verify the exposure?

1. Read the anonymous root once. The Chartbrew API server answers the literal
   `Welcome to chartBrew server API`; the client origin serves a page titled
   `Chartbrew - Visualize your data in one place`. Either exact marker
   attributes the product.
2. Send one anonymous `GET /apps/queues`.
3. Require HTTP `200`, a `text/html` content type, and Bull Board's entry
   document: `<title>Chartbrew Jobs</title>`, the `id="__UI_CONFIG__"` block
   with `"boardTitle":"Chartbrew Jobs"`, and the
   `<base href="/apps/queues/">` mount path.
4. Report the unauthenticated dashboard exposure. A fixed server answers
   `401`/`503`; a blocked route answers `3xx`/`403`/`404`; a default Bull Board
   install carries the `Bull Dashboard` title and fails step 3.

Only the root and the `/apps/queues` entry document are requested. The queue
JSON API, job payloads, logs and the job mutation endpoints are not touched,
so the finding confirms the exposure and does not claim that a job was read or
altered.

## What does the detector miss?

- The route is mounted only when Redis and BullMQ are configured. An instance
  without them answers `404` and is not reported, even if the backend is
  otherwise vulnerable.
- A reverse proxy that blocks `/apps/queues`, or an external Basic Auth layer,
  produces a clean result. The evidence is the observed anonymous dashboard,
  not the deployed source revision.
- A Chartbrew fork that changes the board title away from `Chartbrew Jobs`
  fails the entry-document check.
- A fixed server answers `401` or `503`; as with any scanner, a missing
  finding proves nothing about patching.

## How was the detector validated?

Real upstream tags were installed from `server/package.json` (Node.js 22) and
served on loopback with PostgreSQL 16.2 and Redis 6.2: v5.2.2 (vulnerable),
v5.0.0 (vulnerable variant) and v5.2.3 (fixed, both with Basic Auth configured
and unconfigured). An independent stdlib oracle read each fixture's
`setUpQueues.js` and, for the fixed tag, `bullBoardAuth.js`, queried the service
with its own anonymous requests, and checked the status and entry-document
markers. A separate adapter imported the registered Asteroid detector and
called `accept`/`check` with only target scheme/host/port.

`run_cases.py`: **TP 3 / TN 5 / FP 0 / FN 0 / inconclusive 0**

| Case | Kind | Result |
| --- | --- | --- |
| v5.2.2 (real, Redis + BullMQ) | vulnerable | TP |
| v5.0.0 (real, earlier release) | variant | TP |
| v5.2.2 behind a proxy that forwards `/apps/queues` | variant | TP |
| v5.2.3 with Basic Auth credentials | fixed | TN |
| v5.2.3 without credentials (fail closed) | fixed | TN |
| v5.2.2 with `/apps/queues` blocked by the proxy | benign | TN |
| generic Bull Board install with the default title | benign | TN |
| non-Chartbrew origin with an unrelated `/apps/queues` page | benign | TN |

These are curated fixtures, not a production false-positive rate.

## Run the detector

```shell
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2026-86005"]' link --url https://chartbrew.example.org
```

The only requests are the anonymous root and `/apps/queues` entry document
described in [How does the detector verify the exposure?](#how-does-the-detector-verify-the-exposure).
See the [README coverage table](../README.md#detected-cves) for the rest of the
Asteroid checks.
