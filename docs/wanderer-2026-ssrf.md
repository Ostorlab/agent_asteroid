# Wanderer CVE-2026-71495 unauthenticated download-endpoint SSRF

**CVE-2026-71495** is an unauthenticated server-side request forgery in
Wanderer, a self-hosted SvelteKit trail database. Before 0.20.0 the public
`POST /api/v1/trail/download` handler passed a caller-supplied JSON `url` value
directly to `event.fetch()` and returned the fetched body. When
`PUBLIC_PRIVATE_INSTANCE` is not `true`, the route is not protected, so an
unauthenticated caller could make the server request loopback, RFC1918,
link-local and cloud-metadata destinations, read the responses and enumerate
internal services (CWE-918, CVSS 3.1 10.0
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H`).

The 0.20.0 fix requires an authenticated user, validates the protocol,
hostname and resolved address (IPv4/IPv6, including tunneled forms), pins the
connection to the validated address and rejects redirects.

Checked 8 November 2026. Baseline `6f3faf7` on `main`.

## Sources

- GitHub advisory:
  <https://github.com/open-wanderer/wanderer/security/advisories/GHSA-7vqq-mjjr-h9j5>
  (published 2026-09-28; NVD published 2026-11-06).
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-71495> (CWE-918, CVSS 3.1
  10.0, secondary CNA vector).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-71495>.
- Upstream fix pull request:
  <https://github.com/open-wanderer/wanderer/pull/1104> (commit `c371337`),
  released in <https://github.com/open-wanderer/wanderer/releases/tag/v0.20.0>.
- Fixed code:
  `web/src/lib/util/secure_fetch_util.ts` (protocol, hostname and DNS-resolved
  address validation, pinned connection, redirect rejection) and
  `web/src/routes/api/v1/trail/download/+server.ts` (the `event.locals.user`
  401 gate).

## How does the detector verify the SSRF?

1. Read the anonymous home page and require a title ending in `| wanderer`
   plus the project's `wanderer.to` / `open-wanderer/wanderer` links. Read
   `/_app/version.json` (the SvelteKit generated version document) to obtain
   the observed release.
2. A release at or above 0.20.0 is fixed and is not probed further.
3. For an HTTP origin, ask the download endpoint for
   `http://localhost:<observed-port>/_app/version.json` and require the
   response to be the same version document, carrying the pre-fix handler's
   hardcoded placeholder `Content-Type` value
   (`determine the content type here`). That string is the literal header the
   vulnerable handler copied from the `event.fetch()` response, so it
   fingerprints handler execution rather than a generic error page. If the
   version document is unavailable, fall back to fetching the origin's own
   home page over `http://127.0.0.1:<observed-port>/` and matching the home
   title.
4. On HTTPS origins the plain-HTTP loopback probe cannot reach the TLS
   listener. The detector then sends one POST with an invalid URL: the
   vulnerable handler answers `500`, while 0.20.0 answers `401` before reading
   the URL. Only that exact `500` counts; 3xx redirects, other 4xx/2xx
   responses and gateway-generated 502/503/504 answers produce no finding.
   Combined with an observed release before 0.20.0, a `500` is reported as
   **POTENTIAL EXPOSURE**, not confirmed SSRF.
5. Send only anonymous requests. The server is asked only to fetch its own
   version/home document on its own loopback port; the detector never asks it
   to contact another internal service, a cloud metadata endpoint or
   application data, and it never reads a protected file.

Deployments that set `PUBLIC_PRIVATE_INSTANCE=true` are not vulnerable even on
an old release; the detector's 401 / 403 result produces no finding. A
reverse proxy or WAF that blocks the route also produces no finding. The
version document reflects the built release, not a backport, so HTTPS
deployments get a potential-exposure finding rather than a confirmed one.

## How was the detector validated?

Real upstream releases v0.19.3 and v0.19.0 (affected) and v0.20.0 (fixed) were
built with Node.js 22 and served on loopback with a minimal PocketBase/
Meilisearch stand-in. A TLS-terminating reverse proxy covers the HTTPS path.
An independent stdlib oracle reads each fixture's `web/package.json` and
download route source for ground truth, then exercises the public version
document and the anonymous download endpoint itself.

| Case | Kind | Oracle | Detector |
| --- | --- | --- | --- |
| v0.19.3 direct HTTP | vulnerable | vulnerable | TP (confirmed) |
| v0.19.0 direct HTTP | variant | vulnerable | TP (confirmed) |
| v0.19.3 behind TLS | vulnerable | vulnerable | TP (potential) |
| v0.20.0 direct HTTP | fixed | not vulnerable | TN |
| version-only lookalike (0.19.3, route 404) | benign | not vulnerable | TN |
| protected lookalike (0.19.3, route 401) | benign | not vulnerable | TN |
| WAF-blocked lookalike (0.19.3, route 403) | benign | not vulnerable | TN |
| other-product lookalike (0.19.3, route 200) | benign | not vulnerable | TN |

Result: **TP 3 / TN 5 / FP 0 / FN 0 / inconclusive 0**. These are curated
fixture results, not a production false-positive rate. No customer target was
contacted.

Reproduce the validation with the focused suites:

```shell
pytest tests/exploits/wanderer_fetch_test.py tests/exploits/cve_2026_71495_test.py
```

Run the detector in a standard scan:

```shell
oxo scan run --install --agent agent/ostorlab/asteroid ip 8.8.8.8
```

Filter it with the `custom_cve_list` scanner setting; see
[the README coverage section](../README.md#defensive-assessment-coverage-for-20252026-cves).
The detector ships as part of the Asteroid agent and uses only anonymous
HTTP(S) requests.
