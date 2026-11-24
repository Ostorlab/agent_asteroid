# CVE-2026-69158: Atomic Server unauthenticated full-response SSRF

**[CVE-2026-69158](https://nvd.nist.gov/vuln/detail/CVE-2026-69158) is an
unauthenticated full-response server-side request forgery** in Atomic Server
before 0.40.3 (CWE-918, CVSS 3.1 8.6). Atomic Server is an open-source
headless CMS and real-time graph database.

The bookmark endpoint reads a caller-supplied `url` query parameter and passes
it to `fetch_data`/`fetch_body`. Before the fix, `fetch_body` checked only that
the value started with `http`. The endpoint is dispatched before the read
authorization check, and the handler discards the caller, so the request is
anonymous.

After fetching, the handler reflects the page's title, description, image and
markdown preview in the returned `Bookmark` resource. An attacker can therefore
make the server request loopback, RFC1918, link-local and cloud-metadata targets
and read the response, not merely observe a timing or error difference.

**Affected:** Atomic Server before 0.40.3
([GHSA-ff87-73jp-f3v4](https://github.com/ontola/atomic-server/security/advisories/GHSA-ff87-73jp-f3v4))

**Fixed:** Atomic Server 0.40.3. The outbound fetch helper resolves each target
and rejects loopback, RFC1918/CGNAT and link-local addresses, including on every
redirect hop
([fix commit 006ff290](https://github.com/ontola/atomic-server/commit/006ff290f7ec976c8cbafdceb7b6899389abd5be),
[fix commit 2d4535fc](https://github.com/ontola/atomic-server/commit/2d4535fcd84761288027616505cc61abdf05bc50),
[fix commit e7f551d3](https://github.com/ontola/atomic-server/commit/e7f551d385045708240ca56889d1334a39349735)).
The fixed release keeps an explicit `ATOMIC_ALLOW_PRIVATE_FETCH=1` opt-out for
intentional LAN fetches.

**Severity:** CVSS 3.1 8.6 (High) —
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`. NVD and the GitHub advisory publish this
score and vector; the scope-changed CVSS 3.1 formula applies the 1.08 multiplier
and yields 8.6 for this vector.

The affected 0.39 and 0.40 releases register the handler at
`/fetch-bookmark` (`PATH_FETCH_BOOKMARK`); the advisory's `/bookmark` is the
same bookmark handler.

## How does the detector verify the SSRF?

1. `GET /` must return the Atomic Server landing document: the
   `<title>Atomic Data</title>` title, the template meta description
   `The easiest way to create, share and model Linked Atomic Data.`, and the
   `Meta tags and code added by Atomic-Server` comment.
2. It sends one anonymous
   `GET /fetch-bookmark?url=http://127.0.0.1:<observed-port>/&name=<random>`
   request with `Accept: application/ad+json`.
3. A vulnerable server fetches its own loopback landing page and returns a
   `Bookmark` resource whose `name` and `description` are that page's title and
   meta description, whose `url` property is the loopback URL, whose
   `@id` quotes this probe's URL and random name token, and whose `preview` is
   non-empty.
4. A fixed server refuses the loopback target with a non-public-address error
   before reading the URL. A 0.40.3-or-later release is also excluded when its
   `x-atomic-server-version` header is present, because the fixed release can
   intentionally re-enable private fetches with `ATOMIC_ALLOW_PRIVATE_FETCH=1`.

The check sends only anonymous GETs to the origin's own loopback page. It
never makes the server request another internal service, a cloud metadata
endpoint, a local file or a third-party host, and it changes no state.

## What does a positive finding claim?

**The finding confirms the unauthenticated SSRF dispatch:** the server fetched
the caller-supplied loopback URL and reflected that page's title and
description. It does not claim that a specific internal service, cloud metadata
credential or local file was read; the probe stops at the origin's own landing
page. The advisory's internal-service and metadata impact uses the same fetch
primitive.

## What does the detector miss?

**The detector does not report a deployment when it cannot reach the origin's
own loopback page, when the landing is customised past its markers, or when the
SSRF is gated by configuration.** The enumerated cases are:

- An HTTPS-only deployment whose plain-HTTP loopback listener is not reachable
  is not reported; the probe uses `http://127.0.0.1:<port>/`.
- A deployment bound to a specific public address rather than loopback is not
  reported, because the self-referential loopback probe cannot connect.
- A reverse proxy that blocks `/fetch-bookmark` prevents the probe even when
  the backend is vulnerable.
- A customised landing that lacks the template meta description or the
  `Atomic-Server` comment is not attributed.
- A 0.40.3-or-later deployment with `ATOMIC_ALLOW_PRIVATE_FETCH=1` is not
  reported as this CVE; the fetch is intentional configuration, not the
  affected release.
- A deployment that exposes only the advisory's `/bookmark` alias and not
  `/fetch-bookmark` is not probed.
- Network errors, timeouts, redirects, oversized bodies and malformed JSON are
  inconclusive; a missing finding is not proof that the SSRF is absent.

## How do I run the check?

```sh
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2026-69158"]' ip 10.0.0.10
```

Atomic Server listens on port 9883 by default; adjust the port in each command
if the deployment differs. The equivalent manual differential on the same
origin is:

```sh
curl -i 'http://10.0.0.10:9883/'
curl -i -H 'Accept: application/ad+json' \
  'http://10.0.0.10:9883/fetch-bookmark?url=http%3A%2F%2F127.0.0.1%3A9883%2F&name=probe'
```

| Request | Vulnerable 0.39.x / 0.40.x | Fixed 0.40.3+ |
| --- | --- | --- |
| `GET /` | `200`, title `Atomic Data`, template description, `Atomic-Server` comment | same landing |
| `GET /fetch-bookmark?url=http://127.0.0.1:9883/&name=probe` | `200` `Bookmark` resource reflecting the landing title/description and the loopback URL | `500` error: target address is not a public address |
| Same request with a fixed release and `ATOMIC_ALLOW_PRIVATE_FETCH=1` | n/a | `200`; the `x-atomic-server-version` header shows the fixed release |

## How do I fix CVE-2026-69158?

Upgrade Atomic Server to 0.40.3 or later, which validates every outbound fetch
target at resolution time and on redirects. Do not set
`ATOMIC_ALLOW_PRIVATE_FETCH=1` on an internet-facing deployment.

If the upgrade cannot be applied immediately, block `/fetch-bookmark` and
`/import` at the reverse proxy and restrict the container's outbound network
access so it cannot reach loopback, private or link-local addresses. Review
access logs and network egress for anonymous `/fetch-bookmark` requests whose
`url` names a loopback, private, link-local or metadata address, and rotate any
credential reachable from that container.

## How was the detector validated?

Real upstream release binaries were run on loopback with separate data,
configuration and search-index directories. An independent stdlib
`http.client` oracle that never imports the detector reproduced the landing
markers and the reflected Bookmark resource. The registered detector then ran
from a separate client process:

| Fixture | Release | Oracle | Detector | Result |
| --- | --- | --- | --- | --- |
| Atomic Server binary | 0.40.1 (v0.40.0 asset) | vulnerable | 1 finding | TP |
| Atomic Server binary | 0.39.0 | vulnerable | 1 finding | TP |
| Atomic Server binary | 0.41.0-beta.2 (fixed) | fixed | no finding | TN |
| landing-only lookalike (Atomic landing, no bookmark route) | N/A | not exploitable | no finding | TN |
| static-bookmark lookalike (fixed `@id`, no probe token) | N/A | not exploitable | no finding | TN |
| wrong-url lookalike (reflected name but a different `url`) | N/A | not exploitable | no finding | TN |
| wrong-class lookalike (non-Bookmark resource) | N/A | not exploitable | no finding | TN |
| other-product lookalike | N/A | not Atomic Server | no finding | TN |

N/A indicates a Python standard-library fixture with no source distribution.

**TP 2 / TN 6 / FP 0 / FN 0 / inconclusive 0** (8 cases). These are curated
fixture results, not a production false-positive rate.

The companion [WhatWeb plugin](https://github.com/Ostorlab/agent_whatweb/pull/186)
(`plugins/atomic_server.rb`, 2.0.14 → 2.0.15) was validated with WhatWeb 0.6.4
at default aggression: it identified the 0.39.0, 0.40.1 and 0.41.0-beta.2
landings and did not match a title-only page, a title-and-description page
without the Atomic-Server comment, or an unrelated dashboard. The release is
only in the `x-atomic-server-version` header on 0.41 and later, so version
extraction for the affected 0.39/0.40 releases is a recorded fingerprint gap.
