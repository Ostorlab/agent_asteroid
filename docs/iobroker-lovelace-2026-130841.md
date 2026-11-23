# CVE-2026-130841: ioBroker.lovelace unauthenticated static-route path traversal

**[CVE-2026-130841](https://www.cve.org/CVERecord?id=CVE-2026-130841) is an unauthenticated arbitrary file read** in the
ioBroker.lovelace adapter (CWE-22, CVSS 3.1 7.5). Before 7.0.0, `onCards` and the generic static handler in
`src/lib/server.ts` joined a caller-controlled request path to the directory
they served on the `/cards/`, `/hacsfiles/`, `/local/custom_ui/` and
`/static/icons/` routes without resolving or confining the final path. The
routes are reachable without authentication, so a remote client could read any
file readable by the ioBroker process, including the adapter configuration and
the credentials the advisory names.

**Affected:** ioBroker.lovelace releases before 7.0.0

**Fixed:** ioBroker.lovelace 7.0.0 ([fix commit
e8dee3d](https://github.com/ioBroker/ioBroker.lovelace/commit/e8dee3d08bddef088901326dab1ac7f12c2237d6)).
The fix resolves every static path inside its served folder and answers 404
for a path that escapes it.

**Severity:** CVSS 3.1 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

## How does the detector verify the traversal?

1. `GET /auth/providers` must return the adapter's own anonymous provider
   document: a provider with `type` `iobroker` and `name` `ioBroker Local`.
2. `GET /` must return the Home Assistant-compatible dashboard landing
   document (an `ioBroker` title and the `<home-assistant>` element).
3. `GET /static/icons/%2e%2e/%2e%2e/package.json` must answer HTTP 200 with
   the adapter's own `package.json` (`name` `iobroker.lovelace`, a release
   below 7.0.0). The request carries literal `..` segments on the wire; the
   percent encoding only keeps the client from normalizing the path before it
   is sent.
4. The same two-level traversal naming a missing file must answer 404, so a
   catch-all server that serves any path is not reported.

The check reads only the adapter's public `package.json` metadata. It never
requests a configuration value, credential, token, certificate, user record or
other private file, and it changes no state.

## What does a positive finding claim?

The finding confirms the unauthenticated static-route path traversal: the
resolved path escaped the served directory and the server returned its own
`package.json` while the missing-file control returned 404. It does not claim
that the adapter configuration or any stored credential was read; that part of
the advisory's impact was deliberately not exercised.

## What does the detector miss?

- A reverse proxy that normalizes dot segments or rejects requests containing
  `..` prevents the probe from reaching the vulnerable handler, so a vulnerable
  backend is not reported.
- A deployment mounted under a path prefix is not probed; the check uses the
  adapter's standard root paths.
- A customized landing page that removes both the `ioBroker` title and the
  `<home-assistant>` element is not attributed.
- A deployment whose `/auth/providers` route is hidden or rewritten is not
  attributed.
- Network errors, timeouts, redirects, oversized bodies and malformed JSON are
  inconclusive and produce no finding; a missing finding is not proof that the
  traversal is absent.

## How do I run the check?

Run the check with a single oxo command; it reports a finding only when the
two-level traversal returns the adapter's `package.json` and the missing-file
control answers 404.

```sh
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2026-130841"]' ip 10.0.0.10
```

The equivalent manual differential on the same origin is (`--path-as-is` keeps
curl from folding the `..` segments client-side, mirroring the encoded probe):

```sh
curl -i 'http://10.0.0.10:8080/auth/providers'
curl -i 'http://10.0.0.10:8080/'
curl -i --path-as-is 'http://10.0.0.10:8080/static/icons/../../package.json'
curl -i --path-as-is 'http://10.0.0.10:8080/static/icons/../../ostorlab-missing-package.json'
```

| Request | Vulnerable 6.1.x | Fixed 7.0.0 |
| --- | --- | --- |
| `/auth/providers` | `200` ioBroker Local provider | `200` ioBroker Local provider |
| `/` | `200` dashboard | `200` dashboard |
| `/static/icons/../../package.json` | `200` `{"name":"iobroker.lovelace",...}` | `404` |
| `/static/icons/../../ostorlab-missing-package.json` | `404` | `404` |

## How do I fix CVE-2026-130841?

Upgrade ioBroker.lovelace to 7.0.0 or later and restart the adapter. While
preparing the upgrade, put the adapter behind a reverse proxy that rejects
requests whose decoded path contains a `..` segment (covering percent-encoded
`%2e%2e` and double-encoded `%252e`) and restrict the HTTP endpoint to trusted
clients. Do not rely on URL rewriting alone as containment.

If an affected deployment was reachable by untrusted clients, review the access
log for `/static/icons/`, `/cards/`, `/hacsfiles/` and `/local/custom_ui/`
requests containing `..` in literal or percent-encoded form (`%2e%2e`,
`%252e`, and case variants such as `%2E%2E`), and treat the adapter
configuration and any stored credentials as exposed.

## How was the detector validated?

Real npm releases were installed on loopback with a minimal adapter host, an
independent stdlib `http.client` oracle that never imports the detector, and
the registered detector run from a separate client process:

| Release / fixture | Oracle | Detector | Result |
| --- | --- | --- | --- |
| ioBroker.lovelace 6.1.3 | traversal read the package (`6.1.3`) | 1 finding | TP |
| ioBroker.lovelace 6.1.2 (earlier release, same handlers) | traversal read the package (`6.1.2`) | 1 finding | TP |
| ioBroker.lovelace 7.0.0 fixed | traversal 404 | no finding | TN |
| ioBroker.lovelace 7.1.0 fixed | traversal 404 | no finding | TN |
| Home Assistant provider lookalike | not ioBroker | no finding | TN |
| other-package lookalike (same route) | not ioBroker.lovelace | no finding | TN |
| catch-all missing control (200) | not a real file read | no finding | TN |

**TP 2 / TN 5 / FP 0 / FN 0 / inconclusive 0** (7 live cases). These are
curated fixture results, not a production false-positive rate.

The companion fingerprint is
[`plugins/iobroker_lovelace.rb`](https://github.com/Ostorlab/agent_whatweb/blob/master/plugins/iobroker_lovelace.rb)
in [Ostorlab/agent_whatweb#191](https://github.com/Ostorlab/agent_whatweb/pull/191)
(pending). The landing page is shared with Home Assistant branding, so the
fingerprint matches the `ioBroker` title plus the `<home-assistant>` element;
the fingerprint cannot extract a version because the landing page carries no
adapter release.
