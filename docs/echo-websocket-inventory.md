# Echo Proxy WebSocket bypass inventory assessment

GHSA-cxf3-9h37-7rr8 is assessed **offline**, through
`python -m agent.utils.inventory inventory.json`. The policy lives in
[`ghsa_cxf3_9h37_7rr8.py`](../agent/exploits/ghsa_cxf3_9h37_7rr8.py).
It is separate from the remote exploit registry and `custom_cve_list`.
The existing result field `cve_ids` contains the GHSA identifier for this check;
no CVE alias is invented.

## Verified scope

Sources were checked on 2026-10-29, starting with the
[Ostorlab article](https://blog.ostorlab.co/labstack-echo-websocket-proxy-bypass-ghsa-cxf3-9h37-7rr8.html)
and verifying against the
[vendor advisory](https://github.com/labstack/echo/security/advisories/GHSA-cxf3-9h37-7rr8).
The vendor currently rates the issue Critical, CVSS v4.0 9.1; the article's
earlier statement that the vendor rates it Moderate is stale.

| Go module | Affected stable releases | First fixed release |
| --- | --- | --- |
| `github.com/labstack/echo/v4` | `>=4.0.0, <4.16.1` | `4.16.1` |
| `github.com/labstack/echo/v5` | `>=5.0.0, <5.4.1` | `5.4.1` |

The [v4 fix](https://github.com/labstack/echo/commit/3fb0ba7e17645bb65611e2a08875d0a2f65c421f)
and [v5 fix](https://github.com/labstack/echo/commit/1855061e572ae9dab727c811d8382f266bfbaaec)
remove the raw WebSocket proxy path and use Go's HTTP reverse proxy, which
validates the upstream response before tunneling. The relevant regression is
`TestProxyRejectedUpgradeKeepsRouting` in both
[v4](https://github.com/labstack/echo/blob/3fb0ba7e17645bb65611e2a08875d0a2f65c421f/middleware/proxy_security_test.go)
and [v5](https://github.com/labstack/echo/blob/1855061e572ae9dab727c811d8382f266bfbaaec/middleware/proxy_security_test.go).
It checks that after an ordinary 200, 401, or 403 response to an upgrade, a
subsequent request on that connection still encounters Echo's route guard and
does not reach the protected upstream handler. These sources were inspected;
the Go regression suite was not executed as part of this Python assessment.

The bypass is limited to the configured upstream and cannot defeat its own
authorization. An upstream non-101 response alone is neither a mitigation nor
proof of exploitability. Plain Echo routing without Proxy is outside this path.

## Owner evidence contract

Provide one record per deployed Echo proxy route, configured upstream, and
protected resource on that upstream. All fields must describe the same
deployment and security context. For a load-balanced deployment, assess each
backend/resource combination separately. A negative result for one combination
does not clear the service as a whole.

Collect the actual deployed module identity/release from trusted build inventory
or binary build information, accounting for Go module replacements and forks.
A `go.sum` entry alone does not establish what the running service uses. Gather
effective route/middleware configuration, upstream authorization policy, and
existing owner-controlled staging observations for upgrade response/lifetime
behavior. Do not supply credentials, response bodies, or private resource data.
The assessor trusts these assertions; it does not collect or authenticate them.

| Field | Meaning |
| --- | --- |
| `product` | Exactly `Echo`. |
| `module` | Exactly one of the Go module paths above. |
| `version` | Canonical three-component stable version, e.g. `4.16.0`. Normalize the Go tag's leading `v` only after verifying the actual release. Prereleases, pseudo-versions, forks and custom/backported builds require manual review. |
| `proxy_middleware_enabled` | Echo's built-in `middleware.Proxy` or `ProxyWithConfig` handles this route. A generic reverse proxy or library import does not qualify. |
| `websocket_upgrade_reaches_proxy` | A client in the assessed security context can reach the route and its upgrade request reaches Echo Proxy, accounting for authentication, middleware order, and any ingress upgrade blocking. |
| `upstream_rejects_upgrade` | That upstream returns an ordinary final HTTP response instead of accepting the WebSocket upgrade. |
| `upstream_keeps_connection_alive` | The upstream connection remains open for subsequent HTTP requests after that rejection. A generic keep-alive setting alone is insufficient. |
| `echo_route_authorization_enforced` | Echo's routing/middleware normally prevents this client from accessing the assessed resource. |
| `upstream_resource_authorization_enforced` | Independent upstream authorization protects this resource against the same client. Set `false` only when the owner has verified its absence. |

All six prerequisite fields require JSON booleans. Missing, null, numeric or
string values are unknown, never converted to booleans. Supply incomplete
records if evidence is unavailable; do not guess missing facts.

Example of a complete affected-path inventory record:

```json
[
  {
    "product": "Echo",
    "module": "github.com/labstack/echo/v4",
    "version": "4.16.0",
    "proxy_middleware_enabled": true,
    "websocket_upgrade_reaches_proxy": true,
    "upstream_rejects_upgrade": true,
    "upstream_keeps_connection_alive": true,
    "echo_route_authorization_enforced": true,
    "upstream_resource_authorization_enforced": false
  }
]
```

For v5 use `github.com/labstack/echo/v5` and the corresponding deployed version.
The module major and version major must agree.

- `potential_exposure`: an affected stable release and all six prerequisites
  match. Exploitability and backports remain unconfirmed.
- `not_matched`: a fixed stable release within v4/v5, or complete prerequisite
  evidence excluding this route/resource path. This is not a global safety claim.
- `inconclusive`: unknown identity, ambiguous version, or incomplete/invalid
  prerequisites for an affected release. Version or feature presence alone
  never produces a positive result. Fixed releases do not require prerequisites.

This implementation sends no traffic and reads no protected resources. A
generic remote probe cannot establish the deployment's route authorization
boundary or identify a harmless protected upstream canary. Confirmation would
require an explicitly designated owner-controlled test resource and paired
route-guard controls; this assessor does not claim that coverage.

Upgrade to the fixed release in the relevant major line. Until then, reject
WebSocket upgrades before the affected proxy route or independently enforce
authorization at every upstream resource.
