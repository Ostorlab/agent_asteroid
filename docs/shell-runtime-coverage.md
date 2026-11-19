# PHP2Shell, React2Shell and Node2Shell: PHP, React, Brotli, Node.js and Bun

The PHP2Shell, React2Shell and Node2Shell detectors retain their existing remote
checks and finding identities. Owner-supplied offline inventory adds deployment
and package evidence without running target code. Neither mode sends command,
memory-exhaustion, compressed-decoder or RSC exploitation payloads.

## Remote evidence

PHP2Shell reads anonymous HTTP response headers for one unambiguous canonical
PHP release. Node2Shell retains the same header-only Node.js check, without
reading response bodies. Both report potential version exposure and cannot
verify the running binary, distributor backports or input reachability.

React2Shell retains `GET /_rsc/version`, an optional application-provided
metadata route, without assuming that React exposes this endpoint by default.
It accepts only exact RSC server package names and stable versions, rejects
conflicting identity/version aliases and duplicate JSON keys, and reads a
bounded response without following redirects or sending credentials. Missing
optional provenance/runtime fields do not establish an unmodified binary or
live server-side processing. An absent or ambiguous endpoint yields no finding
and does not establish a patched target.

## Trusted inventory schema

Trusted inventory means owner- or operator-supplied evidence about the deployed
runtime, resolved packages and effective configuration. The CLI does not collect,
authenticate or verify this evidence. Save records for the same running target
as a normalized JSON array:

```json
[
  {
    "product": "PHP",
    "version": "8.4.26",
    "serves_web_requests": true,
    "session_upload_progress_enabled": false,
    "verified_fixed_cves": ["CVE-2026-109618"]
  },
  {
    "product": "npm:react-server-dom-webpack",
    "version": "19.1.1",
    "server_rsc_enabled": true
  },
  {
    "product": "Node.js",
    "version": "26.12.1",
    "brotli_version": "1.2.0",
    "untrusted_brotli_input": true
  },
  {
    "product": "pypi:brotlicffi",
    "version": "1.2.0.2",
    "untrusted_brotli_input": true
  }
]
```

Run `python -m agent.utils.inventory inventory.json`. Results contain only CVE
IDs, status, reason and recommendation; arbitrary input fields and secrets are
not echoed. Native Ruby records also emit optional `advisory_ids` for their
three GHSA assessments, as documented in [Ruby regexp coverage](shell-ruby-coverage.md).

| Field | Meaning |
| --- | --- |
| `product` | Exact identity from the tables below. npm/PyPI prefixes distinguish genuine server/decoder packages from similarly named products. |
| `version` | Canonical three-component numeric release, or four components for `pypi:brotlicffi`. Custom/prerelease suffixes require per-CVE verified fix evidence or manual review. |
| `verified_fixed_cves` | Optional list of canonical CVE IDs whose fixes the owner verified in the deployed build. Each assessor honors only its own ID. Missing/empty means no verified fix assertion; malformed lists are inconclusive. A claim must cover the actual running workers/loaded decoder, rather than an available update or an unrelated binary. |
| `build_provenance` | Optional `upstream_release`. Other supplied values require a matching verified fix for a version verdict. An omitted field does not prove upstream binary provenance. |
| `serves_web_requests` | Optional effective boolean for PHP. `false` excludes the documented web-request path only, independently for all three PHP CVEs. |
| `session_upload_progress_enabled` | Effective PHP startup boolean for the assessed writer. Use `true` for the within-process exposure check. `false` excludes that writer. |
| `configured_serialize_handler` | PHP startup serializer. The within-process check matches `php_binary` or `php_serialize`. |
| `runtime_serialize_handler_before_session_start` | Effective PHP serializer immediately before session start. The within-process check matches `php`. |
| `server_rsc_enabled` | Optional effective boolean for React. `false` excludes the server-side RSC processing path. |
| `untrusted_brotli_input` | Optional effective boolean for the new Brotli/runtime products. `false` excludes the untrusted-decoding path. Envoy retains its existing effective `brotli_decompressor_enabled` boolean requirement. |

An omitted prerequisite remains unknown. Supplied prerequisite values must be
booleans; strings, numbers and `null` are inconclusive.

A matching affected release without prerequisite evidence remains
`potential_exposure`, with exploitability unconfirmed. `not_matched` applies only
to this CVE and supplied path or fix evidence; it never establishes overall
product safety.

## PHP2Shell and the upload-progress follow-up

Every `PHP` record receives three independent assessments and recommendations:

| CVE | Verified version boundaries | Path-specific interpretation |
| --- | --- | --- |
| [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | Original fix points: 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Earlier releases in these branches and known EOL branches 7.4, 8.0 and 8.1 match the affected matrix. Older/unlisted branches are inconclusive. | Allocation failure/OOM corruption. `memory_limit=-1` and disabled upload progress do not clear all paths. |
| [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | Same original fixed/EOL matrix, with its own verified-fix decision. | Stale request-owned global state. Disabling upload progress addresses particular paths only. |
| [CVE-2026-115560](https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx) | Upstream fix points are 8.2.36, 8.3.37, 8.4.28 and 8.5.13. Unsupported branches have no published fix bounds. | An anonymous PHP banner can flag potential version exposure. Inventory can also identify a within-process serializer change while upload progress is enabled. |

For CVE-2026-115560, supply `product: "PHP"`, an affected branch release in
`version`, and all three matching PHP settings above for a `potential_exposure`
result. Missing or malformed settings cannot establish a match. A verified fix
for this CVE or disabled upload progress excludes the assessed local path.

A single worker's settings cannot establish how every participant reads and writes
a shared session store. When upload progress is enabled, check that all participants
use the same serializer, including on patched releases. Disabling upload progress
excludes the assessed worker as an upload-progress writer. Check other writers separately.
The original pair's October fix does not clear the follow-up.

## React2Shell

Accepted products are `npm:react-server-dom-webpack`,
`npm:react-server-dom-turbopack` and `npm:react-server-dom-parcel`.
`npm:react` and `npm:react-dom` do not identify an affected RSC server package.

The [React advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
identifies exactly 19.0.0, 19.1.0, 19.1.1 and 19.2.0 as affected by
CVE-2025-55182. Its original fixes are 19.0.1, 19.1.2 and 19.2.1. Fixed and
later stable releases within these three branches are excluded for this CVE;
unlisted branches and custom/prerelease builds are inconclusive. Later React
CVEs require their own assessment. Conflicting supplied package aliases,
version aliases, unknown provenance or unspecified nonempty `applied_hotfixes`
remain inconclusive without a matching verified fix.

## Brotli / Node2Shell

All rows below assess CVE-2026-111497, including the existing Envoy assessment.
Native `Google Brotli` and exact upstream alias `Brotli` records describe the
decoder actually loaded by an application across ecosystems. Runtime and
Python package records establish only their published bundled decoder versions;
they do not independently prove what an application loaded. No .NET or other
wrapper bounds are inferred from their unrelated version numbers.

| Product | Verified boundaries |
| --- | --- |
| `Node.js` | Official branches 22, 24 and 26 fixed at 22.23.4, 24.22.1 and 26.12.1 respectively. Other branches are inconclusive. |
| `Bun` | 1.x fixed at 1.4.4. Other major branches are inconclusive. Rebuild executables produced by `bun build --compile`; upgrading host Bun does not replace their embedded runtime. |
| `Google Brotli`, `Brotli`, `pypi:brotli` | Native/Python Brotli affected ranges `[1.0.3,1.0.10)`, `[1.1.0,1.1.1)` and `[1.2.0,1.2.1)`. No bounds are inferred for other branches. |
| `pypi:brotlicffi` | Exact releases 1.0.9.0, 1.0.9.1, 1.0.9.2 and 1.1.0.0 bundle affected native versions; 1.2.0.x bundles affected 1.2.0. Fixed at 1.2.1.0 within 1.2.x. Other older wrapper releases are inconclusive. |
| `Envoy` | Existing effective decompressor configuration and explicitly verified affected releases 1.39.2, 1.38.5, 1.37.7 and 1.36.11 remain unchanged. Matching verified backport evidence can clear this CVE. |

For Bun compiled deployments, inventory must describe the embedded runtime in
the deployed executable and its decoder. A build host's installed Bun version
does not establish that binary's patch state.

The brotlicffi [v1.0.9.1](https://github.com/python-hyper/brotlicffi/tree/v1.0.9.1)
and [v1.0.9.2](https://github.com/python-hyper/brotlicffi/tree/v1.0.9.2)
tag trees pin `libbrotli` to
[`e61745a6b7add50d380cfd7d3883dd6c62fc2c71`](https://github.com/google/brotli/commit/e61745a6b7add50d380cfd7d3883dd6c62fc2c71),
the upstream Brotli 1.0.9 commit also used by v1.0.9.0. These three exact
wrapper releases are verified; arbitrary 1.0.9.x releases are not inferred.

Fixed official Node.js **26.12.1 still reports Brotli 1.2.0**. The decoder's
unmodified version string must not override the vendor's patched runtime
release. Distributor/custom builds require specific verified fix evidence;
an upstream-looking release alone does not establish the deployed patch state.

Boundary sources: [Node.js security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases),
[Google CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/111xxx/CVE-2026-111497.json),
[Brotli releases](https://github.com/google/brotli/releases),
[Bun 1.4.4](https://bun.com/blog/bun-v1.4.4),
[brotlicffi history](https://github.com/python-hyper/brotlicffi/blob/main/HISTORY.rst),
and [Envoy advisory](https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr).
The normalized npm/PyPI metadata snapshots in
[`tests/fixtures/shell_runtime_packages.json`](../tests/fixtures/shell_runtime_packages.json)
retain their source URLs and independently exercise genuine package identities
and affected/fixed boundaries.
