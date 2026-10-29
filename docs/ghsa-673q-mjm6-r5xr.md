# Next.js use-cache RCE: owner-inventory assessment

Verified on 2026-10-29. This coverage is an **offline applicability assessment**,
not a remote exploit detector. It is dispatched by `python -m
agent.utils.inventory inventory.json`, separately from the remote exploit
registry and `custom_cve_list`.

## Verified sources and detection decision

- The [Ostorlab starting article](https://blog.ostorlab.co/ghsa-673q-mjm6-r5xr-nextjs-use-cache-rce.html)
  was used to locate primary sources, not as the authority for applicability.
- The [Next.js vendor advisory](https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr)
  identifies stable `next` releases **16.0.0 through 16.4.0 inclusive**, fixed in
  **16.4.1**. It requires App Router, Cache Components, and a `use cache`
  function returning multiple typed arrays. Its CVSS is **4.0 / 9.5**, with
  attack requirements present. No CVE is assigned. There is no known workaround;
  the vendor recommends upgrading even without such functions.
- The [React advisory](https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3)
  additionally specifies multiple typed arrays and attacker-controlled data in
  the transported response. This assessment requires that data-flow evidence,
  plus owner verification that the particular function is reachable without
  authentication. These checks conservatively qualify the unauthenticated path.
- [Next.js patch a4cea6a](https://github.com/vercel/next.js/commit/a4cea6aec5da89d116b8960e113189cf51745d2f)
  updates bundled RSC implementations: typed-array buffer handling, separation
  of backing entries, server-reference validation, and thenable handling.
  Its 52-file diff contains no regression tests. The
  [16.4.1 release](https://github.com/vercel/next.js/releases/tag/v16.4.1)
  explicitly lists this advisory as fixed.
- Inspected upstream [React transport tests at 16a1d5d](https://github.com/react/react/blob/16a1d5d780b9cbbe2e1ac5f3dc6db8df6e7983ec/packages/react-server-dom-webpack/src/__tests__/ReactFlightDOMNode-test.js#L2727)
  cover full-buffer consumption, partial views, promised subarrays sharing a
  buffer, repeated buffer-spanning views, and resizable buffers. These are
  transport regressions, not a verified exploit reproduction for this GHSA.
  They were reviewed, not executed. Their sizes and buffer-sharing arrangements
  are not treated as additional necessary vulnerability conditions.

None of these sources establishes a safe, application-independent HTTP oracle.
Product headers, RSC content types, an enabled feature, or a package version do
not establish exploitability. Sending crafted Flight payloads would also violate
this task's probe constraints. The implementation therefore reuses the existing
owner-inventory result type and release parser; it sends no requests and executes
no application code.

## Evidence contract

Supply an array of records, one per reviewed function path. For example:

```json
[
  {
    "product": "Next.js",
    "version": "16.4.0",
    "app_router_enabled": true,
    "cache_components_enabled": true,
    "use_cache_function": {
      "returned_typed_array_count": 2,
      "attacker_controlled_value_in_same_response": true,
      "unauthenticated_reachable": true
    }
  }
]
```

This is an Asteroid schema, not a Next.js API response. The owner must collect
and verify evidence for the **same deployed build and function path**:

| Field | Required owner evidence |
| --- | --- |
| `product`, `version` | Actual deployed `next` package identity and resolved release, not a dependency range or a fingerprint header. |
| `app_router_enabled` | The reviewed route uses the App Router; an unrelated `app/` directory is insufficient. |
| `cache_components_enabled` | Effective deployed configuration, not a commented setting or a development-only config. |
| `use_cache_function` | A reviewed server function with the active `use cache` directive in this build and path. |
| `returned_typed_array_count` | Nonnegative integer count of distinct typed-array values in one return from that function. Include nested values; do not count array elements, ordinary arrays, repeated references to one view, or aggregate across separate functions or calls. |
| `attacker_controlled_value_in_same_response` | Data-flow review establishes attacker-controlled data in the same transported response as those typed arrays. Unrelated request input does not qualify. |
| `unauthenticated_reachable` | Route and authorization review establish that an unauthenticated caller can reach this function path. |

Use actual JSON booleans. Missing or uncertain observations must be omitted or
set to `null`, not guessed as `false`. Keep evidence provenance in the owner's
inventory system; the CLI does not authenticate assertions or read source files,
lockfiles, config files, or live targets on their behalf. No supplied source code,
URLs, credentials, or arbitrary record fields are echoed into assessment output.

## Result semantics

- `potential_exposure`: affected canonical stable release and all path
  prerequisites supplied. Exploitability remains unconfirmed.
- `inconclusive`: version or required evidence is missing, malformed, or
  ambiguous. Prerelease, canary, custom, and build-metadata versions are not
  guessed into the stable range. A version alone is insufficient.
- `not_matched`: the canonical release is outside the published range, or the
  complete supplied path evidence explicitly lacks a prerequisite. This is not
  a whole-application safety verdict. An assessment of one function does not
  exclude a different vulnerable function. Upgrade guidance remains present.

For compatibility, the existing result field `cve_ids` carries
`GHSA-673q-mjm6-r5xr`; this does **not** assign a CVE. The only shared dispatch
change is the `Next.js` entry in `agent/utils/inventory.py`.

## Implementation and validation scope

The implementation sequence is: establish existing inventory baseline; add
failing dispatch/applicability tests; implement bounded prerequisite checks;
verify CLI output, regression behavior, format, lint, and typing; review locally
and commit. Tests cover affected boundaries, patched/out-of-range versions,
unknown builds, disabled features, zero/single typed arrays, missing data flow
or reachability, malformed evidence, output sanitization, and no HTTP calls.

No command-execution, crash, authentication, cache mutation, or public target
probe is part of this assessment or its tests. Local assessment fixtures test
the policy; they do not claim to reproduce RCE in a Next.js runtime.

Validation on Python 3.14.6, using `/tmp/asteroid-next-cache-venv/bin` tools:

```sh
python -m pytest -q tests/exploits/ghsa_673q_mjm6_r5xr_test.py \
  tests/utils/inventory_test.py tests/exploits/cve_2026_110264_test.py \
  tests/exploits/cve_2026_114625_test.py tests/exploits/cve_2026_115560_test.py \
  tests/exploits/cve_2026_111497_test.py tests/exploits_registry_test.py
ruff check agent/exploits/ghsa_673q_mjm6_r5xr.py agent/utils/inventory.py \
  tests/exploits/ghsa_673q_mjm6_r5xr_test.py
ruff format --check agent/exploits/ghsa_673q_mjm6_r5xr.py agent/utils/inventory.py \
  tests/exploits/ghsa_673q_mjm6_r5xr_test.py
mypy --follow-imports=silent agent/exploits/ghsa_673q_mjm6_r5xr.py \
  agent/utils/inventory.py tests/exploits/ghsa_673q_mjm6_r5xr_test.py
git diff --check
```

Results: **202 tests passed**, Ruff lint/format passed, scoped mypy passed.
The pre-change baseline passed 27 tests. The new affected-path test first failed
because inventory dispatch did not support Next.js. Initial system-Python test
collection lacked `cloudscraper`; installing the declared requirements in the
task-specific environment resolved it without changing repository dependencies.
Existing third-party deprecation warnings remain. The full repository suite and
a live vulnerable/patched Next.js lab were not run.
