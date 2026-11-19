# Java4Shell: fresh remote hints and trusted JVM inventory

Asteroid assesses CVE-2026-114938 through anonymous management metadata and
owner-supplied offline inventory. Both report potential exposure without
sending malformed Base64 or proving exploitability. Inventory covers protected
management endpoints and the exact Oracle Java SE performance build that the
remote detector cannot identify reliably.

The existing remote response shapes, request/response bounds and finding
identity are retained. Positive and negative observations expire after five
seconds measured with a monotonic clock, starting when the probe completes.
`accept()` and `check()` reuse fresh evidence, including negative results.
Concurrent callers share one probe per target; the cache holds at most 64
targets. A later scan refreshes expired evidence. An absent remote finding does
not establish a fixed runtime.

## Primary evidence and product limits

[Calif's disclosure](https://calif.io/java4shell) identifies the x86-64 Base64
intrinsic path, all four required CPU features, its application-specific
prerequisites and the preferred `-XX:-UseBASE64Intrinsics` workaround.
[Red Hat's advisory](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018)
and the [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
provide the JVM release context. Oracle's
[November CSPU](https://www.oracle.com/security-alerts/cspunov2026.html) and
[Oracle CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/114xxx/CVE-2026-114938.json)
identify separate Oracle products and affected builds; their product identities
must stay separate.

| Exact `product` | Inventory version interpretation |
| --- | --- |
| `OpenJDK` | Published affected intervals: `[17.0.6,17.0.21.1)`, `[21.0.0,21.0.13.1)`, `[25.0.0,25.0.5.1)`, `[27.0.0,27.0.1.1)`. Earlier/fixed releases within these branches are `not_matched`. Unambiguous standard Java 8 and Java 11 exclude this intrinsic. |
| `Oracle Java SE` | Same JVM intervals, including the CNA's `17.0.21.0.3`, `21.0.13.0.3`, `25.0.5.0.3`, `27.0.1.0.3`. Exact `8u511b33-perf` is affected; generic Oracle Java 8 identifiers are inconclusive because they do not distinguish the performance build. Canonical Java 11 excludes this intrinsic. |
| `Oracle GraalVM for JDK` | Only the documented Java 17/21 lines are assessed, with their JVM intervals and Oracle five-component builds. Java 25/27 and all other unlisted branches remain inconclusive. |
| `Oracle GraalVM Enterprise Edition` | Exact release `21.3.20.0.3` matches. `21.3.20.1` and later fourth-component updates within `21.3.20` exclude this CVE. Other identifiers/branches remain inconclusive. |

Java 18–20, 22–24, 26 and future JVM branches are inconclusive. No fixed point
is inferred for an unlisted branch. The GraalVM EE `21.3` line never matches an
OpenJDK, Oracle Java SE or GraalVM for JDK record. Five-component Oracle
identifiers do not match `OpenJDK`.

## Exact normalized schema

Supply a JSON array to `python -m agent.utils.inventory inventory.json`.
The CLI collects no runtime commands, authenticates no inventory and contacts
no target. Evidence must describe the same deployed runtime and all relevant
workers, containers and replicas. Results contain only `cve_ids`, `status`,
`reason` and `recommendation`; arbitrary input fields are not echoed.

| Field | Accepted type and meaning |
| --- | --- |
| `product` | Required exact case-sensitive string from the table above. Aliases such as `Java`, `GraalVM` and `openjdk` are unsupported. |
| `version` | Canonical numeric release with 3, 4 or (Oracle only) 5 components. Each component is 0–999 with no leading zeroes. Optional suffixes are `+` followed by a positive numeric build (1–6 digits, no leading zero), `-LTS`, or both in that order. Arbitrary vendor text, whitespace, custom/prerelease/early-access suffixes and incomplete versions are inconclusive. Only the validated numeric release is passed to shared JVM range helpers. The fifth Oracle component does not change the fourth-component fixed boundary. |
| `version` for Java 8 | Standard OpenJDK accepts canonical `8.0.N`, `1.8.0_N` or `8uN`, with optional `-bN` on the latter two forms; update/build numbers are positive, without leading zeroes. Oracle Java SE requires exact `8u511b33-perf` to identify the affected performance build. Generic Oracle Java 8 versions remain inconclusive. |
| `verified_fixed_cves` | Optional JSON list of canonical `CVE-YYYY-NNNN...` strings verified by the owner in the running binary. Missing/empty means no verified fix. A matching `CVE-2026-114938` excludes only this CVE; other IDs do not clear it. Malformed lists are inconclusive. |
| `build_provenance` | Optional exact `upstream_release`. Any other supplied value requires a matching verified fix or a known absent path. Omission does not prove a verified upstream binary or absence of vendor backports. |
| `architecture` | Optional nonempty string, normalized with whitespace trimming and lowercase. `x86_64` / `amd64` identify the relevant architecture. Known alternatives `arm64`, `aarch64`, `arm`, `armv7l`, `x86`, `i386`, `i686`, `ppc64`, `ppc64le`, `s390x`, `riscv64` exclude the described x86-64 intrinsic path. Other strings are inconclusive unless independent fix/path evidence already excludes it. |
| `cpu_flags` | Optional JSON list of lowercase `[a-z0-9_]+` feature strings from the actual running hardware. The required set is `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`. A missing feature excludes the path only with `cpu_flags_complete: true`. An absent/partial list cannot establish that a feature is unavailable. |
| `cpu_flags_complete` | Optional boolean asserting that `cpu_flags` contains the complete effective set. `true` requires a supplied valid list. An empty complete list excludes the path; an empty partial list does not. |
| `use_base64_intrinsics` | Optional effective boolean. `false` excludes the intrinsic path. |
| `use_avx` | Optional effective nonnegative integer. `0`, `1`, `2` exclude the AVX-512 path. Other nonnegative values do not clear it. Booleans, strings, floats, negative numbers and `null` are malformed. |
| `untrusted_base64_reachable` | Optional effective boolean. `false` excludes the described untrusted-decoding path only. |

Optional booleans must be JSON booleans; strings, numbers and `null` are
malformed. Missing prerequisites stay unknown. Unrecognized fields are ignored;
a momentary lack of C2 compilation is never treated as permanent protection.

## Decision order and interpretation

1. Require an exact supported product identity.
2. Validate the fix list and every supplied hardware/configuration field before
   considering exclusions. Malformed configuration stays inconclusive even
   alongside a matching fix or a disabled intrinsic.
3. Honor a matching owner-verified per-CVE fix.
4. Honor a known absent path: disabled intrinsic, excluded untrusted input,
   known non-x86-64 architecture, effective `UseAVX <= 2`, or a complete CPU
   feature set missing at least one prerequisite.
5. Reject explicit unknown/custom build provenance and unknown architecture
   before applying the strict product-specific version matrix.
6. An affected release without an exclusion is `potential_exposure`; fixed or
   documented unaffected releases are `not_matched`; unverified identifiers and
   branches are `inconclusive`.

`not_matched` applies only to this CVE and the described path or fix. An affected
release remains a potential exposure even when every supplied prerequisite is
present: inventory does not establish C2 state, heap grooming, the running
binary or exploitability. Missing evidence remains explicitly unverified.

```json
[
  {
    "product": "Oracle Java SE",
    "version": "8u511b33-perf",
    "architecture": "amd64",
    "cpu_flags": ["avx512f", "avx512bw", "avx512vbmi", "bmi2"],
    "cpu_flags_complete": true,
    "use_base64_intrinsics": true,
    "use_avx": 3,
    "untrusted_base64_reachable": true
  },
  {
    "product": "OpenJDK",
    "version": "21.0.13",
    "build_provenance": "custom",
    "verified_fixed_cves": ["CVE-2026-114938"]
  }
]
```

These yield `potential_exposure` and `not_matched`, respectively. Upgrade to
the vendor's fixed build and restart every running JVM/worker. If patching must
wait, prefer `-XX:-UseBASE64Intrinsics`. `-XX:UseAVX=2` is an x86-only alternative;
it must not be applied on ARM64. Verify effective flags and patch state in each
running process.

Public-interface tests cover cache freshness/expiry, negative caching,
singleflight, bounded eviction, exception cleanup, request deadlines, product
and release boundaries, hardware/configuration validation, selective verified
fixes, inventory dispatch and the CLI. See the
[remote detector contract](java4shell-2026-114938.md) for endpoint details and
its prior loopback/real-Solr validation.
