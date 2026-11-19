# Native Ruby regexp compilation assessments

Trusted offline `Ruby` records receive three independent native CRuby/Onigmo
assessments. The [Ruby security announcement](https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/)
and official ruby/ruby security advisory API records were checked on
18 November 2026. All three Ruby advisories still have `cve_id: null`.
The four related GitLab CVEs retain their existing GitLab product assessments;
their product release bounds and identifiers are not reused for Ruby runtimes.

| Ruby advisory | Upstream bug | Affected Ruby releases | First fixed releases | Related GitLab CVEs |
| --- | --- | --- | --- | --- |
| [GHSA-gfj3-8wj9-qx8p](https://github.com/ruby/ruby/security/advisories/GHSA-gfj3-8wj9-qx8p) | Double free after a failed pattern parse | `<=3.3.12`; `3.4.0`–`3.4.11` | `3.3.13`, `3.4.12`, `4.0.0` | CVE-2026-89078 |
| [GHSA-22mf-ggw7-pxfx](https://github.com/ruby/ruby/security/advisories/GHSA-22mf-ggw7-pxfx) | Compiled-pattern size overflow | `<=3.3.12`; `3.4.0`–`3.4.11`; `4.0.0`–`4.0.7` | `3.3.13`, `3.4.12`, `4.0.8` | CVE-2026-93577, CVE-2026-97229 |
| [GHSA-qm4g-8pfh-6996](https://github.com/ruby/ruby/security/advisories/GHSA-qm4g-8pfh-6996) | Internal-ID overflow with many repeats | `<=3.3.12`; `3.4.0`–`3.4.11`; `4.0.0`–`4.0.8` | `3.3.13`, `3.4.12`, `4.0.9` | CVE-2026-110264 |

The explicit `<=3.3.12` range includes EOL releases such as Ruby 2.7.8 and
3.2.x. Fixed and later canonical releases within 3.3, 3.4 and 4.0 are excluded
per advisory. Unlisted branches such as 3.5 or 4.1 remain `inconclusive`.
Ruby 4.0.8 is fixed for the first two advisories and still potentially exposed
for the internal-ID overflow. Ruby 4.0.9 contains all three fixes.

## Trusted evidence schema

Collect evidence for the same deployed runtime and effective application path.
Run `python -m agent.utils.inventory inventory.json` with a normalized array:

```json
[
  {
    "product": "Ruby",
    "version": "4.0.8",
    "ruby_engine": "ruby",
    "build_provenance": "upstream_release",
    "compiles_untrusted_regex": true,
    "verified_fixed_advisories": []
  }
]
```

| Field | Interpretation |
| --- | --- |
| `product` | Exact `Ruby` identity. |
| `ruby_engine` | Required native engine evidence: actual `RUBY_ENGINE` value `ruby`, or normalized alias `CRuby`. Missing, unknown, JRuby and TruffleRuby engines are inconclusive. A Ruby language compatibility version alone does not identify the native engine. |
| `version` | Exact canonical three-component release, without prefixes, padding, custom suffixes or prerelease markers. Noncanonical versions require manual verification or a matching verified advisory fix. |
| `compiles_untrusted_regex` | Optional effective boolean covering all attacker-controlled compilation paths. `false` excludes this described compilation path only; omitted or `true` leaves affected-version exposure potential. Non-boolean values are inconclusive. |
| `verified_fixed_advisories` | Optional list of canonical `GHSA-xxxx-xxxx-xxxx` identifiers whose specific fixes the owner verified in the deployed build. Missing or empty means no fix assertion. A matching entry excludes only that advisory; malformed lists are inconclusive. GitLab CVE IDs in `verified_fixed_cves` do not establish Ruby fixes. |
| `build_provenance` | Shared runtime schema: optional `upstream_release`; other supplied values require a matching per-advisory verified fix for a version verdict. Omission does not prove binary provenance. |

Native engine validation is required for every Ruby verdict. Malformed fix or
reachability evidence is inconclusive before applying fix/path exclusions.
Specific verified fixes may identify patched custom or distributor builds;
other advisories retain their own uncertainty. A fix assertion must cover the
actual running workers, rather than an available update or build host.

Each Ruby result has `cve_ids: []` and one `advisory_ids: ["GHSA-..."]`.
Recognized Ruby records retain those advisory identities when inconclusive.
Existing results with no advisory identity retain the original four JSON keys:
`cve_ids`, `status`, `reason`, and `recommendation`. The CLI emits only these
assessment fields and never echoes arbitrary records or secrets. The three
GHSA assessments are counted separately from CVE coverage totals.

## Reachability and limits

These bugs occur while compiling attacker-controlled pattern strings, including
`Regexp.new`, `Regexp.compile`, `Regexp.union` and regexp interpolation.
Applications using only developer-written patterns exclude this specific path.
`Regexp.timeout` and pattern-length limits do not protect against the described
compilation bugs. No supplied pattern is compiled, no target code is run and no
network request or exploitation probe is made by these assessors.

Affected versions yield `potential_exposure`, with backports, binary patch state,
reachability and exploitability unconfirmed. The CLI does not collect,
authenticate or independently verify owner evidence. `not_matched` applies only
to the advisory and supplied fix/path evidence, never overall product safety.
