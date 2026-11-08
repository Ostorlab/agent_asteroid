# FTS3 Web Monitoring CVE-2025-71458 unauthenticated `/linkinfo` SQL injection

**CVE-2025-71458** is an unauthenticated SQL injection in FTS3 Web Monitoring
(`cern-fts/fts-monitoring`), the Django monitoring front end for an FTS3
transfer service. The `source_se` and `dest_se` query parameters of
`GET /linkinfo` are interpolated directly into SQL statements.

Releases **3.12.0 through 3.13.2** and **3.14.0** are affected. The EGI SVG
advisory states that blind injection can read stored cloud-storage credentials
and token-provider client secrets (CWE-89; CVSS 3.1 7.5
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`).

The fix in **3.13.3** and **3.14.1** replaces every interpolation with a
driver parameter binding. The shipped `[linkinfo] enabled` switch is a
mitigation, not the fix, and it defaults to true.

Checked 8 November 2026. Baseline `cb27f14` on `main`.

## Sources

- EGI SVG advisory:
  <https://advisories.egi.eu/Advisory-EGI-SVG-2025-09> (published
  2025-06-26, updated 2025-07-30).
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-71458> (published
  2026-11-06; CWE-89, CVSS 3.1 7.5).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-71458>.
- VulnCheck advisory:
  <https://www.vulncheck.com/advisories/fts3-web-monitoring-3.12.0-through-3.13.2-and-3.14.0-sql-injection-via-linkinfo>.
- Vulnerable view at v3.14.0:
  `src/apps/ftsmon/views/linkinfo.py` (`get_linkinfo`).
- Fix commits `e993c27` (3.13.3) and `96241f6` (3.14.1); releases
  <https://github.com/cern-fts/fts-monitoring/releases/tag/v3.13.3> and
  <https://github.com/cern-fts/fts-monitoring/releases/tag/v3.14.1>.

## How does the detector verify the injection?

1. Read the anonymous home page and require the FTS3 markers
   (`ng-app="ftsmon"`, the Overview/Activities and GFAL2 navigation anchors)
   plus a title ending in `FTS3`. Read `/ftsmon/version` when the release
   exposes it; a 3.12.x deployment has no version endpoint.
2. A readable release outside the affected intervals is not probed.
3. Select the path used by the release: `/ftsmon/linkinfo` for 3.13+/3.14,
   `/ftsmon/linkinfo/` for the 3.12.x line (with a fallback to the other).
4. Send four anonymous GETs: `source_se` carries two true boolean payloads
   (`OR 1=1`, `OR 2=2`) and two false ones (`OR 1=2`, `OR 2=3`); `dest_se`
   carries a constant true payload so the view's unconditional
   `t_optimizer_evolution` lookup returns a row and the page renders at all.
5. Read the rendered response: a true expression makes the view render the
   configured storage element (`source.config_type == "specific"`), a false
   one falls back to `"generic"`. The two true and two false answers must
   agree, and `dest_se` must stay `"specific"`.
6. Requiring both true pairs and both false pairs to agree makes a non-SQL
   lookalike fail closed: it treats all four values as literal storage-element
   names and always falls back to `"generic"`. The check never uses `UNION`,
   stacked statements, time delays, writes or row extraction, and it extracts
   no row contents, credential or client secret: the only signal is whether
   the view renders the storage-element row or the `generic` fallback.
   The advisory's confidentiality impact is therefore not claimed as
   observed.

## What does the detector miss?

- The view indexes `t_optimizer_evolution` unconditionally. An instance whose
  optimization table is empty answers `500` for every probe and is not
  reported, even if the injection is present.
- The endpoint must be reachable without a client certificate. A TLS/mTLS
  gateway that rejects anonymous requests produces no finding.
- A reverse proxy or WAF that blocks the SQL metacharacters produces no
  finding; the evidence is the observed differential, not the deployed
  release.
- A fixed server answers `500` to the parameterised probes because the
  literal optimizer pair has no row. The detector never treats `500` as a
  finding, so a clean result on a fixed server is expected; as with any
  scanner, a missing finding proves nothing about patching — it is not
  evidence the server is fixed.

## How was the detector validated?

Real upstream tags were built with Django 5.2.19 and served on loopback with
a minimal SQLite database containing the `t_se`, `t_file`,
`t_optimizer_evolution`, `t_link_config` and `t_authz_dn` tables. The 3.12.0
fixture needed two fixture-local Django-compatibility edits (`on_delete` on
its foreign keys and `re_path` instead of `url`); the vulnerable
`get_linkinfo` view is unchanged.

An independent stdlib oracle read each fixture's `settings/version.py` and
`views/linkinfo.py`, then exercised the endpoint with its own boolean payloads
(`OR 9=9` / `OR 9=8`). A separate adapter imported the registered Asteroid
detector and called `accept`/`check` with only target scheme/host/port.

`run_cases.py`: **TP 3 / TN 8 / FP 0 / FN 0 / inconclusive 0**

| Case | Kind | Result |
| --- | --- | --- |
| 3.14.0 (real) | vulnerable | TP |
| 3.12.0 (real, slash path, no `/version`) | variant | TP |
| 3.13.2 (real) | vulnerable | TP |
| 3.14.1 (real) | fixed | TN |
| 3.13.3 (real) | fixed | TN |
| 3.14.2 (real, later release) | benign | TN |
| FTS-shaped, version 3.14.0, linkinfo 500 | benign | TN |
| FTS-shaped, linkinfo disabled (`[]`) | benign | TN |
| FTS-shaped, static generic response | benign | TN |
| non-FTS product with the same `/version` JSON | benign | TN |
| FTS-shaped, WAF 403 | benign | TN |

These are curated fixtures, not a production false-positive rate.

## Run the detector

```shell
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2025-71458"]' link --url https://fts3.example.org
```

The probe payloads are limited to the anonymous boolean expressions in
[How does the detector verify the injection?](#how-does-the-detector-verify-the-injection):
no UNION, no writes, and no row contents or credentials are extracted. See the
[README coverage table](../README.md#detected-cves) for the rest of the
Asteroid checks.
