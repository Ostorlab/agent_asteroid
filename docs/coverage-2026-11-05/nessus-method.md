# Nessus 2026 detection inventory

Snapshot retrieved 2026-11-05 UTC. Asteroid baseline: `571a9bc` in `/tmp/asteroid-2026-coverage`, runtime registry supplied by the parent investigator. No target scanning, code changes, or PRs were performed by this research task.

## Result and scope

The complete public **Nessus** catalogue slice contains **88,395 distinct plugin IDs** whose `plugin_publication_date` is 2026-01-01 through 2026-11-05 inclusive: 86,871 Local, 991 Combined, 530 Remote, and 3 Summary. These reference 57,477 distinct CVE IDs. Every partition's reported total equals its downloaded row count and unique plugin count. The newest returned publication date is November 4; the November 5 query returned Tenable's empty-result 404 response. This is exhaustive for that public catalogue slice at retrieval time, not a claim about unpublished/private detections or later publications on November 5.

The date belongs to a **plugin ID's first publication**, not the CVE disclosure date, CVE year, plugin modification date, or first-ever Nessus coverage of that CVE. An older CVE may correctly appear because a new detector was published in 2026. For example, CVE-2025-49844 has a 2026 Redis plugin and earlier Nessus detections. Historical exclusions were deliberately not applied after the user's date clarification.

Network qualification remains an evidence classification, not a claim that every listed CVE is exploitable against an arbitrary remotely reachable system:

- 50,520 plugins advertise an AV:N vector in CVSS v3 or v4, referencing 41,609 distinct CVEs.
- 41,545 of those CVEs are absent from registered Asteroid metadata.
- 13,951 missing CVEs have at least one **single-CVE plugin** whose preferred available CVSS version has AV:N.
- 27,387 missing CVEs occur only in network-scored bundles; the network score may belong to another CVE in that bundle.
- 207 missing CVEs have single-CVE network evidence in an older CVSS version but the newer version disagrees.
- Restricting to Remote or Combined detection methods gives 3,858 missing network candidates, of which 902 have single-CVE preferred-vector network evidence.

A Local detector can detect a remotely exploitable vulnerability. Remote/Combined detector types do not themselves establish remote exploitation. AV:N also does not establish no authentication, no user interaction, or a safe active proof. CVSS v4 takes precedence over v3, then v2 for the preferred-vector field. All original vectors are retained. Plugin descriptions and vendor advisories must be consulted for prerequisites, affected releases and applicability before implementing individual checks.

Asteroid comparison uses runtime **registered** detector `cve_ids` and CVEs extracted from `metadata.reference`, not arbitrary text matches, filenames, offline helper modules, or advisory links. There are 177 registered detectors and **213 distinct valid CVE IDs**. A compound reference (`CVE-2025-48827, CVE-2025-48828`) and a non-CVE Jetpack reference must not inflate the distinct-CVE count. 65 of the full catalogue's CVEs are registered; 64 of the network-candidate CVEs are registered.

## Files

The repository ships the compact exports below. The other named files are local-only research artifacts; they are not required to use the committed tables.

- [nessus-remote-combined-candidates.csv](nessus-remote-combined-candidates.csv): Remote/Combined missing candidates, exported from local-only `missing-remote-combined-network.csv`.
- [nessus-all-types-candidates.csv](nessus-all-types-candidates.csv): broader inventory candidates, exported from local-only `missing-all-types-candidates-compact.csv`.
- [nessus-pagination.json](nessus-pagination.json): exact partition counts, copied from local-only `all-manifest.json`.
- [asteroid-registry.json](asteroid-registry.json): runtime registration baseline.
- [summary.json](summary.json) and [manifest.json](manifest.json): consolidated audit counts and committed-file hashes; these are distinct from local-only source-specific files with the same names.
- Local-only: `cves.csv`, `cves.jsonl`, `missing-network-candidates.jsonl`, `missing-single-cve-network.jsonl`, source-specific `summary.json`, source-specific `manifest.json`, and `SHA256SUMS` retain full cross-references and source checks.
- Local-only: `collect_all.py`, `collect.py`, and `analyze.py` are the original collection/normalization scripts.
- Local-only: `nessus-all-2026.json`, `nessus-remote-combined-2026.json`, `priority-candidates.json`, `plugins.csv`, and `raw/` contain provider descriptions/solutions and are not published in bulk.

## Collection method

Primary catalogue API: https://www.tenable.com/plugins/api/v1/search

The supported filter is `plugin_type:remote`, not `type:remote`. Restrict the product using `sensor:nessus`. Full collection query:

```
sensor:nessus AND plugin_publication_date:[2026-01-01 TO 2026-11-05]
```

Date partitions begin as nonoverlapping seven-day inclusive intervals. Tenable caps the reported total at 10,000, so a partition at that cap is recursively bisected; October 1–7 required this. `size=1000` is supported, but **page offsets remain fixed at 50 rows** regardless of requested size: use `page=1,21,41,...` for consecutive 1,000-row batches. Exact downloaded counts and deduplication caught this API behavior before the final export. `collect_all.py` checks each partition and the global result for missing/duplicate IDs.

The original collection scripts and their task-specific paths are local-only; they are not an executable reproduction entry point in this PR. To collect a fresh snapshot, use the public API endpoint and filter above, split the date range as described, and reconcile each page/partition's count against [nessus-pagination.json](nessus-pagination.json). The committed tables are immutable evidence from this dated collection, not a live feed.

The direct public API and public plugin pages were cross-checked for priority examples. No authentication or license-protected feed was used. There is no unresolved pagination or access blocker for the catalogue slice. The unresolved work is **per-CVE applicability and exploitation classification**, especially 27,387 missing CVEs seen only through network-scored bundles; it would be inaccurate to call these 41,545 confirmed remotely exploitable gaps.

## Actionable examples for implementation review

These all lack a registered CVE mapping at the baseline. Each needs primary vendor verification and a read-only product/version or configuration evidence design before implementation.

| CVE(s) | Plugin / first publication | Affected releases and prerequisite |
|---|---|---|
| CVE-2026-72898, CVE-2026-72899, CVE-2026-72900 | [334690](https://www.tenable.com/plugins/nessus/334690), 2026-08-12 | Metabase 0.x/1.x branches 58–63; fixes .58.24, .59.21, .60.17, .61.11, .62.9, .63.5. Different endpoints and privilege prerequisites apply per CVE. |
| CVE-2026-48558 | [333310](https://www.tenable.com/plugins/nessus/333310), 2026-08-07 | SimpleHelp 5.5 before 5.5.16 and 6.0 prereleases before RC2; requires OIDC configuration. |
| CVE-2026-1731 | [298511](https://www.tenable.com/plugins/nessus/298511), 2026-02-10 | BeyondTrust PRA through 24.3.4; upgrade to 25.1.1. Separate RS plugin 298510 covers RS before 25.3.2. |
| CVE-2026-102764 | [367772](https://www.tenable.com/plugins/nessus/367772), 2026-10-20 | BeyondTrust RS through 26.2.3; apply BT26-05-RS patch. Versions alone cannot establish patch absence. |
| CVE-2026-42945 | [316773](https://www.tenable.com/plugins/nessus/316773), 2026-05-26 | nginx 0.6.27 before 1.30.1; vulnerable rewrite configuration required; code execution additionally depends on ASLR conditions. |
| CVE-2026-34197 | [305955](https://www.tenable.com/plugins/nessus/305955), 2026-04-10 | ActiveMQ Classic before 5.19.4 or 6.x before 6.2.3; authenticated Jolokia exposure. |
| CVE-2026-15409, CVE-2026-15410 | [327020](https://www.tenable.com/plugins/nessus/327020), 2026-07-15 | SonicWall SMA1000 through 12.4.3-03434 / 12.5.0-02800. SSRF and administrator code-injection prerequisites differ. |
| CVE-2026-83548, CVE-2026-83549 | [342663](https://www.tenable.com/plugins/nessus/342663), 2026-09-03 | SonicWall SMA1000 through 12.4.3-03453 / 12.5.0-02835; fixes 12.4.3-03526 / 12.5.0-02952. |
| CVE-2026-59310 | [337680](https://www.tenable.com/plugins/nessus/337680), 2026-08-18 | vCenter 8.0, 9.0, 9.1 affected branches; fixes include 8.0 U3k/U2f, 9.0.2.0100, 9.1.0.0300. Syslog reachability is relevant. |

For full affected-version evidence and advisory links see each public plugin URL and local `priority-candidates.json`. Raw titles/version summaries can be stale, incomplete for backports, or superseded; individual implementation review must resolve this.
