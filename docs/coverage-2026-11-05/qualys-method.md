# Qualys 2026 public detection inventory

Snapshot date: 2026-11-05. Scope requested: detection first published 2026-01-01 through 2026-11-05 and absent from registered Ostorlab/agent_asteroid coverage. This deliverable is a sourced candidate inventory, not a completed list of every remotely exploitable Qualys vulnerability.

## Results and files

The repository ships [qualys-public-qids.csv](qualys-public-qids.csv), [qualys-source-manifest.json](qualys-source-manifest.json), and the consolidated tables. The filenames below refer to local-only research artifacts unless a committed equivalent is linked.

- `qualys_qids_2026.json`: 2,757 unique QIDs extracted from the January–October 2026 Qualys WAS/Application Security monthly publication tables. It preserves QID, official title, CVEs, release-month evidence, URLs, source-capture filenames/line references, missing/covered CVEs and explicit uncertainty fields.
- `missing_cves_candidates.json`: 2,768 distinct CVEs with no match in the supplied Asteroid runtime registry; each retains its Qualys QID/month/source mappings. These have not all been verified as remotely exploitable.
- `priority_product_candidates.json`: grouped subsets for further research, with the same evidence and uncertainty fields. Grouping does not imply implementation feasibility.
- `asteroid_runtime_registry.json`: actual imported registry supplied by the parent task, containing 177 detectors and 213 distinct CVE IDs. Runtime registry matching supersedes the earlier static AST extraction file `asteroid_registered_cves.json`.
- `summary.json`: counts, full Asteroid commit SHA, caveats, and per-month source-line completeness.
- `source_manifest.json`: byte counts and SHA-256 hashes of all saved web-tool text captures. `sources/*.web.txt` preserves public-source text, including failed October/November docs URL responses. `source_fetches.json` records direct HTTP requests that returned 403 and were replaced by successful web-tool retrieval.

All 3,047 source lines across the ten successful monthly pages were recovered by merging overlapping web-tool windows. The recovered QID counts are:

| Month | QIDs recovered |
| --- | ---: |
| January | 104 |
| February | 143 |
| March | 120 |
| April | 211 |
| May | 177 |
| June | 248 |
| July | 319 |
| August | 399 |
| September | 448 |
| October | 588 |

No QID repeated between these ten monthly tables and no conflicting QID titles were observed. Source-line coverage measures retrieval completeness for these particular pages, not catalogue completeness.

## Primary sources and publication-date handling

January–September follow `https://docs.qualys.com/en/tas/release-notes/was_detections/{month}_2026.htm`. October is https://notifications.qualys.com/notifications/2026/10/30/application-security-detections-published-in-october-2026 . The October docs URL was unavailable through the web tool; the official October 30 notification was retrieved instead. No November monthly release table was available as of the task date.

These official pages describe QIDs published/released in a named month. That month is stored as `first_published_month_claimed`; exact publication datetime remains null. Document “Last updated” timestamps and the year embedded in a CVE identifier are never substituted for detection publication dates. The October notification's article date establishes a latest availability date for its listed table, not each QID's exact publication date. The inventory's `release_window_end` is a coarse month boundary rather than an asserted publication date.

The tables are evidence of Qualys's release-month claim; the KnowledgeBase PUBLISHED_DATETIME was not obtained, and pre-2026 archives were not independently searched to rule out re-publication or documentation mistakes. Accordingly all entries remain candidates for the user's exact first-publication criterion. Older CVEs first appearing in these 2026 tables are retained.

## Extraction and coverage comparison

For each monthly page, merge captured lines by their `L<number>:` indexes and assert that every source line from zero to Total lines minus one is present. Extract table rows matching `^L\d+:\s*(\d{5,7})\s*\|\s*(.+)` (or the corresponding pattern after removing line prefixes), then extract case-sensitive CVE tokens matching `CVE-\d{4}-\d{4,}`. Deduplicate QIDs and CVE tokens. Tables with multiple CVEs per QID retain all tokens; QIDs without CVE tokens remain in the main inventory for manual mapping. There are 111 such QIDs.

Compare normalized CVE strings only to `cve_ids` in the actual imported Asteroid registry; search hits in documentation, tests or filenames are not accepted as registration. There are 2,629 QIDs containing at least one missing CVE. Product labels are heuristics for navigation; the official title is authoritative. A metadata match establishes registered detector coverage only. Existing detectors may check versions and explicitly report potential exposure rather than demonstrate exploitation.

## Remote exploitability remains unverified

A remote discovery method does not establish remote exploitability. This extraction never equates Qualys Remote discovery with CVSS AV:N, never treats every WAS QID as remotely exploitable, and never excludes authenticated remote issues merely because authentication is required.

The title classifier only flags explicit “remote code execution”, “remote command execution”, or “unauthenticated” language; 178 missing-CVE QIDs have such title language. That is a prioritization signal, not a verified final inclusion. Other issues, including SQL injection, SSRF, path traversal, XSS and authenticated command injection, can also be remote, but need vendor/CNA evidence. CVSS attack vector, required privileges, user interaction, affected configurations, patch ranges and feasible read-only detection must be reviewed before an implementation or final remote-exploitability claim. Informational and end-of-life titles are retained with a separate provisional category rather than silently lost.

## Catalogue limitations and how to close them

The monthly tables cover Application Security/WAS. They are not an export of the entire Qualys VMDR KnowledgeBase. Qualys says its public security-alerts page is a sample (https://www.qualys.com/research/security-alerts), and its public detection pipeline covers only QIDs added in the past 14 days (https://www.qualys.com/vulnerability-detection-pipeline). No authenticated Qualys account/session/export was available to this research subtask. No credential files were searched. November 1–5 detections and VMDR-only detections remain unenumerated.

The authoritative complete-source route is an authorized KnowledgeBase export using the current documented endpoint `/api/4.0/fo/knowledge_base/vuln/` with `action=list`, `details=All`, `published_after=2025-12-31T23:59:59Z`, and `published_before=2026-11-06T00:00:00Z`, then exact filtering on `PUBLISHED_DATETIME` to the requested interval. See https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-scan/kbase/knowledgebase.htm and https://blog.qualys.com/product-tech/2021/03/02/qualys-api-best-practices-knowledgebase-api . Do not initially filter `discovery_method=Remote`: locally authenticated detection may cover a remotely exploitable flaw. Preserve the original XML and hash it; extract CVEs and exploitability evidence, and compare with the runtime registry.

No production scans, exploit attempts, repository changes or PRs were performed by this research subtask.
