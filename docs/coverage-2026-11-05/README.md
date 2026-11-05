# 2026 scanner publication and Asteroid coverage audit

**6,955 missing-CVE candidates** were recorded across the scanner sources: **1,680** carry CVE-specific network-vector evidence and **5,275** require further classification.

Snapshot: 5 November 2026. This is an incomplete coverage audit and implementation backlog; not every remotely exploitable vulnerability has been enumerated, validated or implemented.

The requested window is detection publication from `2026-01-01T00:00:00Z` through the available snapshot on 5 November. The exclusive upper date filter is `2026-11-06T00:00:00Z`. CVE year and last modification date are not publication-date substitutes. Older CVEs are retained when a new detector was published in this window. A newly published detector is retained even if another detector covered the same CVE before 2026.

Baseline Asteroid: [`571a9bc8217cd2c9a327d73ef309e3ad70e3784f`](https://github.com/Ostorlab/agent_asteroid/tree/571a9bc8217cd2c9a327d73ef309e3ad70e3784f). Importing its registry produces **177 detector instances and 213 distinct valid CVE identifiers**. Compound references are split; non-CVE references are excluded from the CVE set. The registry snapshot is [asteroid-registry.json](asteroid-registry.json). An identity match establishes registration, not complete coverage of every affected product, deployment, version or exploitation path.

**Existing inventory coverage:** the dispatcher assesses seven CVEs, six of which lack remote registration. All seven are recorded in [asteroid-inventory-assessors.json](asteroid-inventory-assessors.json) and excluded from the consolidated missing list. Product-specific gaps within an already covered CVE still require separate review.

For example, CVE-2026-111497 has both a Node.js remote check and an **Envoy** inventory assessor. The latter is deliberately attributed to Envoy: [the baseline implementation](https://github.com/Ostorlab/agent_asteroid/blob/571a9bc8217cd2c9a327d73ef309e3ad70e3784f/agent/exploits/cve_2026_111497.py#L162) requires an Envoy release and enabled Brotli decompressor, following [Envoy's downstream advisory](https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr). Sharing a CVE does not make the two product assessments interchangeable.

## Audit data files

| File | Contents and use |
| --- | --- |
| [missing-cves.csv](missing-cves.csv) | Deduplicated candidate CVEs absent from both the baseline remote registry and inventory dispatcher, joining Nuclei network/review records, Nessus Remote/Combined network candidates, and public Qualys WAS records. Each row retains publication evidence and classification. `not_implemented` is an explicit backlog status. |
| [nuclei-new-detections.csv](nuclei-new-detections.csv) | New template identities, including exclusions, non-CVE checks and review cases. Includes the first-main-commit URL and the pinned source-snapshot URL. Non-CVE checks require semantic matching against Asteroid; they are not automatically absent. |
| [nessus-remote-combined-candidates.csv](nessus-remote-combined-candidates.csv) | Missing CVEs referenced by in-window Remote/Combined plugins with network-vector evidence somewhere in the relevant plugin records. Single-CVE network evidence is distinguished from a combined unconfirmed category for bundles or vector conflicts; the recorded vectors preserve the conflict evidence. |
| [nessus-all-types-candidates.csv](nessus-all-types-candidates.csv) | Broader candidate list including authenticated Local plugin checks. These additional candidates are not automatically network-assessable Asteroid checks. |
| [qualys-public-qids.csv](qualys-public-qids.csv) | All QIDs recovered from the official January–October WAS/Application Security release tables, including records without CVEs. Publication precision is a month; remote exploitability is unverified. |
| [summary.json](summary.json) | Machine-readable snapshot counts and limitations. |
| [manifest.json](manifest.json) | SHA-256 hashes and byte counts of the data files. |

Do not sum source counts: many vulnerabilities occur in multiple scanners and several plugins can reference the same CVE. Candidate rows are not confirmed vulnerable hosts. Neither a missing finding nor absence of scanner metadata establishes that a target is patched.

## Source selection and evidence

### Nuclei

Source snapshot: [`fef763cd6e1da264eca8668741edef52faa743f6`](https://github.com/projectdiscovery/nuclei-templates/tree/fef763cd6e1da264eca8668741edef52faa743f6). Publication is the first observed addition of a template identity to the default branch's first-parent history, normalized to UTC. Renames/re-additions and prior identities must be reconciled with historical blobs and the pre-2026 baseline rather than treating every new path as a new detection. Records absent from the current tree remain marked as historical, not currently maintained.

The template's declared CVSS network attack vector supplies scanner-level classification. This is not an independent vendor validation of the CVE, template accuracy or actual exploitability. Non-network/local templates and information-only templates are separated. Missing or conflicting vectors, adjacent-network vectors and non-CVE security issues remain review cases. Multi-CVE templates require per-CVE review because one declared vector need not apply to every listed identifier.

Publication timestamps are Git metadata, not cryptographic proof of when a public scanner feed became available. See [Nuclei method and limitations](nuclei-method.md): 2,284 new identities were audited; transient identities introduced only by modifications and deleted before the snapshot remain unenumerated. The Nuclei snapshot ends at 02:06:02 UTC on 5 November.

### Nessus

The public [Tenable plugin catalogue](https://www.tenable.com/plugins) was enumerated through `https://www.tenable.com/plugins/api/v1/search`, with the sensor fixed to `nessus` and publication-date filters. The complete all-types export contains **88,395 distinct plugin IDs**: **86,871 Local, 991 Combined, 530 Remote and 3 Summary**. Weekly date partitions and pagination counts were reconciled; the retrieved snapshot had no 5 November additions. The raw catalogue references **57,477 distinct CVEs** before exploitability filtering.

The primary network-assessment table contains **3,858 missing CVE candidates**, including **902** supported by a single-CVE plugin whose preferred modern CVSS vector is network. A Remote plugin's discovery method is not synonymous with remote exploitation. Combined plugins may require authenticated inventory. A plugin-level CVSS score attached to a bundle cannot establish the attack vector of each CVE in that bundle; the primary table groups those rows and conflicting vectors as `network_scored_bundle_or_vector_conflict_per_cve_unconfirmed`. The all-types table separates bundle-only and single-CVE vector-conflict categories. UI requirements and required privileges are preserved in vectors rather than silently excluding those vulnerabilities.

The wider all-types table has **41,545 missing network candidates**: **13,951** with single-CVE preferred-network-vector evidence, **27,387** bundle-only candidates, and **207** conflicts. Most do not describe a vulnerability Asteroid can reliably assess through anonymous service metadata. These counts are not a claim that 41,545 remotely exploitable vulnerabilities have been individually validated.

### Qualys

The official monthly [WAS detection release tables](https://docs.qualys.com/en/tas/release-notes/was_detections/january_2026.htm) were collected for January–September; October uses the [30 October Application Security announcement](https://notifications.qualys.com/notifications/2026/10/30/application-security-detections-published-in-october-2026). All lines of those ten pages were recovered, yielding **2,757 distinct QIDs and 2,782 CVEs**. **2,768 CVE candidates** are absent from the supplied remote registry. The tables provide release-month claims, not exact KnowledgeBase publication timestamps, and do not establish every entry's remote exploitability. Entries without a CVE are retained for semantic review.

**Coverage is incomplete:** public WAS tables are not the full VMDR KnowledgeBase, and November 1–5 releases are unavailable. Qualys explicitly describes its [public security alerts](https://www.qualys.com/research/security-alerts) as a sample. A complete comparison requires an authorized KnowledgeBase export, including exact `PUBLISHED_DATETIME`, CVE mappings, discovery methods and exploitability fields. The [KnowledgeBase API documentation](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-scan/kbase/knowledgebase.htm) documents the publication filters. No private subscription data, credentials or customer findings are included here.

## Implementation and review requirements

Implementation PRs and their validation results are tracked in [audit PR #278](https://github.com/Ostorlab/agent_asteroid/pull/278). The CSV's `not_implemented` values describe the pinned baseline; opening a detector PR does not change that baseline or establish complete coverage.

The inventory is larger than the implemented detector changes. Before converting a row into code:

1. Verify the CVE/product mapping, network attack vector, privileges, user interaction and affected configuration using the vendor/CNA source. Resolve scanner misidentification and contradictory release boundaries explicitly.
2. Check Asteroid's actual remote registry, its existing offline inventory policies, and open PRs. A string match in a README or test is not a registered check; a shared CVE may still leave product-specific gaps.
3. Implement a bounded probe with a product-specific oracle. Separate installed-version exposure from confirmed behavior. Unknown versions, forks, redirects, conflicting evidence and hidden metadata must not become positive findings.
4. Test affected/fixed boundary releases, prerequisite failures, unrelated products and request failures. Preserve stable finding identities and `custom_cve_list` behavior.
5. Record the reviewed PR and assessment limitations. A backlog row is complete only when its implementation and evidence have been reviewed.

Read-only release assessments can improve product identification and false-positive handling while leaving exploitation unconfirmed. They do not replace authenticated patch/backport verification or prove that a configuration-dependent attack path is reachable.

## Validation

The unmodified baseline passed `pytest -m 'not docker'`: **4,516 tests** on Python 3.14.5. Audit data checks cover unique identities, valid CVE identifiers, baseline-registry exclusion, source/date fields, classifications and checksums. This does not validate upstream scanner signatures or the security state of any target. No production scanning was performed for this audit.

## Method documentation and source-capture hashes

See the [Nessus collection method](nessus-method.md), [pagination manifest](nessus-pagination.json), [Qualys method](qualys-method.md), and [public-source capture hashes](qualys-source-manifest.json). Source-specific missing counts compare only the remote registry; the consolidated missing list also excludes existing inventory assessors. Raw source captures and collectors mentioned by those notes were retained locally for the audit; they are not shipped as scanner code.
