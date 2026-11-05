# Nuclei detection-publication inventory

**2,284 template identities** were first added to the observed main-branch history in 2026; **814 network-vector CVE templates / 812 distinct CVEs** have no registered Asteroid match. These are scanner classifications, not independently confirmed exploitability.

Snapshot: `projectdiscovery/nuclei-templates@fef763cd6e1da264eca8668741edef52faa743f6` (2026-11-05 02:06:02 UTC). Asteroid comparison: registered instances from `571a9bc`, recorded in `/tmp/asteroid-2026-registry.json`.

## Results

The audit finds **2,284 template identities first added to the main first-parent history between January 1 and the snapshot**. Exact UTC boundaries are `2026-01-01T00:00:00Z` inclusive and `2026-11-06T00:00:00Z` exclusive, subject to the earlier snapshot cutoff.

* **814 network-vector CVE templates / 812 distinct CVEs** have no matching CVE in Asteroid's registered metadata. Their Nuclei CVSS metadata specifies `AV:N`.
* **401 non-CVE remote security templates** require semantic coverage mapping: 148 have network-vector CVSS metadata, and 253 have non-informational vulnerability/exposure/default-login/misconfiguration evidence. An unmatched template identifier alone does not prove that Asteroid lacks equivalent behavior.
* **99 templates need scope review**: 88 CVE templates lack a usable attack vector, three have adjacent-network vectors, three have local/physical vectors conflicting with remote template behavior, and five non-CVE templates need exploitability review.
* 927 informational and 30 local/non-network template rows are excluded, with reasons recorded.
* 18 new CVE-template rows match registered Asteroid identities across all scope categories. Registration does not prove equivalent coverage or check quality.

## Files

- **Committed dated table:** [nuclei-new-detections.csv](nuclei-new-detections.csv) contains every new identity, including exclusions and review categories, exported from local-only `all-first-published-2026.json` / `.csv`.
- **Committed consistency checks:** [nuclei-verification.json](nuclei-verification.json) copies local-only `verification.json`.
- **Local-only CVE and non-CVE subsets:** `missing-remote-cves.json`, `remote-new.json`, and `requires-review.json` preserve the detailed research rows. The committed dated table retains their scope categories.
- **Local-only earlier coverage:** `prior-vulnerability-detections.json` records other template identities covering the CVE before 2026. New in-window identities remain included.
- **Local-only research planning:** source-specific `summary.json` and `implementation-batches.json` retain product groupings and candidate batches. They differ from the committed consolidated summary.
- **Local-only reconstruction:** `build_inventory.py` and cached history/blobs are original research artifacts, not shipped scanner code.

## Method

1. Extract all YAML addition events across the complete first-parent chain with `--no-renames --diff-filter=A --raw --abbrev=40`. Read actual YAML IDs from all **22,480 unique original added blobs / 22,874 events**, retaining first commit, timestamp, path, and blob identity.
2. Read all **11,965 YAML blobs** from the December 31 baseline (`f3ac217f07c5718694c91ab990fde0e1c8fd1aeb`) to detect identities that existed before 2026 through modifications. This prevents path moves and re-additions from being mistaken for first publication. Baseline evidence is an upper bound on earlier publication, not an invented exact first date.
3. Use current template metadata where the identity is still present, otherwise the original template. When old YAML is malformed but the top-level ID remains readable, recover only the ID for historical deduplication; CVE-2026-44551 is such a case. Its current metadata parses successfully.
4. Compare CVE IDs from template identity/classification with registered Asteroid `cve_ids` and vulnerability references. No incidental code-text CVE matching is used.
5. Preserve attack-vector evidence, protocol, CVSS, severity, product, references, immutable source URLs, scope confidence/reason, covered/missing identities, methods, OAST usage, and version-comparison hints. Original descriptions and template bodies are not reproduced in the inventory.

## Limits

First-main commit time is a reproducible publication proxy; it is not a GitHub publication API timestamp. The snapshot precedes November 5 end of day. Remote exploitability is classified from Nuclei evidence and is not independently vendor-validated. Authentication and user-interaction requirements are retained in the CVSS vector; `AV:N` does not mean unauthenticated exploitation. A version fingerprint can establish only potential exposure, especially where patch/backport or configuration evidence is unavailable.

Two current IDs are absent from both added-blob history and the baseline: `hydracrypt-malware` is a local informational file detector; `fortinet-fortisandbox-panel` is an informational panel fingerprint. Both are outside the requested vulnerability scope. Transient identities introduced only through modifications and deleted before the snapshot have not been exhaustively audited: 2026 contains 1,430,202 modification events, mostly metadata/signature churn. This remaining bound prevents an unqualified claim of exhaustive coverage of every historical template mutation.

The script `build_inventory.py` regenerates the main files from the cached history, baseline, local checkout, and registry snapshot. The raw history/cache files are local audit material and need not be published in a pull request.
