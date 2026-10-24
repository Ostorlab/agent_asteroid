# Critical advisory coverage implementation plan

> **For agentic workers:** Use subagent-driven-development for implementation and independent spec and quality review.

**Goal:** Audit critical advisories reported or materially updated during 2026-10-22 09:27 UTC through 2026-10-24 09:27 UTC, and add safe detection for missing coverage.

**Architecture:** Reuse Asteroid's registered detectors and anonymous bounded HTTP transport. Use only verified product metadata and one read-only SNMP sysDescr query for Aruba. When public metadata cannot establish prerequisites, record the limitation and supply an offline evidence assessment rather than send exploit traffic or invent endpoints. Findings are potential exposure; a negative result is inconclusive.

**Tech stack:** Python 3.14, requests, packaging, pysnmp6, pytest, ruff0.16, mypy.

## Task 1: HPE wireless critical rollup

Create `agent/exploits/hpe_2026_05162.py` and `tests/exploits/hpe_2026_05162_test.py`.

- [x] Write parameterized public-interface tests for all33 critical CVEs in HPESBNW05162, platform-specific membership, the five fixed boundaries, unknown/product-conflicting/suffixed versions, errors, unsupported target transports, registry metadata, and exactly one bounded sysDescr GET.
- [x] Run tests to observe missing implementation failure.
- [x] Implement a registered grouped detector (metadata cve_ids includes all33) returning only the applicable AOS8/AOS10 CVEs in each finding. Use one SNMP GET of1.3.6.1.2.1.1.1.0 on explicitly supplied UDP/SNMP161, public community only, retries0, bounded timeout, engine cleanup. Never send PAPI traffic. Parse actual ArubaOS sysDescr format and strict four-component release, with documented SSR/LSR/build suffix only.
- [x] Run targeted tests and static checks. Review spec and quality independently. Result: 44 tests pass; spec and quality APPROVED.

Primary data: https://csaf.arubanetworking.hpe.com/2026/hpe_networking_-_hpesbnw05162.json . AOS10-only:79844,79845,79847,79851,79853,79854,79861,79864,79865,79869,79871,79873,79874,79876. AOS8-only:79846,79848,79849,79850,79855,79856,79857,79858,79859,79860,79866,79867,79868,79870,79875. Both:79852,79862,79863,79872. Ranges:10.8.0.0..<10.8.1.2;10.7.0.0..<10.7.2.7;10.4.0.0..<10.4.1.14;8.13.0.0..<8.13.3.1;8.10.0.0..<8.10.0.24.

## Task 2: Missing application checks

Research actual upstream metadata formats before writing fixtures. Add registered modules/tests for Collabora CVE-2026-110447, LiteLLM CVE-2026-114612, Okta CVE-2026-115547, and Kiloview CVE-2026-107861/CVE-2026-110243/CVE-2026-109122. Reject ambiguous versions, redirects, error pages and unrelated products. Use existing defensive_http and cap reads. Validate fixed and vulnerable boundaries, malformed inputs, target scoping and credential isolation through public accept/check methods. Run tests red before implementation, then green.

Verified paths: LiteLLM `GET /openapi.json` (actual FastAPI title/version plus known paths); Collabora static installed `appinfo/info.xml` under `apps` and `custom_apps` (never proxy.php); Kiloview `GET /api/systemctrl/system/getSystemInfo` (actual vendor/product/softwareVersion); Okta `GET /` (only the vendor-documented product/footer version if exposed). Responses requiring authentication are inconclusive.

Completed: 115 HTTP tests pass. Independent spec and quality review APPROVED after a regression-tested XML encoding exception fix.

## Task 3: Conditional evidence and research record

PHP CVE-2026-115560 needs runtime serialize-handler switching and active session upload progress. VCO CVE-2026-114625 requires on-premises deployment evidence, absent from the actual version API; GitLab CVE-2026-110264 version APIs require authentication. Provide a small offline JSON inventory assessment CLI for these three, separate from the remote registry and documented as such. Accept only canonical product/version and explicit prerequisite evidence; missing or unknown evidence is inconclusive. Never log arbitrary records or secrets, connect to targets, or execute uploaded code/configuration. Tests cover complete, mitigated, missing, malformed, and future/unknown evidence and actual CLI output.

Audit older NGINX/FortiSIEM/Bifrost disclosures for actual changes in window; do not relabel old disclosures as new. Correct material errors found in existing PHP range/remediation metadata, preserving finding DNA and avoiding unrelated changes. Add regression cases at the newly verified four branch boundaries before changing the implementation; retain the existing feature-probe behavior to avoid mixing the pending exposure-risk-tier PR into this work.

Completed: 86 offline assessment tests and 91 PHP tests pass. Historical PHP title literals independently compared unchanged. Independent spec and quality review APPROVED. Envoy inventory evidence adds downstream coverage for an already registered CVE. KSMBD remains a documented source-provenance assessment gap because no released-kernel patch matrix was verified.

## Task 4: Integration and PR

- [x] Record candidate-by-candidate baseline coverage, sources, dates, safety, limits and final disposition in repository documentation; update README coverage.
- [x] Run `pytest -m 'not docker'`, `ruff check .`, `ruff format --check .`, and `mypy` in the isolated environment. Result: 4,082 tests pass; mypy checks 374 source files; Ruff lint and formatting pass.
- [x] Independently review full diff and address confirmed defects. Final integrated verdict: APPROVED. Commit and push follow this verified local gate.
- [ ] Open PR with research references and exact validation. Trigger repository review workflow, check CI and address blockers. Leave PR open for human review.
