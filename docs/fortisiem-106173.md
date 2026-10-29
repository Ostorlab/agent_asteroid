# FortiSIEM CVE-2026-106173 owner-inventory assessment

CVE-2026-106173 permits unauthenticated file writes through FortiSIEM
phQueryMaster gRPC. This **offline owner-inventory assessment** reports
`potential_exposure` when owner evidence identifies self-managed 7.5.0 with
phQueryMaster gRPC enabled, reachable from the assessed untrusted network, and
allowing unauthenticated RPC requests. Exploitability remains unconfirmed.

Research checked 2026-10-29. This assessment is separate from the remote exploit
registry and `custom_cve_list`.

## Evidence and limits

- [Fortinet FG-IR-26-180](https://fortiguard.fortinet.com/psirt/FG-IR-26-180)
  and its [vendor CSAF](https://filestore.fortinet.com/fortiguard/psirt/csaf_arbitrary-file-write-in-grpc-phquerymaster_fg-ir-26-180.json)
  identify self-managed 7.5.0 as affected, 7.5.1 as fixed, and 7.6 as unaffected.
  They exclude FortiSIEM Cloud and recommend restricting TCP 27918.
- [Fortinet's CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/106xxx/CVE-2026-106173.json)
  additionally lists 7.0.0–7.0.4, 7.1.0–7.1.9, 7.2.0–7.2.7,
  7.3.0–7.3.5 and 7.4.0–7.4.2. Its solution mentions Cloud and FortiSOC
  upgrades, contradicting the PSIRT cloud exclusion. These cases remain
  inconclusive pending vendor clarification; no older branch is declared safe.
- The advisory/CSAF give 9.4, while their CVSS vector's base metrics calculate
  to 9.8 (the vector also contains temporal metrics). The assessor emits no
  numerical score, avoiding propagation of inconsistent metadata.
- [Horizon3's original analysis](https://horizon3.ai/attack-research/cve-2026-106173-deep-dive-fortisiem-grpc-path-traversal-file-write-rce/)
  shows that the `SendQueryResult` handler combines untrusted metadata with
  filesystem paths and opens output with truncation. Traversal and embedded
  NULs permit arbitrary writes; overwriting a periodically executed script
  leads to code execution. The documented listener is TLS gRPC in phQueryMaster
  on TCP 27918, with no client-certificate requirement.
- The [research repository](https://github.com/horizon3ai/CVE-2026-106173)
  contains an exploit and README, not a vulnerable/patched regression suite.
  Its README describes blind execution. No published safe response oracle,
  vendor source patch or upstream regression test was found in the linked
  material. The [7.5.1 release-note page](https://docs.fortinet.com/document/fortisiem/7.5.1/user-guide/789002/whats-new-in-7-5-1)
  was retrieved, but supplied no matching CVE, gRPC or phQueryMaster patch
  detail. Fix boundaries rely on PSIRT/CSAF, not an independently tested
  binary patch.

A port check, TLS handshake, gRPC error, or generic FortiSIEM banner cannot
establish this vulnerability. Even an empty stream may create/truncate files.
Accordingly, this implementation sends no RPC, traversal, file-write, callback,
command-execution or HTTP request. The original
[Ostorlab article](https://blog.ostorlab.co/fortisiem-grpc-path-traversal-rce-cve-2026-106173.html)
was a research starting point, not the applicability authority.

## Input and results

Run `python -m agent.utils.inventory inventory.json` with an array such as:

```json
[
  {
    "product": "FortiSIEM",
    "version": "7.5.0",
    "deployment": "self-managed",
    "phquerymaster_grpc_enabled": true,
    "grpc_reachable_from_untrusted_network": true,
    "grpc_allows_unauthenticated_requests": true
  }
]
```

This is Asteroid's normalized schema, not a vendor API response. Collect all
fields from trusted owner administration/configuration evidence for the same
running appliance and assessment time. Keep provenance and network vantage
information in the owner's inventory system; do not supply credentials or
configuration dumps. The CLI trusts these assertions and does not collect or
authenticate them.

- `version`: canonical three-component installed release, with no suffix or
  build normalization. Custom/backported releases require manual verification.
- `deployment`: `self-managed`; `fortisiem-cloud` explicitly returns inconclusive
  because of the source conflict. Other/missing values are also inconclusive.
- `phquerymaster_grpc_enabled`: actual effective service state and identity,
  not an arbitrary listener at port 27918.
- `grpc_reachable_from_untrusted_network`: owner-verified access to that service
  from the network position under assessment, considering filtering and port
  remapping. A local listener alone is insufficient.
- `grpc_allows_unauthenticated_requests`: effective RPC authentication policy,
  including any proxy or client-certificate enforcement. A successful TLS
  handshake alone does not prove unauthenticated RPC access.

All three prerequisites must be JSON booleans for affected 7.5.0. All true gives
`potential_exposure`, with backports and exploitability explicitly unconfirmed.
Missing or ambiguous prerequisites give `inconclusive`. An explicitly false
prerequisite gives `not_matched` for this exposure path, with an explicit warning
that mitigation is not a patch and 7.5.0 still needs upgrading. Other network
positions may remain exposed. No result claims confirmed exploitation.

Self-managed 7.5.1+ within 7.5 and 7.6.x give `not_matched` based on vendor release
guidance; service evidence is unnecessary for that release-only exclusion.
All other releases remain inconclusive. Outputs use the existing bounded
`Assessment` schema: CVE IDs, status, static reason and recommendation. Unknown
fields, credentials and target addresses are never echoed.

## Implementation and verification

The assessor reuses the existing release parser and result type. Its tests
exercise public inventory dispatch, affected/fixed boundaries, conflicting
sources, unknown builds, exact product identity, strict boolean prerequisites,
mitigation semantics, sanitized CLI output and absence of target I/O.

Validation used an environment installed from repository requirements without
project dependency changes. The assessor and inventory regression tests,
focused Ruff/mypy checks and `git diff --check` passed. Statement and branch
coverage for the new assessor reached **100%**. Tests use synthetic inventory
and network/command guards; no appliance or exploit was exercised. Reproduce
the checks from an environment containing the repository test dependencies
and `pytest-cov`:

```sh
python -m pytest -q tests/exploits/cve_2026_106173_test.py tests/utils/inventory_test.py tests/exploits/cve_2026_110264_test.py tests/exploits/cve_2026_114625_test.py tests/exploits/cve_2026_115560_test.py tests/exploits/cve_2026_111497_test.py tests/exploits_registry_test.py --cov=agent.exploits.cve_2026_106173 --cov-branch --cov-report=term-missing
ruff check agent/exploits/cve_2026_106173.py agent/utils/inventory.py tests/exploits/cve_2026_106173_test.py
ruff format --check agent/exploits/cve_2026_106173.py agent/utils/inventory.py tests/exploits/cve_2026_106173_test.py
mypy agent/exploits/cve_2026_106173.py agent/utils/inventory.py tests/exploits/cve_2026_106173_test.py
git diff --check
```

Focused local review: no harmful probes or target I/O; no version/port-only
positive; no claims of confirmed exploitability; source disagreements remain
inconclusive; exact product dispatch and direct-call identity guards tested.
Shared implementation changes are limited to the FortiSIEM import and dispatch
entry. No remote detector or dependency change was introduced.
