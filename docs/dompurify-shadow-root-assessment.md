# DOMPurify shadow-root inventory assessment

Verified 29 October 2026 for **GHSA-cg2g-xh64-v4q7**. This is an executable
owner-inventory assessment, not remote exploit detection. Run it with the
existing CLI: `python -m agent.utils.inventory inventory.json`.

## Verified applicability

The [requested research article](https://blog.ostorlab.co/ghsa-cg2g-xh64-v4q7-dompurify-shadow-root-bypass.html)
led to the [vendor advisory](https://github.com/cure53/DOMPurify/security/advisories/GHSA-cg2g-xh64-v4q7),
which lists **3.4.4 through 3.4.16 inclusive**, fixed in **3.4.17**.
The vendor labels the advisory Low, while the article and GitHub Advisory
Database display Critical/9.2. This assessment assigns no severity and invents
no CVE identifier. The existing result schema's `cve_ids` field carries the GHSA
identifier without changing that shared contract.

The [3.4.17 release](https://github.com/cure53/DOMPurify/releases/tag/3.4.17),
[release PR](https://github.com/cure53/DOMPurify/pull/1672), and
[patch a77a3e7](https://github.com/cure53/DOMPurify/commit/a77a3e78b59f72fa4d1c83f22e121ad9cc7d3575)
confirm that the shadow DOM walk now calls `_scrubOwnCharacterData` when
`SAFE_FOR_TEMPLATES` is enabled. Removing disallowed separator elements can
join individually harmless text fragments into `${...}`, `{{...}}`, or
`<%...%>` expressions. The added pass normalizes and scrubs each fragment.
The [upstream regression tests](https://github.com/cure53/DOMPurify/blob/a77a3e78b59f72fa4d1c83f22e121ad9cc7d3575/test/test-suite.js#L1014)
cover `IN_PLACE` with attached roots, nested roots, and templates inside roots.

DOM-node modes alone are insufficient: a root must exist before sanitization,
remain accessible in its output, and reach an evaluator that understands the
attacker's expression dialect. Clone/import behavior differs across DOM
implementations; `RETURN_DOM` and `RETURN_DOM_FRAGMENT` can discard ordinary
non-clonable roots. Closed roots cannot be inspected by DOMPurify and are not
evidence of this fixed traversal bug. Plain HTML responses cannot reliably
reveal these application call-path properties. No generic HTTP oracle is used.

## Owner evidence schema

Collect evidence from the deployed bundle, effective configuration, and
application data flow for **one call path in one runtime**. Do not combine a
version from one bundle with flags or evaluator behavior from another. Account
for `setConfig`, hooks, wrappers, vendored copies, and backports. A package lock
entry or public script banner alone does not establish this evidence.

```json
[
  {
    "product": "DOMPurify",
    "version": "3.4.16",
    "sanitization_mode": "IN_PLACE",
    "safe_for_templates": true,
    "dom_node_input": true,
    "attached_shadow_root": true,
    "attacker_controlled_shadow_content": true,
    "shadow_root_reaches_output": true,
    "downstream_template_evaluation": true
  }
]
```

| Field | Required meaning |
| --- | --- |
| `product` | Exact normalized identity `DOMPurify`. |
| `version` | Canonical deployed upstream numeric release; custom/prerelease/build suffixes are inconclusive. |
| `sanitization_mode` | Effective `IN_PLACE`, `RETURN_DOM`, `RETURN_DOM_FRAGMENT`, or `STRING` after configuration precedence. `STRING` includes serialized/TrustedHTML output with no preserved root. |
| `safe_for_templates` | Effective `SAFE_FOR_TEMPLATES` setting. |
| `dom_node_input` | The sanitize call receives a DOM node, not an HTML string. |
| `attached_shadow_root` | The input already contains an accessible attached shadow root in a supporting runtime, possibly nested or under template content. An inert declarative template is insufficient. |
| `attacker_controlled_shadow_content` | An untrusted source can construct the split text and removable separator nodes inside that root. |
| `shadow_root_reaches_output` | That same root content survives the application's actual sanitize/clone/import/return path. Do not infer this from a return-mode flag. |
| `downstream_template_evaluation` | The application passes this sanitized shadow content to an evaluator supporting the attacker-controlled expression syntax. Merely displaying text is insufficient. |

All prerequisite values must be JSON booleans. Missing/null/string/integer values
remain inconclusive. All prerequisites plus an affected release yield only
`potential_exposure`; the assessor does not authenticate owner assertions or
prove expression execution. An absent prerequisite, string output, or a release
outside the advisory range yields `not_matched` for this advisory only.
Older releases may have other shadow-root issues. The CLI emits bounded reasons
and recommendations, never the supplied raw record.

## Local validation

Python tests exercise the real inventory dispatch, all three DOM-node modes,
affected/fixed boundaries, missing and malformed evidence, each false
prerequisite, version-only controls, output redaction, and no network access.
The assessor is deliberately absent from the remote exploit registry and
`custom_cve_list`. Its only shared registration change is the additive
`DOMPurify` entry in `agent/utils/inventory.py`.

The optional fixture below checks actual vendor bundles with harmless arithmetic
text; **no expressions are evaluated and no target is contacted**. Dependencies
are pinned in a temporary directory, without modifying project dependencies:

```sh
npm install --prefix /tmp/dompurify-local-lab --ignore-scripts --no-audit --no-fund jsdom@26.1.0 dompurify-vulnerable@npm:dompurify@3.4.16 dompurify-patched@npm:dompurify@3.4.17
node tests/fixtures/dompurify_shadow_roots.cjs /tmp/dompurify-local-lab/node_modules
python -m pytest tests/exploits/ghsa_cg2g_xh64_v4q7_test.py tests/utils/inventory_test.py -q
```

The local lab covers three expression dialects, ordinary/nested shadow roots,
templates within roots, light-DOM controls, disabled template safety, and the
loss of shadow roots in jsdom's two return modes. It does not validate clonable
roots in a real browser or any customer application's downstream evaluator.

Validation on 29 October used Python 3.14.6 in an isolated environment with the
repository requirements. Baseline inventory tests: 10 passed. Final verification
commands:

```sh
python -m pytest tests/exploits/ghsa_cg2g_xh64_v4q7_test.py tests/utils/inventory_test.py tests/exploits/cve_2026_110264_test.py tests/exploits/cve_2026_114625_test.py tests/exploits/cve_2026_115560_test.py tests/exploits/cve_2026_111497_test.py tests/exploits_registry_test.py -q --cov=agent.exploits.ghsa_cg2g_xh64_v4q7 --cov-branch --cov-report=term-missing
mypy agent/exploits/ghsa_cg2g_xh64_v4q7.py agent/utils/inventory.py tests/exploits/ghsa_cg2g_xh64_v4q7_test.py
ruff check agent/exploits/ghsa_cg2g_xh64_v4q7.py agent/utils/inventory.py tests/exploits/ghsa_cg2g_xh64_v4q7_test.py
ruff format --check agent/exploits/ghsa_cg2g_xh64_v4q7.py agent/utils/inventory.py tests/exploits/ghsa_cg2g_xh64_v4q7_test.py
git diff --check
```

Results: 213 tests passed; the new assessor has 100% statement and branch
coverage. Five warnings originate in existing third-party dependencies
(SQLAlchemy, tld, pysnmp/pysmi, jaydebeapi). The local JavaScript fixture passes
30 differential/control checks. Mypy passes for all three changed Python files.
Focused local review covered version boundaries, strict evidence types, bounded
reporting, no target I/O, inventory dispatch, and exclusion from remote scanning.
