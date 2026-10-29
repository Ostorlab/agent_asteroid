# Sentry Next.js middleware bypass assessment

Goal: implement CVE-2026-114139 as an offline owner-inventory assessment,
following the existing per-CVE modules and shared inventory dispatcher. The user
authorized design, implementation, tests and local review in this worktree.

Anonymous product fingerprints or successful tunnel requests cannot establish
application routing and authorization. A remote heuristic would mislabel public
routes and routes protected server-side. Use trusted deployment evidence instead;
return only potential exposure, not matched, or inconclusive.

Implementation steps:

- [x] Verify managed worktree and branch from refreshed origin/main
  (`079c19dd6096d0ff3e7a7671c0cd541c1b620673`).
- [x] Read vendor advisory, v9/v10/v11 patches and wrapper regression tests.
- [x] Establish inventory baseline and a failing dispatcher test for Sentry.
- [x] Add `agent/exploits/cve_2026_114139.py` with canonical release handling,
  explicit bundler and tunnel configuration, verified route collision, middleware
  authorization, and independent route/layout/data-access authorization controls.
  Version or feature presence alone must never produce potential exposure.
- [x] Add one product import and dispatch entry to `agent/utils/inventory.py`.
  Keep the remote exploit registry unchanged, matching other offline assessors.
- [x] Test affected/fixed version boundaries, prereleases, malformed evidence,
  missing prerequisites, false-positive controls, CLI dispatch and output privacy
  in `tests/exploits/cve_2026_114139_test.py`.
- [x] Document normalized evidence and source discrepancies in
  `docs/sentry-nextjs-cve-2026-114139.md`; link from the README inventory table.
- [x] Run targeted pytest, Ruff lint/format and scoped mypy; review diff for
  overclaimed evidence, unsafe I/O and missing registration.

Validation commands (use the task-local Python environment):

```sh
python -m pytest -q tests/exploits/cve_2026_114139_test.py tests/utils/inventory_test.py tests/exploits/cve_2026_114625_test.py tests/exploits/cve_2026_110264_test.py tests/exploits/cve_2026_115560_test.py
ruff check agent/exploits/cve_2026_114139.py agent/utils/inventory.py tests/exploits/cve_2026_114139_test.py
ruff format --check agent/exploits/cve_2026_114139.py agent/utils/inventory.py tests/exploits/cve_2026_114139_test.py
mypy --strict --follow-imports=silent agent/exploits/cve_2026_114139.py agent/utils/inventory.py tests/exploits/cve_2026_114139_test.py
```

Results: 194 tests passed; Ruff formatting/lint and scoped strict mypy passed.
Baseline before implementation: 25 existing tests passed and the new Sentry
dispatch test failed as expected. Review confirmed no target I/O, no confirmed
exploit verdict, conservative unknown handling and offline registration.

Validation used Python 3.12.3 in `/tmp/asteroid-sentry-py312` with repository
requirements installed. The system environment initially lacked `cloudscraper`;
the task environment resolved that without changing repository dependencies.
Inherited system packages caused a mypy path failure; disabling that inheritance
resolved it. One existing Ostorlab/SQLAlchemy deprecation warning remains.
The full repository suite, CI's Python 3.14 environment and a live Next.js lab
were not run. No production or public application was probed.
