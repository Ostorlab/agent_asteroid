# Laravel token guard assessment implementation plan

**Goal:** Implement CVE-2026-114509 owner-inventory coverage without target requests.

**Architecture:** Reuse `inventory_definitions.Assessment`, canonical release parsing,
and the existing inventory CLI. Register only with the inventory dispatcher; no
network exploit registration. Assess one effective guard/entry point per record.

**Execution:** Inline in the authorized isolated worktree; no delegation, push, or PR.

## Work and validation

- [x] Verify clean managed worktree and branch from refreshed `origin/main` (`079c19dd`).
- [x] Verify vendor advisory, both patches, regression tests, and tagged source.
- [x] Establish baseline: inventory and PHP inventory tests, 27 passed in `.venv`.
- [x] Add failing Laravel dispatch test in `tests/utils/inventory_test.py`.
- [x] Add `agent/exploits/cve_2026_114509.py` and its matching test module.
  Require standard token guard, standard user provider, MySQL/MariaDB, text token
  storage, reachable non-string numeric input, and source evidence of missing
  type rejection. Distinguish `user()` hashing from un-hashed `validate()`.
- [x] Add the smallest import/product mapping to `agent/utils/inventory.py`.
- [x] Test fixed, unpatched, missing/invalid/conflicting evidence, other guards,
  other databases, hashing/PHP versions, legacy builds, no I/O, and no secret echo.
- [x] Document normalized inputs and primary evidence in `docs/cve-2026-114509.md`.
- [x] Run targeted pytest, Ruff format/check, mypy, and focused local review.
- Integration: one local task commit; retain the branch/worktree, with no push or PR.

## Research constraint

The vendor advertises fixes at 12.68.0 and 13.29.0. Tagged source confirms
11.56.1 is also patched, but **13.27.0 and 13.28.0 already contain the checks**.
Do not treat every release below the advertised floor as unpatched. Explicit
deployed-source evidence is required for potential results, including old branches
and backports. PHP 7 with hashing remains inconclusive, not a presumed bypass.

Commands: `.venv/bin/python -m pytest -q tests/exploits/cve_2026_114509_test.py
tests/utils/inventory_test.py tests/exploits/cve_2026_115560_test.py
tests/exploits_registry_test.py`; `.venv/bin/ruff format --check <changed Python files>`;
`.venv/bin/ruff check <changed Python files>`; `.venv/bin/mypy <changed Python files>`.

## Validation and review record

- The new dispatch test first failed with `inconclusive` instead of
  `potential_exposure`; the initial evidence matrix had 51 expected failures.
  Additional patched-tag and provider-binding controls failed before their fixes.
- Final targeted command above: **157 passed**. Warnings came from existing
  SQLAlchemy, pysmi, and jaydebeapi dependencies.
- Ruff check and format check: passed on the detector, dispatcher, and both test
  files. Configured mypy: **no issues in 4 source files**. `git diff --check`: passed.
- The system pytest baseline initially failed importing missing `cloudscraper`.
  A worktree-local `.venv` using Python 3.13.2 and the existing requirements resolved
  that failure. CI specifies Python 3.14; that interpreter was not used locally.
  No project dependency files were changed. No PHP executable was available;
  validation used normalized local fixtures, not a live Laravel/database lab.
- Focused local review checked all positive prerequisites, unknown/contradictory
  evidence, strict boolean handling, both hashing paths, secret-safe CLI output,
  and the absence of target I/O and remote exploit registration. The shared
  production diff is exactly one import and one `Laravel` dispatcher mapping.
