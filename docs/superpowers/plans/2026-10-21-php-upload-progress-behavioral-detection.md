# Two-Tier PHP Detection (Header Matching + Behavioral Upload Progress Probe) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flag potential exposure to CVE-2026-109618 and CVE-2026-109619 in Agent Asteroid when `expose_php = Off` or reverse proxies strip version headers. CVE-2026-109618 is the PHP session upload progress use-after-free; CVE-2026-109619 is the companion SAPI multipart (rfc1867.c) request-handling flaw in the php2shell chain. The non-destructive differential `PHP_SESSION_UPLOAD_PROGRESS` probe confirms the upload-progress subsystem is active—not binary patch status—so Tier 2 reports POTENTIAL EXPOSURE rather than confirmed RCE. No heap-corrupting payload or malformed boundary fragment is sent.

**Architecture:** Implement a two-tier evaluation in `CVE2026109618Exploit` and `CVE2026109619Exploit`: Tier 1 performs fast version header regex matching; if headers are absent or stripped, Tier 2 sends a control multipart POST and a `PHP_SESSION_UPLOAD_PROGRESS` probe POST to `/`, then `/index.php` on static or 404/405 responses, filters infrastructure/CDN/load-balancer cookies via `_extract_cookie_keys()` (prefixes such as `__cf`, `cf_`, `aws`, `bigip`, `_ga`, `incap_ses`), and compares the remaining `Set-Cookie` names to confirm dynamic session initialization.

**Tech Stack:** Python 3.12+, Requests, Packaging, Pytest, Requests-Mock, Agent Asteroid, OXO SDK.

---

### File Structure Map

```text
agent/exploits/
├── cve_2026_109618.py       # Core detector with Tier 1 (Version) and Tier 2 (Behavioral probe)
└── cve_2026_109619.py       # Companion SAPI multipart parser detector inheriting Tier 1 & 2
tests/exploits/
├── cve_2026_109618_test.py  # Unit tests covering header exposure, behavioral probe, and edge cases
└── cve_2026_109619_test.py  # Unit tests covering companion exploit behavior and probe triggers
```

---

### Task 1: Implement Differential Behavioral Probe in `cve_2026_109618.py`

**Files:**
- Modify: `agent/exploits/cve_2026_109618.py`
- Test: `tests/exploits/cve_2026_109618_test.py`

- [ ] **Step 1: Write the failing unit test for the behavioral probe**

In `tests/exploits/cve_2026_109618_test.py`:
```python
def testCVE2026109618_whenHeadersStrippedAndProbeEmitsSession_reportsBehavioralExposure(
    requests_mock: requests_mock.Mocker,
) -> None:
    # Baseline GET: server does not emit PHPSESSID and hides PHP version in Server header
    requests_mock.get(f"{TARGET.origin}/", text="OK", headers={"Server": "nginx/1.24"})
    # Control POST has no session cookie
    requests_mock.post(
        f"{TARGET.origin}/",
        text="OK",
        headers={"Server": "nginx/1.24"},
        additional_matcher=lambda req: b"asteroid_control" in (req.body or b""),
    )
    # Probe POST with upload progress dynamically returns PHPSESSID
    requests_mock.post(
        f"{TARGET.origin}/",
        text="OK",
        headers={
            "Server": "nginx/1.24",
            "Set-Cookie": "PHPSESSID=session_probe_id_999; path=/",
        },
        additional_matcher=lambda req: (
            b"PHP_SESSION_UPLOAD_PROGRESS" in (req.body or b"")
        ),
    )
    detector = cve_2026_109618.CVE2026109618Exploit()

    assert detector.accept(TARGET) is True
    findings = detector.check(TARGET)
    assert len(findings) == 1
    assert "POTENTIAL EXPOSURE" in findings[0].entry.title
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. pytest tests/exploits/cve_2026_109618_test.py -k testCVE2026109618_whenHeadersStrippedAndProbeEmitsSession_reportsBehavioralExposure`
Expected: FAIL.

- [ ] **Step 3: Implement `probe_behavioral_exposure` in `agent/exploits/cve_2026_109618.py`**

Add differential multipart probe logic:
```python
def probe_behavioral_exposure(
    self, target: agent_definitions.Target
) -> tuple[str, str] | None:
    """Differential probe comparing control POST vs probe POST with PHP_SESSION_UPLOAD_PROGRESS."""
```

Update `accept()` and `check()` to evaluate both Tier 1 (Version) and Tier 2 (Behavioral probe).

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. pytest tests/exploits/cve_2026_109618_test.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/exploits/cve_2026_109618.py tests/exploits/cve_2026_109618_test.py
git commit -m "feature: add behavioral upload progress probe to CVE-2026-109618 detector"
```

---

### Task 2: Extend Companion Detector `cve_2026_109619.py`

**Files:**
- Modify: `agent/exploits/cve_2026_109619.py`
- Test: `tests/exploits/cve_2026_109619_test.py`

- [ ] **Step 1: Write unit test in `tests/exploits/cve_2026_109619_test.py`**

```python
def testCVE2026109619_whenHeadersStrippedAndProbeEmitsSession_reportsBehavioralExposure(
    requests_mock: requests_mock.Mocker,
) -> None:
    requests_mock.get(f"{TARGET.origin}/", text="OK", headers={"Server": "cloudflare"})
    requests_mock.post(
        f"{TARGET.origin}/",
        text="OK",
        headers={"Server": "cloudflare"},
        additional_matcher=lambda req: b"asteroid_control" in (req.body or b""),
    )
    requests_mock.post(
        f"{TARGET.origin}/",
        text="OK",
        headers={
            "Server": "cloudflare",
            "Set-Cookie": "PHPSESSID=session_probe_id_109619; path=/",
        },
        additional_matcher=lambda req: (
            b"PHP_SESSION_UPLOAD_PROGRESS" in (req.body or b"")
        ),
    )
    detector = cve_2026_109619.CVE2026109619Exploit()

    assert detector.accept(TARGET) is True
    findings = detector.check(TARGET)
    assert len(findings) == 1
    assert "POTENTIAL EXPOSURE" in findings[0].entry.title
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. pytest tests/exploits/cve_2026_109619_test.py -k testCVE2026109619_whenHeadersStrippedAndProbeEmitsSession_reportsBehavioralExposure`
Expected: FAIL.

- [ ] **Step 3: Update `check()` in `agent/exploits/cve_2026_109619.py`**

Ensure `CVE2026109619Exploit` checks `probe_behavioral_exposure()` when version headers are missing, generating finding with reference `CVE-2026-109619`.

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. pytest tests/exploits/cve_2026_109619_test.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/exploits/cve_2026_109619.py tests/exploits/cve_2026_109619_test.py
git commit -m "feature: support behavioral probe in CVE-2026-109619 detector"
```

---

### Task 3: Edge Case Testing & Defensive Validation

**Files:**
- Modify: `tests/exploits/cve_2026_109618_test.py`
- Modify: `tests/exploits/cve_2026_109619_test.py`

- [ ] **Step 1: Add negative tests**
  - Probe when upload progress is disabled (`session.upload_progress.enabled = Off` -> no `Set-Cookie`).
  - Probe when the control POST already sets a session cookie (e.g. `laravel_session`) — inconclusive, so `check()` returns `[]`.
  - Probe when POST returns 500 or network timeout.
  - Infrastructure/CDN cookie exclusion (`AWSALB`, `__cf_bm` must not be attributed as a session).
  - Static root fallback from `/` to `/index.php` on 404/405 or static responses.
  - Framework CSRF 403/419 rejections that still execute PHP's SAPI multipart parser.

- [ ] **Step 2: Run full test suite**

Run: `PYTHONPATH=. pytest tests/exploits/cve_2026_109618_test.py tests/exploits/cve_2026_109619_test.py -v`
Expected: All tests PASS.

- [ ] **Step 3: Run Linters**

Run: `ruff check agent/ tests/ && ruff format --check agent/ tests/`
Expected: All checks pass.

- [ ] **Step 4: Push to branch and update PR #234**

```bash
git push origin feature/php-behavioral-upload-progress-detection
```
Verify PR status and update PR body.
