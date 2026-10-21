# Two-Tier PHP Detection (Header Matching + Behavioral Upload Progress Probe) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand detection for CVE-2026-109618 and CVE-2026-109619 in Agent Asteroid to detect unmitigated PHP targets even when `expose_php = Off` or headers are stripped by reverse proxies, using a safe differential `PHP_SESSION_UPLOAD_PROGRESS` behavioral probe.

**Architecture:** Implement a two-tier evaluation in `CVE2026109618Exploit` and `CVE2026109619Exploit`: Tier 1 performs fast version header regex matching; if headers are absent or stripped, Tier 2 performs a non-destructive differential multipart probe comparing baseline cookie responses against `PHP_SESSION_UPLOAD_PROGRESS` session initialization.

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
def testCVE2026109618_whenHeadersStrippedButUploadProgressEmitsSession_reportsPotentialExposure(
    requests_mock: requests_mock.Mocker,
) -> None:
    # Baseline GET: server does not emit PHPSESSID and hides PHP version in Server header
    requests_mock.get(
        f"{TARGET.origin}/",
        text="<html>Welcome</html>",
        headers={"Server": "nginx/1.24.0"},
    )
    # Behavioral probe POST: multipart containing PHP_SESSION_UPLOAD_PROGRESS triggers PHPSESSID
    requests_mock.post(
        f"{TARGET.origin}/",
        text="<html>Welcome</html>",
        headers={
            "Server": "nginx/1.24.0",
            "Set-Cookie": "PHPSESSID=asteroid_probe_session_123; path=/",
        },
    )
    detector = cve_2026_109618.CVE2026109618Exploit()

    findings = detector.check(TARGET)

    assert len(findings) == 1
    finding = findings[0]
    assert "POTENTIAL EXPOSURE" in finding.entry.title
    assert "session.upload_progress" in finding.technical_detail
    assert "PHPSESSID" in finding.technical_detail
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. /home/sohaib-harraoui/miniconda3/envs/ae_env/bin/pytest tests/exploits/cve_2026_109618_test.py -k testCVE2026109618_whenHeadersStrippedButUploadProgressEmitsSession_reportsPotentialExposure`
Expected: FAIL (findings is empty list `[]` because headers lack PHP version).

- [ ] **Step 3: Implement `_probe_upload_progress_behavior` in `agent/exploits/cve_2026_109618.py`**

Add multipart probe logic:
```python
def _probe_upload_progress_behavior(self, target: agent_definitions.Target) -> bool:
    """Test if server initializes session on PHP_SESSION_UPLOAD_PROGRESS multipart POST."""
    if target.scheme not in {"http", "https"}:
        return False
    try:
        # Baseline request: inspect if baseline response already sets PHPSESSID
        baseline_resp = self.session.get(
            f"{target.origin}/",
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=False,
        )
        if "PHPSESSID" in baseline_resp.headers.get("Set-Cookie", ""):
            return False

        # Benign multipart payload triggering upload progress session initialization
        boundary = "----AsteroidProbeBoundary84920"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"asteroid_probe\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}

        with http_metadata.send_anonymous(
            self.session,
            "POST",
            f"{target.origin}/",
            headers=headers,
            data=body,
            timeout=DEFAULT_TIMEOUT,
        ) as probe_resp:
            set_cookie = probe_resp.headers.get("Set-Cookie", "")
            if "PHPSESSID" in set_cookie:
                return True
            return False
    except requests_exceptions.RequestException:
        return False
```

Update `accept()` and `check()` to evaluate both Tier 1 (Version) and Tier 2 (Behavioral probe).

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. /home/sohaib-harraoui/miniconda3/envs/ae_env/bin/pytest tests/exploits/cve_2026_109618_test.py -v`
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
def testCVE2026109619_whenHeadersStrippedButUploadProgressEmitsSession_reportsPotentialExposure(
    requests_mock: requests_mock.Mocker,
) -> None:
    requests_mock.get(
        f"{TARGET.origin}/",
        text="<html>Welcome</html>",
        headers={"Server": "cloudflare"},
    )
    requests_mock.post(
        f"{TARGET.origin}/",
        text="<html>Welcome</html>",
        headers={
            "Server": "cloudflare",
            "Set-Cookie": "PHPSESSID=asteroid_probe_session_456; path=/",
        },
    )
    detector = cve_2026_109619.CVE2026109619Exploit()

    findings = detector.check(TARGET)

    assert len(findings) == 1
    finding = findings[0]
    assert "POTENTIAL EXPOSURE" in finding.entry.title
    assert "CVE-2026-109619" in finding.entry.title
    assert "session.upload_progress" in finding.technical_detail
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. /home/sohaib-harraoui/miniconda3/envs/ae_env/bin/pytest tests/exploits/cve_2026_109619_test.py -k testCVE2026109619_whenHeadersStrippedButUploadProgressEmitsSession_reportsPotentialExposure`
Expected: FAIL.

- [ ] **Step 3: Update `check()` in `agent/exploits/cve_2026_109619.py`**

Ensure `CVE2026109619Exploit` checks `_probe_upload_progress_behavior()` when version headers are missing, generating finding with reference `CVE-2026-109619`.

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. /home/sohaib-harraoui/miniconda3/envs/ae_env/bin/pytest tests/exploits/cve_2026_109619_test.py -v`
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
  - Probe when baseline already sets `PHPSESSID` (inconclusive -> return `[]`).
  - Probe when POST returns 500 or network timeout.

- [ ] **Step 2: Run full test suite**

Run: `PYTHONPATH=. /home/sohaib-harraoui/miniconda3/envs/ae_env/bin/pytest tests/exploits/cve_2026_109618_test.py tests/exploits/cve_2026_109619_test.py -v`
Expected: All tests PASS.

- [ ] **Step 3: Run Linters**

Run: `/home/sohaib-harraoui/miniconda3/bin/ruff check agent/ tests/ && /home/sohaib-harraoui/miniconda3/bin/ruff format --check agent/ tests/`
Expected: All checks pass.

- [ ] **Step 4: Push to branch and update PR #233**

```bash
git push origin feature/php-cve-2026-109618-109619
```
Verify PR status and update PR body.
