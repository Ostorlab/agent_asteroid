# Pillow Ghostscript: CVE-2026-112900

Coverage: **offline owner-inventory assessment**, registered as `Pillow` in
`agent.utils.inventory`. It is not registered as a remote HTTP exploit.
The assessor never uploads images, runs Ghostscript, or executes target code.

## Verified basis (29 October 2026)

Research began with the [Ostorlab article](https://blog.ostorlab.co/pillow-ghostscript-argument-injection-rce-cve-2026-112900.html).
The [Pillow advisory](https://github.com/python-pillow/Pillow/security/advisories/GHSA-w889-685w-c8fh)
lists affected releases **2.6.0 through 12.3.0**, fixed in **13.0.0**, and rates
the issue **Moderate**. Its reported tests used Ghostscript 10.02.1 and 10.07.1;
these are observations, not Ghostscript affected/fixed version boundaries.
Default `-dSAFER` does not prevent the filename argument injection. The reported
RCE chain additionally needs a leading `@` filename and control of the referenced
argument file. This assessment does not verify that chain or assign a CVSS score.

The [upstream patch and regression test](https://github.com/python-pillow/Pillow/commit/a2c363141da31a265dd536c945677db4b64f3ec9)
replace direct use of `fp.name` with `os.path.abspath(fp.name)`. The test renders
a benign EPS named `-h` and checks the resulting image dimensions; it skips when
Ghostscript is unavailable. A missing/nonexistent `fp.name` instead uses a generated
temporary path. The [13.0.0 release](https://github.com/python-pillow/Pillow/releases/tag/13.0.0)
is the fixed release, published October 16, 2026.

Inference for detection: there is no generic Pillow HTTP endpoint exposing the
required application data flow. Version banners, successful uploads, and image
errors cannot establish which filename reaches the renderer. Application-specific
owner evidence is required. Merely calling lazy `Image.open()` without reaching
EPS rendering does not establish this path.

## Input contract

Run with the repository's Python environment:

```sh
python -m agent.utils.inventory /path/to/pillow-inventory.json
```

The JSON file contains an array of records. Collect evidence for the **same
running application worker/container**, using trusted package/build provenance,
effective renderer configuration, and review of the application path to
`EpsImagePlugin.Ghostscript`. A lockfile or the scanner host's installed packages
are insufficient. Keep supporting evidence in the owner's audit records; this
assessor evaluates normalized assertions and does not authenticate them.

```json
[
  {
    "product": "Pillow",
    "version": "12.3.0",
    "filename_normalization_fix_applied": false,
    "ghostscript_available": true,
    "eps_rendering_reachable": true,
    "attacker_controls_filename": true,
    "filename_handling": "unmodified_relative"
  }
]
```

| Field | Required meaning |
| --- | --- |
| `product` | Exact identity `Pillow`. |
| `version` | Canonical three-component deployed upstream release. Vendor suffixes, prereleases, and ambiguous versions are inconclusive. |
| `filename_normalization_fix_applied` | Boolean confirming whether the deployed code contains the upstream fix or equivalent backport; `false` requires verified absence, not an assumption from the version. |
| `ghostscript_available` | Boolean: the Pillow runtime can resolve and invoke Ghostscript, including any explicitly configured executable. A package installed in another container is insufficient. |
| `eps_rendering_reachable` | Boolean: untrusted input can reach actual EPS rendering, such as `load()`, conversion, thumbnail generation, or saving. An accepted MIME type alone is insufficient. |
| `attacker_controls_filename` | Boolean: the untrusted actor controls the filename used on this rendering path, not just image contents. |
| `filename_handling` | One of the exact policies below, verified at the actual Ghostscript input argument. |

Filename policies must hold for the assessed path, including every downstream
transformation. Use a separate record for each distinct rendering path.

| Value | Meaning |
| --- | --- |
| `unmodified_relative` | Caller-controlled relative names beginning with `-` or `@` are permitted, refer to an existing input file, and reach Ghostscript unchanged. Basename preservation alone does not prove this. |
| `absolute_path` | Input always becomes an absolute path before Ghostscript invocation. |
| `dot_relative_path` | Input retains a safe `./` (or platform equivalent) prefix. |
| `directory_prefixed_path` | Input retains a trusted directory prefix that itself starts with neither `-` nor `@`, e.g. `uploads/-h`. |
| `generated_safe_path` | Application-generated input names cannot begin with either special prefix. |
| `unnamed_stream` | No usable caller-controlled `fp.name`; Pillow uses its generated temporary input path. Named file-like objects do not automatically qualify. |
| `rejects_special_prefixes` | Both leading `-` and `@` are rejected before reaching the Ghostscript input argument. Blocking only one does not qualify. |

A generic claim such as `sanitized` is inconclusive. Do not label a path safe
based only on the browser upload filename or an early normalization step that
later code reverses.

## Results and limits

- `potential_exposure`: affected release, verified absent fix, available
  Ghostscript, reachable EPS rendering, attacker filename control, and unsafe
  relative filename handling all match. Exploitability and RCE remain unconfirmed.
- `not_matched`: release outside the listed range (before 2.6.0 or at least
  13.0.0), verified fix, a missing prerequisite, or a verified safe filename
  policy. For in-range releases, all evidence fields must be well formed first.
  This is a statement about this CVE and supplied evidence, not overall safety.
- `inconclusive`: missing/malformed evidence, custom releases, or unlisted
  releases between 12.3.0 and 13.0.0. Version alone cannot produce a positive.

The CLI emits only CVE IDs, status, reason, and recommendation; raw input paths,
credentials, and extra fields are not echoed. Ghostscript version and `-dSAFER`
are not used as negative controls. No package presence or remote response is
promoted to confirmed exploitability. Owner verification remains necessary.

## Local validation

Validated with Python 3.14.6 in `/tmp/pillow-gs-venv`, using repository requirements
and test requirements. The initial global environment lacked `cloudscraper` and
automatic pytest plugin loading stalled; the isolated environment and explicit
plugin selection resolved these environment issues. No dependency files changed.

Commands below assume that environment's `bin` directory is on `PATH`:

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 COVERAGE_FILE=/tmp/pillow-gs-coverage python -m pytest -q -p pytest_cov --cov=agent.exploits.cve_2026_112900 --cov-branch --cov-report=term-missing tests/exploits/cve_2026_112900_test.py tests/utils/inventory_test.py tests/exploits/cve_2026_115560_test.py tests/exploits/cve_2026_110264_test.py tests/exploits/cve_2026_114625_test.py
ruff format --check agent/exploits/cve_2026_112900.py agent/utils/inventory.py tests/exploits/cve_2026_112900_test.py
ruff check agent/exploits/cve_2026_112900.py agent/utils/inventory.py tests/exploits/cve_2026_112900_test.py
mypy --follow-imports=silent agent/exploits/cve_2026_112900.py agent/utils/inventory.py tests/exploits/cve_2026_112900_test.py
git diff --check
```

Baseline: 27 existing inventory/PHP tests passed. Before implementation, the new
suite had 34 failures demonstrating missing Pillow dispatch/results. Final:
**166 passed**, with **100% statement and branch coverage** for the new assessor.
Ruff 0.17.3 format/lint and scoped mypy 2.4.1 passed. The documented JSON example
also passed through the real `python -m agent.utils.inventory` entry point.
The existing Ostorlab dependency emits a SQLAlchemy deprecation warning.

Focused review checked version bounds, backports, lazy rendering, Ghostscript
availability, effective filename policies, strict evidence types, sanitized
output, and dispatch integration. Tests block network connections, HTTP requests,
and subprocess creation during CLI assessment. No live target or command-execution
probe was performed, and the full repository test suite was not run.
