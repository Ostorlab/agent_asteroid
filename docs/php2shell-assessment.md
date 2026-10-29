# PHP2Shell assessment: CVE-2026-109618 and CVE-2026-109619

Verified against primary PHP sources on 2026-10-29. This completes the two existing
Asteroid detectors without adding duplicate detector identities.

## Evidence and limits

The [PHP release notice](https://www.php.net/archive/2026.php#2026-10-21-5) and
[OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
identify fixed releases **8.2.35, 8.3.36, 8.4.27, 8.5.12** (CVSS v4.0 9.2).
The [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
uses the same release boundaries and score. Branches are assessed independently.
PHP also published source backports for 7.4, 8.0 and 8.1. Earlier branches, future
branches and noncanonical builds remain inconclusive unless the owner explicitly
verifies a running-worker backport. This deliberately avoids extrapolating the
blog's PHP 5.4 lower bound. PHP's 8.6 prerelease notice identifies RC4 as fixed;
prerelease assessment is outside this implementation's canonical-release scope.

The [fix commit](https://github.com/php/php-src/commit/3584a98bda) replaces OOM
bailout with delayed handling and resets globals used before request initialization.
Reviewed regression tests include
[`oom_request_parsing.phpt`](https://github.com/php/php-src/blob/3584a98bda/Zend/tests/oom_request_parsing.phpt)
and [`rfc1867_no_user_code.phpt`](https://github.com/php/php-src/blob/3584a98bda/ext/session/tests/rfc1867_no_user_code.phpt).
The former deliberately exhausts memory; the latter exercises upload progress in
patched PHP. Neither provides a safe black-box vulnerability oracle. These upstream
tests were inspected, not executed against a service.

Remote coverage is **potential version exposure only**. Each detector uses an
anonymous GET of the origin root, without redirects, credentials or uploads. It
accepts an unambiguous canonical version from successful response headers and
never reports confirmed exploitability. Unknown/custom/conflicting versions,
errors and feature-only evidence produce no finding; this is **not a safety verdict**.
The original class names, references and titles remain unchanged for registry/DNA
compatibility. The historically inaccurate titles are explained in the metadata.
No cookie-based title variant or alternate DNA is generated.

The removed multipart probe could not establish a vulnerable binary. In particular,
PHP's patched session callback still implements upload progress, and cookie
creation can come from the application. No OOM, crash, stale-memory disclosure,
command execution or public-target testing is part of this implementation.

## Owner inventory usage

Use the existing CLI, explicitly selecting one CVE per PHP record:

```sh
python -m agent.utils.inventory php-inventory.json
```

```json
[
  {
    "product": "PHP",
    "cve_id": "CVE-2026-109618",
    "version": "8.4.26",
    "backport_status": "not_applied",
    "serves_web_requests": true,
    "sapi": "apache2handler",
    "automatic_request_body_parsing": true,
    "multipart_reaches_php": true,
    "memory_limit_bytes": 134217728
  },
  {
    "product": "PHP",
    "cve_id": "CVE-2026-109619",
    "version": "8.4.26",
    "backport_status": "not_applied",
    "serves_web_requests": true,
    "sapi": "fpm-fcgi",
    "worker_reuse": true,
    "multipart_reaches_php": true,
    "session_upload_progress_enabled": true,
    "session_state_interruption_reachable": true
  }
]
```

Both examples return `potential_exposure`; they are examples of collected evidence,
not settings to assume for an arbitrary PHP service. The CLI's existing PHP default
(CVE-2026-115560) remains unchanged when `cve_id` is omitted. An unsupported explicit
selection returns `inconclusive`. The JSON output contains only CVE IDs, status,
reason and recommendation, with no raw inventory fields.

All evidence must describe the **same running workers and effective web SAPI**.
Collect it through owner-approved package/build provenance, deployment configuration
and application/source review. CLI `php -v` or an installed package alone may describe
a different runtime. The assessor never authenticates evidence or contacts a target.
Missing booleans, integer/string substitutes for booleans, and unverified paths do
not count as positive evidence. Omit unknown fields; do not guess.

| Field | Evidence contract |
| --- | --- |
| `version` | Canonical three-component upstream runtime version, without a package suffix. |
| `backport_status` | `applied` means the relevant fix is verified in every running worker, including restart/redeployment. `not_applied` means vendor/source provenance was checked and the fix is absent. Missing/`unknown` cannot establish exposure on an old release. A verified `applied` result also handles custom builds. |
| `serves_web_requests`, `sapi` | Actual deployment. Accepted SAPI values: `apache2handler`, `fpm-fcgi`, `cgi-fcgi`, `frankenphp`, `litespeed`. A CLI-only deployment is outside the assessed remote paths. Recognizing a SAPI does not prove any specific path. |
| `automatic_request_body_parsing` | Effective startup body parsing, including the applicable `enable_post_data_reading` configuration. |
| `multipart_reaches_php` | Routing and frontend policy allow multipart input to reach PHP; an open port is insufficient. |
| `memory_limit_bytes` | Effective PHP limit as an integer. A positive finite limit supports the mod_php startup assessment. `-1` does not prove safety: underlying allocation failure remains possible. |
| `application_oom_reachable` | Source/configuration evidence that attacker-controlled input can cause OOM during application execution. This is the alternative CVE-2026-109618 path; do not infer it merely from a finite limit or an FPM banner. Invalid-state consumption remains unconfirmed. |
| `worker_reuse` | The same live worker can process another request. `false` requires verified process lifecycle/recycling, not merely multiple workers or load balancing. Required for CVE-2026-109619. |
| `session_upload_progress_enabled` | Effective setting before request parsing; a cookie does not establish it. |
| `session_state_interruption_reachable` | Code/configuration evidence of a reachable fatal interruption after request-owned session/decoder state is published and before its matching reset. An arbitrary application fatal error or enabled upload progress alone is insufficient. No crash probe should be used to collect this field. |
| `fatal_error_backtraces`, `fatal_error_reachable`, `preinit_ini_diagnostic` | Alternative CVE-2026-109619 path, requiring PHP 8.5 and all three booleans. Verify fatal-backtrace production plus a diagnostic before normal initialization on a subsequent request. For FPM this means early FastCGI INI parameters; pool startup values and `.user.ini` do not qualify. |

The mod_php startup assessment requires automatic multipart parsing and a finite
memory limit on an unpatched build. Actual allocation feasibility is untested.
FPM exits its child on startup failure, so startup configuration alone cannot
trigger its positive OOM assessment. FrankenPHP/LSAPI startup candidates are not
automatically promoted to this demonstrated mod_php path.

The stale-state assessment implements the session and PHP 8.5 fatal-backtrace paths
for mod_php/FPM with worker reuse. It does not infer arbitrary producer/consumer
pairs for other state families or SAPIs. Disabled upload progress, absent early
diagnostics or missing path evidence yield `inconclusive`, not a blanket clean bill.

`not_matched` is scoped to supplied fixed releases/backports, non-web deployment,
or (for stale state) verified absence of worker reuse. It is never a global security
verdict. Only `potential_exposure`, `inconclusive` and `not_matched` are emitted.
