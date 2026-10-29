# OpenCode MCP OAuth Windows/WSL command injection

Verified 2026-10-29. This is an **offline owner-inventory assessment**, not a
remote exploit detector. No CVE is assigned. No official security advisory was
published; the researcher's disclosure is corroborated by vendor source,
patches, regression tests, tagged manifests, and npm publication metadata.
No CVSS score is assigned here: the disclosure's proposed UI:N score does not
describe the required user-initiated sign-in/browser flow accurately.

## Verified applicability

| npm package | Affected stable releases | First fixed release |
| --- | --- | --- |
| `opencode-ai` | 1.0.137 through 1.18.32 | 1.18.33 |
| `@opencode/cli` | 2.0.0 through 2.0.17 | 2.0.18 |

The flow consumes a remote MCP server's OAuth `authorization_endpoint` and
passes the resulting URL to `open`. The vulnerable PowerShell path interpolates
the URL into a double-quoted expression. The fixed dependency uses literal
single-quoted arguments and escapes embedded quotes. Restricting URL schemes
to HTTP(S) alone does not fix this interpolation problem.

Required evidence applies to the machine opening the browser, which can differ
from the machine hosting the MCP client backend:

- The installed package and release match one of the two affected lines.
- The runtime is Windows or WSL, and the effective launcher uses the vulnerable
  PowerShell path. Native Linux/macOS are outside this path. WSL by itself is
  insufficient: `open@10.1.2` excludes containers and explicit app overrides
  from its WSL PowerShell branch.
- A configured remote MCP server supports OAuth and supplies an authorization
  endpoint outside the owner's control.
- A user initiates this server's OAuth sign-in, and that flow requests opening
  the authorization URL through the application browser launcher.

Ordinary connection/configuration is insufficient. In v1, `authenticate` only
opens the browser when `startAuth` produces an authorization URL; already valid
authentication can bypass it. In v2, the tagged CLI `mcp auth` handler prints the
authorization URL and polls; it does **not** launch the browser. The TUI's
integration dialog has `open(attempt.url)` and `open(field.url)` paths. Therefore,
running the v2 CLI command alone does not satisfy the browser-launch condition.
This corrects the starting blog's blanket CLI-flow description for both lines.

## Owner evidence contract

Run `python -m agent.utils.inventory inventory.json` with normalized records:

```json
[
  {
    "product": "OpenCode",
    "package_name": "opencode-ai",
    "version": "1.18.32",
    "platform": "windows",
    "browser_launcher": "powershell",
    "remote_mcp_oauth_enabled": true,
    "authorization_endpoint_untrusted": true,
    "user_initiated_oauth": true,
    "oauth_browser_launch_requested": true
  }
]
```

This example is a schema example, not evidence collected by Asteroid. For v2,
use `package_name: "@opencode/cli"` and its installed version. Each record must
describe **one installation and one server's sign-in flow**, never facts merged
from different machines, packages, or servers.

| Field | Owner evidence required |
| --- | --- |
| `package_name`, `version` | Installed artifact/package inventory, for example existing `npm ls -g opencode-ai @opencode/cli` output. Resolve which installation actually launches the browser. Use exact canonical upstream releases. |
| `platform` | `windows`, `wsl`, `linux`, or `macos`; `linux` explicitly means native Linux, excluding WSL. Do not map WSL's Node `process.platform = linux` to native Linux. |
| `browser_launcher` | `powershell` for the effective Windows/WSL launcher path; `native` only for a verified path bypassing PowerShell. Establish from the deployed source, dependency resolution, and launcher configuration. |
| `remote_mcp_oauth_enabled` | Boolean from effective configuration of this remote server, including OAuth discovery defaults. A local server or explicitly disabled OAuth does not match. |
| `authorization_endpoint_untrusted` | Boolean describing whether the server/discovery chain can supply an endpoint outside the owner's control. A vetted hostname or HTTPS certificate alone does not prove owner control; compromise or changed discovery can still affect trusted servers. |
| `user_initiated_oauth` | Boolean from existing user-action/audit evidence of sign-in to this server, not merely a configured connection. |
| `oauth_browser_launch_requested` | Boolean from existing flow evidence that the application handed the sign-in URL to its browser launcher. False for v2 CLI print-only flows, manual copy/paste, cached-auth flows without a redirect, or canceled flows before browser launch. |

Do not initiate an untrusted OAuth flow to gather evidence. Missing or unknown
values should be omitted or null, never guessed. Do not include tokens, client
secrets, authorization URLs, or full configuration dumps. The assessor emits
only its shared result fields and does not echo arbitrary input values.

All prerequisites must be true for `potential_exposure`. A checked prerequisite
that is verified absent, or a release outside the affected interval within the
verified major line, yields `not_matched` for this issue only. Checks stop at the
first decisive or missing condition. Missing/ambiguous prerequisites,
unknown package/major lines, prereleases, and custom/backport version strings
yield `inconclusive`. The result preserves `cve_ids: []` and names the no-CVE
issue in `reason`. Even a positive result leaves exploitability and backports
unconfirmed; owner assertions are not independently authenticated. A patched
dependency under an unchanged upstream version needs manual verification.

The implementation reuses the shared release parser and assessment result,
adds one `OpenCode` entry in `agent/utils/inventory.py`, and deliberately does
not enter the network exploit registry or `custom_cve_list`. No target requests,
OAuth callbacks, shell payloads, or process launches are implemented.

## Evidence and local validation

Implementation sequence: establish the existing inventory test baseline; write
failing dispatch/applicability tests; implement the pure assessment and additive
dispatch; test both release boundaries, unknowns, absent prerequisites, v2
print-only and WSL-native controls; run Ruff and mypy; review and commit locally.

Primary source evidence reviewed:

- [Researcher disclosure](https://www.pillar.security/blog/open-and-shut-remote-code-execution-in-opencode-via-mcp-oauth): v1 affected matrix, root cause, and disclosure timeline. The [starting Ostorlab article](https://blog.ostorlab.co/opencode-mcp-oauth-signin-rce-windows.html) also identifies the v2 line.
- [Introduction commit 509e43d6](https://github.com/anomalyco/opencode/commit/509e43d6) and [v1.0.137 MCP source](https://github.com/anomalyco/opencode/blob/v1.0.137/packages/opencode/src/mcp/index.ts): explicit `authenticate` browser call versus ordinary connection callback.
- [v1.18.32 MCP source](https://github.com/anomalyco/opencode/blob/v1.18.32/packages/opencode/src/mcp/index.ts): remote/OAuth guards, empty-authorization-URL control, and browser handoff.
- [v1 patch #51414 / 29f07e0c](https://github.com/anomalyco/opencode/pull/51414): centralized opener, OAuth boundary scheme checks, `open` 10.1.2 to 11.0.4. Regression tests reject invalid URLs, file/custom/JavaScript/UNC schemes and verify HTTP(S) forwarding; they do not establish that scheme checks alone prevent shell injection.
- [v1.18.32 manifest](https://github.com/anomalyco/opencode/blob/v1.18.32/packages/opencode/package.json) and [v1.18.33 manifest](https://github.com/anomalyco/opencode/blob/v1.18.33/packages/core/package.json): dependency change at the published fix boundary.
- [v2 patch #51412 / 29ce49db](https://github.com/anomalyco/opencode/pull/51412): equivalent opener/dependency change and regression tests for non-HTTP OAuth endpoints and invalid browser URLs.
- [v2.0.0 CLI manifest](https://github.com/anomalyco/opencode/blob/v2.0.0/packages/cli/package.json), [v2.0.17 CLI manifest](https://github.com/anomalyco/opencode/blob/v2.0.17/packages/cli/package.json), and [v2.0.18 util manifest](https://github.com/anomalyco/opencode/blob/v2.0.18/packages/util/package.json): vulnerable dependency at the initial/final affected releases and fixed dependency at 2.0.18.
- [v2.0.17 CLI auth handler](https://github.com/anomalyco/opencode/blob/v2.0.17/packages/cli/src/commands/handlers/mcp/auth.ts), [v2.0.0 integration dialog](https://github.com/anomalyco/opencode/blob/v2.0.0/packages/tui/src/component/dialog-integration.tsx), and [v2.0.17 integration dialog](https://github.com/anomalyco/opencode/blob/v2.0.17/packages/tui/src/component/dialog-integration.tsx): print-only CLI versus browser-opening TUI paths.
- [open 10.1.2 source](https://github.com/sindresorhus/open/blob/v10.1.2/index.js) and [quoting fix 274d704](https://github.com/sindresorhus/open/commit/274d704): actual PowerShell interpolation and WSL branch conditions; the fix also adds backtick URL regression tests. These browser-opening upstream tests were inspected, not executed.
- npm [opencode-ai metadata](https://registry.npmjs.org/opencode-ai) and [@opencode/cli metadata](https://registry.npmjs.org/@opencode/cli): 1.0.137 published December 9, 2025; 1.18.32 September 21, 2026; 1.18.33 September 28, 2026; 2.0.0 September 11, 2026; 2.0.17 and 2.0.18 September 25, 2026.

Local tests use synthetic normalized owner records. They validate applicability
and dispatch, not exploitation. Network connection and subprocess creation are
blocked in the CLI integration test. No public or production target was probed.

Validation on the dedicated worktree:

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /tmp/opencode-test-venv/bin/python -m coverage run \
  --branch --source=agent.exploits.opencode_mcp_oauth -m pytest -q \
  tests/exploits/opencode_mcp_oauth_test.py tests/utils/inventory_test.py
/tmp/opencode-test-venv/bin/python -m coverage report -m
ruff check agent/exploits/opencode_mcp_oauth.py agent/utils/inventory.py tests/exploits/opencode_mcp_oauth_test.py
ruff format --check agent/exploits/opencode_mcp_oauth.py agent/utils/inventory.py tests/exploits/opencode_mcp_oauth_test.py
mypy --follow-imports=silent agent/exploits/opencode_mcp_oauth.py agent/utils/inventory.py tests/exploits/opencode_mcp_oauth_test.py
git diff --check
```

Results: 97 tests passed; the new assessor has 100% statement and branch
coverage; targeted Ruff format/lint and mypy checks passed. The pre-change
inventory baseline passed 10 tests in the temporary environment; the new
positive dispatch test first failed as expected with `inconclusive` before
implementation. The default environment could not collect tests because
`cloudscraper` was missing. A Python 3.14 environment under `/tmp` supplied
missing dependencies without repository dependency changes. Existing Paramiko
and SQLAlchemy deprecation warnings remain. The full repository suite and
upstream browser-opening tests were not run.
