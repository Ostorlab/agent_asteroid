# nginxWebUI CVE-2023-54419 case-variant runCmd bypass

**CVE-2023-54419 is an authentication bypass leading to remote command
execution** in nginxWebUI 3.0.0 before 3.5.8. One capital letter in the request
path is the difference between a 302 to the login page and root-level command
execution.

`AppFilter.doFilter` decides whether a request belongs to the protected admin
area by testing the raw request path with `contains("/adminPage/")`, which is
case-sensitive. The Solon router matches routes case-insensitively by default,
so `/AdminPage/conf/runCmd` does not contain the lowercase filter marker, skips
the login check, and still resolves to `ConfController.runCmd`.

That handler takes the `cmd` parameter, escapes `;`, backtick, `|`, `{` and
`}`, requires the string `nginx`, and then runs the result through
`/bin/sh -c`. The `&` and `$()` metacharacters are not escaped, so an
unauthenticated request can append or substitute arbitrary commands. nginxWebUI
normally runs as root because it manages the nginx service, so the command
execution is usually privileged.

**Affected:** nginxWebUI `>= 3.0.0, < 3.5.8`
**Fixed:** 3.5.8 (commit
[`6b8c9bceb0d210632a35cd324db6b43caf442a23`](https://github.com/cym1102/nginxWebUI/commit/6b8c9bceb0d210632a35cd324db6b43caf442a23))
**Severity:** CVSS 3.1 9.8 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`;
CVSS 4.0 9.3; CWE-178. VulnCheck lists the issue in KEV, and the Shadowserver
Foundation first observed exploitation on 2023-10-14.

## How does the detector verify the bypass?

1. `GET /` must return the nginxWebUI landing document,
   `<title>nginxWebUI</title>`. The landing page is an HTML document that
   JavaScript-redirects to `/adminPage/login`; it is not an HTTP redirect.
2. `GET /adminPage/conf/runCmd?cmd=nginx$(id)` is the control. The exact-case
   path matches the login filter, so an unauthenticated request must be
   refused: 3.4.8 redirects to `/adminPage/login`, and a fixed host does the
   same. If this request executes the command, the deployment has no working
   login filter at all and the case bypass is not the demonstrated cause, so
   the detector returns no finding.
3. `GET /AdminPage/conf/runCmd?cmd=nginx$(id)` is the case variant. On a
   vulnerable host it returns HTTP 200 with a JSON document whose
   `success` is `true`, whose body echoes `nginx$(id)`, and whose text
   contains `id` output shaped `uid=<n>(<name>)`. A fixed host does not route
   the case variant (3.6.2 answers the login redirect) and produces no
   finding.

The command is `nginx$(id)`: it contains the `nginx` substring that `runCmd`
requires, and the unescaped `$()` substitution runs the read-only `id`
command. No credential, cookie or session is sent, no nginxWebUI
configuration is changed, and the only process the probe causes is the shell
running `id` inside the substitution. Because the payload has no space before
`$()`, the expanded command is `nginxuid=0(root)...` — a single unknown
command name that fails, so the nginx binary itself is never started.

Reproduce the two requests by hand with the same single-quoted URLs the
detector uses. Single quotes stop the local shell from expanding `$()` — the
literal substitution is the payload, and a double-quoted copy would silently
run `id` on your own machine instead of the target:

```sh
# Control: exact-case path, expect the 302 to /adminPage/login
curl -s -i 'http://TARGET:8080/adminPage/conf/runCmd?cmd=nginx$(id)'

# Case variant: expect the success JSON below on a vulnerable host
curl -s 'http://TARGET:8080/AdminPage/conf/runCmd?cmd=nginx$(id)'
```

On a vulnerable 3.4.8 fixture the case-variant request answered:

```
{"success":true,"status":"200","obj":"<span class='blue'>nginx$(id)</span><br>运行失败<br>/bin/sh: 1: nginxuid=0(root): not found<br>"}
```

## What does a positive finding claim?

The finding confirms unauthenticated command execution through the
case-variant admin route, and records the `uid` observed in the command
output. It does not claim that a persistent change, file write, reverse shell
or nginx restart was performed.

## What does the detector miss?

- The probe relies on a Unix `/bin/sh`; a Windows-hosted nginxWebUI takes the
  `cmd /c start` branch, where `$()` does not expand, so the `id` evidence is
  not produced. Such a host is not reported even when the case bypass exists.
- The release is not present on the anonymous landing document. The login page
  leaks it as the `getCode` `t=` value and `/adminPage/about` is behind the
  filter, so the detector cannot attribute the finding to a specific build.
  It reports the demonstrated case bypass, which also matches a later release
  that was left with a case-insensitive router and the same filter defect.
- A reverse proxy that normalizes path case before nginxWebUI sees it defeats
  the bypass and is not reported. A proxy that blocks the case variant is
  likewise not reported.
- A deployment mounted under a custom context path is not probed, because the
  standard paths are not rewritten.
- Network errors, timeouts, redirects, oversized bodies and malformed JSON
  are inconclusive; a missing finding is not proof that the deployment is
  patched.

## How was the detector validated?

The registered detector was run from a separate network client against real
upstream releases: nginxWebUI 3.4.8 (`nginxWebUI-3.4.8.jar`, SHA-256
`61d71a76bd58a8dc11fee8b0d4d301e7d00379325cc2e01b0b3cbd438989ea22`) and
3.6.2 (`nginxWebUI-3.6.2.jar`, SHA-256
`9eb85093875dc8c4942a8d312ed5e216eb028813406585332ea72c494c22b431`) under
Temurin 17.0.21.1.

| Case | Result |
| --- | --- |
| 3.4.8, direct | Detected |
| 3.4.8, via case-preserving TCP proxy | Detected |
| 3.6.2, fixed | Clean |
| Title-only lookalike | Clean |
| Loose JSON lookalike | Clean |
| Unprotected no-case-differential fixture | Clean |

**TP 2 / TN 4 / FP 0 / FN 0 / inconclusive 0 out of 6 cases.**

## How do I remediate and run this check?

**Remediate:** upgrade nginxWebUI to 3.5.8 or later, which makes the router
case-sensitive and lowercases the login-filter comparison, then restart the
service. Until the upgrade, restrict the management port to trusted
administrative networks, require an authenticating reverse proxy that
normalizes path case in front of it, and inspect the `runCmd` history and
nginx configuration for unexpected changes while the instance was exposed.

To check a host for this bypass, restrict a scan to this CVE (see the
[README](../README.md)):

```sh
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2023-54419"]' url http://TARGET:8080
```

A fixed 3.5.8 or later host answers the login redirect on the case variant and
produces no finding.
