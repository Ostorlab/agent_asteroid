# nginxWebUI CVE-2023-54419 case-variant runCmd bypass

**CVE-2023-54419 is an authentication bypass leading to remote command
execution** in nginxWebUI 3.0.0 before 3.5.8. `AppFilter.doFilter` decides
whether a request belongs to the protected admin area by testing the raw
request path with `contains("/adminPage/")`, which is case-sensitive. The
Solon router matches routes case-insensitively by default, so
`/AdminPage/conf/runCmd` does not contain the lowercase filter marker, skips
the login check, and still resolves to `ConfController.runCmd`. That handler
takes the `cmd` parameter, escapes `;`, backtick, `|`, `{` and `}`, requires
the string `nginx`, and then runs the result through `/bin/sh -c`. The `&` and
`$()` metacharacters are not escaped, so an unauthenticated request can append
or substitute arbitrary commands. nginxWebUI normally runs as root because it
manages the nginx service, so the command execution is usually privileged.

**Affected:** nginxWebUI `>= 3.0.0, < 3.5.8`
**Fixed:** 3.5.8 (commit `6b8c9bceb0d210632a35cd324db6b43caf442a23`)
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
running `id` inside the substitution. On a vulnerable 3.4.8 fixture the
observed answer was:

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

## Validation

The registered detector was run from a separate network client against real
upstream releases: nginxWebUI 3.4.8 (`nginxWebUI-3.4.8.jar`, SHA-256
`61d71a76bd58a8dc11fee8b0d4d301e7d00379325cc2e01b0b3cbd438989ea22`) and
3.6.2 (`nginxWebUI-3.6.2.jar`, SHA-256
`9eb85093875dc8c4942a8d312ed5e216eb028813406585332ea72c494c22b431`) under
Temurin 17.0.21.1. Results: vulnerable 3.4.8 and the same release through a
case-preserving TCP proxy detected; fixed 3.6.2, a title-only lookalike, a
loose JSON lookalike and an unprotected no-case-differential fixture all
clean. TP 2, TN 4, FP 0, FN 0, inconclusive 0 out of 6 cases.
