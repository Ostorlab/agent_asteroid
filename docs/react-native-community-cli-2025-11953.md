# React Native Community CLI CVE-2025-11953 Metro open-url command injection

**CVE-2025-11953** is an unauthenticated OS command injection in the Metro
development server started by the React Native Community CLI (CWE-78). Metro binds
to external interfaces and exposes an unauthenticated `/open-url` endpoint that
passes the `url` value to the OS `open()` helper without validating the scheme; on
Windows this reaches `cmd`, giving arbitrary command execution on the developer
machine.

```text
GET  /status
POST /open-url      {"url":"asteroid-probe-<nonce>://x"}
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-11953> (published 2025-11-03, CWE-78, CVSS 3.1 9.8).
- JFrog advisory: <https://jfrog.com/blog/cve-2025-11953-critical-react-native-community-cli-vulnerability/>.
- GitHub advisory GHSA-399j-vxmf-hjvr: <https://github.com/advisories/GHSA-399j-vxmf-hjvr>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-11953>.

## Affected and fixed versions
`@react-native-community/cli-server-api` before the backported fixes. Fixed in
**17.0.1**, **18.0.1**, **19.1.2** and **20.0.0** (the fix for the line in use).
The version number alone does not indicate exposure, so the detection probes
endpoint behaviour.

## How the detection confirms it
The reader fingerprints Metro via `/status` (`packager-status:running` plus the
`x-react-native-project-root` header), then posts a benign unregistered scheme
(`asteroid-probe-<nonce>://x`) with no shell metacharacters, so nothing is
launched. A finding needs HTTP 200 with an empty body and no `Invalid URL`
rejection, i.e. the endpoint performs no scheme validation. No state is changed
and redirects are not followed.

## Remediation
Upgrade `@react-native-community/cli-server-api` to the fixed release for the line
in use, bind Metro to `127.0.0.1`, and block inbound access to the bundler port.
