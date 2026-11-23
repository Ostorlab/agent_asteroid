# CyberPanel CVE-2024-51567 pre-auth command injection

**CVE-2024-51567** is a pre-auth remote command execution in CyberPanel through
2.3.6 (and unpatched 2.3.7), exploited in the wild by the PSAUX campaign in
October 2024 (CWE-306). `upgrademysqlstatus` in `databases/views.py` only guards
POST requests through `secMiddleware`, so a `PUT` to
`/dataBases/upgrademysqlstatus` bypasses authentication, and shell metacharacters
in the `statusfile` field run arbitrary commands.

```text
GET /
PUT /dataBases/upgrademysqlstatus
{"statusfile":"/dev/null; echo $((a*b)); #","csrftoken":"<token>"}
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-51567> (published 2024-10-29, CWE-306, CVSS 3.1 10.0).
- dreyand.rs write-up: <https://dreyand.rs/code/review/2024/10/27/what-are-my-options-cyberpanel-v236-pre-auth-rce>.
- CyberPanel community advisory: <https://community.cyberpanel.net/t/cyberpanel-2-1-remote-code-execution-rce/31760>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-51567>.

## Affected and fixed versions
CyberPanel **through 2.3.6** and unpatched **2.3.7**. Upgrade to a patched release
beyond 2.3.7.

## How the detection confirms it
The reader reads the anonymous `csrftoken` cookie from `GET /`, then sends an
unauthenticated `PUT` whose `statusfile` injects `echo $((a*b))` with a random
product never placed on the wire. A finding needs HTTP 200 and a `requestStatus`
JSON reporting the evaluated product, proving command execution. The payload
writes only to `/dev/null` and echoes a number; no state is changed and redirects
are not followed.

## Remediation
Upgrade CyberPanel beyond 2.3.7, restrict network access to the management
interface, and review for compromise given in-the-wild exploitation.
