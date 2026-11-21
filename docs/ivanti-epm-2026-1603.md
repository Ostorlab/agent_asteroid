# Ivanti Endpoint Manager CVE-2026-1603 RemoteControlAuth authentication bypass

**CVE-2026-1603** is an access-control vulnerability in Ivanti Endpoint
Manager that can expose RemoteControl sessions to unauthenticated callers
(CWE-284).

```text
POST /RemoteControlAuth/api/Auth    {"logintype":"64","username":"administrator"}
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-1603> (published 2026-02-10, CVSS 3.1 8.6).
- Ivanti advisory: <https://hub.ivanti.com/s/article/Security-Advisory-EPM-February-2026-for-EPM-2024?language=en_US>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-1603>.

## How the detection confirms it
One anonymous `POST` requesting a session for `administrator`. A finding needs HTTP 200 and a non-null `sessionid` in the JSON body. No further action is taken; the request is bounded.

## Remediation
Apply the Ivanti EPM February 2026 update and restrict access to the RemoteControlAuth API.
