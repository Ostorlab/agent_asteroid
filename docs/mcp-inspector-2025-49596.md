# CVE-2025-49596: MCP Inspector unauthenticated RCE via the stdio proxy

**CVE-2025-49596 is an unauthenticated remote code execution** in MCP Inspector
(CWE-306, CVSS 4.0 9.4). There is no authentication between the Inspector client
and the proxy, so an anonymous `GET /sse` can spawn a stdio transport that runs
an arbitrary command.

**Affected:** MCP Inspector < 0.14.1

**Fixed:** MCP Inspector 0.14.1

**Severity:** CVSS 4.0 9.4 (Critical) —
`AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

## How does the detector verify it?

This is an **active, non-destructive, unforgeable** check. It launches a benign
`echo` of a random nonce over stdio and confirms the proxy minted a fresh SSE
message endpoint, which only a proxy that accepted the anonymous command launch
can return:

```
GET /sse?transportType=stdio&command=echo&args[]=<nonce>    Accept: text/event-stream
# vulnerable: HTTP 200, SSE "event: endpoint" / "data: /message?sessionId=<uuid>"
```

The `echo` **writes nothing and changes no state**, and the `sessionId` is a
server-generated token: an authenticated (patched) proxy rejects the anonymous
request and mints no session. The SSE stream is read with a deadline and byte
cap and closed as soon as the endpoint event arrives, so the probe never blocks.
No credential or cookie is sent and redirects are not followed.

**Limitation:** the check confirms the proxy accepted an anonymous stdio command
launch (the RCE primitive) via the minted session, rather than reading the
command's stdout back over the separate message channel. A proxy that accepts
the launch but returns no endpoint event produces no match — a conservative
false negative, never a false positive.

## Remediation

Upgrade MCP Inspector to 0.14.1 or later, which adds authentication between the
client and the proxy. Never expose the Inspector proxy to untrusted networks;
bind it to localhost.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-49596> (published 2025-06-13,
  CWE-306, CVSS 4.0 9.4).
- Project advisory:
  <https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-7f8r-222p-6f5g>.
- Oligo Security write-up:
  <https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-49596>.
