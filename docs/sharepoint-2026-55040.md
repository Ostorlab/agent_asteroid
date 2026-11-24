# CVE-2026-55040: Microsoft SharePoint Server JWT authentication bypass

**CVE-2026-55040 is an authentication bypass** in Microsoft SharePoint Server
(CWE-1390, CVSS 3.1 9.1). The `SPJsonWebSecurityTokenHandlerV2` validation
pipeline disables signature requirements (`RequireSignedTokens=false`, accepting
`alg:none` tokens), resolves the actor-token `x5t` thumbprint against the
server's own STS signing certificate — published unauthenticated at
`/_layouts/15/metadata/json/1` — without verifying the signature, and only
checks that the actor-token signature is non-empty. An unauthenticated remote
attacker can therefore forge a JWT and authenticate as any SharePoint user.

**Affected:** Microsoft SharePoint Server (on-premises) without the
CVE-2026-55040 security update.

**Fixed:** the Microsoft SharePoint Server security update for CVE-2026-55040.

**Severity:** CVSS 3.1 9.1 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

## How does the detector verify it?

This is an **active, non-destructive** check. It reads the STS metadata
anonymously, computes the signing certificate's SHA-1 thumbprint, forges an
`alg:none` outer token wrapping an actor token bound (unsigned) to that
thumbprint, and confirms the bypass by obtaining a SharePoint form digest:

```
1. GET  /_layouts/15/metadata/json/1          -> issuer (realm) + STS certificate
2. compute x5t = base64url(sha1(certificate DER))
3. forge actor token  {alg:RS256, x5t} . {iss, nameid} . AAAA   (unsigned)
   forge outer token  {alg:none} . {aud, iss, nameid, actortoken} .  (empty sig)
4. POST /_api/contextinfo   Authorization: Bearer <forged outer token>
# confirm: a garbage token is refused, then the forged token returns
#          HTTP 200 with "FormDigestValue"
```

`/_api/contextinfo` only returns a request-digest token (the value a client
fetches *before* performing any write); returning it is not itself a state
change, so the probe reads the digest and writes nothing. The check first proves
a garbage token (`invalid.invalid.invalid`) is refused; only if the forged
`alg:none` token is then accepted with a form digest is the bypass reported, so a
server that hands a digest to any caller is not flagged. The forged
`Authorization` header is sent on an isolated prepared request (never
`Session.prepare_request`), so no scanner cookie or auth is merged; reads are
bounded and no redirect is followed. The SHA-1 use is an X.509 certificate
thumbprint (`usedforsecurity=False`), not a security primitive.

**Limitation:** the check forges the well-known `nt authority\local service`
system identity and requires a `FormDigestValue` in the response. A deployment
whose STS metadata endpoint is not reachable, or that only yields the bypass for
a different forged identity, is not reported (a conservative false negative,
never a false positive).

## Remediation

Apply the Microsoft SharePoint Server security update for CVE-2026-55040 and
restrict network access to SharePoint. Because authentication can be bypassed,
review for unauthorized access to SharePoint APIs and content.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-55040> (published 2026-07-14,
  CWE-1390, CVSS 3.1 9.1).
- Rapid7 analysis:
  <https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040/>.
- Proof of concept (sfewer-r7): <https://github.com/sfewer-r7/CVE-2026-55040>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-55040>.
