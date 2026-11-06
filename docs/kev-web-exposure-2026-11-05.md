# Anonymous web metadata exposure checks — 2026-11-05

This batch registers four remote metadata checks covering seven CVE identifiers.
A finding means **POTENTIAL EXPOSURE; exploitability unconfirmed**. It records a
corroborated product and advertised affected release, without asserting that the
vulnerable feature, configuration, permissions or exploit chain was verified.
`has_public_exploit=False` describes these release assessments, not the existence
of third-party exploit code.

Each `accept()` or `check()` performs one anonymous GET to the target origin and
fixed metadata path. The shared transport defaults to at most 256 KiB. The new
LiteLLM check explicitly allows up to 8 MiB for its larger OpenAPI document; this
constant is not controlled by target metadata. Both limits use a five second
requests timeout, reject redirects and non-200 responses, and close responses.
The timeout is a socket timeout, not an overall wall-clock deadline.
Session auth, cookies, headers, client certificates and netrc credentials are not
attached. Scanner TLS verification and explicitly configured proxies are retained.
Target paths and queries are discarded. Findings contain the origin and validated
release only; raw responses, instance identifiers and machine identifiers are not
included. Malformed or duplicate JSON keys and ambiguous evidence yield no finding.

| Detector | Metadata evidence | Affected release assessment | Prerequisites left unverified |
| --- | --- | --- | --- |
| LiteLLM CVE-2026-59822 | `/openapi.json`: supported OpenAPI marker, `info.title=LiteLLM API`, canonical three-part stable version, GET readiness and POST key-generation route shapes | Stable versions below 1.84.0 | MCP availability, OAuth2 passthrough credential fallback behavior, access controls and backports |
| Kestra CVE-2026-49869 | `/api/v1/configs`: `edition=OSS`, canonical version, boolean task-run/Basic Auth fields, nonempty system namespace and integer plugin hash | Below 1.0.45, or at least 1.1.0 and below 1.3.21 | Effective Basic Auth bypass, script plugins/settings, workflow privileges, execution and backports |
| Plex CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656 | `/identity` with `Accept: application/json`: `MediaContainer` containing integer size, boolean claimed status, nonempty machine identifier and canonical four-part version, optionally followed by a hexadecimal build suffix | Known 1.x releases below 1.43.3.10861; unknown major branches remain inconclusive | Chain reachability, individual stage access, authenticated user/admin privileges, configuration and backports |
| ownCloud CVE-2023-49105 | `/status.php`: installed=true, boolean maintenance/upgrade fields, both product fields exactly ownCloud, canonical public release agreeing with the internal version's first three components | 10.6.0 through 10.13.0 inclusive; fixed in 10.13.1 | Known victim username, absence of a signing key, WebDAV exploitability and backports |

The advertised LiteLLM POST route is inspected only as JSON; it is never called.
Kestra is queried only at its ordinary configuration endpoint. No bypass suffixes,
workflow creation or script execution are attempted. Plex reports one family
finding and includes all four CVE identifiers; this does not imply four independent
pre-authentication exploits. No tokens, subscriptions, SSRF destinations, transcode
requests or preferences are submitted. ownCloud performs no WebDAV read, upload,
file change or pre-signed URL request.

## Sources and interpretation

- LiteLLM's [vendor advisory](https://github.com/BerriAI/litellm/security/advisories/GHSA-7488-6r32-c95q)
  supplies the 1.84.0 boundary and MCP prerequisites. The OpenAPI contract follows
  affected [v1.83.7-stable proxy implementation](https://github.com/BerriAI/litellm/blob/v1.83.7-stable/litellm/proxy/proxy_server.py),
  which supplies the FastAPI title and package version. The
  [health router](https://github.com/BerriAI/litellm/blob/v1.83.7-stable/litellm/proxy/health_endpoints/_health_endpoints.py)
  and [key management router](https://github.com/BerriAI/litellm/blob/v1.83.7-stable/litellm/proxy/management_endpoints/key_management_endpoints.py)
  establish the required GET/POST route shapes. The proxy's `0.0.0` fallback when
  version import fails is rejected as ambiguous. CVE-2026-114612 is outside this
  fix's scope; its release ranges and default response cap are unchanged.
- Kestra's [vendor advisory](https://github.com/kestra-io/kestra/security/advisories/GHSA-5vc5-wxxq-3fjx)
  identifies the OSS filter bug and the two patch releases. The precise split
  ranges come from the [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/49xxx/CVE-2026-49869.json).
  The [configuration controller](https://github.com/kestra-io/kestra/blob/v1.0.44/webserver/src/main/java/io/kestra/webserver/controllers/api/MiscController.java)
  and [edition provider](https://github.com/kestra-io/kestra/blob/v1.0.44/core/src/main/java/io/kestra/core/utils/EditionProvider.java)
  establish endpoint fields and OSS/EE values. A task-run flag does not establish
  enabled script execution.
- Plex's [official API](https://developer.plex.tv/pms/) documents anonymous
  `GET /identity` and the explicit JSON Accept header; XML is the default.
  The [vendor security update](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319/1)
  identifies the four-stage chain and exact 1.43.3.10861 fix. Older release thread
  build 10828 is not evidence of the fix. Machine identity is checked for type and
  presence but never reported.
- ownCloud's [vendor advisory](https://owncloud.com/security-advisories/webdav-api-authentication-bypass-using-pre-signed-urls/)
  identifies the affected range and signing-key/username conditions. The
  [status endpoint](https://github.com/owncloud/core/blob/v10.13.0/status.php) calls
  [the status metadata producer](https://github.com/owncloud/core/blob/v10.13.0/lib/public/Util.php).
  Product fields can be themed and versions can be hidden, so those deployments
  intentionally remain inconclusive. The [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2023/49xxx/CVE-2023-49105.json)
  identifies 10.13.1 as the fixed boundary.

## Verification and limitations

Tests use public `accept()`/`check()` interfaces and offline HTTP adapter fixtures.
They cover affected lower bounds and exact patch boundaries, alternate/unknown
branches, prereleases, malformed strings, conflicting product evidence and types,
duplicate JSON keys, malformed/oversized bodies, network failures, redirects,
authentication challenges, credential isolation, fixed metadata paths and finding
redaction. Agent-level selection tests exercise each of the seven CVE identifiers,
including each Plex family member. Shared helper tests retain compatibility with
existing detectors and the earlier LiteLLM CVE.

The LiteLLM regression fixture is a static, reduced schema derived from affected
v1.83.7-stable source. It retains 521 path/method entries and has a serialized size
of 276,878 bytes, already beyond the previous 262,144-byte limit. The committed
[compact structure](../tests/exploits/fixtures/cve_2026_59822/openapi-structure.json)
stores description byte counts; tests reconstruct same-length neutral text instead
of copying upstream descriptions. Its
[provenance](../tests/exploits/fixtures/cve_2026_59822/provenance.json) records source
URLs and hashes, the original reduced fixture hash, and the sanitized fixture hash.
It is a reduced lower-bound fixture, not a complete live affected-version export
or a proven maximum schema size.

As a separate sizing reference, the official
[current OpenAPI export](https://docs.litellm.ai/openapi.json) measured 2,044,774
bytes with `info.version=1.108.0` on 2026-11-05. That newer export supports choosing
an 8 MiB bounded allowance; the provenance file includes its immutable source URL
and hash. It is not evidence of the full historical export's size. Tests accept
exactly 8 MiB and reject 8 MiB plus one byte, and still reject
duplicate version keys in the larger historical fixture.

The tests validate the implemented contracts against published metadata schemas;
they are not evidence from deployed target instances. No live target was probed.
Hidden, rebranded, redirected or authenticated metadata can produce false negatives.
Canonical version metadata can be stale, spoofed or patched without changing the
reported release. No finding therefore does not establish that a target is safe;
a finding requires authorized configuration/package review to confirm exploitability.
