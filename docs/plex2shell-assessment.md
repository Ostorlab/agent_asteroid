# Plex2Shell owner-inventory assessment

Coverage: **offline potential chain exposure**, not remote detection or confirmed
exploitation. `agent/exploits/cve_2026_96656.py` assesses all four chain members
through `python -m agent.utils.inventory inventory.json`. It is deliberately
absent from the remote exploit registry and `custom_cve_list`.

## Verified applicability and severity (29 October 2026)

The [Plex vendor notice](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319)
identifies the four-CVE unauthenticated RCE chain and states that
**1.43.3.10861 and later are unaffected**. The CNA records mark releases below
that build affected. Use numeric comparison of all four components; 1.43.3.10828
is still in range.

| CVE / primary CNA record | Individual vulnerability | CVSS 3.1 | CVSS 4.0 |
| --- | --- | --- | --- |
| [CVE-2026-96652](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/96xxx/CVE-2026-96652.json) | Companion `/player/timeline` SSRF with an arbitrary token value | 4.3 | 5.3 |
| [CVE-2026-96654](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/96xxx/CVE-2026-96654.json) | `searchOne` URL injection into internal plugin function calls | 6.5 | 6.9 |
| [CVE-2026-96655](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/96xxx/CVE-2026-96655.json) | Authenticated arbitrary-address transcoder SSRF | 4.3 | 5.3 |
| [CVE-2026-96656](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/96xxx/CVE-2026-96656.json) | Administrator-controlled transcoder preference permits file writes that can lead to code loading | 7.2 | 8.6 |

The [researcher's chain rating](https://github.com/code-zm/plex2shell) is CVSS 3.1
**9.8**, vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. This is a combined-chain
rating, not the severity of any individual member. The inventory result has no
severity field; its `cve_ids` list identifies chain membership, not four separate
confirmed findings. CVE-2026-96651 is outside this assessment.

The vendor's short table labels 96655 as owner-token disclosure, whereas its CNA
record describes transcoder SSRF. The researcher also groups some primitives
differently. The individual descriptions above follow the CNA records; the
combined assessment follows the vendor's fixed-build statement. The
[starting blog](https://blog.ostorlab.co/plex2shell-plex-rce-cve-2026-96656.html)
was a discovery source, not the sole basis for applicability.

The [1.43.3.10861 release notes](https://forums.plex.tv/t/plex-media-server/30447/712)
identify a CompanionProxy security fix (PM-5763) and removal of network updates
to both H.264 transcoder option preferences (PM-5766). No public vendor source
patch or vendor vulnerability regression suite was located. The
[researcher's tests](https://github.com/code-zm/plex2shell/blob/main/detection/tests/run_tests.sh)
exercise synthetic compromise artifacts and YARA/hunt rules, not vulnerable
versus patched servers. They were inspected, not executed. The linked researcher
write-up returned HTTP 403; the available repository and CNA records supplied
the primary technical evidence. No exploit or payload was executed.

## Normalized evidence contract

The owner must collect and verify evidence for the **same running installation**.
This is an Asteroid schema, not a raw Plex API response. The assessor trusts the
supplied assertions; it does not authenticate them or collect host data.

| Field | Required evidence |
| --- | --- |
| `product` | Exactly `Plex Media Server`; Plex Web, Plexamp, ports and branding do not identify the server build. |
| `version` | Four canonical numeric components from running server/package evidence, e.g. `1.43.3.10828`. Verify any package hash suffix against vendor metadata before normalizing; never truncate arbitrary custom version strings. |
| `official_vendor_build` | Boolean `true` only for verified vendor build provenance. Custom builds remain inconclusive, even with a high version. |
| `plex2shell_backport_applied` | For older builds, explicit boolean indicating an owner-verified equivalent chain fix applied to the running installation. `false` means the owner verified no equivalent backport, not merely that the field was unavailable. |
| `untrusted_clients_reach_companion` | Boolean from effective listener, proxy/authentication and network policy evidence: can an untrusted client reach the Companion timeline handler? Remote Access being enabled, or TCP 32400 being open, is insufficient. Internet exposure is not required when another untrusted network path exists. |
| `legacy_agent_framework_enabled` | Boolean from installed/enabled framework and bundled agent evidence for the documented internal function-call and owner-token pivot. |
| `outbound_http_allowed` | Boolean from effective egress policy: can the service contact untrusted HTTP destinations for the documented pivot and media-fetch steps? Do not induce callbacks or disclose a token to determine this. |
| `transcoder_available` | Boolean from effective installation/configuration showing that the service can invoke its transcoder. |
| `codec_directory_writable` | Boolean from filesystem ownership/ACL and mount evidence showing that the service identity can write its codec directory. Do not write test files or load a codec. |

Example `inventory.json`:

```json
[
  {
    "product": "Plex Media Server",
    "version": "1.43.3.10828",
    "official_vendor_build": true,
    "plex2shell_backport_applied": false,
    "untrusted_clients_reach_companion": true,
    "legacy_agent_framework_enabled": true,
    "outbound_http_allowed": true,
    "transcoder_available": true,
    "codec_directory_writable": true
  }
]
```

This produces `potential_exposure`, with exploitability explicitly unconfirmed.
A version or enabled feature alone is insufficient. Missing, malformed, or
ambiguous prerequisites produce `inconclusive`. Verified vendor fixed releases
produce `not_matched` without requiring chain prerequisites. An owner-asserted
equivalent backport also produces `not_matched`, explicitly qualified as not
independently verified. On older builds, complete prerequisite evidence with
one false value produces `not_matched` **for this chain only**; individual CVEs
and alternative paths remain unresolved. No result rules out past compromise.

The CLI emits only its shared assessment fields, never supplied tokens, paths,
or raw records. Do not supply secrets. This implementation performs no network
requests, authentication, preference changes, transcodes, file writes to targets,
or command execution. Local tests cover affected/fixed boundaries, unsupported
products, unknown and malformed evidence, prerequisite controls, dispatch,
sanitized output, and prohibited network/subprocess calls.
