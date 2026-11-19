# Critical advisory coverage audit, 24 October 2026

Window: **22 October 2026 09:27 UTC through 24 October 2026 09:27 UTC**
(10:27 local time in Africa/Casablanca). Sources were checked on 24 October.
Baseline: `c97b77c` on `main`. This is a reviewed advisory set, not an assertion
that every CVE published worldwide in the window has been enumerated.

## Candidate reconciliation

| Product and CVEs | Why considered | Baseline coverage | Safe assessment and limitations |
| --- | --- | --- | --- |
| Arista VeloCloud Orchestrator, CVE-2026-114625 | Vendor disclosure 22 October; confirmed exploitation; KEV addition 23 October. CVSS 3.1 9.9 /4.0 9.4. | Missing | Offline inventory check using an explicitly verified on-premises deployment and full four-component release. The real version API normally requires authentication and has no deployment discriminator. Hosted/Dedicated services were already patched. No SQL injection, privilege changes, or access to internal services. |
| HPE AOS-8/AOS-10, CVE-2026-79844 through CVE-2026-79876 | Bulletin HPESBNW05162 released 22 October 16:00 UTC. **33 critical CVEs** out of 72 total. | Missing | One SNMP sysDescr GET on an explicitly supplied UDP/SNMP 161 service. Match actual ArubaOS product and release; report only CVEs applicable to that OS family. No PAPI packets, SNMP walks, writes, or community guessing. Missing or protected metadata is inconclusive. |
| Okta Access Gateway, CVE-2026-115547 | Vendor disclosure 22 October; CVSS 3.1 9.1. Requires an authenticated administrator. | Missing | Read advertised OAG product/version metadata, if available; before 2026.10.2 is potentially affected. Do not submit configuration or test command execution. Okta's documented footer is normally visible after sign-in; hidden version information is inconclusive. |
| Collabora Online built-in CODE server for Nextcloud, CVE-2026-110447 | Originally disclosed 14 October; materially updated by KEV inclusion 23 October. Vendor CVSS 4.0 9.2; confirmed exploitation. | Missing | Read the installed app's `appinfo/info.xml` only if exposed; require the exact `richdocumentscode` app identity and version before 26.4.303. Do not call `proxy.php`, start/stop CODE, or infer the app version from Nextcloud or standalone Collabora versions. Disabling the app is insufficient remediation. |
| LiteLLM, CVE-2026-114612 / GHSA-7hp6-4w63-5g45 | CVE published 22 October 18:01 UTC; upstream advisory and fixes date from 30 September. Upstream CVSS 3.1 9.9. | Missing | Inspect the generated OpenAPI schema for product/version metadata only. No API-key creation, credential replay, admin session, or MCP client registration. Experimental login configuration and backports require local verification. |
| Kiloview E3, CVE-2026-107861, CVE-2026-110243, CVE-2026-109122 | CISA ICSA-26-295-01 dated 22 October; critical authenticated command injections, fixed firmware 1.30. | Missing | GET `/api/systemctrl/system/getSystemInfo`, documented in the official E3 API manual. Require `product=E3`, `oem=kiloview`, and actual `softwareVersion`; ignore serial numbers and hardware/NDI versions. Authentication failure is inconclusive; never log in, forge sessions, or submit configuration. |
| PHP, CVE-2026-115560 | New informational advisory 23 October. **No published vendor CVSS score** at verification. | Missing | The unusual serialize-handler transition and upload-progress setting require application/configuration evidence. An enabled feature, a session cookie, or an old PHP version alone does not establish this CVE. Disable `session.upload_progress.enabled=0` and restart workers pending the regular fix. |
| PHP, CVE-2026-109618 and CVE-2026-109619 | Original disclosure 21 October; significant exploitation research and downstream updates within the window. CVSS 4.0 9.2 each. | Present, with incorrect release boundaries | Correct fixed upstream releases to 8.2.35, 8.3.36, 8.4.27, 8.5.12. Distributor backports require inventory verification. Existing normal upload-progress probing is feature evidence only, not proof of memory corruption. Preserve existing finding identities. |
| GitLab CE/EE, CVE-2026-110264 | Critical 10.0 issue reported widely in the window; original vendor disclosure 21 October, explicitly outside the window. | Missing | Catch-up item: offline assessment of trusted product/version inventory, comparing each maintenance branch separately. The vendor version API requires authentication, and the current Help page hides the version before sign-in. No regular-expression compilation or Org-mode rendering. |
| Node/Brotli, CVE-2026-111497 | CNA record/research 22 October; Node security release 21 October. CNA CVSS 4.0 9.2; Node rates it High. | Present | No duplicate detector. |
| Envoy, CVE-2026-111497 / GHSA-3wvj-j6qm-62mr | Critical 9.2 downstream advisory 23 October. | CVE present for Node; Envoy product coverage missing | Offline inventory check requires a verified Envoy release and enabled Brotli decompressor. Vendor explicitly lists 1.39.2, 1.38.5, 1.37.7, 1.36.11; do not extrapolate to every earlier release. No compressed payload or complete configuration dump is requested. |
| TeamCity, CVE-2026-63077 | Search results linked an older updated bulletin; original disclosure predates window. | Present | No duplicate detector. |

## Excluded or unresolved candidates

- **NGINX CVE-2026-15176, CVE-2026-93479, CVE-2026-97205:** original
  disclosure 14 October, with fixes available before this window. F5 rates
  them 9.2; upstream NGINX labels them medium. No verified new change in this
  window; do not recast older headlines as newly disclosed flaws.
- **FortiSIEM CVE-2026-106173:** CERT-In issued a 23 October notice, but the
  underlying vendor disclosure/fix predates the window. No newly verified
  technical change identified during this pass.
- **Bifrost CVE-2026-90898:** September disclosure. A secondary source claimed
 23 October exploitation; no primary evidence corroborating that dated claim
  was established. Retain as WATCH, not confirmed exploitation.
- **Azure CVE-2026-97785, CVE-2026-83938, CVE-2026-110063,
  CVE-2026-105014:** 22 October cloud-service disclosures, already mitigated by
  Microsoft. A customer-side version probe cannot detect historical exposure;
  no exploit or cloud-control-plane test belongs in Asteroid for these.
- **LiteLLM 1.107.0 supply-chain incident:** compromised release 21 October;
  Microsoft published detailed analysis 23 October. This is an artifact/recovery
  investigation, separate from CVE-2026-114612. A remote version banner cannot
  prove a wheel/image digest or whether credentials were stolen. Verify local
  artifacts, isolate/rebuild exposed environments, and rotate exposed secrets
  according to the maintainer incident report.
- Strands Agents CVE-2026-115419, Aider CVE-2026-115726, and Java ADK
  CVE-2026-107858 are below the critical severity threshold for this change.
- **Bun HTTP/3 QPACK GHSA-cf8x-9m69-3gg3:** vendor rates it High, not Critical.
  Bun's Brotli advisory GHSA-663w-cv8g-jj2p also rates that downstream issue High;
  the underlying CVE-2026-111497 already has Node coverage. Bundled Bun exposure
  is not established by that Node check.

## KSMBD: researched gaps requiring deployed-source verification

**ZDI-CAN-33549 and ZDI-CAN-33774** are critical 9.0 reports covered by the
[23 October government warning](https://csirt.sk/posts/4181.html).
They do not have verified released-kernel fixed-version boundaries in the
sources reviewed. No synthetic Linux-version or open-SMB-port detector is added:
neither establishes that the deployed kernel contains the affected code.

Maintainer fixes exist; this is not a claim that no fix is available:

- For ZDI-CAN-33774, verify the deployed source/build includes
  [fix 68f410faedaf6ee74d81e574733c50ebcc1bd8ed](https://git.kernel.org/pub/scm/linux/kernel/git/linkinjeon/smb.git/commit/?id=68f410faedaf6ee74d81e574733c50ebcc1bd8ed)
  or an equivalent vendor backport. The [LKML discussion](https://lore.landau.one/lkml/BYAPR01MB383076AC412E19C48CFBEAE980662@BYAPR01MB3830.prod.exchangelabs.com/T/)
  documents the race and test environment. Verify KSMBD service exposure and the
  relevant share/authentication configuration independently.
- For ZDI-CAN-33549, compare the deployed SMB Direct source against the
  [23 October maintainer patch](https://lkml.rescloud.iu.edu/2610.2/18418.html),
  commit `5b8ce2e5670ebe31970b6718403197ae51d47e43`, fixing buffer-length underflow
  in `fs/smb/smbdirect/rw.c`. Verify `CONFIG_SMB_SERVER_SMBDIRECT`, RDMA and the
  relevant share access; generic TCP 445 exposure does not establish this path.

Absent a trusted mapping from deployed builds to those changes, the result is
**inconclusive**, not a positive CVE finding. Restrict KSMBD access while owners
verify source provenance and distribution updates. Revisit automatic coverage
when authoritative vendor patch matrices are published.

## Primary references

- [Arista advisory 0199](https://www.arista.com/en/support/advisories-notices/security-advisory/24838-security-advisory-0199)
  and [Cyber Centre KEV update](https://www.cyber.gc.ca/en/alerts-advisories/arista-networks-security-advisory-av26-1080).
- [HPE bulletin](https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05162en_us&docLocale=en_US),
  [HPE CSAF](https://csaf.arubanetworking.hpe.com/2026/hpe_networking_-_hpesbnw05162.json),
  [HPE AOS-10 version output](https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos10/sh-version.htm),
  [Recog SNMP examples](https://github.com/rapid7/recog/blob/main/xml/snmp_sysdescr.xml).
- [Okta command-execution advisory](https://trust.okta.com/security-advisories/command-execution-via-admin-console-input-in-okta-access-gateway-cve-2026-115547),
  [Okta version-identification instructions](https://help.okta.com/oag/en-us/Content/Topics/Access-Gateway/determine-oag-version.htm).
- [Collabora advisory](https://github.com/CollaboraOnline/online/security/advisories/GHSA-g3vx-3m76-fghh),
  [upstream app manifest](https://github.com/CollaboraOnline/richdocumentscode/blob/master/appinfo/info.xml),
  [NVD KEV record](https://nvd.nist.gov/vuln/detail/CVE-2026-110447).
- [LiteLLM advisory](https://github.com/BerriAI/litellm/security/advisories/GHSA-7hp6-4w63-5g45),
  [CVE publication record](https://osv.dev/vulnerability/CVE-2026-114612),
  [maintainer supply-chain incident report](https://docs.litellm.ai/blog/security-incident-oct-21-2026),
  [Microsoft artifact analysis](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/).
- [Kiloview CISA advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-01),
  [CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-110243),
  [vendor E3 API manual, section 1.3.15](https://cnstatic.kiloview.com/wp-content/uploads/2026/02/E3-WEB-API%E8%AF%B4%E6%98%8E%E4%B9%A6-cnVersion-1.21.0008-1.pdf).
- [Envoy critical advisory](https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr),
  [Bun Brotli advisory](https://github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p),
  [Bun HTTP/3 advisory](https://github.com/oven-sh/bun/security/advisories/GHSA-cf8x-9m69-3gg3).
- Microsoft public advisory records, each declaring customer action unnecessary
  and Microsoft mitigation complete:
  [AAD App Proxy](https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2026-97785),
  [Azure Kubernetes Configuration Service](https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2026-83938),
  [VM Inspector](https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2026-110063),
  [Azure Pipelines](https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2026-105014).
- [PHP notices](https://www.php.net/),
  [Cyber Centre update](https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619),
  [AWS telemetry](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/),
  [VulnCheck 23 October exploit research](https://docs.vulncheck.com/initial-access/2026-10-23).
- [GitLab vendor release](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/),
  [Node release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases),
  [NGINX advisories](https://nginx.org/en/security_advisories.html),
  [FortiSIEM CERT-In notice](https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIVN-2026-0521&pageid=PUBVLNOTES01).

Coverage gaps: CISA direct pages and Fortinet PSIRT returned 403 to the research
browser; corresponding government/CNA records were used where available.
No customer inventory or production scan was accessed or run.
