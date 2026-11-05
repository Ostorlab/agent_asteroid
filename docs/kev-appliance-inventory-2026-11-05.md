# Offline appliance inventory assessments — 2026-11-05

This batch assesses eleven CVEs from normalized owner evidence. It is **offline inventory coverage**, not automated network coverage, exploitation proof, or an assertion that a device is safe. The modules expose `assess_record(dict[str, object]) -> Assessment`; they are not registered remote `Exploit` classes. They execute no commands, send no probes or payloads, and do not authenticate the supplied evidence.

Collect current release, patch/build and effective configuration from the **same running node**, and repeat for every cluster member. An observed closed port, login page, SMTP greeting or SSH banner does not replace the required owner evidence. The JSON field names below are Asteroid's normalized schema, not vendor API field names. Normalize trustworthy GUI, authenticated administration or local status evidence into it; do not mix nodes, downloaded packages, historical versions or scheduled installations.

Run an example with:

```sh
python -m agent.utils.inventory docs/examples/secure-email-inventory.json
```

- Input is an array of records. The CLI rejects duplicate JSON keys and
  nonstandard JSON values, and limits files to 1 MiB.
- Output contains only CVE IDs, status, reason and recommendation. The CLI never
  echoes records or supplied version/patch strings.
- `potential_exposure` means the supplied version/configuration matches the
  advisory; exploitability remains unconfirmed.
- `not_matched` is a CVE-specific fix or configuration exclusion, not whole-device
  remediation.
- Missing, unsupported, malformed or contradictory material evidence produces
  `inconclusive`.
- Boolean facts must be JSON `true`/`false`; strings and integers are not booleans.
  `null` represents unknown evidence and never means false.
- Known independent software fixes can exclude applicability without
  otherwise-required configuration facts, but do not bypass malformed supplied
  evidence.

Vendor-managed deployments require the exact service deployment label plus `service_identity_verified: true`. That owner assertion must be supported by service identity evidence; arbitrary hosted appliances do not qualify. Known contradictions with a reported service update stay inconclusive. Optional supplied patch/build evidence is checked before managed-service or fixed-release shortcuts. Assessors do not independently establish patch authenticity, backports or fix incorporation into custom builds.

## Cisco Catalyst SD-WAN Manager — CVE-2026-76504

Source: [Cisco advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU) and [Cisco-authored CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/76xxx/CVE-2026-76504.json). Collect the exact running label from the owner's management GUI (Help).

Use `product: "Cisco Catalyst SD-WAN Manager"`, string `version`, and `deployment: "customer-managed"` or `"cisco-managed-cloud"`. Optional `hotfixes` must be an explicitly empty array; nonempty/unverified hotfix evidence is inconclusive. An optional `contradictory` field must be false.

The module preserves all 415 exact CNA affected labels, including embedded spaces and apparent source typos. It performs no suffix stripping, general whitespace normalization or numeric ordering. Exact affected labels take priority: `20.12.401`, `20.12.501`, fixed-looking `_LI_Images` variants and extra-component special builds remain potential exposures. An unlisted spelling is inconclusive, even if it resembles a source typo.

The only modeled customer-managed fixed labels are `20.9.10.1`, `20.12.8.2`, `20.15.6.1`, `20.18.4.1`, `26.1.2.1` and `26.2.1`. Verified Cisco-managed cloud `20.15.605` is a distinct fixed release; that label under customer management is inconclusive. Unlisted later releases also require Cisco confirmation. Live Protect is partial temporary protection and does not clear an affected software label.

[Example](examples/sdwan-manager-inventory.json): affected exact label, exact customer fix, then an unlisted build → potential exposure, not matched, inconclusive.

## FortiMail — CVE-2026-104286

Source: [Fortinet FG-IR-26-175](https://fortiguard.fortinet.com/psirt/FG-IR-26-175). Collect effective IBE Service configuration from Encryption → IBE → IBE Service.

Use `product: "FortiMail"`, a canonical three-component `version`, `deployment: "customer-managed"` or `"fortimail-cloud"`, and boolean `ibe_enabled`.

| Train | Affected patches | First fixed |
| --- | --- | --- |
| 8.0 | 0–1 | 8.0.2 |
| 7.6 | 0–6 | 7.6.7 |
| 7.4 | 0–8 | 7.4.9 |
| 7.2 | 0–9 | 7.2.10 |
| 7.0 | All | Migrate |

The vendor still calls 7.2.10 upcoming; confirm package availability. Disabling IBE excludes the current affected configuration as a workaround while retaining upgrade guidance. Unknown IBE cannot establish applicability on an affected release. FortiMail Cloud was updated October 5, 2026; verified service identity plus a release below its fixed point is contradictory and inconclusive. Unknown trains remain inconclusive.

[Example](examples/fortimail-inventory.json): enabled affected IBE, fixed release, then disabled IBE → potential exposure, not matched, not matched.

## Cisco Secure Email Gateway — two independent assessments

Use `product: "Cisco Secure Email Gateway"`, `version` in exact AsyncOS `M.m.p-NNN` grammar, and `deployment: "customer-managed"` or `"cisco-secure-email-cloud"`. The assessed trains are 13.0, 13.5, 14.0, 14.2, 14.3, 15.0, 15.5, 16.0 and 16.5, established by the Cisco CNA entries and advisory fix matrix. Unknown trains remain inconclusive. Earlier assessed trains require migration. Email and Web Manager and Secure Web Appliance are different products.

[CVE-2026-76461 advisory, revised November 3, 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX) and [CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/76xxx/CVE-2026-76461.json): the vulnerability is independent of configuration. Supply `retro_remediation_engine_version` as three canonical numeric components, collected with owner-operated `retroscannerstatus`. The 15.5 fix requires **both** image 15.5.5-014 or later within 15.5 **and** engine 4.0.2 or later. Engine 4.0.1 still matches; missing engine is inconclusive. Later 15.5 images retain this engine requirement conservatively. The 16.0.4-302 and 16.5.0-780 image fixes do not require a newer engine. Cisco Secure Email Cloud was upgraded to 16.5.0-780; contradictory older cloud image evidence is inconclusive.

[CVE-2026-76519 advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-afw-zqYJkjxp) and [CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/76xxx/CVE-2026-76519.json): supply booleans `file_reputation_enabled` and `file_reputation_assigned_to_mail_policy`, plus string `content_scanner_tools_version`. Collect owner-operated `contentscannerstatus` and effective incoming/outgoing AMP mail-policy assignment. Exposure requires both policy facts true, an affected image, and tools below 25.3.0.5525. Either policy fact false excludes the current configuration, not the need to patch.

Fixed images are 15.5.5-014 within 15.5 and 16.5.0-780 within 16.5. **16.0.4-302 is not this CVE's image fix**; 16.0 needs the component update or migration. Fixed tools independently exclude applicability on the assessed trains. The parser validates the whole tools string before comparing its first four components: a real value such as `25.2.0.5427.15.5.001` is accepted, including zero-padded numeric suffix fields. Up to eight trailing numeric fields of one to four digits are accepted; arbitrary suffixes, empty fields and excessive components are inconclusive. Verified cloud service is reported patched; an old tools value combined with an affected image conflicts with that claim. An independently fixed image does not require newer tools.

[Example](examples/secure-email-inventory.json): first record is potential for 76461 but excluded for 76519; second is excluded for 76461 but potential for 76519; third is excluded for both. Missing component/policy facts stay unknown unless the respective CVE has an independent fix.

## Check Point VPN — CVE-2026-85102

Sources: [SK1000117](https://support.checkpoint.com/results/sk/sk1000117), [R82.10 Take 44](https://sc1.checkpoint.com/documents/Jumbo_HFA/R82.10/Take_44.html), [R82 Take 126](https://sc1.checkpoint.com/documents/Jumbo_HFA/R82/Take_126.html), [R81.20 resolved issues](https://sc1.checkpoint.com/documents/Jumbo_HFA/R81.20/All_Resolved_Issues.html), [R81.10 Take 190](https://sc1.checkpoint.com/documents/Jumbo_HFA/R81.10/R81.10/Take_190.htm), and [LivePatch correction](https://community.checkpoint.com/t5/General-Topics/Important-Update-For-customers-that-installed-manual-LivePatch/td-p/282306).

Use `product: "Check Point Quantum Security Gateway"` with exact `version` and integer `jumbo_hotfix_take`, or `product: "Check Point Spark Firewall"` with exact `version` and integer `build`. These integers and `livepatch_take` accept 0–9999, never booleans; zero explicitly means none. Do not interchange Gateway JHF and Spark build evidence.

| Platform/train | First fixed |
| --- | --- |
| Gateway R82.10 | JHF 44 |
| Gateway R82 | JHF 126 |
| Gateway R81.20 | JHF 166 |
| Gateway R81.10 | JHF 190 |
| Gateway R82.20 | Explicitly unaffected |
| Spark R82.00.10 | Build 2325 |
| Spark R81.10.17 | Build 4968 |

Earlier Spark maintenance releases in the R82.00/R81.10 families are affected; later maintenance releases in those same families meet the fix. Known EoS Gateway R80, R80.10, R80.20, R80.30, R80.40 and R81 require migration. Other trains remain unknown.

Supply booleans `remote_access_vpn_enabled`, `site_to_site_vpn_enabled` and `site_to_site_certificate_auth_allowed`. Remote access **or** certificate-capable site-to-site VPN establishes the configuration prerequisite. PSK-only site-to-site VPN is excluded. DAIP/LSV communities permit certificates and must be normalized accordingly. A generic `vpn_enabled` or an IKE port observation is insufficient. Effective site-to-site disabled plus effective certificate authentication allowed is contradictory in this schema.

Supply `livepatch_take` and boolean `livepatch_cpcert_active` from current owner-operated `cpinfo -y CPupdates` and `cplp list` evidence (use each member's effective state). Active CVE-specific cpcert coverage with Take ≥26 is modeled only for Gateway R82.10, R82 and R81.20, the trains with published packages. Installed packages, automatic updates, inactive coverage or earlier takes do not prove mitigation. Active coverage with take zero is contradictory. Unsupported LivePatch claims on Spark, R81.10, EoS or unknown trains remain inconclusive, including before a fixed-image shortcut. Missing coverage/take on an otherwise matching affected node stays inconclusive. This temporary mitigation is distinct from CVE-2026-93616, which has no modeled LivePatch fix.

[Example](examples/checkpoint-vpn-inventory.json): affected Gateway, actively mitigated Gateway, affected Spark, fixed Spark → potential, not matched, potential, not matched.

## F5 BIG-IP APM — CVE-2026-94127

Primary source: [F5-authored CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/94xxx/CVE-2026-94127.json), which links [K000162605](https://my.f5.com/manage/s/article/K000162605). The advisory page exposed a JavaScript shell during research; the CNA supplies the modeled intervals and configuration requirements.

Use `product: "F5 BIG-IP APM"`, full three/four-component base `version`, optional exact `engineering_hotfix` (null when no engineering hotfix is inventoried), and booleans `apm_access_policy_on_virtual_server`, `oauth_profile_on_same_virtual_server`, `oauth_authorization_server_enabled`. All three must describe the **same virtual server**. Client/resource-server-only roles exclude the required condition. This is a data-plane issue and appliance mode does not exclude it.

| Branch | Exact fixed engineering hotfix |
| --- | --- |
| 21.1 | `Hotfix-BIGIP-21.1.0.2.0.30.22-ENG` |
| 17.5 | `Hotfix-BIGIP-17.5.1.9.0.160.12-ENG` |
| 17.1 | `Hotfix-BIGIP-17.1.3.5.0.41.14-ENG` |

The full seven-component identifier must be exact and its first four components must match the running base. Plain 17.1.3.5 is not proof of a fix. Canonical plain releases from 21.1.0/17.5.0/17.1.0 through the respective hotfix base match the affected interval; higher bases, unsupported/EoTS branches and unrecognized engineering identifiers require F5 confirmation. Three-component base releases imply base patch zero. No generic `irule_installed` claim is accepted as mitigation; the source says to obtain an iRule from F5 support.

[Example](examples/f5-apm-inventory.json): plain affected base, exact matching hotfix, then a wrong-base hotfix → potential, not matched, inconclusive.

## MikroTik RouterOS — CVE-2026-67279 and CVE-2026-86060

Sources: [MikroTik September advisory](https://mikrotik.com/supportsec/september-2026-vulnerability/), [67279 CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/67xxx/CVE-2026-67279.json) and [86060 CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/86xxx/CVE-2026-86060.json).

Use `product: "MikroTik RouterOS"`, canonical two/three-component stable `version`, boolean `ssh_enabled`, and optional `release_channel: "stable"` or `"long-term"`. Two components imply patch zero. Effective SSH disablement excludes this attack surface, while an unreachable port does not establish disablement.

Affected stable intervals: 6.0 ≤ version <6.49.21; 7.0 ≤ version <7.23.4; **7.24 ≤ version <7.24.2**. In particular, 7.24.1 remains affected despite being numerically greater than 7.23.4. The known fixes are 6.49.21, 7.23.4 and 7.24.2. Later patches in those assessed branches are excluded for these two CVEs only. Stable branches beyond 6.49/7.24, unsupported majors, beta/rc/custom strings and other channels are conservatively inconclusive. Vendor 7.25beta3 is not modeled through guessed prerelease ordering. Do not substitute the higher floors for the separate CVE-2026-67278.

[Example](examples/routeros-inventory.json): 7.24.1 potential for both CVEs, 7.24.2 not matched for both, emitted as one family assessment carrying both IDs.

## WatchGuard Fireware OS — CVE-2025-9242

Source: [WatchGuard advisory](https://psirt.watchguard.com/CVE-2025-9242), revised August 10, 2026.

Use `product: "WatchGuard Fireware OS"`, `platform: "Default"`, `"T15/T35"` or `"FIPS"`, two/three-component `version` with optional `+build`, and optional integer `build` (0–999999). If both build forms are supplied they must agree. Six-digit build numbers are preserved. Missing build at an equal-base build boundary is inconclusive.

| Platform | Affected interval / boundary |
| --- | --- |
| Default 11 | 11.0 through 11.12.4+541730 inclusive |
| Default 12 | Below 12.11.4 |
| Default 2025 | Below 2025.1.1 |
| T15/T35 12 | Below 12.5.13 |
| FIPS 12 | Below 12.3.1+722811 |

Use booleans `mobile_ikev2_enabled`, `bovpn_ikev2_dynamic_peer_enabled`, `bovpn_static_peer_enabled`, and `historical_dynamic_or_mobile_ikev2`. Current mobile IKEv2 or dynamic-peer IKEv2 qualifies; historical use also qualifies when static-peer BOVPN remains. Removing the first two settings alone does not exclude the condition. When only static-peer BOVPN remains, unknown history produces inconclusive. Platform thresholds are independent; Default 12.11.4 is not applied to FIPS/T15/T35.

[Example](examples/fireware-inventory.json): FIPS build 722810 potential, 722811 excluded, equal base with explicitly unknown build inconclusive. Default 11.12.4+541731 is outside the affected interval, not an asserted named upgrade package.

## NetScaler ADC/Gateway — CVE-2026-19490

Source: [Citrix CTX696939](https://support.citrix.com/external/article/CTX696939/). Its fixed-at boundaries take precedence over the CNA's inclusive off-by-one values.

Use `product: "NetScaler ADC"` or `"NetScaler Gateway"`, `version` in `train-build` grammar such as `14.1-73.31`, `edition: "standard"`, `"FIPS"` or `"NDcPP"`, `deployment: "customer-managed"` or `"citrix-managed"`, and booleans `gateway_or_aaa_vserver` and `saml_action_configured`. Normalize same-node effective configuration from owner evidence for `add authentication samlAction`, `add authentication vserver`, and `add vpn vserver`.

| Edition/train | First fixed build | Additional SAML prerequisite starts at |
| --- | --- | --- |
| standard 14.1 | 73.32 | 43.56 |
| standard 13.1 | 63.21 | 61.28 |
| FIPS 14.1 | 73.32 | 66.68 |
| FIPS/NDcPP 13.1 | 37.277 | None stated |

Gateway/AAA role is required throughout the affected intervals. Older intervals must **not** be cleared by SAML=false. For FIPS 14.1 below 66.68 the source is less explicit; conservatively retain the Gateway/AAA requirement and do not extrapolate the standard SAML threshold. Required but missing SAML state is inconclusive. 13.1-37.277 fixes FIPS/NDcPP, not standard. Unsupported edition/train pairs remain inconclusive. Verified Citrix-managed services are reported patched; third-party hosting does not qualify.

[Example](examples/netscaler-inventory.json): affected standard build, exact standard fix, older standard build with SAML=false still potential, then the distinct FIPS fix.

## VeloCloud Orchestrator — CVE-2026-93952

Source: [Arista advisory 0183](https://www.arista.com/en/support/advisories-notices/security-advisory/24765-security-advisory-0183), revision 1.1.

Use `product: "VeloCloud Orchestrator"`, canonical four-component `version`, `deployment: "on-premises"`, `"hosted"` or `"dedicated"`, and boolean `edge_certificate_authentication_enabled`. Managed labels require verified Arista service identity. The earlier CVE-2026-114625 assessor remains registered and emits its own independent verdict.

Named affected upper bounds are 5.2.3.15, 6.1.3.7, 6.4.2.7 and 7.0.0.2 within their corresponding two-component branches. The modeled explicit fixes are 5.2.3.16 within **5.2.3** and 6.4.2.8 within **6.4.2**. The source also calls unlisted releases unaffected, but this implementation conservatively leaves other maintenance branches and releases above the 6.1/7.0 named bounds inconclusive without explicit fix confirmation. In particular, do not borrow 6.1.3.10 from CVE-2026-114625.

Edge certificate authentication disabled excludes the current condition, not software remediation. Attack feasibility additionally requires web access and an Edge certificate's public portion, but absence of observed disclosure is not an exclusion. `edge_public_certificate_accessible` is not required or used to suppress potential exposure. Hosted/dedicated services were reported patched.

[Example](examples/vco-inventory.json): 5.2.3.16 remains potential for 114625 but is excluded for 93952; 5.2.3.15 matches both; 6.1.3.10 is excluded for 114625 and inconclusive for 93952.
