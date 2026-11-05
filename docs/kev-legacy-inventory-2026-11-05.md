# Legacy owner-inventory coverage — 2026-11-05

Five pure assessors cover six CVEs from owner-supplied inventory. This is **offline inventory coverage**, not a remote detector, proof of exploitation, or lab-validated vulnerability detection. Each module exposes `assess_record(dict[str, object]) -> Assessment`; none registers an `Exploit`, contacts a target, runs commands, invokes a protocol method, or authenticates the supplied evidence. No Nuclei templates are added.

Collect current product identity, running release and effective configuration from trustworthy owner-operated local status, authenticated administration or deployment records, for the **same running instance**. Repeat for every cluster member and application deployment. Installed-but-inactive packages, scheduled upgrades, stale configuration files, public banners and another node's version are insufficient. Resolve contradictory evidence before normalizing it; otherwise mark `contradictory: true`. A closed port from one scan vantage cannot prove a service is disabled everywhere.

The JSON names below are Asteroid's normalized schema, not vendor API keys. Input is an array of records. Every field listed in each schema is required, including a real JSON boolean for configuration, even when supplying a fixed version. Missing/null/malformed facts and unsupported releases yield `inconclusive`. Numeric version components are canonical decimal integers of up to four digits, without leading zeros, whitespace or prefixes. Custom/distribution suffixes are not stripped. All records may optionally carry `contradictory: false`; any other value for that field makes the assessment inconclusive. Unmodeled extra fields are ignored, never used as fix evidence and never echoed.

For Salt, Struts and ProFTPD, `release_origin` must be `"upstream"` to apply these rules. This is an owner assertion backed by evidence that the **running artifact is the unmodified upstream release**, not merely that its version looks upstream. Use `"distribution"` or `"custom"` for repackaged or modified builds; those values remain inconclusive even if the version equals a named fix. The module does not verify package signatures, ancestry or backports. Do not relabel an unverified package as upstream to obtain a definitive result.

`potential_exposure` means supplied facts match an advisory rule; exploitability is unconfirmed. `not_matched` means only a CVE-specific software interval/fix or a current configuration exclusion. Configuration exclusions do not establish software remediation or rule out historical compromise. `inconclusive` requires owner/vendor review. The CLI rejects duplicate keys, nonstandard JSON and input larger than 1 MiB; output contains only `cve_ids`, `status`, `reason` and `recommendation`.

Run the complete examples through the public CLI from the repository root with the project's Python environment:

```sh
python -m agent.utils.inventory docs/examples/salt-inventory.json
python -m agent.utils.inventory docs/examples/routeros-winbox-inventory.json
python -m agent.utils.inventory docs/examples/struts-inventory.json
python -m agent.utils.inventory docs/examples/proftpd-inventory.json
python -m agent.utils.inventory docs/examples/trueconf-inventory.json
```

## Salt master — CVE-2020-11651

The [Salt 3000.2 release notes](https://github.com/saltstack/salt/blob/v3000.2_docs/doc/topics/releases/3000.2.rst) identify vulnerable Salt before 2019.2.4 and 3000 before 3000.2, affecting the master ClearFuncs interface.

| Required field | Exact normalized meaning |
| --- | --- |
| `product` | `"SaltStack Salt"`; no alias matching |
| `version` | Running upstream release: `3000`, `3000.N` with positive N, or three-component calendar release |
| `release_origin` | `"upstream"` backed by the running-artifact evidence described above |
| `role` | `"master"` for an instance configured to provide the master role, even if currently disabled; `"minion"` means minion-only |
| `master_service_enabled` | Effective master service enabled (`true`) or absent/disabled (`false`), from owner configuration and runtime state |

The reviewed calendar trains are 2016.3, 2016.11, 2017.7, 2018.3 and 2019.2. Releases in those trains before 2019.2.4 match the affected software range. Within 2019.2, patch 4 and later meet the fixed point. Canonical `3000` and `3000.1` match; `3000.2` and later maintenance patches within 3000 meet the fixed point. `3000.0`, three-component `3000.1.0`, unlisted calendar trains, older unlisted naming schemes and newer numbered trains such as 3001 remain inconclusive. No general future-version safety claim is made.

For an affected release, disabled master service excludes the current configuration. A minion-only role must agree with disabled/absent master service; `role: "minion"` with `master_service_enabled: true` is contradictory, including on fixed software. A host running both master and minion should be normalized as `"master"`. Neither role names nor unreachable master ports replace effective service evidence. No token retrieval, ClearFuncs method, runner or ZeroMQ call is performed.

[Example](examples/salt-inventory.json): canonical 3000 master → potential exposure; 2019.2.4 → not matched; 3000.1 minion-only → configuration exclusion; 3001 → inconclusive.

## RouterOS Winbox — CVE-2018-14847

The [MikroTik advisory](https://mikrotik.com/supportsec/winbox-vulnerability/) supplies independent intervals for the historical bugfix, current and RC channels.

| Required field | Exact normalized meaning |
| --- | --- |
| `product` | `"MikroTik RouterOS"` |
| `version` | Canonical stable `6.minor` or `6.minor.patch`; RC `6.minorrcN` with positive N |
| `installed_release_channel` | `"bugfix"`, `"current"` or `"rc"`: provenance of the **installed image** |
| `winbox_enabled` | Effective Winbox service state, a real boolean collected from current owner administration |

| Installed image provenance | Affected inclusive interval | Exact recognized fixed release |
| --- | --- | --- |
| bugfix | 6.30.1–6.40.7 | 6.40.8 |
| current | 6.29–6.42 | 6.42.1 |
| rc | 6.29rc1–6.43rc3 | 6.43rc4 |

Two-component stable releases imply patch zero. Stable and RC grammars cannot be interchanged. The installed image's release provenance must come from retained package/release evidence, not the currently selected update channel, which can change without replacing firmware. `selected_update_channel` is an optional illustrative metadata field that this assessor ignores. The existing SSH-family `release_channel` field also does **not** substitute for installed provenance. Thus installed bugfix 6.40.8 remains excluded even when the selected update channel is current. Reporting it as an installed current image is contradictory and inconclusive; current provenance with any 6.40 patch ≥8 is likewise inconclusive.

Stable major-6 current releases before 6.29 and major-6 RC releases before 6.29rc1 are outside the source's affected intervals. Bugfix releases below 6.30.1 stay inconclusive because this model does not establish their provenance. Releases above each exact fixed boundary and unsupported major versions are conservatively inconclusive, including later 6.40 bugfix patches, 6.42 current patches and 6.43 RCs. The policy does not infer fix inheritance for future channels/trains. Effective Winbox disablement excludes only current configuration for a known affected release. A filtered port is insufficient. No user database or credentials are requested.

RouterOS dispatch retains the existing CVE-2026-67279/CVE-2026-86060 family result and appends a separate Winbox result. Supply `ssh_enabled` too when assessing both families; their evidence and version ranges remain independent. [Example](examples/routeros-winbox-inventory.json): 6.40.7/6.40.8 yield potential/excluded Winbox results while both still match the SSH CVEs; 6.43rc3/6.43rc4 yield potential/excluded Winbox results while the stable-only SSH assessment is inconclusive. The [existing modern RouterOS example](examples/routeros-inventory.json) retains its SSH verdicts and now emits an additional inconclusive Winbox assessment.

## Apache Struts S2-032 — CVE-2016-3081

[Apache's S2-032 advisory](https://cwiki.apache.org/confluence/spaces/WW/pages/62693266/S2-032) identifies 2.3.20 through 2.3.28, except **2.3.20.3** and **2.3.24.3**, and recommends those fixes or **2.3.28.1**. The historical `.2` exception values are incorrect.

| Required field | Exact normalized meaning |
| --- | --- |
| `product` | `"Apache Struts"` |
| `version` | Running Struts library release, three or four canonical numeric components |
| `release_origin` | `"upstream"` with running-artifact provenance |
| `dynamic_method_invocation_enabled` | Effective DMI state of the deployed application after configuration overrides, a boolean |

Three-component releases imply fourth component zero. The three named fixed labels are excluded. Within the reviewed 2.3 train, releases before 2.3.20 are outside the affected interval; the inclusive 2.3.20–2.3.28 interval otherwise matches with DMI enabled, except the two exact maintenance fixes. Releases above 2.3.28 other than exact 2.3.28.1, other trains, custom libraries and distribution builds require manual review. This deliberately avoids extrapolating fix inheritance to unreviewed releases.

Collect the deployed library identity and effective `struts.enable.DynamicMethodInvocation` configuration for each application, not a web-server version or a framework default. DMI false excludes only current configuration and retains upgrade guidance. No OGNL, method expression or command is sent.

[Example](examples/struts-inventory.json): 2.3.20.2 with DMI → potential; 2.3.20.3 → named fix; 2.3.28 with DMI disabled → configuration exclusion; unverified distribution 2.3.28.1 → inconclusive.

## ProFTPD mod_copy — CVE-2015-3306

First-party NEWS for [1.3.5a](https://github.com/proftpd/proftpd/blob/v1.3.5a/NEWS) and [1.3.6rc1](https://github.com/proftpd/proftpd/blob/v1.3.6rc1/NEWS) both list Bug 4169, with May 27, 2015 release dates. The [upstream fix PR](https://github.com/proftpd/proftpd/pull/109) addresses unauthenticated copying. [Ubuntu's notice](https://ubuntu.com/security/CVE-2015-3306) also lists fixed packages based on older 1.3.4a and 1.3.5rc3; an older version cannot be declared safe from the narrow 1.3.5 description.

| Required field | Exact normalized meaning |
| --- | --- |
| `product` | `"ProFTPD"` |
| `version` | Exact running upstream release label |
| `release_origin` | `"upstream"` with running-artifact provenance |
| `mod_copy_enabled` | Effective module availability in the running server, a boolean; true means loaded and enabled, false means absent or effectively disabled |

Only upstream `1.3.5` is modeled as affected. Exact `1.3.5a` and `1.3.6rc1` are modeled as fixed. Maintenance `a` is a **post-release fix**, not a PEP 440 alpha; the implementation compares these exact labels without generic package-version ordering. All other releases remain inconclusive, including older versions, later maintenance letters, later RCs, later stable trains and distribution suffixes. There is no assumed ancestry or backport validation. For known affected 1.3.5, disabling mod_copy excludes only current configuration. Collect runtime module availability and effective server/virtual-host configuration; the mere presence of a module file is insufficient. No FTP SITE CPFR/CPTO command or file copy occurs.

[Example](examples/proftpd-inventory.json): 1.3.5 enabled → potential; 1.3.5a and 1.3.6rc1 → fixed; disabled 1.3.5 → configuration exclusion; Ubuntu package label → inconclusive despite the source documenting its fix, because distro package validation is outside this model.

## TrueConf Server — CVE-2026-72529 and CVE-2026-72530

The primary researcher advisories [KLCERT-26-057](https://ics-cert.kaspersky.com/advisories/2026/08/11/trueconf-server-missing-authentication-for-critical-function/) and [KLCERT-26-058](https://ics-cert.kaspersky.com/advisories/2026/08/11/trueconf-server-breakout-from-isolated-environment/) have the same Windows/Linux Server intervals and TCP 4307 prerequisite. One family assessment carries both CVE IDs.

| Required field | Exact normalized meaning |
| --- | --- |
| `product` | `"TrueConf Server"`, not a conferencing client |
| `version` | Canonical three-component running server release |
| `platform` | `"Windows"` or `"Linux"` |
| `tcp_4307_service_enabled` | Effective service availability, a boolean derived from current owner server configuration/runtime evidence |

All versions before 5.3 are affected. In train 5.3, versions **before 5.3.9** are affected; in 5.4, before **5.4.9**; in 5.5, before **5.5.5**. Those three boundaries are fixed, and later maintenance patches in the same trains meet the fixed point. Unknown future trains such as 5.6 and 6.0 remain inconclusive. Disabled TCP 4307 service excludes current configuration, not vulnerable software. A closed port, transient failure or network ACL from one vantage is not normalized as service disablement. The assessor does not call undocumented functions, run scripts, escape isolation or investigate compromise.

[Example](examples/trueconf-inventory.json): 5.3.8 → potential for both CVEs; each of the three exact boundaries → not matched for both; 5.5.4 with the service disabled → configuration exclusion for both; 5.6.0 → inconclusive for both. These conclusions describe supplied inventory only and do not rule out prior compromise.
