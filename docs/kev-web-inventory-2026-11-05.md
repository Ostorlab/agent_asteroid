# Offline management and web-product inventory assessments

Evidence reviewed November 5, 2026. These six CVE modules expose
`assess_record(dict[str, object]) -> inventory_definitions.Assessment`. They are
owner-inventory assessors, **not registered remote Exploit classes**. The public
`agent.utils.inventory.assess_records(record)` dispatcher preserves existing
products and emits separate CVE results for AhsayCBS and BeyondTrust Remote
Support. Privileged Remote Access receives only CVE-2024-12356.

Run the existing offline CLI with a normalized JSON array:

```sh
python -m agent.utils.inventory docs/examples/cisco-ise-inventory.json
python -m agent.utils.inventory docs/examples/ahsaycbs-inventory.json
python -m agent.utils.inventory docs/examples/checkpoint-management-inventory.json
python -m agent.utils.inventory docs/examples/beyondtrust-inventory.json
```

These are complete synthetic examples, not vendor API responses. There is no
target I/O, authentication bypass, receiver modification, JSP upload, RCE check,
or automatic remote coverage in this batch. Reasons and recommendations contain
only bounded policy text; input records, secrets, hostnames, and arbitrary field
values are never echoed.

## Evidence contract

Collect product identity, running product version, effective role/configuration,
and installed patch state for **one running node** per record. Assess every
serving/failover node separately. A scheduled installation or a hotfix awaiting
its required reboot does not establish a fixed running version.

Exact product names and case-sensitive release grammar are required. Numeric
release components use `0` or one to four ASCII digits without leading zeroes.
No whitespace, prefixes, custom suffixes, or inferred release/patch conversions
are accepted. Patch/take fields are JSON integers from 0 through 9999; zero
explicitly means none. Booleans are real JSON `true`/`false`, never strings or
integers. Unknown fields are ignored and cannot establish remediation. Normalize
conflicting raw evidence before assessment; do not combine nodes or silently
select the more favorable value. The CLI rejects duplicate JSON keys.

`potential_exposure` means owner evidence matches a documented affected condition;
exploitability has not been proven. `not_matched` describes a fix or exclusion for
**that CVE**, never whole-device safety. `inconclusive` means missing, malformed,
unverified, unsupported, or contradictory evidence requires owner/vendor review.
Unsupported/future branches remain inconclusive unless the vendor expressly
includes later releases in its policy.

`deployment="beyondtrust-saas"` and `deployment="smart-1-cloud"` require
`service_identity_verified: true`: the owner verified the actual vendor-managed
service identity. A third-party cloud VM, a hostname, or a generic hosting flag
is insufficient. Once that identity is verified, the vendor's SaaS remediation
statement applies without a local self-hosted patch inventory. Supplied malformed
or contradictory patch evidence still remains inconclusive.

## Cisco ISE and ISE-PIC — CVE-2026-76460

Use exact `product: "Cisco ISE"` or `"Cisco ISE-PIC"`, a two-component train in
`version`, and a separate installed `patch` integer. For example, `version:
"3.4", patch: 6` is potentially exposed; patch 7 is fixed for this CVE.
Normalize an owner-visible build/patch display into those separate fields. A
base build such as `3.4.0.123` is not patch evidence, and strings such as `3.4.7`,
`3.1.0 p11`, or `3.3 Patch 11` are deliberately rejected as input versions.

| Train | First fixed patch |
| --- | --- |
| 3.1 | 12 |
| 3.2 | 11 |
| 3.3 | 12 |
| 3.4 | 7 |
| 3.5 | 4 |

Earlier patches on these trains are potentially exposed regardless of
configuration; at/above the fixed patch excludes this CVE. Missing patch state
is inconclusive. Version 3.0 is End of Software Maintenance and requires
migration. Older/future trains are inconclusive, never presumed unaffected.
The [Cisco advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ISE-ABP-VNSW7Tn5)
is the source for the complete matrix. No public version/patch endpoint is
assumed. [Examples](examples/cisco-ise-inventory.json) produce potential exposure
for ISE 3.4/p6 and not matched for ISE-PIC 3.5/p4.

## AhsayCBS — CVE-2026-105133 and CVE-2026-105134

Use `product: "AhsayCBS"` and the four-component **running** `version`.
The [corrected vendor announcement](https://www.ahsay.com/en/company/announcements/patch-cve-105133-105134-update)
covers v7/v8/v9/v10 and retracts the earlier incomplete patches. Versions
9.15.2.59 and 10.3.4.0 remain affected. The corrected fixed releases are
9.15.2.70 and 10.3.4.45, respectively, followed by the required reboot.
Later canonical releases in those same major branches are accepted as fixed;
unknown major versions and custom builds are inconclusive.

For v7/v8 the [vendor migration guidance](https://www.ahsay.com/en/company/announcements/ahsaycbs-vulnerability-status-update)
is to upgrade through 9.15.0.0 and then apply 9.15.2.70. Earlier v9/v10 releases
are also covered, even where a CNA version enumeration begins later.

CVE-2026-105133 requires no replication configuration prerequisite. An affected
release remains potentially exposed even when replication is unavailable.

CVE-2026-105134 additionally uses `replication_capability_available: true` to
mean that the owner has verified the effective appliance licensing and operating
mode permit replication-receiver creation/activation. This is **not** a synonym
for an existing receiver's enabled setting. Optional `receiver_enabled` describes
that existing receiver and must be boolean when supplied. A missing/false
capability yields inconclusive on affected releases, including when a receiver
is enabled. A corrected running release excludes this CVE without capability
evidence. Invalid boolean fields remain inconclusive.

The [primary technical analysis](https://horizon3.ai/attack-research/attack-blogs/ahsaycbs-cve-2026-105133-cve-2026-105134-technical-analysis/)
demonstrates creation of receivers through the authentication bypass; the
[vendor UpdateReceivers documentation](https://www.ahsay.com/en/support/help-centre/doc/cbs/v10/api/replication/update-receivers)
documents the writable enabled property. Thus an affected release with verified
capability is chain-potential even with `receiver_enabled: false`. Published
prerequisites differ between “configured and licensed” and “configured or
licensed”; the assessor does not infer a blanket globally disabled or unlicensed
exclusion. A generic `replication_enabled` field has no normalized policy meaning.
No API calls or configuration writes are performed.

[Examples](examples/ahsaycbs-inventory.json) produce two potential-exposure
results for 10.3.4.0 with capability available and a disabled receiver, followed
by two not-matched results for corrected running 9.15.2.70.

## Check Point management — CVE-2026-93616

Use `product: "Check Point Quantum Security Management"`, an exact `version`
train below, `deployment: "customer-managed"` or verified `"smart-1-cloud"`, and
an effective `role`. Accepted affected role values are
`security-management-server`, `multi-domain-management-server`, `log-server`,
`multi-domain-log-server`, `smartevent`, and `combined-management-firewall`.
A standalone firewall hosting management remains within scope. Gateway-only
and Spark products are outside this management CVE; supplying those roles with
a management product identity is contradictory and returns inconclusive.

Customer-managed records require `jumbo_hotfix_take` and `security_hotfixes`.
Use `security_hotfixes: []` only after confirming no separate security hotfix is
installed. Missing/malformed inventory or a nonempty special-hotfix claim remains
inconclusive. Optional `livepatch_take` must be a bounded integer; it cannot
establish remediation for this CVE.

| Train | Last explicitly affected JHF | First fixed JHF |
| --- | --- | --- |
| R82.20 | 0 (base, no applicable security fix) | 10 |
| R82.10 | 44 | 45 |
| R82 | 126 | 127 |
| R81.20 | 166 | 170 |
| R81.10 | 190 | 192 |

The gaps R82.20 takes 1–9, R81.20 takes 167–169, and R81.10 take 191 remain
inconclusive. At/above a documented fixed JHF on the same train is not matched.
Named EOS trains R80, R80.10, R80.20, R80.30, R80.40, and R81 are affected and
require migration/vendor support; unknown trains remain inconclusive.

[SK1000171](https://support.checkpoint.com/results/sk/sk1000171) and its
[vendor clarification](https://community.checkpoint.com/t5/General-Topics/Action-required-Critical-Vulnerability-CVE-2026-93616-in-Check/td-p/282631)
state that Smart-1 Cloud is patched and **no LivePatch exists for this CVE**.
Even LivePatch Take 30 must not clear affected JHF state. This differs from VPN
CVE-2026-85102. Port restrictions are mitigation, not a fixed-version indicator.

Fixed points are corroborated by release notes for
[R82.20 Take 10](https://sc1.checkpoint.com/documents/Jumbo_HFA/R82.20/Take_10.html),
[R82.10 Take 45](https://sc1.checkpoint.com/documents/Jumbo_HFA/R82.10/Take_45.html),
[R82 Take 127](https://sc1.checkpoint.com/documents/Jumbo_HFA/R82/R82.00/R82-List-of-all-Resolved-Issues.htm),
[R81.20 Take 170](https://sc1.checkpoint.com/documents/Jumbo_HFA/R81.20/R81.20/Take_170.htm),
and [R81.10 Take 192](https://sc1.checkpoint.com/documents/Jumbo_HFA/R81.10/R81.10/R81.10-List-of-all-Resolved-Issues.htm).

The separate R82.20 Security Hot Fix Take 1 is linked as
[download 145757](https://support.checkpoint.com/results/download/145757), but its
exact installed package identity was not publicly verified. No identifier is
invented, and JHF Take 1 is never equated with this security fix. Special-hotfix
claims require vendor review even if their label mentions the advisory.
[Examples](examples/checkpoint-management-inventory.json) yield potential,
inconclusive, not matched, and not matched, in that order.

## BeyondTrust RS/PRA patch evidence

Use exact `product: "BeyondTrust Remote Support"` or
`"BeyondTrust Privileged Remote Access"`, a canonical three-component product
`version`, and `deployment: "self-hosted"` or verified `"beyondtrust-saas"`.
Read the running **Product Name / Product Version** through owner-authorized
`/login` → Status → Information; the [documented status screen](https://docs.beyondtrust.com/rs/v25.3/docs/on-prem-status)
distinguishes those from Product Build and API Version. Read actual installed
packages under `/appliance` → Updates →
[Installed Patches](https://docs.beyondtrust.com/rs/v26.1/docs/on-prem-appliance-installed-patches).
Check each serving/failover node per the
[cluster update reference](https://docs.beyondtrust.com/rs/docs/cluster-updates-reference).

On an otherwise affected self-hosted release, `installed_patches` is required.
An explicit empty list permits potential exposure; missing/malformed inventory
is inconclusive. Every entry needs all five fields:

```json
{
  "name": "BT24-10-ONPREM1",
  "product": "BeyondTrust Remote Support",
  "application_version": "24.3.1",
  "install_status": "installed",
  "applicability_verified": true
}
```

`product` and `application_version` must match the same running record exactly.
`name` is an exact package identifier (1–128 ASCII letters, digits, dots,
underscores, or hyphens, beginning with an alphanumeric character). Duplicated
names, mixed-version/product entries, missing fields, and invalid booleans are
inconclusive. `install_status` accepts `installed`, `downloaded`, `scheduled`,
or `failed`; only installed proves patch state. `applicability_verified: true`
means the owner matched the vendor-offered package to this running product and
release. It is not permission to guess an unpublished variant mapping. A known
relevant patch with unverified applicability remains inconclusive. Unrelated
patches do not implicitly clear another CVE. Supplied relevant patch claims are
checked against the published application prerequisites before either SaaS or
fixed-release exclusions. Unsupported or unverified applicability remains
inconclusive even if the claimed patch is downloaded, scheduled, or failed.
A fixed running release or verified SaaS deployment does not require a local
backport inventory; absent evidence differs from a contradictory supplied claim.

### CVE-2024-12356

[BT24-10](https://www.beyondtrust.com/trust-center/security-advisories/bt24-10)
affects **both RS and PRA** through 24.3.1. Both products are fixed from 24.3.2,
as explicitly documented in the
[RS release notes](https://docs.beyondtrust.com/rs/changelog/remote-support-24-3-2)
and [PRA release notes](https://docs.beyondtrust.com/pra/changelog/privileged-remote-access-24-3-2).
Verified vendor-managed SaaS was patched by December 16, 2024.

Self-hosted BT24-10-ONPREM1/2 patches are supported starting at 22.1.x. The
variant-to-version mapping is unpublished, so an exact name alone is insufficient.
An owner-verified, installed applicable variant can clear this CVE; a claimed
variant on 21.3.x is contradictory/inconclusive. Older versions must upgrade.
BT26-05-RS does not implicitly clear this older CVE.

### CVE-2026-102764

[BT26-05, revised November 4](https://www.beyondtrust.com/trust-center/security-advisories/bt26-05)
affects **Remote Support only**, through 26.2.3; releases 26.3.1 and greater are
fixed. The 26.2.4–26.3.0 gap is inconclusive. The exact BT26-05-RS backport applies
to 24.3.1–26.2.3 inclusive. Claims on 24.3.0 or above 26.2.3 (including fixed
26.3.1) are contradictory/inconclusive, even for verified SaaS. Older versions
must upgrade. SaaS was patched by October 9, 2026. PRA
is not dispatched to this CVE.

The [BeyondTrust examples](examples/beyondtrust-inventory.json) demonstrate:
RS 24.3.1 with only the old patch (old CVE not matched, new CVE potential);
RS 26.2.3 with the new patch (both not matched); PRA 24.3.1 with a verified
old variant (only old CVE not matched); RS 26.2.4 (old CVE not matched, new CVE
inconclusive); and verified SaaS (both not matched). The synthetic variant
examples illustrate the evidence schema, not a published applicability mapping.

### Remote metadata limits

The [RS Command API](https://docs.beyondtrust.com/rs/v25.2/reference/command-api)
and [PRA Command API](https://docs.beyondtrust.com/pra/v25.1/reference/command-api)
require authentication for `get_api_info`. Its version is an API version, not
product patch state; the [API version reference](https://docs.beyondtrust.com/rs/reference/api-change)
maps API versions to entire release families. A supported anonymous `/get_rdf`
schema and product specificity were not established. This batch invents no
endpoint or automated remote detector from those metadata hints.
