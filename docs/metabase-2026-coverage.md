# Metabase 2026 release-exposure coverage

Sources checked 2026-11-05. These seven independent registered checks report
**POTENTIAL EXPOSURE; exploitability unconfirmed**, based on installed release
metadata. They do not test vulnerable operations. A missing finding means only
that the available evidence did not match a supported interval, not that the
installation is safe.

## Scanner provenance

The 2026 public Nessus inventory contains five Metabase plugins covering these
seven CVEs. The dates below are plugin first-publication dates, not modification
dates or CVE publication dates.

| CVE-2026- | Nessus plugin | First publication | Vendor severity / CVSS 3.1 |
| --- | --- | --- | --- |
| 27464 | [299881](https://www.tenable.com/plugins/nessus/299881) | 2026-02-24 | High / 7.7 |
| 33725 | [304390](https://www.tenable.com/plugins/nessus/304390) | 2026-03-31 | High / 7.2 |
| 59826 | [331861](https://www.tenable.com/plugins/nessus/331861) | 2026-08-04 | Critical / 9.1 |
| 59827 | [331862](https://www.tenable.com/plugins/nessus/331862) | 2026-08-04 | Critical / 9.9 |
| 72898 | [334690](https://www.tenable.com/plugins/nessus/334690) | 2026-08-12 | Critical / 10.0 |
| 72899 | [334690](https://www.tenable.com/plugins/nessus/334690) | 2026-08-12 | Critical / 9.6 |
| 72900 | [334690](https://www.tenable.com/plugins/nessus/334690) | 2026-08-12 | Medium / 6.5 |

The [first Nuclei main-branch template for 72898](https://github.com/projectdiscovery/nuclei-templates/blob/a346ec28473d4d1608cd75ff7c3dddc2ddf71136/http/cves/2026/CVE-2026-72898.yaml)
was published 2026-08-12T06:06:01Z. The collected public Qualys inventory provided
no Metabase match; it is not a complete authenticated Qualys KnowledgeBase and
cannot prove absence of a QID.

## Release evidence

Product source is pinned to Metabase v0.63.2, commit
`9a6cadd7ffbf8d294737300b35d7167234bb7049`:

- [GET /api/session/properties](https://github.com/metabase/metabase/blob/9a6cadd7ffbf8d294737300b35d7167234bb7049/src/metabase/session/api.clj#L391)
  returns public settings for an anonymous request.
- The [public read-only version setting](https://github.com/metabase/metabase/blob/9a6cadd7ffbf8d294737300b35d7167234bb7049/src/metabase/version/settings.clj#L9)
  uses the installed build's [version.properties](https://github.com/metabase/metabase/blob/9a6cadd7ffbf8d294737300b35d7167234bb7049/src/metabase/config/core.clj#L134).
  Only `version.tag` is release evidence. `version-info` describes available
  updates and is normally [excluded from the response](https://github.com/metabase/metabase/blob/9a6cadd7ffbf8d294737300b35d7167234bb7049/test/metabase/session/api_test.clj#L581).
- The [HTML template](https://github.com/metabase/metabase/blob/9a6cadd7ffbf8d294737300b35d7167234bb7049/resources/frontend_client/index_template.html#L26)
  embeds public settings in one `application/json` script named
  `_metabaseBootstrap`. Require its `version.tag` to agree with the API tag.
  The page title may be customized; localization marker names change between
  releases and are not required for identification.

The collector makes bounded anonymous GETs to the origin root, the properties
endpoint and one random nonexistent `/api/asteroid-metadata-<uuid>` path. The
control path rejects API catch-all responses containing an installed release;
ordinary SPA HTML fallbacks are allowed. The shared defensive metadata transport
caps each response at 256 KiB, uses a five-second socket timeout, does not follow
redirects and does not forward session credentials or cookies. HTML base URLs
are ignored. Only origin-root installations are assessed; installation subpaths
are a coverage gap. No reset, import, notification, database creation or query
request is made. The finding location remains the origin root, independent of
release or the random control path.

Require stable `v?0.branch.point[.patch]` (OSS) or
`v?1.branch.point[.patch]` (Enterprise). Reject development, prerelease, suffix,
truncated, malformed, duplicate or conflicting release evidence. Preserve the
fourth component; omitted trailing zero compares as zero, consistent with
[the vendor's tag convention](https://github.com/metabase/metabase/issues/76268).

## Supported intervals

Here `x` means the observed edition, 0 or 1. Every upper bound is exclusive.
Branches outside the explicit intervals remain unclassified.

| CVE-2026- | Matched intervals | Fixed releases |
| --- | --- | --- |
| [27464](https://github.com/metabase/metabase/security/advisories/GHSA-vcj8-rcm8-gfj9) | Branch 57: `.0` to `.13`; branch 58: `.0` to `.7` | x.57.13, x.58.7 |
| [33725](https://github.com/metabase/metabase/security/advisories/GHSA-fppj-vcm3-w229) | EE only: 1.47.0 to 1.54.0; branches 54/55/56 below .22, 57 below .16, 58 below .10, 59 below .4, each starting at .0 | 1.54.22, 1.55.22, 1.56.22, 1.57.16, 1.58.10, 1.59.4 |
| [59826](https://github.com/metabase/metabase/security/advisories/GHSA-8wx2-rxp2-4x35) | x.55.0 to x.58.15.1; branch 59 below .12, 60 below .7, 61 below .2, each starting at .0 | x.58.15.1, x.59.12, x.60.7, x.61.2 |
| [59827](https://github.com/metabase/metabase/security/advisories/GHSA-w95f-x9v9-wv36) | Branch 58 below .15, 59 below .12, 60 below .6.3, 61 below .1.4, each starting at .0 | x.58.15, x.59.12, x.60.6.3, x.61.1.4 |
| [72898](https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf) | Branch 58 below .23, 59 below .20, 60 below .16, 61 below .10, 62 below .8, 63 below .3, each starting at .0 | x.58.24, x.59.21, x.60.17, x.61.11, x.62.9, x.63.5 |
| [72899](https://github.com/metabase/metabase/security/advisories/GHSA-r8h2-qpfx-mx59), [72900](https://github.com/metabase/metabase/security/advisories/GHSA-8hmm-hrhg-ppqp) | Branch 58 below .24, 59 below .21, 60 below .17, 61 below .11, 62 below .9, 63 below .5, each starting at .0 | x.58.24, x.59.21, x.60.17, x.61.11, x.62.9, x.63.5 |

27464's broad earlier-version shorthand has no documented introduction minimum;
this implementation conservatively covers branches 57 and 58 only. The
[CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/27xxx/CVE-2026-27464.json)
clarifies the separate 58 interval, so patched 57 releases must not match a broad
"before 58.7" comparison. Older branches are a coverage gap.

33725's narrative explicitly excludes OSS and dates serialization to at least
1.47. Its headline shorthand is imprecise; use the narrative minimum and each
listed branch fix. Versions before 1.47 remain unclassified.

59826/59827 tables show 1.x ranges, while their patch sections explicitly list
both 0.x and 1.x fixed releases; Nessus also lists both editions. A fourth
component is necessary for 58.15.1, 60.6.3 and 61.1.4.

72898 has a primary-source conflict. The [August 6 announcement](https://www.metabase.com/blog/security-update-6-aug-2026)
says releases below the fixed versions are affected. The newer advisory
(updated 2026-08-11T03:18:39Z) gives narrower explicit affected bounds. Use the
intersection and leave these intervals **unknown, not safe or confirmed
affected**: `[x.58.23,x.58.24)`, `[x.59.20,x.59.21)`,
`[x.60.16,x.60.17)`, `[x.61.10,x.61.11)`, `[x.62.8,x.62.9)`,
`[x.63.3,x.63.5)`. Sibling CVEs retain their own wider bounds.

## Prerequisites that anonymous metadata does not establish

| CVE-2026- | Unverified conditions |
| --- | --- |
| 27464 | Authenticated low-privilege user and available notification/template path. |
| 33725 | Authenticated administrator, Enterprise serialization and reachable import endpoint. |
| 59826 | Authenticated administrator and reachable vulnerable database-creation path. |
| 59827 | H2 source, possibly the sample database, and authenticated native-query permission. |
| 72898 | Reachable password-reset endpoint without a targeted proxy workaround. |
| 72899 | Public sharing, published card/dashboard with a field-filter parameter, known public UUID. |
| 72900 | Audit database, authenticated user, public sharing and affected authorization path; cleartext credential exposure additionally depends on the encryption-key setting. |

`enable-public-sharing` is [authenticated-only](https://github.com/metabase/metabase/blob/9a6cadd7ffbf8d294737300b35d7167234bb7049/src/metabase/public_sharing/settings.clj#L6),
despite defaulting to true. Its absence from anonymous properties does not mean
sharing is disabled; its presence alone does not establish a qualifying public
object or the vulnerable audit path.

The audit database is normally Enterprise-only, but upstream expressly supports
[retained audit content after EE-to-OSS downgrade](https://github.com/metabase/metabase/blob/9a6cadd7ffbf8d294737300b35d7167234bb7049/src/metabase/audit_app/impl.clj#L8).
72900 therefore includes both editions with audit presence explicitly unverified.
Its vendor score is **Medium 6.5**, not the bundle's Critical rating. 72899's
individual score is **Critical 9.6, PR:N/UI:R**, not the bundle's 10.0/UI:N.
