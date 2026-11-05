# WordPress plugin potential exposure checks added in the 2026 gap batch

Verified 2026-11-05. This batch adds **19 independent remote CVE checks across 16
plugin slugs**, plus **one owner-inventory-only Avada Builder assessment** (17
slugs and 20 CVEs total). The CVE year is not the batch year: these templates
first appeared on Nuclei main during 2026. Nuclei establishes candidate scope;
the primary advisory and vendor readmes establish each policy.

## Evidence and result semantics

Remote findings prominently say **POTENTIAL ADVERTISED-RELEASE EXPOSURE**.
An exposed readme's `Stable tag` is distribution metadata. The installed plugin's
main PHP `Version` is authoritative for the installed version, and the readme
can be stale, copied, or inconsistent with deployed code. Remote checks leave
activation, privileges, prerequisite configuration, backports and exploitability
unknown. A matching tag establishes only an advertised affected release. An
empty result never establishes that a site is unaffected or patched.

The shared reader makes anonymous GET requests through the existing defensive
transport, without inherited credentials or cookies, redirects, or response
caching. At most two REST-index candidates are tried: the target's literal base
path first, then the origin root. Each must corroborate `wp/v2`, its routes map,
the root route's self URL, and the same-origin `home` base. The index's `url`
(`siteurl`) then determines the same-origin WordPress core/plugin base. This
supports a root REST index with core installed in `/wordpress` and a REST index
under `/blog`. Host/scheme/port mismatches, URL credentials, query strings,
encoded or dot path segments and inconsistent bases are rejected.

After that independent WordPress evidence, the reader fetches only the profile's
exact static `wp-content/plugins/<slug>/readme.txt` path (`README.txt` for
WPBookit). It requires an exact observed plugin heading, allowing an initial
UTF-8 BOM and surrounding ASCII whitespace, and exactly one canonical `Stable
tag` in the initial block of recognized metadata fields. Markdown/WordPress
headings, free-form prose and unknown fields end that block; later tags cannot
supply the version. Duplicate tags, duplicate explicit `Version` headers,
conflicting explicit versions, malformed text, HTML documents and fork/build
suffixes are inconclusive. Inline Markdown/HTML examples in genuine readmes are
not HTML-document evidence. One to four canonical numeric components are retained
in reported evidence and compared after zero-padding; the fourth component is
never dropped. Requires/Tested/changelog values never supply the release.

A random nonexistent `.txt` path in the same plugin directory must return
404 or 410. Catch-all/soft-404 200 responses, redirects, errors and unavailable
controls are inconclusive. Metadata bodies are bounded to 256 KiB with five-second
request timeouts. Negative control bodies are never consumed. A normal successful
check uses three requests, or four when the first REST candidate does not match.
No plugin AJAX actions, private REST records, logins, forms, OAST, state changes,
or exploitation payloads are used.

REST-hidden sites, custom content directories, nonstandard REST prefixes,
query-form REST routing, cross-origin mappings and unknown heading variants
remain inconclusive. Authoritative owner inventory is preferred.

Primary WordPress behavior sources:

- [How the readme works](https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/)
- [REST index fields, including siteurl and home](https://developer.wordpress.org/reference/classes/wp_rest_server/get_index/)
- [REST route self links](https://developer.wordpress.org/reference/classes/wp_rest_server/get_data_for_route/)
- [REST URLs use the home base](https://developer.wordpress.org/reference/functions/get_rest_url/)

## Per-CVE source table

`<=` includes its upper boundary; `<` excludes it. An absent lower bound means
the source identifies all releases through/before the upper bound, not a guessed
introduction version. Risk is the advisory CVSS severity, not confidence in
remote exploitation. Each remote profile has its own CVE metadata and registry
key, so `custom_cve_list` selects exactly one CVE even for shared plugin slugs.

| CVE | Plugin slug | Affected release interval | Severity | Assessment | Range authority | First on Nuclei main (UTC) |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2024-5333 | `the-events-calendar` | `< 6.8.2.1` | Medium | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/5xxx/CVE-2024-5333.json) | [2026-01-29T06:14:45+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2024/CVE-2024-5333.yaml) |
| CVE-2023-3452 | `canto` | `<= 3.0.4` | Critical | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2023/3xxx/CVE-2023-3452.json) | [2026-02-25T07:27:14+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2023/CVE-2023-3452.yaml) |
| CVE-2025-12536 | `sureforms` | `<= 1.13.1` | Medium | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/12xxx/CVE-2025-12536.json) | [2026-04-07T04:57:10+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2025/CVE-2025-12536.yaml) |
| CVE-2026-2416 | `geo-mashup` | `<= 1.13.17` | High | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/2xxx/CVE-2026-2416.json) | [2026-04-13T16:16:26+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-2416.yaml) |
| CVE-2025-69411 | `ioncube-tester-plus` | `<= 1.3` | High | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/69xxx/CVE-2025-69411.json) | [2026-04-19T08:11:36+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2025/CVE-2025-69411.yaml) |
| CVE-2025-13801 | `yoco-payment-gateway` | `<= 3.9.0` | High | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/13xxx/CVE-2025-13801.json) | [2026-04-23T08:24:23+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2025/CVE-2025-13801.yaml) |
| CVE-2025-9209 | `restropress` | `>= 3.0.0 and <= 3.2.1` | Critical | Advertised readme release | [Primary record](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/restropress/restropress-online-food-ordering-system-300-3192-unauthenticated-information-exposure-to-authentication-bypass-via-forged-jwt) | [2026-04-23T10:39:42+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2025/CVE-2025-9209.yaml) |
| CVE-2025-12841 | `bookit` | `< 2.5.1` | Medium | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/12xxx/CVE-2025-12841.json) | [2026-05-20T06:58:20+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2025/CVE-2025-12841.yaml) |
| CVE-2026-8181 | `burst-statistics` | `>= 3.4.0 and <= 3.4.1.1` | Critical | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/8xxx/CVE-2026-8181.json) | [2026-05-27T06:26:59+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-8181.yaml) |
| CVE-2025-13773 | `woocommerce-delivery-notes` | `<= 5.8.0` | Critical | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/13xxx/CVE-2025-13773.json) | [2026-06-02T17:21:36+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2025/CVE-2025-13773.yaml) |
| CVE-2026-9290 | `wp-user-manager` | `<= 2.9.17` | High | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/9xxx/CVE-2026-9290.json) | [2026-06-11T00:09:01+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-9290.yaml) |
| CVE-2026-1980 | `wpbookit` | `<= 1.0.8` | Medium | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/1xxx/CVE-2026-1980.json) | [2026-07-21T05:34:06+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-1980.yaml) |
| CVE-2026-8713 | `fusion-builder` | `<= 3.15.3` | Critical | Owner inventory | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/8xxx/CVE-2026-8713.json) | [2026-07-27T13:06:41+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-8713.yaml) |
| CVE-2026-39468 | `meta-box` | `<= 5.11.1` | Medium | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/39xxx/CVE-2026-39468.json) | [2026-07-29T05:31:59+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-39468.yaml) |
| CVE-2019-14793 | `meta-box` | `< 4.16.3` | Medium | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2019/14xxx/CVE-2019-14793.json) | [2026-08-03T00:22:53+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2019/CVE-2019-14793.yaml) |
| CVE-2026-4060 | `geo-mashup` | `<= 1.13.18` | High | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/4xxx/CVE-2026-4060.json) | [2026-08-18T06:33:04+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-4060.yaml) |
| CVE-2026-49772 | `the-events-calendar` | `>= 6.15.12 and <= 6.16.2` | Critical | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/49xxx/CVE-2026-49772.json) | [2026-10-20T09:53:09+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-49772.yaml) |
| CVE-2026-52715 | `geo-my-wp` | `<= 4.5.5` | Critical | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/52xxx/CVE-2026-52715.json) | [2026-10-21T02:07:42+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-52715.yaml) |
| CVE-2026-9848 | `wp-ticket` | `<= 6.0.4` | High | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/9xxx/CVE-2026-9848.json) | [2026-10-26T08:41:27+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-9848.yaml) |
| CVE-2026-3296 | `everest-forms` | `<= 3.4.3` | Critical | Advertised readme release | [Primary record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/3xxx/CVE-2026-3296.json) | [2026-07-21T15:19:52+00:00](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-3296.yaml) |

CNA severity is retained except CVE-2024-5333 and CVE-2025-12841, whose Medium
5.3 ratings come from CISA ADP enrichment in their CVE records. Meta Box
CVE-2019-14793 uses NVD's Medium 6.5 CVSS 3.0 enrichment with `PR:L`, verified
through the [NVD API](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14793).
Its minimum WordPress role is unresolved.

## Source conflicts and prerequisite limits

- **Yoco CVE-2025-13801:** CNA says through **3.9.0**. Nuclei's 3.8.8 cap is not
  used, so 3.8.9 and 3.9.0 are included.
- **RestroPress CVE-2025-9209:** the current publishing Wordfence advisory gives
  **3.0.0–3.2.1**, fixed in **3.2.2**. Historical CVEProject CNA JSON still says
  through 3.1.9.2. The implementation uses the live publishing-CNA interval and
  explicitly preserves this discrepancy in findings, rather than treating the
  conflicting historical JSON as newer evidence.
- **Meta Box CVE-2026-39468:** the CNA narrative and Patchstack require
  **Contributor or higher** access, despite the inconsistent CVSS `PR:N` field.
  Findings retain the role prerequisite and Medium 6.8 advisory severity.
- **Everest Forms CVE-2026-3296:** an unauthenticated attacker can submit a form
  value, but an **administrator views stored form entries** before deserialization.
  Maximum impact requires a usable gadget chain. The Nuclei template's passive
  label does not justify its serialized OAST POST; it is not reproduced here.
- **Burst CVE-2026-8181:** only **3.4.0–3.4.1.1** matches, and an administrator
  username is required. Affected SVN tags were unavailable. Allowed headings
  come from the vendor's fixed-version commit and current trunk; older unverified
  variants remain inconclusive.
- **The Events Calendar CVE-2026-49772:** the introduction version **6.15.12**
  is enforced; earlier versions are not swept into this CVE's interval.
- **Geo Mashup:** CVE-2026-2416 ends at **1.13.17**; CVE-2026-4060 extends through
  **1.13.18** because other map-rendering/template paths remained affected after
  the AJAX fix. The two profiles never share an inferred fixed boundary.
- **Canto:** remote inclusion/code execution requires `allow_url_include`;
  local inclusion to code execution also requires suitable attacker-controlled
  readable PHP content. **WP User Manager** has a similar includable-file
  prerequisite for escalation beyond LFI.
- Data/configuration prerequisites remain unknown: password-protected Events
  Calendar events; SureForms notification metadata; WPBookit customer records;
  Bookit payment options; WooCommerce document/template processing; GEO my WP
  boundary search; and WP Ticket's front-end search hook.

## Avada owner inventory

CVE-2026-8713 is **not registered as a remote detector**. There is no verified
public installed-version signal. The inventory dispatcher accepts this normalized
owner evidence, gathered for the same deployment from trusted administration or
WP-CLI/main plugin headers:

```json
[
  {
    "product": "Avada Builder",
    "plugin_slug": "fusion-builder",
    "version": "3.15.3",
    "active": true,
    "published_form": true,
    "form_saves_to_database": true
  }
]
```

```sh
python -m agent.utils.inventory inventory.json
```

All three flags must be explicit booleans, not missing values, strings, or
integers. Any verified false prerequisite yields `not_matched` for the supplied
configuration. A canonical release through 3.15.3 with all three prerequisites
true yields `potential_exposure`; 3.15.4 or later yields `not_matched` for the
supplied release. A numeric release between the affected maximum and fixed
release is inconclusive. Wrong product/slug, custom builds, explicit conflicting
evidence, and absent prerequisites are inconclusive. Asset query strings never
supply the installed version. This offline assessment makes no network requests,
independently authenticates no inventory, and emits no supplied private fields.
See the [publishing Wordfence advisory](https://www.wordfence.com/blog/2026/06/critical-unauthenticated-arbitrary-file-deletion-vulnerability-patched-in-avada-builder-wordpress-plugin/).

## Readme identity provenance

Exact headings were checked at current trunk and representative affected tags,
not every historical release. The test fixture
`tests/exploits/fixtures/wordpress_readme_headers.json` preserves all 38 fetched
header excerpts and the SHA-256 of each full source readme. Tests exercise each
heading through the public detector, including version boundaries and unchanged
vendor header whitespace. The reviewed source revision for candidate discovery
is [Nuclei fef763cd6e1da264eca8668741edef52faa743f6](https://github.com/projectdiscovery/nuclei-templates/tree/fef763cd6e1da264eca8668741edef52faa743f6).

- **CVE-2024-5333 / `the-events-calendar`:** [trunk](https://plugins.svn.wordpress.org/the-events-calendar/trunk/readme.txt); [tags/6.8.2](https://plugins.svn.wordpress.org/the-events-calendar/tags/6.8.2/readme.txt).
- **CVE-2023-3452 / `canto`:** [trunk](https://plugins.svn.wordpress.org/canto/trunk/readme.txt); [tags/3.0.4](https://plugins.svn.wordpress.org/canto/tags/3.0.4/readme.txt).
- **CVE-2025-12536 / `sureforms`:** [trunk](https://plugins.svn.wordpress.org/sureforms/trunk/readme.txt); [tags/1.13.1](https://plugins.svn.wordpress.org/sureforms/tags/1.13.1/readme.txt).
- **CVE-2026-2416 / `geo-mashup`:** [trunk](https://plugins.svn.wordpress.org/geo-mashup/trunk/readme.txt); [tags/1.13.17](https://plugins.svn.wordpress.org/geo-mashup/tags/1.13.17/readme.txt).
- **CVE-2025-69411 / `ioncube-tester-plus`:** [trunk](https://plugins.svn.wordpress.org/ioncube-tester-plus/trunk/readme.txt); [tags/1.3](https://plugins.svn.wordpress.org/ioncube-tester-plus/tags/1.3/readme.txt).
- **CVE-2025-13801 / `yoco-payment-gateway`:** [trunk](https://plugins.svn.wordpress.org/yoco-payment-gateway/trunk/readme.txt); [tags/3.9.0](https://plugins.svn.wordpress.org/yoco-payment-gateway/tags/3.9.0/readme.txt).
- **CVE-2025-9209 / `restropress`:** [trunk](https://plugins.svn.wordpress.org/restropress/trunk/readme.txt); [tags/3.2.1](https://plugins.svn.wordpress.org/restropress/tags/3.2.1/readme.txt).
- **CVE-2025-12841 / `bookit`:** [trunk](https://plugins.svn.wordpress.org/bookit/trunk/readme.txt); [tags/2.5.0](https://plugins.svn.wordpress.org/bookit/tags/2.5.0/readme.txt).
- **CVE-2026-8181 / `burst-statistics`:** [trunk](https://plugins.svn.wordpress.org/burst-statistics/trunk/readme.txt); [commit/2488d3fa54045e7e5342b0445b9f6b5eaac9ea7c](https://raw.githubusercontent.com/Burst-Statistics/burst-statistics/2488d3fa54045e7e5342b0445b9f6b5eaac9ea7c/readme.txt).
- **CVE-2025-13773 / `woocommerce-delivery-notes`:** [trunk](https://plugins.svn.wordpress.org/woocommerce-delivery-notes/trunk/readme.txt); [tags/5.8.0](https://plugins.svn.wordpress.org/woocommerce-delivery-notes/tags/5.8.0/readme.txt).
- **CVE-2026-9290 / `wp-user-manager`:** [trunk](https://plugins.svn.wordpress.org/wp-user-manager/trunk/readme.txt); [tags/2.9.17](https://plugins.svn.wordpress.org/wp-user-manager/tags/2.9.17/readme.txt).
- **CVE-2026-1980 / `wpbookit`:** [tags/1.0.8](https://plugins.svn.wordpress.org/wpbookit/tags/1.0.8/README.txt); [trunk](https://plugins.svn.wordpress.org/wpbookit/trunk/README.txt).
- **CVE-2026-39468 / `meta-box`:** [trunk](https://plugins.svn.wordpress.org/meta-box/trunk/readme.txt); [tags/5.11.1](https://plugins.svn.wordpress.org/meta-box/tags/5.11.1/readme.txt).
- **CVE-2019-14793 / `meta-box`:** [trunk](https://plugins.svn.wordpress.org/meta-box/trunk/readme.txt); [tags/4.16.2](https://plugins.svn.wordpress.org/meta-box/tags/4.16.2/readme.txt).
- **CVE-2026-4060 / `geo-mashup`:** [trunk](https://plugins.svn.wordpress.org/geo-mashup/trunk/readme.txt); [tags/1.13.18](https://plugins.svn.wordpress.org/geo-mashup/tags/1.13.18/readme.txt).
- **CVE-2026-49772 / `the-events-calendar`:** [trunk](https://plugins.svn.wordpress.org/the-events-calendar/trunk/readme.txt); [tags/6.16.2](https://plugins.svn.wordpress.org/the-events-calendar/tags/6.16.2/readme.txt).
- **CVE-2026-52715 / `geo-my-wp`:** [trunk](https://plugins.svn.wordpress.org/geo-my-wp/trunk/readme.txt); [tags/4.5.5](https://plugins.svn.wordpress.org/geo-my-wp/tags/4.5.5/readme.txt).
- **CVE-2026-9848 / `wp-ticket`:** [trunk](https://plugins.svn.wordpress.org/wp-ticket/trunk/readme.txt); [tags/6.0.4](https://plugins.svn.wordpress.org/wp-ticket/tags/6.0.4/readme.txt).
- **CVE-2026-3296 / `everest-forms`:** [trunk](https://plugins.svn.wordpress.org/everest-forms/trunk/readme.txt); [tags/3.4.3](https://plugins.svn.wordpress.org/everest-forms/tags/3.4.3/readme.txt).

## Deferred candidates

**CVE-2025-2558** and **CVE-2026-3326** concern WordPress themes. Neither is
implemented or counted as covered by this plugin batch. Separate verified theme
identity/version evidence is needed before adding them.

No KEV, active exploitation, malware, or exploitation-success claims are inferred
from Nuclei tags. Lack of a remote finding remains inconclusive for deployed-code
security.
