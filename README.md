<h1 align="center">Agent Asteroid</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_asteroid">
<img src="https://img.shields.io/github/stars/ostorlab/agent_asteroid">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

**Agent Asteroid is an open-source scanner for known, remotely exploitable vulnerabilities.**
It checks internet-facing IP addresses, domains and links for the products and
versions associated with those vulnerabilities, using read-only, non-destructive
probes that do not change appliance configuration or application data. It is also one of the
scanners in the [Ostorlab KEV agent group](https://github.com/Ostorlab/KEV),
which adds Nuclei, Tsunami, Nmap and Metasploit coverage.

A credential-bypass check that confirms a public in-product secret is accepted
submits only locally minted bearer tokens for a fabricated identity to
non-sensitive identity or RBAC endpoints. A detector that proves an elevated
role mints that role's claims (for example `roles: [public, admin]` with
`options.showSettings: true`) and exercises them only against the identity
endpoint and a non-existent-resource lookup that cannot succeed; it never
performs an administrative action. Default-credential checks, such as the
MLflow CVE-2026-2635 detector, read the affected account's own metadata and
document that in their module. The
separate CVE-2026-76504 authentication-bypass check submits a random synthetic
login to the documented encoded login path to prove the bypass; it stores no
token or cookie, reads only the session's
own role document, and changes no configuration.

| Coverage | Count |
| --- | ---: |
| CVEs checked automatically during an `oxo` scan | 619 |
| Additional CVEs assessed from owner-supplied inventory | 85 |
| **Unique CVEs covered** | **704** |
| Ruby GHSA assessments (CVE assignment pending) | 3 |
| Non-CVE exposure checks | 3 |

_Coverage snapshot: 27 November 2026._

A finding means the observed evidence matches a known-vulnerable condition. A
clean scan does not prove a target is patched: backports, hotfixes,
configuration and authenticated-only checks can require local verification.

## What it detects

- **Remote checks (619 CVEs).** Version, banner, metadata and behaviour checks
  for exposed services: web applications, VPNs, firewalls, mail servers,
  databases, network appliances and developer tools.
- **Offline inventory assessments (95 CVEs: 85 inventory-only and 10 also covered remotely).**
  `python -m agent.utils.inventory` assesses normalized evidence supplied by the
  owner, including runtime configuration that remote metadata cannot establish.
  It makes no network requests. Overlapping CVEs are counted once in the unique total.
- **Ruby GHSA inventory assessments (3).** Native CRuby/Onigmo regexp bugs
  have separate advisory identities while upstream CVE assignment is pending.
  These do not change the CVE totals above.
- **Non-CVE exposure checks (3).** Unauthenticated ADB, the Docker Registry API,
  and the Jetpack contact-form data exposure.

The ten CVEs covered by both modes are:

- Log4Shell (CVE-2021-44228)
- Spring4Shell (CVE-2022-22965)
- Text4Shell (CVE-2022-42889)
- PHP2Shell (CVE-2026-109618 and CVE-2026-109619)
- React2Shell (CVE-2025-55182)
- Brotli/Node2Shell (CVE-2026-111497)
- Java4Shell (CVE-2026-114938)
- PHP Core (CVE-2026-115560)
- GreaterWMS (CVE-2026-130867)

See [Java4Shell coverage](docs/shell-java4shell-coverage.md) for trusted JVM
inventory, hardware prerequisites and short-lived remote observations.

Each detector owns its prerequisites and limitations in its module. Positive
results that cannot confirm exploitability say so explicitly.

## How to use it

### Install and run

```shell
pip install -U ostorlab
oxo scan run --install --agent agent/ostorlab/asteroid ip 8.8.8.8
```

Scan a domain or a link:

```shell
oxo scan run --install --agent agent/ostorlab/asteroid domain-name example.com
oxo scan run --install --agent agent/ostorlab/asteroid link --url https://example.com --method GET
```

### Run selected CVEs

Pass `custom_cve_list` as a JSON array. If it is omitted, every detector runs.

```shell
oxo scan run --install --agent agent/ostorlab/asteroid \
  --arg 'custom_cve_list:["CVE-2026-71495","CVE-2026-123201"]' ip 8.8.8.8
```

### Assess an offline inventory

For CVEs that need configuration or deployment evidence, supply a normalized
inventory JSON. The assessor makes no network requests and executes no target
code.

```shell
python -m agent.utils.inventory inventory.json
```

Example input:

```json
[
  {
    "product": "GitLab EE",
    "version": "19.4.2",
    "deployment": "self-managed"
  },
  {
    "product": "Envoy",
    "version": "1.39.2",
    "brotli_decompressor_enabled": true
  }
]
```

PHP2Shell, React2Shell and Brotli/Node2Shell also accept owner-supplied runtime and
resolved-package records. Exact products, branch bounds and optional effective
prerequisites are documented in [Shell runtime coverage](docs/shell-runtime-coverage.md).
Affected runtime/package versions alone can report `potential_exposure`, with
reachability and patch provenance unconfirmed. Optional `verified_fixed_cves`
lists identify owner-verified fixes per CVE; a fix for one PHP CVE does not clear
the other two. Offline assessment does not collect or verify this evidence.

Native Ruby/Onigmo records also receive three independent GHSA assessments.
Engine identity, release bounds, selective backports and compilation reachability
are documented in [Ruby regexp coverage](docs/shell-ruby-coverage.md). Ruby results
have empty `cve_ids` and an `advisory_ids` field; existing CVE-only JSON retains
its original four keys. The GitLab CVE assessments retain their product bounds.

Missing or ambiguous required prerequisites produce `inconclusive`. `not_matched`
applies only to that check, not to the system's overall security. See
[the CVE coverage notes](#coverage-notes) for limitations.

### Read the results

```shell
oxo scan list
oxo vulnz list -s <scan-id>
oxo vulnz describe -v <vuln-id>
```

### Build from source

1. Install `oxo`:

   ```shell
   pip3 install ostorlab
   ```

2. Clone the repository:

   ```shell
   git clone https://github.com/Ostorlab/agent_asteroid.git && cd agent_asteroid
   ```

3. Build the agent image:

   ```shell
   oxo agent build --file=ostorlab.yaml
   ```

   Pass `--organization` to set the organisation. It is empty by default.

4. Run the agent:

   ```shell
   oxo scan run --agent agent//asteroid ip 8.8.8.8
   oxo scan run --agent agent/[ORGANIZATION]/asteroid ip 8.8.8.8
   ```

## Coverage

### Ruby advisories awaiting CVE assignment

These trusted-inventory assessments are additional to the CVE totals.

| Advisory | What is assessed | Mode |
| --- | --- | --- |
| [GHSA-gfj3-8wj9-qx8p](agent/exploits/ruby_regex.py) | Native Ruby regexp parser double free | Offline inventory |
| [GHSA-22mf-ggw7-pxfx](agent/exploits/ruby_regex.py) | Native Ruby compiled-pattern size overflow | Offline inventory |
| [GHSA-qm4g-8pfh-6996](agent/exploits/ruby_regex.py) | Native Ruby regexp internal-ID overflow | Offline inventory |

See [Ruby regexp coverage](docs/shell-ruby-coverage.md) for upstream sources and boundaries.

### Detected CVEs

The table combines the 619 remote checks with the 85 inventory-only assessments:
**704 unique CVEs**. `Remote` runs during an `oxo` scan; `Offline inventory`
runs through `python -m agent.utils.inventory`. `Remote + inventory` and
`Remote SBOM / offline inventory` support both modes. Remote SBOM checks
require the exposed Actuator `/actuator/sbom/application` endpoint.

| Year | Remote | Inventory only | Total |
| --- | ---: | ---: | ---: |
| 2026 | 322 | 63 | 385 |
| 2025 | 97 | 11 | 108 |
| 2024 | 101 | 4 | 105 |
| 2023 | 31 | 2 | 33 |
| 2022 | 12 | 2 | 14 |
| 2021 | 13 | 1 | 14 |
| 2020 | 4 | 1 | 5 |
| 2019 | 9 | 1 | 10 |
| 2018 | 11 | 0 | 11 |
| 2017 | 6 | 0 | 6 |
| 2016 | 3 | 0 | 3 |
| 2015 | 2 | 0 | 2 |
| 2014 | 5 | 0 | 5 |
| 2012 | 1 | 0 | 1 |
| 2010 | 2 | 0 | 2 |
| **Total** | **619** | **85** | **704** |

<details><summary><b>2026 — 385 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2026-0263](agent/exploits/cve_2026_0263.py) | PAN-OS IKEv2 CVE-2026-0263 | Offline inventory |
| [CVE-2026-0264](agent/exploits/cve_2026_0264.py) | PAN-OS DNS CVE-2026-0264 | Offline inventory |
| [CVE-2026-0265](agent/exploits/cve_2026_0265.py) | PAN-OS CAS CVE-2026-0265 | Offline inventory |
| [CVE-2026-0288](agent/exploits/cve_2026_0288.py) | PAN-OS Terminal Server Agent CVE-2026-0288 | Offline inventory |
| [CVE-2026-0300](agent/exploits/cve_2026_0300.py) | PAN-OS Authentication Portal CVE-2026-0300 | Offline inventory |
| [CVE-2026-0310](agent/exploits/cve_2026_0310.py) | PAN-OS XML-processing CVE-2026-0310 | Offline inventory |
| [CVE-2026-0545](agent/exploits/cve_2026_0545.py) | MLflow CVE-2026-0545 job authentication bypass | Remote |
| [CVE-2026-0650](agent/exploits/cve_2026_0650.py) | OpenFlagr CVE-2026-0650 authentication bypass | Remote |
| [CVE-2026-0768](agent/exploits/cve_2026_0768.py) | Langflow <= 1.2.x unauthenticated remote code execution via validate_code (CVE-2026-0768) | Remote |
| [CVE-2026-0920](agent/exploits/wordpress_readme_2026.py) | LA-Studio Element Kit for Elementor (CVE-2026-0920) | Remote |
| [CVE-2026-0926](agent/exploits/wordpress_readme_2026.py) | Prodigy Commerce (CVE-2026-0926) | Remote |
| [CVE-2026-1207](agent/exploits/cve_2026_1207.py) | Django GIS raster error-based SQL injection (CVE-2026-1207) | Remote |
| [CVE-2026-1306](agent/exploits/wordpress_readme_2026.py) | midi-Synth (CVE-2026-1306) | Remote |
| [CVE-2026-1357](agent/exploits/wordpress_readme_2026.py) | WPvivid Backup & Migration (CVE-2026-1357) | Remote |
| [CVE-2026-1405](agent/exploits/wordpress_readme_2026.py) | Slider Future (CVE-2026-1405) | Remote |
| [CVE-2026-1492](agent/exploits/wordpress_readme_2026.py) | User Registration & Membership (CVE-2026-1492) | Remote |
| [CVE-2026-1581](agent/exploits/cve_2026_1581.py) | wpForo Forum WordPress plugin unauthenticated SQL injection (CVE-2026-1581) | Remote |
| [CVE-2026-1603](agent/exploits/cve_2026_1603.py) | Ivanti EPM RemoteControlAuth authentication bypass (CVE-2026-1603) | Remote |
| [CVE-2026-1830](agent/exploits/wordpress_readme_2026.py) | Quick Playground (CVE-2026-1830) | Remote |
| [CVE-2026-1980](agent/exploits/wordpress_readme_2026.py) | WPBookit (CVE-2026-1980) | Remote |
| [CVE-2026-2413](agent/exploits/cve_2026_2413.py) | Ally - Web Accessibility & Usability WordPress plugin unauthenticated SQL injection (CVE-2026-2413) | Remote |
| [CVE-2026-2416](agent/exploits/wordpress_readme_2026.py) | Geo Mashup (CVE-2026-2416) | Remote |
| [CVE-2026-2635](agent/exploits/cve_2026_2635.py) | MLflow default administrator credential permits account read access | Remote |
| [CVE-2026-2699](agent/exploits/cve_2026_2699.py) | ShareFile configuration exposure | Remote |
| [CVE-2026-3055](agent/exploits/cve_2026_3055.py) | NetScaler SAML IDP memory overread (CVE-2026-3055) | Remote |
| [CVE-2026-3296](agent/exploits/wordpress_readme_2026.py) | Everest Forms – Contact Form, Payment Form, Quiz, Survey & Custom Form Builder (CVE-2026-3296) | Remote |
| [CVE-2026-3326](agent/exploits/cve_2026_3326.py) | XStore WordPress theme SQL injection (CVE-2026-3326) | Remote |
| [CVE-2026-3584](agent/exploits/wordpress_readme_2026.py) | Kali Forms (CVE-2026-3584) | Remote |
| [CVE-2026-3593](agent/exploits/cve_2026_3593.py) | BIND DoH assessment; no memory-corruption probe | Offline inventory |
| [CVE-2026-3630](agent/exploits/cve_2026_3630.py) | CVE-2026-3630 | Offline inventory |
| [CVE-2026-3844](agent/exploits/wordpress_readme_2026.py) | Breeze Cache (CVE-2026-3844) | Remote |
| [CVE-2026-3891](agent/exploits/wordpress_readme_2026.py) | Pix for WooCommerce (CVE-2026-3891) | Remote |
| [CVE-2026-4020](agent/exploits/cve_2026_4020.py) | Gravity SMTP information exposure | Remote |
| [CVE-2026-4060](agent/exploits/wordpress_readme_2026.py) | Geo Mashup (CVE-2026-4060) | Remote |
| [CVE-2026-4257](agent/exploits/wordpress_readme_2026.py) | Contact Form by Supsystic (CVE-2026-4257) | Remote |
| [CVE-2026-4800](agent/exploits/cve_2026_4800.py) | assessment of lodash template imports, without target I/O | Offline inventory |
| [CVE-2026-4858](agent/exploits/cve_2026_4858.py) | Mattermost CVE-2026-4858 (advertised release) | Remote |
| [CVE-2026-5430](agent/exploits/cve_2026_5430.py) | WSO2 API Manager JWT algorithm authentication bypass (CVE-2026-5430) | Remote |
| [CVE-2026-6516](agent/exploits/cve_2026_6516.py) | CVE-2026-6516 | Offline inventory |
| [CVE-2026-6875](agent/exploits/cve_2026_6875.py) | ServiceNow remote code execution | Remote |
| [CVE-2026-7873](agent/exploits/cve_2026_7873.py) | Langflow CVE-2026-7873 code-validation RCE | Remote |
| [CVE-2026-8024](agent/exploits/cve_2026_8024.py) | CVE-2026-8024 | Offline inventory |
| [CVE-2026-8037](agent/exploits/cve_2026_8037.py) | Progress ADC LoadMaster unauthenticated OS command injection (CVE-2026-8037) | Remote |
| [CVE-2026-8054](agent/exploits/cve_2026_8054.py) | dotCMS Core Publish Audit API unauthenticated blind SQL injection (CVE-2026-8054) | Remote |
| [CVE-2026-8181](agent/exploits/wordpress_readme_2026.py) | Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) (CVE-2026-8181) | Remote |
| [CVE-2026-8364](agent/exploits/cve_2026_8364.py) | assessment of Triofox Server Agent CVE-2026-8364 | Offline inventory |
| [CVE-2026-8644](agent/exploits/cve_2026_8644.py) | CVE-2026-8644 | Offline inventory |
| [CVE-2026-8713](agent/exploits/cve_2026_8713.py) | Avada Builder assessment for CVE-2026-8713; no remote probe | Offline inventory |
| [CVE-2026-8763](agent/exploits/cve_2026_8763.py) | assessment of CVE-2026-8763; no remote detector or target I/O | Offline inventory |
| [CVE-2026-9006](agent/exploits/cve_2026_9006.py) | CVE-2026-9006 | Offline inventory |
| [CVE-2026-9082](agent/exploits/cve_2026_9082.py) | Drupal core anonymous PostgreSQL SQL injection (CVE-2026-9082) | Remote |
| [CVE-2026-9103](agent/exploits/cve_2026_9103.py) | Langflow CVE-2026-9103 auto-login token issuance | Remote |
| [CVE-2026-9198](agent/exploits/cve_2026_9198.py) | IBM Langflow unauthenticated remote code execution (CVE-2026-9198) | Remote |
| [CVE-2026-9290](agent/exploits/wordpress_readme_2026.py) | WP User Manager – User Profile Builder & Membership (CVE-2026-9290) | Remote |
| [CVE-2026-9319](agent/exploits/cve_2026_9319.py) | CVE-2026-9319 | Offline inventory |
| [CVE-2026-9848](agent/exploits/wordpress_readme_2026.py) | Customer Support Ticket System & Helpdesk (CVE-2026-9848) | Remote |
| [CVE-2026-10520](agent/exploits/cve_2026_10520.py) | Ivanti Sentry unauthenticated OS command injection (CVE-2026-10520) | Remote |
| [CVE-2026-10580](agent/exploits/wordpress_readme_2026.py) | Hippoo Mobile App for WooCommerce (CVE-2026-10580) | Remote |
| [CVE-2026-11374](agent/exploits/cve_2026_11374.py) | AD360 predictable SSO tickets | Offline inventory |
| [CVE-2026-11387](agent/exploits/wordpress_readme_2026.py) | SMS Alert (CVE-2026-11387) | Remote |
| [CVE-2026-11541](agent/exploits/cve_2026_11541.py) | CVE-2026-11541 | Offline inventory |
| [CVE-2026-11546](agent/exploits/cve_2026_11546.py) | CVE-2026-11546 | Offline inventory |
| [CVE-2026-11714](agent/exploits/cve_2026_11714.py) | CVE-2026-11714 | Offline inventory |
| [CVE-2026-12227](agent/exploits/cve_2026_12227.py) | Visual Composer Website Builder <= 45.16.0 unauthenticated local file inclusion (CVE-2026-12227) | Remote |
| [CVE-2026-12394](agent/exploits/wordpress_readme_2026.py) | MemberGlut (CVE-2026-12394) | Remote |
| [CVE-2026-12741](agent/exploits/cve_2026_12741.py) | WP Fast Total Search SQL injection (CVE-2026-12741) | Remote |
| [CVE-2026-13001](agent/exploits/wordpress_readme_2026.py) | Podlove Podcast Publisher (CVE-2026-13001) | Remote |
| [CVE-2026-14446](agent/exploits/cve_2026_14446.py) | CVE-2026-14446 | Offline inventory |
| [CVE-2026-14483](agent/exploits/wordpress_readme_2026.py) | Realtyna Organic IDX plugin + WPL Real Estate (CVE-2026-14483) | Remote |
| [CVE-2026-14525](agent/exploits/cve_2026_14525.py) | CVE-2026-14525 | Offline inventory |
| [CVE-2026-15015](agent/exploits/wordpress_readme_2026.py) | MountDev AI MCP Connector for WordPress (CVE-2026-15015) | Remote |
| [CVE-2026-15176](agent/exploits/cve_2026_15176.py) | NGINX alias/rewrite CVE-2026-15176 | Offline inventory |
| [CVE-2026-15826](agent/exploits/wordpress_readme_2026.py) | User Profile Builder (CVE-2026-15826) | Remote |
| [CVE-2026-16184](agent/exploits/cve_2026_16184.py) | CVE-2026-16184 | Offline inventory |
| [CVE-2026-16627](agent/exploits/cve_2026_16627.py) | GitLab CI job-modal CVE-2026-16627 | Offline inventory |
| [CVE-2026-18315](agent/exploits/wordpress_readme_2026.py) | TrueBooker (CVE-2026-18315) | Remote |
| [CVE-2026-19089](agent/exploits/wordpress_readme_2026.py) | Product Input Fields for WooCommerce (CVE-2026-19089) | Remote |
| [CVE-2026-19092](agent/exploits/wordpress_readme_2026.py) | Tutor LMS (CVE-2026-19092) | Remote |
| [CVE-2026-19598](agent/exploits/cve_2026_19598.py) | Pods - Custom Content Types and Fields (CVE-2026-19598) | Remote |
| [CVE-2026-19632](agent/exploits/wordpress_readme_2026.py) | TranslatePress (CVE-2026-19632) | Remote |
| [CVE-2026-19868](agent/exploits/cve_2026_19868.py) | SonicWall SonicOS SSLVPN SAML Authentication Bypass (SNWLID-2026-0014 / CVE-2026-19868) | Remote |
| [CVE-2026-20045](agent/exploits/cve_2026_20045.py) | CVE-2026-20045 CUCM-family owner inventory; no HTTP probes | Offline inventory |
| [CVE-2026-20079](agent/exploits/cve_2026_20079.py) | Cisco Secure Firewall Management Center authentication bypass (CVE-2026-20079) | Remote |
| [CVE-2026-20093](agent/exploits/cve_2026_20093.py) | Cisco IMC CVE-2026-20093 owner inventory; no password requests | Offline inventory |
| [CVE-2026-20127](agent/exploits/cve_2026_20127.py) | Cisco Catalyst SD-WAN CVE-2026-20127 | Remote |
| [CVE-2026-20131](agent/exploits/cve_2026_20131.py) | Cisco Secure FMC CVE-2026-20131 | Remote |
| [CVE-2026-20160](agent/exploits/cve_2026_20160.py) | assessment for Cisco SSM On-Prem CVE-2026-20160 | Offline inventory |
| [CVE-2026-20253](agent/exploits/cve_2026_20253.py) | Splunk unauthenticated PostgreSQL recovery endpoint (CVE-2026-20253) | Remote |
| [CVE-2026-20896](agent/exploits/cve_2026_20896.py) | Gitea Docker proxy authentication | Offline inventory |
| [CVE-2026-21445](agent/exploits/cve_2026_21445.py) | Langflow CVE-2026-21445 monitoring authentication bypass | Remote |
| [CVE-2026-21589](agent/exploits/cve_2026_21589.py) | Unauthenticated arbitrary file read in Atlassian Data Center static resources | Remote |
| [CVE-2026-21643](agent/exploits/cve_2026_21643.py) | Fortinet FortiClient EMS CVE-2026-21643 | Remote |
| [CVE-2026-21858](agent/exploits/cve_2026_21858.py) | n8n CVE-2026-21858 unauthenticated file access | Remote |
| [CVE-2026-21877](agent/exploits/cve_2026_21877.py) | n8n CVE-2026-21877 authenticated RCE | Remote |
| [CVE-2026-22557](agent/exploits/cve_2026_22557.py) | UniFi Network Application path traversal (CVE-2026-22557) | Remote |
| [CVE-2026-22769](agent/exploits/cve_2026_22769.py) | CVE-2026-22769 Dell RecoverPoint for Virtual Machines hardcoded credentials | Remote |
| [CVE-2026-22778](agent/exploits/cve_2026_22778.py) | vLLM CVE-2026-22778 video-processing RCE chain | Remote |
| [CVE-2026-23696](agent/exploits/cve_2026_23696.py) | Windmill CVE-2026-23696 folder SQL injection | Remote |
| [CVE-2026-23760](agent/exploits/cve_2026_23760.py) | SmarterTools SmarterMail CVE-2026-23760 | Remote |
| [CVE-2026-24061](agent/exploits/cve_2026_24061.py) | CVE-2026-24061 GNU Inetutils telnetd | Remote |
| [CVE-2026-24207](agent/exploits/cve_2026_24207.py) | NVIDIA Triton Inference Server authentication bypass on the model index (CVE-2026-24207) | Remote |
| [CVE-2026-24423](agent/exploits/cve_2026_24423.py) | SmarterTools SmarterMail CVE-2026-24423 | Remote |
| [CVE-2026-24898](agent/exploits/cve_2026_24898.py) | OpenEMR CVE-2026-24898 MedEx token disclosure | Remote |
| [CVE-2026-25512](agent/exploits/cve_2026_25512.py) | Group-Office CVE-2026-25512 TNEF command injection | Remote |
| [CVE-2026-25939](agent/exploits/cve_2026_25939.py) | FUXA scheduler authorization bypass (CVE-2026-25939) | Remote |
| [CVE-2026-26217](agent/exploits/cve_2026_26217.py) | Crawl4AI Docker API < 0.8.0 unauthenticated local file inclusion via file:// URL (CVE-2026-26217) | Remote |
| [CVE-2026-26980](agent/exploits/cve_2026_26980.py) | Ghost CMS Content API blind SQL injection (CVE-2026-26980) | Remote |
| [CVE-2026-27174](agent/exploits/cve_2026_27174.py) | MajorDoMo admin console unauthenticated remote code execution (CVE-2026-27174) | Remote |
| [CVE-2026-27464](agent/exploits/cve_2026_27464.py) | Metabase CVE-2026-27464 notification template evaluation | Remote |
| [CVE-2026-27604](agent/exploits/cve_2026_27604.py) | FOSSBilling /api/system/* authorization bypass (CVE-2026-27604) | Remote |
| [CVE-2026-27771](agent/exploits/cve_2026_27771.py) | Gitea CVE-2026-27771 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-27944](agent/exploits/cve_2026_27944.py) | Nginx UI backup disclosure | Remote |
| [CVE-2026-28323](agent/exploits/cve_2026_28323.py) | SAML applicability for Web Help Desk CVE-2026-28323 | Offline inventory |
| [CVE-2026-29000](agent/exploits/cve_2026_29000.py) | assessment of pac4j-jwt CVE-2026-29000, without target I/O | Offline inventory |
| [CVE-2026-29059](agent/exploits/cve_2026_29059.py) | Windmill job-log path traversal | Remote |
| [CVE-2026-29145](agent/exploits/cve_2026_29145.py) | Tomcat OCSP CVE-2026-29145 | Offline inventory |
| [CVE-2026-32710](agent/exploits/cve_2026_32710.py) | MariaDB JSON_SCHEMA_VALID memory corruption | Remote |
| [CVE-2026-33017](agent/exploits/cve_2026_33017.py) | Langflow CVE-2026-33017 | Remote |
| [CVE-2026-33032](agent/exploits/cve_2026_33032.py) | Nginx UI unauthenticated MCP message endpoint (CVE-2026-33032) | Remote |
| [CVE-2026-33466](agent/exploits/cve_2026_33466.py) | Logstash GeoIP CVE-2026-33466 (advertised release) | Remote |
| [CVE-2026-33725](agent/exploits/cve_2026_33725.py) | Metabase CVE-2026-33725 Enterprise serialization import code execution | Remote |
| [CVE-2026-34156](agent/exploits/cve_2026_34156.py) | NocoBase CVE-2026-34156 workflow sandbox escape | Remote |
| [CVE-2026-34908](agent/exploits/cve_2026_34908.py) | UniFi OS path-traversal authentication bypass (CVE-2026-34908) | Remote |
| [CVE-2026-34976](agent/exploits/cve_2026_34976.py) | Dgraph CVE-2026-34976 restoreTenant authorization bypass | Remote |
| [CVE-2026-35616](agent/exploits/cve_2026_35616.py) | Fortinet FortiClient EMS CVE-2026-35616 | Remote |
| [CVE-2026-39339](agent/exploits/cve_2026_39339.py) | ChurchCRM API authentication-middleware substring bypass (CVE-2026-39339) | Remote |
| [CVE-2026-39364](agent/exploits/cve_2026_39364.py) | Vite dev server .env raw-query file read (CVE-2026-39364) | Remote |
| [CVE-2026-39468](agent/exploits/wordpress_readme_2026.py) | Meta Box – WordPress Custom Fields Framework (CVE-2026-39468) | Remote |
| [CVE-2026-39813](agent/exploits/cve_2026_39813.py) | Fortinet FortiSandbox JRPC path-traversal authentication bypass (CVE-2026-39813) | Remote |
| [CVE-2026-40281](agent/exploits/cve_2026_40281.py) | Gotenberg CVE-2026-40281 ExifTool argument injection | Remote |
| [CVE-2026-40887](agent/exploits/cve_2026_40887.py) | Vendure Shop API SQL injection (CVE-2026-40887) | Remote |
| [CVE-2026-41428](agent/exploits/cve_2026_41428.py) | Budibase authenticated-middleware regex bypass via query string (CVE-2026-41428) | Remote |
| [CVE-2026-41492](agent/exploits/cve_2026_41492.py) | Dgraph CVE-2026-41492 admin token disclosure | Remote |
| [CVE-2026-41940](agent/exploits/cve_2026_41940.py) | cPanel & WHM CVE-2026-41940 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-42055](agent/exploits/cve_2026_42055.py) | NGINX upstream CVE-2026-42055 | Offline inventory |
| [CVE-2026-42208](agent/exploits/cve_2026_42208.py) | LiteLLM bearer-token SQL injection (CVE-2026-42208) | Remote |
| [CVE-2026-42530](agent/exploits/cve_2026_42530.py) | NGINX HTTP/3 CVE-2026-42530 | Offline inventory |
| [CVE-2026-42533](agent/exploits/cve_2026_42533.py) | NGINX map/regex CVE-2026-42533 | Offline inventory |
| [CVE-2026-42569](agent/exploits/cve_2026_42569.py) | phpVMS < 7.0.6 unauthenticated access to legacy importer (CVE-2026-42569) | Remote |
| [CVE-2026-42589](agent/exploits/cve_2026_42589.py) | Gotenberg CVE-2026-42589 ExifTool metadata-key injection | Remote |
| [CVE-2026-42647](agent/exploits/wordpress_readme_2026.py) | JoomSport (CVE-2026-42647) | Remote |
| [CVE-2026-42796](agent/exploits/cve_2026_42796.py) | Arelle CVE-2026-42796 remote plugin loading | Remote |
| [CVE-2026-42945](agent/exploits/cve_2026_42945.py) | NGINX rewrite CVE-2026-42945 | Offline inventory |
| [CVE-2026-44262](agent/exploits/cve_2026_44262.py) | Scramble Laravel documentation RCE (CVE-2026-44262) | Remote |
| [CVE-2026-44338](agent/exploits/cve_2026_44338.py) | PraisonAI legacy API authentication bypass (CVE-2026-44338) | Remote |
| [CVE-2026-44343](agent/exploits/cve_2026_44343.py) | WGDashboard < 4.3.2 unauthenticated path traversal to arbitrary file read (CVE-2026-44343) | Remote |
| [CVE-2026-45674](agent/exploits/cve_2026_45674.py) | assessment of Netty DNS CVE-2026-45674, without target I/O | Offline inventory |
| [CVE-2026-45695](agent/exploits/cve_2026_45695.py) | Kopia CVE-2026-45695 SSH command injection | Remote |
| [CVE-2026-46339](agent/exploits/cve_2026_46339.py) | 9Router CVE-2026-46339 MCP command execution | Remote |
| [CVE-2026-46442](agent/exploits/cve_2026_46442.py) | Flowise CVE-2026-46442 authenticated Custom Function RCE | Remote |
| [CVE-2026-48313](agent/exploits/cve_2026_48313.py) | Adobe ColdFusion FILEIO path traversal (CVE-2026-48313) | Remote |
| [CVE-2026-48360](agent/exploits/cve_2026_48360.py) | assessment of Adobe Connect clients, CVE-2026-48360 | Offline inventory |
| [CVE-2026-48558](agent/exploits/cve_2026_48558.py) | SimpleHelp CVE-2026-48558 OIDC bypass | Remote |
| [CVE-2026-49352](agent/exploits/cve_2026_49352.py) | 9Router hardcoded fallback JWT secret authentication bypass (CVE-2026-49352) | Remote |
| [CVE-2026-49772](agent/exploits/wordpress_readme_2026.py) | The Events Calendar (CVE-2026-49772) | Remote |
| [CVE-2026-49777](agent/exploits/cve_2026_49777.py) | Product Slider Pro for WooCommerce < 3.5.4 supply-chain backdoor remote code execution (CVE-2026-49777) | Remote |
| [CVE-2026-49869](agent/exploits/cve_2026_49869.py) | Kestra OSS CVE-2026-49869 | Remote |
| [CVE-2026-50751](agent/exploits/cve_2026_50751.py) | Check Point Quantum Security Gateway CVE-2026-50751 | Remote |
| [CVE-2026-52715](agent/exploits/wordpress_readme_2026.py) | GEO my WordPress (CVE-2026-52715) | Remote |
| [CVE-2026-53576](agent/exploits/cve_2026_53576.py) | Kestra OSS CVE-2026-53576 authentication bypass/RCE | Remote |
| [CVE-2026-53753](agent/exploits/cve_2026_53753.py) | Crawl4AI CVE-2026-53753 computed-field sandbox escape | Remote |
| [CVE-2026-53998](agent/exploits/cve_2026_53998.py) | Arize Phoenix unauthenticated format-string injection in applyChatTemplate (CVE-2026-53998) | Remote |
| [CVE-2026-54069](agent/exploits/cve_2026_54069.py) | SiYuan CVE-2026-54069 extension-origin authentication bypass | Remote |
| [CVE-2026-54836](agent/exploits/wordpress_readme_2026.py) | YMC Filter / Filter & Grids (CVE-2026-54836) | Remote |
| [CVE-2026-55040](agent/exploits/cve_2026_55040.py) | Microsoft SharePoint Server JWT authentication bypass (CVE-2026-55040) | Remote |
| [CVE-2026-55450](agent/exploits/cve_2026_55450.py) | Langflow CVE-2026-55450 unauthenticated upload | Remote |
| [CVE-2026-55508](agent/exploits/cve_2026_55508.py) | [Wavelog unauthenticated SQL injection via POST /oqrs/search_log](docs/wavelog-2026-55508.md) | Remote |
| [CVE-2026-56062](agent/exploits/cve_2026_56062.py) | Quotes llama WordPress SQL injection (CVE-2026-56062) | Remote |
| [CVE-2026-56265](agent/exploits/cve_2026_56265.py) | Crawl4AI CVE-2026-56265 default JWT signing key | Remote |
| [CVE-2026-58062](agent/exploits/cve_2026_58062.py) | assessment of CVE-2026-58062; no remote detector or target I/O | Offline inventory |
| [CVE-2026-58138](agent/exploits/cve_2026_58138.py) | Conductor CVE-2026-58138 script evaluation | Remote |
| [CVE-2026-58455](agent/exploits/cve_2026_58455.py) | Dockwatch <= 0.6.567 unauthenticated OS command injection via compose.php (CVE-2026-58455) | Remote |
| [CVE-2026-59309](agent/exploits/cve_2026_59309.py) | vCenter CVE-2026-59309 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-59310](agent/exploits/cve_2026_59310.py) | vCenter CVE-2026-59310 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-59650](agent/exploits/cve_2026_59650.py) | assessment of CVE-2026-59650; no remote detector or target I/O | Offline inventory |
| [CVE-2026-59726](agent/exploits/cve_2026_59726.py) | ruflo < 3.16.3 unauthenticated remote code execution via MCP bridge terminal_execute (CVE-2026-59726) | Remote |
| [CVE-2026-59774](agent/exploits/cve_2026_59774.py) | Gitea CVE-2026-59774 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-59822](agent/exploits/cve_2026_59822.py) | LiteLLM CVE-2026-59822 | Remote |
| [CVE-2026-59826](agent/exploits/cve_2026_59826.py) | Metabase CVE-2026-59826 H2 database creation code execution | Remote |
| [CVE-2026-59827](agent/exploits/cve_2026_59827.py) | Metabase CVE-2026-59827 H2 query-result deserialization | Remote |
| [CVE-2026-60004](agent/exploits/cve_2026_60004.py) | Gitea CVE-2026-60004 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-61560](agent/exploits/cve_2026_61560.py) | GitLab MCP Server unauthenticated SSE transport (CVE-2026-61560) | Remote |
| [CVE-2026-63030](agent/exploits/cve_2026_63030.py) | WordPress pre-auth batch route confusion (CVE-2026-63030) | Remote |
| [CVE-2026-63077](agent/exploits/cve_2026_63077.py) | JetBrains TeamCity CVE-2026-63077 | Remote |
| [CVE-2026-63189](agent/exploits/cve_2026_63189.py) | [Dialoqbase unauthenticated arbitrary file read through the view route](docs/dialoqbase-2026-63189.md) | Remote |
| [CVE-2026-64849](agent/exploits/cve_2026_64849.py) | MLflow CVE-2026-64849 webhook SSRF | Remote |
| [CVE-2026-65182](agent/exploits/cve_2026_65182.py) | Tomcat constraint ordering CVE-2026-65182 | Offline inventory |
| [CVE-2026-65555](agent/exploits/wordpress_readme_2026.py) | Uncanny Toolkit for LearnDash (CVE-2026-65555) | Remote |
| [CVE-2026-65637](agent/exploits/cve_2026_65637.py) | Tomcat HTTP/2 strict-SNI CVE-2026-65637 | Offline inventory |
| [CVE-2026-65761](agent/exploits/cve_2026_65761.py) | Joomla EasyStore 1.0.0-2.0.1 unauthenticated SQL injection via product search (CVE-2026-65761) | Remote |
| [CVE-2026-65905](agent/exploits/cve_2026_65905.py) | Tomcat DIGEST replay CVE-2026-65905 | Offline inventory |
| [CVE-2026-65906](agent/exploits/cve_2026_65906.py) | TeamCity CVE-2026-65906 (advertised release) | Remote |
| [CVE-2026-65907](agent/exploits/cve_2026_65907.py) | TeamCity CVE-2026-65907 (advertised release) | Remote |
| [CVE-2026-67276](agent/exploits/cve_2026_67276.py) | RouterOS SSH RSA CVE-2026-67276 | Offline inventory |
| [CVE-2026-68507](agent/exploits/cve_2026_68507.py) | ideon unauthenticated link-preview server-side request forgery (CVE-2026-68507) | Remote |
| [CVE-2026-68525](agent/exploits/cve_2026_68525.py) | Tomcat FORM constraints CVE-2026-68525 | Offline inventory |
| [CVE-2026-69084](agent/exploits/cve_2026_69084.py) | SiYuan CVE-2026-69084 publish-mode SQL execution | Remote |
| [CVE-2026-69085](agent/exploits/cve_2026_69085.py) | SiYuan CVE-2026-69085 searchDocs SQL injection | Remote |
| [CVE-2026-69158](agent/exploits/cve_2026_69158.py) | [Atomic Server unauthenticated full-response server-side request forgery (CVE-2026-69158)](docs/atomic-server-2026-69158.md) | Remote |
| [CVE-2026-69251](agent/exploits/cve_2026_69251.py) | Flowise CVE-2026-69251 TypeORM RCE | Remote |
| [CVE-2026-69697](agent/exploits/cve_2026_69697.py) | [Faveo Helpdesk unauthenticated checkUrl server-side request forgery (CVE-2026-69697)](docs/cve-2026-69697.md) | Remote |
| [CVE-2026-71495](agent/exploits/cve_2026_71495.py) | Wanderer unauthenticated server-side request forgery (CVE-2026-71495) | Remote |
| [CVE-2026-72898](agent/exploits/cve_2026_72898.py) | Metabase CVE-2026-72898 password-reset SQL injection | Remote |
| [CVE-2026-72899](agent/exploits/cve_2026_72899.py) | Metabase CVE-2026-72899 public-link field-filter SQL injection | Remote |
| [CVE-2026-72900](agent/exploits/cve_2026_72900.py) | Metabase CVE-2026-72900 audit database authorization bypass | Remote |
| [CVE-2026-73453](agent/exploits/cve_2026_73453.py) | Arista EOS P4Runtime CVE-2026-73453 | Offline inventory |
| [CVE-2026-73577](agent/exploits/cve_2026_73577.py) | Apache OFBiz CVE-2026-73577 unauthenticated path-suffix view authorization bypass | Remote |
| [CVE-2026-73969](agent/exploits/cve_2026_73969.py) | AnsibleForms public fallback JWT signing secret authentication bypass (CVE-2026-73969) | Remote |
| [CVE-2026-74849](agent/exploits/cve_2026_74849.py) | CVE-2026-74849 | Offline inventory |
| [CVE-2026-75595](agent/exploits/cve_2026_75595.py) | assessment of Netty SNI CVE-2026-75595, without target I/O | Offline inventory |
| [CVE-2026-76460](agent/exploits/cve_2026_76460.py) | Cisco ISE MNT API authentication bypass (CVE-2026-76460) | Remote |
| [CVE-2026-76461](agent/exploits/cve_2026_76461.py) | Cisco Secure Email Gateway CVE-2026-76461 | Offline inventory |
| [CVE-2026-76465](agent/exploits/cve_2026_76465.py) | MPLS OAM CVE-2026-76465 owner inventory; no packet probes | Offline inventory |
| [CVE-2026-76471](agent/exploits/cve_2026_76471.py) | NX-API CVE-2026-76471 owner inventory; no crafted HTTP requests | Offline inventory |
| [CVE-2026-76504](agent/exploits/cve_2026_76504.py) | Cisco Catalyst SD-WAN Manager URI-encoding authentication bypass (CVE-2026-76504) | Remote |
| [CVE-2026-76904](agent/exploits/cve_2026_76904.py) | GeoServer jsonArrayContains SQL injection (CVE-2026-76904) | Remote |
| [CVE-2026-77295](agent/exploits/cve_2026_77295.py) | MyMangaDB unauthenticated database export (CVE-2026-77295) | Remote |
| [CVE-2026-77338](agent/exploits/cve_2026_77338.py) | [Sprout Track public fallback JWT signing secret authentication bypass (CVE-2026-77338)](docs/sprout-track-2026-77338.md) | Remote |
| [CVE-2026-77367](agent/exploits/cve_2026_77367.py) | Daptin unauthenticated SQL injection via the entity-list sort parameter (CVE-2026-77367) | Remote |
| [CVE-2026-79844](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79845](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79846](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79847](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79848](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79849](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79850](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79851](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79852](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79853](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79854](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79855](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79856](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79857](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79858](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79859](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79860](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79861](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79862](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79863](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79864](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79865](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79866](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79867](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79868](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79869](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79870](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79871](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79872](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79873](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79874](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79875](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-79876](agent/exploits/hpe_2026_05162.py) | HPE AOS HPESBNW05162 | Remote |
| [CVE-2026-81578](agent/exploits/cve_2026_81578.py) | PaperCut NG/MF CVE-2026-81578 | Remote |
| [CVE-2026-82078](agent/exploits/cve_2026_82078.py) | PaperCut NG/MF CVE-2026-82078 | Remote |
| [CVE-2026-82329](agent/exploits/cve_2026_82329.py) | JFrog Artifactory blank join-key authentication bypass (CVE-2026-82329) | Remote |
| [CVE-2026-82489](agent/exploits/cve_2026_82489.py) | openIMIS ReportBro preview unauthenticated arbitrary file read | Remote |
| [CVE-2026-84411](agent/exploits/cve_2026_84411.py) | RouterOS web-management CVE-2026-84411 | Offline inventory |
| [CVE-2026-85595](agent/exploits/cve_2026_85595.py) | Traefik CVE-2026-85595 digestAuth bypass | Remote |
| [CVE-2026-85706](agent/exploits/cve_2026_85706.py) | GitLab unauthenticated arbitrary file read (CVE-2026-85706) | Remote |
| [CVE-2026-85714](agent/exploits/cve_2026_85714.py) | Stirling-PDF CVE-2026-85714 H2 import RCE | Remote |
| [CVE-2026-86005](agent/exploits/cve_2026_86005.py) | Chartbrew CVE-2026-86005 unauthenticated BullMQ dashboard | Remote |
| [CVE-2026-86206](agent/exploits/cve_2026_86206.py) | N-able N-central internal API access-control filter bypass via path confusion and Forwarded header spoofing (CVE-2026-86206) | Remote |
| [CVE-2026-86312](agent/exploits/cve_2026_86312.py) | [Apache Solr PingRequestHandler request-delegate authorization bypass (CVE-2026-86312)](docs/cve-2026-86312.md) | Remote |
| [CVE-2026-86426](agent/exploits/cve_2026_86426.py) | LibreNMS before 26.8.0 API authentication bypass via token type confusion (CVE-2026-86426) | Remote |
| [CVE-2026-87719](agent/exploits/cve_2026_87719.py) | GitLab Duo Chat CVE-2026-87719 | Offline inventory |
| [CVE-2026-87902](agent/exploits/cve_2026_87902.py) | WordPress page-template local file inclusion (CVE-2026-87902) | Remote |
| [CVE-2026-88771](agent/exploits/cve_2026_88771.py) | NetScaler CVE-2026-88771 | Remote |
| [CVE-2026-88772](agent/exploits/cve_2026_88772.py) | NetScaler CVE-2026-88772 | Remote |
| [CVE-2026-89026](agent/exploits/cve_2026_89026.py) | Issabel Framework PBX API hard-coded JWT key (CVE-2026-89026) | Remote |
| [CVE-2026-89078](agent/exploits/cve_2026_89078.py) | CVE-2026-89078 | Offline inventory |
| [CVE-2026-90436](agent/exploits/cve_2026_90436.py) | Apache Axis 1.x CVE-2026-90436 unauthenticated SOAP fault class-loading RCE | Remote |
| [CVE-2026-93479](agent/exploits/cve_2026_93479.py) | NGINX root/access-log CVE-2026-93479 | Offline inventory |
| [CVE-2026-93577](agent/exploits/cve_2026_93577.py) | CVE-2026-93577 | Offline inventory |
| [CVE-2026-93616](agent/exploits/cve_2026_93616.py) | Check Point Management Server unauthenticated directory traversal to RCE (CVE-2026-93616) | Remote |
| [CVE-2026-93674](agent/exploits/cve_2026_93674.py) | Langflow CVE-2026-93674 import-validation RCE | Remote |
| [CVE-2026-94169](agent/exploits/cve_2026_94169.py) | The Grid WordPress plugin <= 2.8.1 unauthenticated local file inclusion (CVE-2026-94169) | Remote |
| [CVE-2026-96652](agent/exploits/cve_2026_96652.py) | Plex Media Server CVE-2026-96652/96654/96655/96656 chain | Remote |
| [CVE-2026-96654](agent/exploits/cve_2026_96652.py) | Plex Media Server CVE-2026-96652/96654/96655/96656 chain | Remote |
| [CVE-2026-96655](agent/exploits/cve_2026_96652.py) | Plex Media Server CVE-2026-96652/96654/96655/96656 chain | Remote |
| [CVE-2026-96656](agent/exploits/cve_2026_96652.py) | Plex Media Server CVE-2026-96652/96654/96655/96656 chain | Remote |
| [CVE-2026-97229](agent/exploits/cve_2026_97229.py) | CVE-2026-97229 | Offline inventory |
| [CVE-2026-100109](agent/exploits/wordpress_readme_2026.py) | Security For WooCommerce (CVE-2026-100109) | Remote |
| [CVE-2026-102084](agent/exploits/cve_2026_102084.py) | Junos ADVPN CVE-2026-102084 | Offline inventory |
| [CVE-2026-102610](agent/exploits/cve_2026_102610.py) | fast-agent MCP server unauthenticated remote agent access (CVE-2026-102610) | Remote |
| [CVE-2026-102782](agent/exploits/cve_2026_102782.py) | OrdaSoft Simple Membership < 7.4.0 unauthenticated SQL injection via checkLoginPass (CVE-2026-102782) | Remote |
| [CVE-2026-102894](agent/exploits/cve_2026_102894.py) | GPUStack CVE-2026-102894 unauthenticated SAML callback account takeover | Remote |
| [CVE-2026-102895](agent/exploits/cve_2026_102895.py) | GPUStack CVE-2026-102895 unauthenticated administrator bypass | Remote |
| [CVE-2026-103956](agent/exploits/cve_2026_103956.py) | Loom CVE-2026-103956 authentication bypass | Remote |
| [CVE-2026-104203](agent/exploits/cve_2026_104203.py) | Traccar CVE-2026-104203 media authentication bypass via semicolon path parameter | Remote |
| [CVE-2026-104608](agent/exploits/cve_2026_104608.py) | GitHub Enterprise Server CVE-2026-104608 (babeld use-after-free RCE) and CVE-2026-110288 (ChatOps CSRF); exploitability unconfirmed | Remote |
| [CVE-2026-104935](agent/exploits/cve_2026_104935.py) | Ivanti Connect Secure CVE-2026-104935 | Remote |
| [CVE-2026-105133](agent/exploits/cve_2026_105133.py) | AhsayCBS ListSystemUsers.do authentication bypass (CVE-2026-105133) | Remote |
| [CVE-2026-105740](agent/exploits/cve_2026_105740.py) | Langflow CVE-2026-105740 authenticated MCP RCE | Remote |
| [CVE-2026-107406](agent/exploits/cve_2026_107406.py) | assessment of NetScaler SAML potential exposure | Offline inventory |
| [CVE-2026-107654](agent/exploits/cve_2026_107654.py) | [WPGuppy advertised-release exposure (CVE-2026-107654)](docs/cve-2026-107654.md) | Remote |
| [CVE-2026-107656](agent/exploits/cve_2026_107656.py) | FortiSandbox GUI exposure assessment with edition-specific bounds | Offline inventory |
| [CVE-2026-107861](agent/exploits/kiloview_2026_10.py) | Kiloview E3 October 2026 critical command injection | Remote |
| [CVE-2026-109122](agent/exploits/kiloview_2026_10.py) | Kiloview E3 October 2026 critical command injection | Remote |
| [CVE-2026-109586](agent/exploits/wp_staging_rest_gate_bypass.py) | [WP STAGING staging-site login gate bypass via empty rest_route](docs/cve-2026-109586.md) | Remote |
| [CVE-2026-109618](agent/exploits/cve_2026_109618.py) | PHP Core CVE-2026-109618 Session Upload Progress Use-After-Free | Remote + inventory |
| [CVE-2026-109619](agent/exploits/cve_2026_109619.py) | PHP Core CVE-2026-109619 SAPI Multipart Request Handling | Remote + inventory |
| [CVE-2026-110003](agent/exploits/cve_2026_110003.py) | Payara Server remote administration access-restriction bypass (CVE-2026-110003) | Remote |
| [CVE-2026-110243](agent/exploits/kiloview_2026_10.py) | Kiloview E3 October 2026 critical command injection | Remote |
| [CVE-2026-110264](agent/exploits/cve_2026_110264.py) | CVE-2026-110264 | Offline inventory |
| [CVE-2026-110288](agent/exploits/cve_2026_104608.py) | GitHub Enterprise Server CVE-2026-104608 (babeld use-after-free RCE) and CVE-2026-110288 (ChatOps CSRF); exploitability unconfirmed | Remote |
| [CVE-2026-110372](agent/exploits/cve_2026_110372.py) | OttoKit (SureTriggers) <= 1.1.40 unauthenticated privilege escalation via the connection-denied token (CVE-2026-110372) | Remote |
| [CVE-2026-110447](agent/exploits/cve_2026_110447.py) | Collabora built-in CODE CVE-2026-110447 | Remote |
| [CVE-2026-111057](agent/exploits/cve_2026_111057.py) | Mercury 3.0.0-3.2.3 unauthenticated Jupyter terminal API access (CVE-2026-111057) | Remote |
| [CVE-2026-111497](agent/exploits/cve_2026_111497.py) | Node.js Brotli Decoder Out-of-Bounds Write (Node2Shell) | Remote + inventory |
| [CVE-2026-114509](agent/exploits/cve_2026_114509.py) | Laravel TokenGuard authentication bypass (CVE-2026-114509) | Remote |
| [CVE-2026-114516](agent/exploits/cve_2026_114516.py) | [Etherpad pre-authentication static-asset path traversal](docs/etherpad-2026-114516.md) | Remote |
| [CVE-2026-114612](agent/exploits/cve_2026_114612.py) | LiteLLM CVE-2026-114612 | Remote |
| [CVE-2026-114625](agent/exploits/cve_2026_114625.py) | CVE-2026-114625 | Offline inventory |
| [CVE-2026-114938](agent/exploits/cve_2026_114938.py) | Java4Shell affected JVM metadata and trusted inventory (potential exposure) | Remote + inventory |
| [CVE-2026-115547](agent/exploits/cve_2026_115547.py) | Okta Access Gateway CVE-2026-115547 | Remote |
| [CVE-2026-115560](agent/exploits/cve_2026_115560.py) | PHP Core CVE-2026-115560 Session Upload Progress Serializer RCE | Remote + inventory |
| [CVE-2026-116485](agent/exploits/cve_2026_116485.py) | danmu_api default admin-token exposure (CVE-2026-116485) | Remote |
| [CVE-2026-116747](agent/exploits/cve_2026_116747.py) | Kener 3.0.0 - 4.1.9 authentication bypass via hardcoded fallback JWT secret (CVE-2026-116747) | Remote |
| [CVE-2026-118066](agent/exploits/cve_2026_118066.py) | LatePoint <= 5.7.6 unauthenticated authentication bypass via order_intent_key SQL operator injection (CVE-2026-118066) | Remote |
| [CVE-2026-118623](agent/exploits/cve_2026_118623.py) | MLflow CVE-2026-118623 pickle evaluation artifact deserialization RCE | Remote |
| [CVE-2026-118627](agent/exploits/cve_2026_118627.py) | MLflow CVE-2026-118627 SHAP explainer deserialization RCE | Remote |
| [CVE-2026-118628](agent/exploits/cve_2026_118628.py) | MLflow CVE-2026-118628 get-artifacts SSRF information disclosure | Remote |
| [CVE-2026-119481](agent/exploits/wordpress_readme_2026.py) | JetFormBuilder (CVE-2026-119481) | Remote |
| [CVE-2026-119923](agent/exploits/cve_2026_119923.py) | Babelfish for PostgreSQL TDS endpoint (CVE-2026-119923 / CVE-2026-119924; running release not observable) | Remote |
| [CVE-2026-119924](agent/exploits/cve_2026_119923.py) | Babelfish for PostgreSQL TDS endpoint (CVE-2026-119923 / CVE-2026-119924; running release not observable) | Remote |
| [CVE-2026-119977](agent/exploits/cve_2026_119977.py) | WordPress Core CVE-2026-119977 upgrade-window remote code execution | Remote |
| [CVE-2026-120201](agent/exploits/cve_2026_120201.py) | Jpom 2.10.0-2.11.12 unauthenticated auth bypass via JPOM-USER-TOKEN header (CVE-2026-120201) | Remote |
| [CVE-2026-120442](agent/exploits/cve_2026_120442.py) | ape-volo-admin hardcoded JWT key authentication bypass (CVE-2026-120442) | Remote |
| [CVE-2026-120656](agent/exploits/cve_2026_120656.py) | OpenKruise unauthenticated pprof debug endpoint exposed (CVE-2026-120656) | Remote |
| [CVE-2026-120705](agent/exploits/cve_2026_120705.py) | [GeoServer WFS GetFeatureById XML injection and local file read](docs/cve-2026-120705.md) | Remote |
| [CVE-2026-123007](agent/exploits/cve_2026_123007.py) | Nginx2Shell nginx HTTP/2 remote code execution exposure (CVE-2026-123007 / CVE-2026-123633) | Remote |
| [CVE-2026-123158](agent/exploits/cve_2026_123158.py) | OpenSSH Password Authentication Bypass on musl libc (CVE-2026-123158, 'sshole') | Remote |
| [CVE-2026-123201](agent/exploits/cve_2026_123201.py) | bukuserver unauthenticated server-side request forgery (CVE-2026-123201) | Remote |
| [CVE-2026-123214](agent/exploits/cve_2026_123214.py) | [Joomla web installer remains usable on an installed site](docs/cve-2026-123214.md) | Remote |
| [CVE-2026-123270](agent/exploits/cve_2026_123270.py) | Redpanda Connect unauthenticated streams management API (CVE-2026-123270) | Remote |
| [CVE-2026-123488](agent/exploits/cve_2026_123488.py) | Craft CMS search SQL injection (CVE-2026-123488) | Remote |
| [CVE-2026-123633](agent/exploits/cve_2026_123007.py) | Nginx2Shell nginx HTTP/2 remote code execution exposure (CVE-2026-123007 / CVE-2026-123633) | Remote |
| [CVE-2026-123807](agent/exploits/cve_2026_123807.py) | Signal K Server unauthenticated resources path traversal (CVE-2026-123807) | Remote |
| [CVE-2026-123903](agent/exploits/cve_2026_123903.py) | VMware vCenter Directory Service authentication bypass potential exposure (CVE-2026-123903) | Remote |
| [CVE-2026-123910](agent/exploits/cve_2026_123910.py) | [VMware ESXi I/O filter service CVE-2026-123910/123911 POTENTIAL EXPOSURE](docs/cve-2026-123910.md) | Remote |
| [CVE-2026-123911](agent/exploits/cve_2026_123910.py) | [VMware ESXi I/O filter service CVE-2026-123910/123911 POTENTIAL EXPOSURE](docs/cve-2026-123910.md) | Remote |
| [CVE-2026-124002](agent/exploits/cve_2026_124002.py) | Copeland/Dixell XWEB EVO pre-authentication OS command injection (CVE-2026-124002) | Remote |
| [CVE-2026-125331](agent/exploits/cve_2026_125331.py) | HarnessRouter console internal-key relay authorization bypass (CVE-2026-125331) | Remote |
| [CVE-2026-125370](agent/exploits/cve_2026_125370.py) | Kubero public fallback JWT secret authentication bypass (CVE-2026-125370) | Remote |
| [CVE-2026-126755](agent/exploits/cve_2026_126755.py) | ArangoDB URL-encoded-underscore authentication bypass (CVE-2026-126755) | Remote |
| [CVE-2026-126984](agent/exploits/cve_2026_126984.py) | [Pulp Python pull-through redirect server-side request forgery](docs/cve-2026-126984.md) | Remote |
| [CVE-2026-126997](agent/exploits/cve_2026_126997.py) | JeecgBoot airag flow-run unauthenticated SSRF dispatch (CVE-2026-126997) | Remote |
| [CVE-2026-126998](agent/exploits/cve_2026_126998.py) | JeecgBoot OpenAPI OPTIONS authentication bypass and admin-data self-proxy (CVE-2026-126998) | Remote |
| [CVE-2026-127024](agent/exploits/cve_2026_127024.py) | WordForm unauthenticated arbitrary file upload leading to remote code execution | Remote |
| [CVE-2026-127046](agent/exploits/cve_2026_127046.py) | MISP Modules unauthenticated external-tools API-key disclosure (CVE-2026-127046) | Remote |
| [CVE-2026-127279](agent/exploits/cve_2026_127279.py) | ACPs-community discovery-server unauthenticated management API (CVE-2026-127279) | Remote |
| [CVE-2026-127286](agent/exploits/cve_2026_127286.py) | Meetily self-hosted backend exposes its unauthenticated API (CVE-2026-127286) | Remote |
| [CVE-2026-129171](agent/exploits/cve_2026_129171.py) | NginxPulse unauthenticated SQL injection via /api/stats/:type (CVE-2026-129171) | Remote |
| [CVE-2026-129243](agent/exploits/cve_2026_129243.py) | [GeoServer prefixed-service authorization bypass](docs/cve-2026-129243.md) | Remote |
| [CVE-2026-129485](agent/exploits/cve_2026_129485.py) | Kroki BlockDiag unauthenticated server-side request forgery (CVE-2026-129485) | Remote |
| [CVE-2026-129493](agent/exploits/cve_2026_129493.py) | Bolo (bolo-solo) unauthenticated article view-password disclosure (CVE-2026-129493) | Remote |
| [CVE-2026-129514](agent/exploits/cve_2026_129514.py) | [hexpm unauthenticated Erlang term parser accepts struct maps (CVE-2026-129514 RCE precondition)](docs/cve-2026-129514.md) | Remote |
| [CVE-2026-129877](agent/exploits/cve_2026_129877.py) | DeepAudit unauthenticated configuration endpoint discloses server secrets (CVE-2026-129877) | Remote |
| [CVE-2026-129968](agent/exploits/cve_2026_129968.py) | [LiteSpeed Cache for PrestaShop unauthenticated Smarty template evaluation](docs/cve-2026-129968.md) | Remote |
| [CVE-2026-130081](agent/exploits/cve_2026_130081.py) | B3log Solo unauthenticated article view-password disclosure (CVE-2026-130081) | Remote |
| [CVE-2026-130591](agent/exploits/cve_2026_130591.py) | [53AIHub unauthenticated file preview and file-version content access](docs/cve-2026-130591.md) | Remote |
| [CVE-2026-130841](agent/exploits/cve_2026_130841.py) | [ioBroker.lovelace unauthenticated static-route path traversal](docs/iobroker-lovelace-2026-130841.md) | Remote |
| [CVE-2026-130860](agent/exploits/cve_2026_130860.py) | Flagr default basic-auth whitelist exposes the flag-management write API (CVE-2026-130860) | Remote |
| [CVE-2026-130867](agent/exploits/cve_2026_130867.py) | [GreaterWMS static route serves files outside the public asset directory to unauthenticated requesters](docs/greaterwms-2026-130867.md) | Remote + inventory |
| [CVE-2026-131971](agent/exploits/cve_2026_131971.py) | [GetPaid unauthenticated invoice disclosure through the payment-form embed endpoint](docs/getpaid-2026-131971.md) | Remote |
| [CVE-2026-132736](agent/exploits/cve_2026_132736.py) | [MediaWiki REST Content-Type expanded as wikitext before the read check](docs/cve-2026-132736.md) | Remote |
| [CVE-2026-133335](agent/exploits/cve_2026_133335.py) | [VirtueMart unauthenticated controller-fallback local file inclusion](docs/cve-2026-133335.md) | Remote |
| [CVE-2026-133469](agent/exploits/cve_2026_133469.py) | [Xen Orchestra REST API authentication bypass with an empty-object token cookie](docs/cve-2026-133469.md) | Remote |
| [CVE-2026-134167](agent/exploits/cve_2026_134167.py) | [devpi-web unauthenticated documentation path traversal](docs/devpi-2026-134167.md) | Remote |
| [CVE-2026-134249](agent/exploits/cve_2026_134249.py) | [SiYuan authentication bypass via trusted loopback-proxy forwarded headers](docs/siyuan-2026-134249.md) | Remote |
| [CVE-2026-134748](agent/exploits/cve_2026_134748.py) | [Members Private Site login-path authorization bypass](docs/members-2026-134748.md) | Remote |
| [CVE-2026-134796](agent/exploits/cve_2026_134796.py) | [Donetick unauthenticated asset signature bypass and path traversal](docs/cve-2026-134796.md) | Remote |
| [CVE-2026-134825](agent/exploits/cve_2026_134825.py) | [Gradio run-history authentication bypass via a forged Host header](docs/gradio-2026-134825.md) | Remote |
| [CVE-2026-135161](agent/exploits/cve_2026_135161.py) | [Interstellar Wisp proxy permits unauthenticated loopback and internal connections](docs/cve-2026-135161.md) | Remote |
| [CVE-2026-135208](agent/exploits/cve_2026_135208.py) | [Kerberos Agent hard-coded JWT fallback key authentication bypass](docs/cve-2026-135208.md) | Remote |
| [CVE-2026-135266](agent/exploits/cve_2026_135266.py) | [Music Player for WooCommerce unauthenticated arbitrary file read (advertised-release exposure)](docs/cve-2026-135266.md) | Remote |
| [CVE-2026-135479](agent/exploits/cve_2026_135479.py) | [Merchant for WooCommerce unauthenticated Quick View disclosure of non-public products](docs/cve-2026-135479.md) | Remote |
| [CVE-2026-135641](agent/exploits/cve_2026_135641.py) | [WP Job Portal unauthenticated socialid-cookie authentication bypass](docs/cve-2026-135641.md) | Remote |
| [CVE-2026-135688](agent/exploits/cve_2026_135688.py) | [Idno webmention source SSRF](docs/cve-2026-135688.md) | Remote |
| [CVE-2026-135697](agent/exploits/cve_2026_135697.py) | [CleverReach WP unauthenticated non-public post disclosure](docs/cve-2026-135697.md) | Remote |
| [CVE-2026-136132](agent/exploits/cve_2026_136132.py) | [Pangolin path-based access-rule bypass through encoded slashes](docs/cve-2026-136132.md) | Remote |
| [CVE-2026-136177](agent/exploits/cve_2026_136177.py) | [Gitea Mirror unauthenticated connection-test server-side request forgery](docs/cve-2026-136177.md) | Remote |
| [CVE-2026-136181](agent/exploits/cve_2026_136181.py) | [cnpmcore unauthenticated upstream registry authToken disclosure](docs/cve-2026-136181.md) | Remote |
| [CVE-2026-137497](agent/exploits/cve_2026_137497.py) | [Budibase public settings endpoint discloses LiteLLM credentials](docs/cve-2026-137497.md) | Remote |
| [CVE-2026-137826](agent/exploits/cve_2026_137826.py) | [Lookyloo unauthenticated remote-capture pull server-side request forgery](docs/cve-2026-137826.md) | Remote |
| [CVE-2026-137955](agent/exploits/cve_2026_137955.py) | [PlantUML Server unauthenticated local file access through @startdot](docs/cve-2026-137955.md) | Remote |

</details>

<details><summary><b>2025 — 108 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2025-0108](agent/exploits/cve_2025_0108.py) | Palo Alto PAN-OS management interface authentication bypass (CVE-2025-0108) | Remote |
| [CVE-2025-0282](agent/exploits/cve_2025_0282.py) | Ivanti Connect Secure Buffer Overflow | Remote |
| [CVE-2025-0674](agent/exploits/cve_2025_0674.py) | Elber ESE DVB-S/S2 Authentication Bypass | Remote |
| [CVE-2025-0890](agent/exploits/cve_2025_0890.py) | Zyxel VMG4325-B10A Default Credentials Leading to RCE | Remote |
| [CVE-2025-1338](agent/exploits/cve_2025_1338.py) | NUUO camera handle_config.php OS command injection (CVE-2025-1338) | Remote |
| [CVE-2025-1974](agent/exploits/cve_2025_1974.py) | Kubernetes ingress-nginx admission controller configuration injection (IngressNightmare, CVE-2025-1974) | Remote |
| [CVE-2025-2221](agent/exploits/cve_2025_2221.py) | WPCOM Member SQL injection (CVE-2025-2221) | Remote |
| [CVE-2025-2505](agent/exploits/wordpress_readme_2026.py) | Age Gate (CVE-2025-2505) | Remote |
| [CVE-2025-2636](agent/exploits/cve_2025_2636.py) | InstaWP Connect <= 0.1.0.85 local file inclusion (CVE-2025-2636) | Remote |
| [CVE-2025-2746](agent/exploits/cve_2025_2746.py) | Kentico Xperience 13 Staging Service authentication bypass (CVE-2025-2746) | Remote |
| [CVE-2025-2747](agent/exploits/cve_2025_2747.py) | Kentico Xperience 13 Staging Service authentication bypass (CVE-2025-2747) | Remote |
| [CVE-2025-3085](agent/exploits/cve_2025_3085.py) | CVE-2025-3085 | Offline inventory |
| [CVE-2025-3248](agent/exploits/cve_2025_3248.py) | Langflow CVE-2025-3248 | Remote |
| [CVE-2025-4008](agent/exploits/cve_2025_4008.py) | Meteobridge <= 6.1 unauthenticated command injection (CVE-2025-4008) | Remote |
| [CVE-2025-4322](agent/exploits/cve_2025_4322.py) | Motors Theme <= 5.6.67 - Unauthenticated Privilege Escalation via Password Update/Account Takeover | Remote |
| [CVE-2025-5777](agent/exploits/cve_2025_5777.py) | NetScaler CVE-2025-5777 | Remote |
| [CVE-2025-6389](agent/exploits/cve_2025_6389.py) | Sneeit Framework <= 8.3 unauthenticated remote code execution via call_user_func (CVE-2025-6389) | Remote |
| [CVE-2025-7659](agent/exploits/cve_2025_7659.py) | GitLab Web IDE CVE-2025-7659 | Offline inventory |
| [CVE-2025-9209](agent/exploits/wordpress_readme_2026.py) | RestroPress – Online Food Ordering System (CVE-2025-9209) | Remote |
| [CVE-2025-10035](agent/exploits/cve_2025_10035.py) | GoAnywhere MFT License Servlet Deserialization Vulnerability | Remote |
| [CVE-2025-11693](agent/exploits/wordpress_readme_2026.py) | Export WP Page to Static HTML & PDF (CVE-2025-11693) | Remote |
| [CVE-2025-11953](agent/exploits/cve_2025_11953.py) | React Native Community CLI Metro open-url command injection (CVE-2025-11953) | Remote |
| [CVE-2025-12480](agent/exploits/cve_2025_12480.py) | Triofox improper access control to admin setup pages (CVE-2025-12480) | Remote |
| [CVE-2025-12536](agent/exploits/wordpress_readme_2026.py) | SureForms – Contact Form, Payment Form & Other Custom Form Builder (CVE-2025-12536) | Remote |
| [CVE-2025-12841](agent/exploits/wordpress_readme_2026.py) | Bookit (CVE-2025-12841) | Remote |
| [CVE-2025-13342](agent/exploits/wordpress_readme_2026.py) | Frontend Admin by DynamiApps (CVE-2025-13342) | Remote |
| [CVE-2025-13390](agent/exploits/wordpress_readme_2026.py) | WP Directory Kit (CVE-2025-13390) | Remote |
| [CVE-2025-13761](agent/exploits/cve_2025_13761.py) | GitLab browser CVE-2025-13761 | Offline inventory |
| [CVE-2025-13773](agent/exploits/wordpress_readme_2026.py) | Print Invoice & Delivery Notes for WooCommerce (CVE-2025-13773) | Remote |
| [CVE-2025-13801](agent/exploits/wordpress_readme_2026.py) | Yoco Payments (CVE-2025-13801) | Remote |
| [CVE-2025-14124](agent/exploits/cve_2025_14124.py) | TLP Team WordPress SQL injection (CVE-2025-14124) | Remote |
| [CVE-2025-14611](agent/exploits/cve_2025_14611.py) | Gladinet CentreStack / Triofox hardcoded cryptoscheme file read (CVE-2025-14611) | Remote |
| [CVE-2025-14733](agent/exploits/cve_2025_14733.py) | WatchGuard Firebox Fireware OS CVE-2025-14733 | Remote |
| [CVE-2025-14847](agent/exploits/cve_2025_14847.py) | MongoDB Server CVE-2025-14847 | Remote |
| [CVE-2025-14917](agent/exploits/cve_2025_14917.py) | CVE-2025-14917 | Offline inventory |
| [CVE-2025-14923](agent/exploits/cve_2025_14923.py) | CVE-2025-14923 | Offline inventory |
| [CVE-2025-14998](agent/exploits/wordpress_readme_2026.py) | Branda (CVE-2025-14998) | Remote |
| [CVE-2025-15403](agent/exploits/wordpress_readme_2026.py) | RegistrationMagic (CVE-2025-15403) | Remote |
| [CVE-2025-20393](agent/exploits/cve_2025_20393.py) | Cisco email quarantine CVE-2025-20393 | Offline inventory |
| [CVE-2025-22457](agent/exploits/cve_2025_22457.py) | Ivanti Stack-based Buffer Overflow | Remote |
| [CVE-2025-23006](agent/exploits/cve_2025_23006.py) | SonicWall SMA1000 / CMS CVE-2025-23006 | Remote |
| [CVE-2025-23016](agent/exploits/cve_2025_23016.py) | FastCGI Integer Overflow Leading to Heap Overflow (CVE-2025-23016) | Remote |
| [CVE-2025-23211](agent/exploits/cve_2025_23211.py) | Tandoor CVE-2025-23211 template injection | Remote |
| [CVE-2025-24514](agent/exploits/cve_2025_24514.py) | Kubernetes ingress-nginx auth-url configuration injection (IngressNightmare, CVE-2025-24514) | Remote |
| [CVE-2025-24893](agent/exploits/cve_2025_24893.py) | XWiki Solr UI CVE-2025-24893 | Remote |
| [CVE-2025-25257](agent/exploits/cve_2025_25257.py) | Fortinet FortiWeb CVE-2025-25257 | Remote |
| [CVE-2025-27223](agent/exploits/cve_2025_27223.py) | TRUfusion Enterprise <= 7.10.4.0 authentication bypass (CVE-2025-27223) | Remote |
| [CVE-2025-27364](agent/exploits/cve_2025_27364.py) | MITRE Caldera Agent Dynamic Compilation RCE | Remote |
| [CVE-2025-28367](agent/exploits/cve_2025_28367.py) | mojoPortal through 2.9.0.1 directory traversal (CVE-2025-28367) | Remote |
| [CVE-2025-29927](agent/exploits/cve_2025_29927.py) | Next.js middleware authorization bypass (CVE-2025-29927) | Remote |
| [CVE-2025-30208](agent/exploits/cve_2025_30208.py) | Vite dev server @fs arbitrary file read (CVE-2025-30208) | Remote |
| [CVE-2025-31125](agent/exploits/cve_2025_31125.py) | Vite development server @fs path traversal file disclosure (CVE-2025-31125) | Remote |
| [CVE-2025-31161](agent/exploits/cve_2025_31161.py) | CrushFTP CVE-2025-31161 | Remote |
| [CVE-2025-31324](agent/exploits/cve_2025_31324.py) | SAP NetWeaver Visual Composer CVE-2025-31324 | Remote |
| [CVE-2025-32432](agent/exploits/cve_2025_32432.py) | Craft CMS CVE-2025-32432 | Remote |
| [CVE-2025-32433](agent/exploits/cve_2025_32433.py) | Erlang/OTP SSH Pre-Auth Command Execution | Remote |
| [CVE-2025-32756](agent/exploits/cve_2025_32756.py) | Fortinet Multiple Products - Stack-Based Overflow (CVE-2025-32756) | Remote |
| [CVE-2025-32966](agent/exploits/cve_2025_32966.py) | DataEase CVE-2025-32966 JDBC code execution | Remote |
| [CVE-2025-34026](agent/exploits/cve_2025_34026.py) | Versa Concerto Spring Boot Actuator authentication bypass (CVE-2025-34026) | Remote |
| [CVE-2025-34030](agent/exploits/cve_2025_34030.py) | sar2html CVE-2025-34030 command injection | Remote |
| [CVE-2025-34035](agent/exploits/cve_2025_34035.py) | EnGenius EnShare usbinteract.cgi root command injection (CVE-2025-34035) | Remote |
| [CVE-2025-34291](agent/exploits/cve_2025_34291.py) | Langflow AI permissive CORS reflection (CVE-2025-34291) | Remote |
| [CVE-2025-37164](agent/exploits/cve_2025_37164.py) | HPE OneView CVE-2025-37164 | Remote |
| [CVE-2025-40551](agent/exploits/cve_2025_40551.py) | SolarWinds Web Help Desk CVE-2025-40551 | Remote |
| [CVE-2025-40552](agent/exploits/cve_2025_40552.py) | SolarWinds Web Help Desk LookAndFeel authentication bypass (CVE-2025-40552) | Remote |
| [CVE-2025-40553](agent/exploits/cve_2025_40553.py) | SolarWinds Web Help Desk unauthenticated deserialization (CVE-2025-40553) | Remote |
| [CVE-2025-40554](agent/exploits/cve_2025_40554.py) | SolarWinds Web Help Desk LoginPref authentication bypass (CVE-2025-40554) | Remote |
| [CVE-2025-47577](agent/exploits/wordpress_readme_2026.py) | TI WooCommerce Wishlist (CVE-2025-47577) | Remote |
| [CVE-2025-47812](agent/exploits/cve_2025_47812.py) | Wing FTP Server CVE-2025-47812 | Remote |
| [CVE-2025-47813](agent/exploits/cve_2025_47813.py) | Wing FTP Server overlong-UID path disclosure (CVE-2025-47813) | Remote |
| [CVE-2025-48281](agent/exploits/wordpress_readme_2026.py) | MyStyle Custom Product Designer (CVE-2025-48281) | Remote |
| [CVE-2025-48827](agent/exploits/cve_2025_48827.py) | vBulletin Unauthenticated RCE via ajax/api/ad/replaceAdTemplate (CVE-2025-48827) | Remote |
| [CVE-2025-48828](agent/exploits/cve_2025_48827.py) | vBulletin Unauthenticated RCE via ajax/api/ad/replaceAdTemplate (CVE-2025-48827) | Remote |
| [CVE-2025-49132](agent/exploits/cve_2025_49132.py) | Pterodactyl Panel locale LFI to configuration disclosure (CVE-2025-49132) | Remote |
| [CVE-2025-49596](agent/exploits/cve_2025_49596.py) | MCP Inspector < 0.14.1 unauthenticated remote code execution via the stdio proxy (CVE-2025-49596) | Remote |
| [CVE-2025-49706](agent/exploits/cve_2025_49706.py) | Microsoft SharePoint ToolPane authentication bypass (CVE-2025-49706) | Remote |
| [CVE-2025-52691](agent/exploits/cve_2025_52691.py) | SmarterTools SmarterMail CVE-2025-52691 | Remote |
| [CVE-2025-52694](agent/exploits/cve_2025_52694.py) | Advantech WISE-IoTSuite SQL injection (CVE-2025-52694) | Remote |
| [CVE-2025-53521](agent/exploits/cve_2025_53521.py) | F5 BIG-IP APM CVE-2025-53521 | Remote |
| [CVE-2025-53770](agent/exploits/cve_2025_53770.py) | SharePoint Server CVE-2025-53770 | Remote |
| [CVE-2025-54253](agent/exploits/cve_2025_54253.py) | Adobe Experience Manager Forms on JEE CVE-2025-54253 | Remote |
| [CVE-2025-54309](agent/exploits/cve_2025_54309.py) | CrushFTP CVE-2025-54309 | Remote |
| [CVE-2025-54531](agent/exploits/cve_2025_54531.py) | Windows plugin-unpacking assessment for TeamCity CVE-2025-54531 | Offline inventory |
| [CVE-2025-54988](agent/exploits/cve_2025_54988.py) | Apache Tika CVE-2025-54988 PDF/XFA XXE | Remote |
| [CVE-2025-55150](agent/exploits/cve_2025_55150.py) | Stirling-PDF CVE-2025-55150 HTML conversion SSRF | Remote |
| [CVE-2025-55182](agent/exploits/cve_2025_55182.py) | Meta React Server Components CVE-2025-55182 | Remote + inventory |
| [CVE-2025-55184](agent/exploits/cve_2025_55184.py) | React Server Components denial of service / source exposure (CVE-2025-55184) | Remote |
| [CVE-2025-57819](agent/exploits/cve_2025_57819.py) | Sangoma FreePBX endpoint CVE-2025-57819 | Remote |
| [CVE-2025-58360](agent/exploits/cve_2025_58360.py) | GeoServer SLD XML External Entity injection (CVE-2025-58360) | Remote |
| [CVE-2025-59287](agent/exploits/cve_2025_59287.py) | Microsoft Windows WSUS CVE-2025-59287 | Remote |
| [CVE-2025-59528](agent/exploits/cve_2025_59528.py) | Flowise CVE-2025-59528 CustomMCP RCE | Remote |
| [CVE-2025-59718](agent/exploits/cve_2025_59718.py) | Fortinet CVE-2025-59718 FortiCloud SSO | Remote |
| [CVE-2025-60188](agent/exploits/cve_2025_60188.py) | Atarim Visual Collaboration unauthenticated data exposure (CVE-2025-60188) | Remote |
| [CVE-2025-61757](agent/exploits/cve_2025_61757.py) | Oracle Identity Manager CVE-2025-61757 | Remote |
| [CVE-2025-61882](agent/exploits/cve_2025_61882.py) | Oracle E-Business Suite CVE-2025-61882 | Remote |
| [CVE-2025-62168](agent/exploits/cve_2025_62168.py) | Squid CVE-2025-62168 authentication credential disclosure | Remote |
| [CVE-2025-62581](agent/exploits/cve_2025_62581.py) | CVE-2025-62581 | Offline inventory |
| [CVE-2025-62582](agent/exploits/cve_2025_62582.py) | CVE-2025-62582 | Offline inventory |
| [CVE-2025-62593](agent/exploits/cve_2025_62593.py) | Ray CVE-2025-62593 browser DNS-rebinding RCE | Remote |
| [CVE-2025-64155](agent/exploits/cve_2025_64155.py) | assessment of FortiSIEM phMonitor; no remote probe | Offline inventory |
| [CVE-2025-64446](agent/exploits/cve_2025_64446.py) | Fortinet FortiWeb CVE-2025-64446 | Remote |
| [CVE-2025-66516](agent/exploits/cve_2025_66516.py) | Apache Tika XFA XML external entity injection (CVE-2025-66516) | Remote |
| [CVE-2025-67303](agent/exploits/cve_2025_67303.py) | ComfyUI-Manager CVE-2025-67303 configuration integrity | Remote |
| [CVE-2025-68645](agent/exploits/cve_2025_68645.py) | Zimbra Collaboration servlet-include local file inclusion (CVE-2025-68645) | Remote |
| [CVE-2025-69258](agent/exploits/cve_2025_69258.py) | CVE-2025-69258 | Offline inventory |
| [CVE-2025-69411](agent/exploits/wordpress_readme_2026.py) | ionCube tester plus (CVE-2025-69411) | Remote |
| [CVE-2025-71334](agent/exploits/cve_2025_71334.py) | Flowise CVE-2025-71334 storage path traversal | Remote |
| [CVE-2025-71458](agent/exploits/cve_2025_71458.py) | FTS3 Web Monitoring unauthenticated SQL injection in /linkinfo (CVE-2025-71458) | Remote |

</details>

<details><summary><b>2024 — 105 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2024-0012](agent/exploits/cve_2024_0012.py) | PAN-OS management interface authentication bypass (CVE-2024-0012) | Remote |
| [CVE-2024-0692](agent/exploits/cve_2024_0692.py) | SolarWinds Security Event Manager unauthenticated remote code execution | Remote |
| [CVE-2024-2194](agent/exploits/cve_2024_2194.py) | WP Statistics Unauthenticated Stored Cross-Site Scripting | Remote |
| [CVE-2024-2879](agent/exploits/cve_2024_2879.py) | LayerSlider 7.9.11 - 7.10.0 - Unauthenticated SQL Injection | Remote |
| [CVE-2024-3273](agent/exploits/cve_2024_3273.py) | D-Link Multiple NAS Devices Command Injection Vulnerability | Remote |
| [CVE-2024-3408](agent/exploits/cve_2024_3408.py) | D-Tale CVE-2024-3408 authentication bypass/RCE | Remote |
| [CVE-2024-3495](agent/exploits/cve_2024_3495.py) | WordPress Country State City Dropdown CF7 SQL injection (CVE-2024-3495) | Remote |
| [CVE-2024-3596](agent/exploits/cve_2024_3596.py) | PAN-OS BlastRADIUS owner inventory; no authentication probes | Offline inventory |
| [CVE-2024-4040](agent/exploits/cve_2024_4040.py) | Unauthenticated arbitrary file read and remote code execution in CrushFTP | Remote |
| [CVE-2024-4439](agent/exploits/cve_2024_4439.py) | Unauthenticated Stored Cross-Site Scripting Vulnerability in WordPress Core | Remote |
| [CVE-2024-4577](agent/exploits/cve_2024_4577.py) | PHP-CGI argument injection remote code execution (CVE-2024-4577) | Remote |
| [CVE-2024-5057](agent/exploits/wordpress_readme_2026.py) | Easy Digital Downloads (CVE-2024-5057) | Remote |
| [CVE-2024-5315](agent/exploits/cve_2024_5315.py) | Dolibarr ERP-CRM 9.0.1 - SQL Injection | Remote |
| [CVE-2024-5333](agent/exploits/wordpress_readme_2026.py) | The Events Calendar (CVE-2024-5333) | Remote |
| [CVE-2024-6235](agent/exploits/cve_2024_6235.py) | NetScaler Console sensitive information disclosure (CVE-2024-6235) | Remote |
| [CVE-2024-6385](agent/exploits/cve_2024_6385.py) | GitLab Authentication Bypass Vulnerability. | Remote |
| [CVE-2024-6386](agent/exploits/cve_2024_6386.py) | WPML Multilingual CMS Authenticated Contributor+ Remote Code Execution (RCE) via Twig Server-Side Template Injection (SSTI) | Remote |
| [CVE-2024-6387](agent/exploits/cve_2024_6387.py) | OpenSSH Remote Code Execution Vulnerability | Remote |
| [CVE-2024-6633](agent/exploits/cve_2024_6633.py) | Default Credentials in Fortra FileCatalyst Workflow HSQLDB | Remote |
| [CVE-2024-6745](agent/exploits/cve_2024_6745.py) | SQL Injection in Simple Ticket Booking | Remote |
| [CVE-2024-6782](agent/exploits/cve_2024_6782.py) | Calibre <= 7.14.0 unauthenticated remote code execution via the content server cdb template (CVE-2024-6782) | Remote |
| [CVE-2024-6911](agent/exploits/cve_2024_6911.py) | PerkinElmer ProcessPlus path traversal (CVE-2024-6911) | Remote |
| [CVE-2024-7029](agent/exploits/cve_2024_7029.py) | AVTECH IP camera Devices Command Injection Vulnerability | Remote |
| [CVE-2024-7120](agent/exploits/cve_2024_7120.py) | Command Injection in RAISECOM Gateway Devices | Remote |
| [CVE-2024-7589](agent/exploits/cve_2024_7589.py) | OpenSSH Pre-Authentication Async Signal Safety Issue | Remote |
| [CVE-2024-8522](agent/exploits/cve_2024_8522.py) | Unauthenticated SQL Injection Vulnerability in LearnPress Plugin | Remote |
| [CVE-2024-8672](agent/exploits/cve_2024_8672.py) | Widget Options Plugin <= 4.0.7 - Authenticated Remote Code Execution | Remote |
| [CVE-2024-8956](agent/exploits/cve_2024_8956.py) | ValueHD PTZ Camera Authentication Bypass | Remote |
| [CVE-2024-8957](agent/exploits/cve_2024_8957.py) | ValueHD PTZ Camera Command Injection | Remote |
| [CVE-2024-8963](agent/exploits/cve_2024_8963.py) | Ivanti Cloud Services Appliance path traversal (CVE-2024-8963) | Remote |
| [CVE-2024-9164](agent/exploits/cve_2024_9164.py) | Gitlab Run pipelines on arbitrary branches. | Remote |
| [CVE-2024-9465](agent/exploits/cve_2024_9465.py) | Palo Alto Expedition SQL injection (CVE-2024-9465) | Remote |
| [CVE-2024-9487](agent/exploits/cve_2024_9487.py) | GITHUB ENTERPRISE SERVER AUTHENTICATION BYPASS | Remote |
| [CVE-2024-9537](agent/exploits/cve_2024_9537.py) | ScienceLogic SL1 CVE-2024-9537 | Offline inventory |
| [CVE-2024-9634](agent/exploits/cve_2024_9634.py) | PHP Object Injection Vulnerability in GiveWP Plugin | Remote |
| [CVE-2024-9643](agent/exploits/cve_2024_9643.py) | Four-Faith router hard-coded default credentials (CVE-2024-9643) | Remote |
| [CVE-2024-10542](agent/exploits/cve_2024_10542.py) | CleanTalk Plugin Arbitrary Plugin Installation (Via Reverse DNS Spoofing) | Remote |
| [CVE-2024-10781](agent/exploits/cve_2024_10781.py) | CleanTalk Unauthorized Arbitrary Plugin Installation | Remote |
| [CVE-2024-10905](agent/exploits/cve_2024_10905.py) | SailPoint IdentityIQ Static File Exposure | Remote |
| [CVE-2024-11205](agent/exploits/cve_2024_11205.py) | WPForms Lite Plugin 1.8.4 - 1.9.2.1 - Missing Authorization to Authenticated (Subscriber+) Payment Refund and Subscription Cancellation | Remote |
| [CVE-2024-11639](agent/exploits/cve_2024_11639.py) | Authentication Bypass in Ivanti CSA Admin Console | Remote |
| [CVE-2024-11667](agent/exploits/cve_2024_11667.py) | Zyxel ATP/USG FLEX/USG FLEX 50(W)/USG20(W)-VPN UP TO 5.38 URL PATH TRAVERSAL | Remote |
| [CVE-2024-11972](agent/exploits/cve_2024_11972.py) | Hunk Companion Plugin Unauthenticated Arbitrary Plugin Installation | Remote |
| [CVE-2024-12084](agent/exploits/cve_2024_12084.py) | Rsync Heap Buffer Overflow | Remote |
| [CVE-2024-12209](agent/exploits/cve_2024_12209.py) | WP Umbrella plugin local file inclusion (CVE-2024-12209) | Remote |
| [CVE-2024-20419](agent/exploits/cve_2024_20419.py) | Account Takeover in Cisco Smart Software Manager On-Prem | Remote |
| [CVE-2024-20767](agent/exploits/cve_2024_20767.py) | Adobe ColdFusion improper access control arbitrary file read (CVE-2024-20767) | Remote |
| [CVE-2024-21287](agent/exploits/cve_2024_21287.py) | Oracle Agile PLM Framework Remote File Disclosure | Remote |
| [CVE-2024-21591](agent/exploits/cve_2024_21591.py) | Junos J-Web CVE-2024-21591 | Offline inventory |
| [CVE-2024-21733](agent/exploits/cve_2024_21733.py) | Apache Tomcat HTTP Request Smuggling (Client- Side Desync) | Remote |
| [CVE-2024-21762](agent/exploits/cve_2024_21762.py) | Fortinet FortiOS Out-of-Bound Write SSL VPN Vulnerability | Remote |
| [CVE-2024-23113](agent/exploits/cve_2024_23113.py) | Critical Fortinet Format String Vulnerability | Remote |
| [CVE-2024-23334](agent/exploits/cve_2024_23334.py) | AIOHTTP Path Traversal | Remote |
| [CVE-2024-24882](agent/exploits/wordpress_readme_2026.py) | Masteriyo LMS (CVE-2024-24882) | Remote |
| [CVE-2024-27198](agent/exploits/cve_2024_27198.py) | JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions | Remote |
| [CVE-2024-27199](agent/exploits/cve_2024_27199.py) | JetBrains TeamCity path-traversal authentication bypass (CVE-2024-27199) | Remote |
| [CVE-2024-27497](agent/exploits/cve_2024_27497.py) | Linksys E2000 1.0.06 authentication bypass | Remote |
| [CVE-2024-28890](agent/exploits/cve_2024_28890.py) | Forminator plugin flaw in WordPress sites | Remote |
| [CVE-2024-28986](agent/exploits/cve_2024_28986.py) | SolarWinds Web Help Desk 12.8.3 - Java Deserialization RCE | Remote |
| [CVE-2024-28987](agent/exploits/cve_2024_28987.py) | SolarWinds Web Help Desk hardcoded credential (CVE-2024-28987) | Remote |
| [CVE-2024-29269](agent/exploits/cve_2024_29269.py) | Telesquare TLR-2005KSH Unauthorized Remote Command Execution Vulnerability | Remote |
| [CVE-2024-30502](agent/exploits/wordpress_readme_2026.py) | WP Travel Engine (CVE-2024-30502) | Remote |
| [CVE-2024-32113](agent/exploits/cve_2024_32113.py) | Apache OFBiz before 18.12.13 unauthenticated directory traversal to ProgramExport (CVE-2024-32113) | Remote |
| [CVE-2024-32114](agent/exploits/cve_2024_32114.py) | Apache ActiveMQ 6.x before 6.1.2 unauthenticated Jolokia API (CVE-2024-32114) | Remote |
| [CVE-2024-33544](agent/exploits/cve_2024_33544.py) | Unauthenticated SQL Injection Vulnerability in WZone Plugin | Remote |
| [CVE-2024-34470](agent/exploits/cve_2024_34470.py) | HSC MAILINSPECTOR PATH TRAVERSAL | Remote |
| [CVE-2024-36104](agent/exploits/cve_2024_36104.py) | Apache OFBiz before 18.12.14 unauthenticated directory traversal to ProgramExport (CVE-2024-36104) | Remote |
| [CVE-2024-37383](agent/exploits/cve_2024_37383.py) | XSS via SVG Animate Attributes in Roundcube Webmail | Remote |
| [CVE-2024-38077](agent/exploits/cve_2024_38077.py) | Windows Remote Desktop Licensing Service RCE | Remote |
| [CVE-2024-38475](agent/exploits/cve_2024_38475.py) | SonicWall SMA100 pre-authentication arbitrary file read (CVE-2024-38475) | Remote |
| [CVE-2024-38773](agent/exploits/wordpress_readme_2026.py) | FormLift for Infusionsoft Web Forms (CVE-2024-38773) | Remote |
| [CVE-2024-38856](agent/exploits/cve_2024_38856.py) | Apache OFBiz through 18.12.14 improper authorization to ProgramExport (CVE-2024-38856) | Remote |
| [CVE-2024-39717](agent/exploits/cve_2024_39717.py) | Versa Director Dangerous File Type Upload Vulnerability | Remote |
| [CVE-2024-40711](agent/exploits/cve_2024_40711.py) | Veeam Backup & Replication Remote Code Execution Vulnerability | Remote |
| [CVE-2024-40725](agent/exploits/cve_2024_40725.py) | Source Code Disclosure in Apache HTTP Server | Remote |
| [CVE-2024-40766](agent/exploits/cve_2024_40766.py) | SonicWall SonicOS Improper Access Control Vulnerability | Remote |
| [CVE-2024-41713](agent/exploits/cve_2024_41713.py) | Mitel MiCollab NuPoint path traversal authentication bypass (CVE-2024-41713) | Remote |
| [CVE-2024-42450](agent/exploits/cve_2024_42450.py) | Versa Director Database exposure | Remote |
| [CVE-2024-42509](agent/exploits/cve_2024_42509.py) | Unauthenticated Command Injection Vulnerability in HPE Aruba Networking Access Points | Remote |
| [CVE-2024-43044](agent/exploits/cve_2024_43044.py) | JENKINS ARBITRARY FILE READ TO RCE | Remote |
| [CVE-2024-43144](agent/exploits/wordpress_readme_2026.py) | Cost Calculator Builder (CVE-2024-43144) | Remote |
| [CVE-2024-43399](agent/exploits/cve_2024_43399.py) | Mobile Security Framework (MobSF) Zip Slip | Remote |
| [CVE-2024-45409](agent/exploits/cve_2024_45409.py) | GitLab SAML Authentication Bypass Vulnerability. | Remote |
| [CVE-2024-46938](agent/exploits/cve_2024_46938.py) | Sitecore Experience Platform XAML path leak (CVE-2024-46938) | Remote |
| [CVE-2024-47374](agent/exploits/cve_2024_47374.py) | Stored Cross-Site Scripting (XSS) Vulnerability in LiteSpeed Cache for WordPress | Remote |
| [CVE-2024-47533](agent/exploits/cve_2024_47533.py) | Cobbler XMLRPC Interface Authentication Bypass | Remote |
| [CVE-2024-47575](agent/exploits/cve_2024_47575.py) | Missing Authentication for critical function in FortiManager | Remote |
| [CVE-2024-48248](agent/exploits/cve_2024_48248.py) | NAKIVO Backup & Replication unauthenticated arbitrary file read (CVE-2024-48248) | Remote |
| [CVE-2024-50340](agent/exploits/cve_2024_50340.py) | symfony/runtime argument-injection profiler exposure (CVE-2024-50340) | Remote |
| [CVE-2024-50379](agent/exploits/cve_2024_50379.py) | Apache Tomcat Race Condition Remote Code Execution | Remote |
| [CVE-2024-50550](agent/exploits/cve_2024_50550.py) | LiteSpeed Cache Vulnerability Allowing privilege escalation | Remote |
| [CVE-2024-50603](agent/exploits/cve_2024_50603.py) | Aviatrix Controller unauthenticated OS command injection (CVE-2024-50603) | Remote |
| [CVE-2024-50623](agent/exploits/cve_2024_50623.py) | Cleo Harmony, VLTrader, and LexiCom - Unrestricted File Upload and Download Leading to Remote Code Execution | Remote |
| [CVE-2024-51378](agent/exploits/cve_2024_51378.py) | CYBERPANEL RCE | Remote |
| [CVE-2024-51479](agent/exploits/cve_2024_51479.py) | Next.js Authorization Bypass via Middleware | Remote |
| [CVE-2024-51567](agent/exploits/cve_2024_51567.py) | CyberPanel <= 2.3.6 pre-auth command injection (CVE-2024-51567) | Remote |
| [CVE-2024-52875](agent/exploits/cve_2024_52875.py) | GFI Kerio Control CRLF injection / HTTP response splitting (CVE-2024-52875) | Remote |
| [CVE-2024-53298](agent/exploits/cve_2024_53298.py) | CVE-2024-53298 | Offline inventory |
| [CVE-2024-53704](agent/exploits/cve_2024_53704.py) | SonicWall SSLVPN Authentication Bypass | Remote |
| [CVE-2024-54134](agent/exploits/cve_2024_54134.py) | MALICIOUS PACKAGES FOUND IN COMPROMISED @SOLANA/WEB3.JS LIBRARY | Remote |
| [CVE-2024-55591](agent/exploits/cve_2024_55591.py) | Fortinet FortiOS Authentication Bypass | Remote |
| [CVE-2024-55956](agent/exploits/cve_2024_55956.py) | Cleo Harmony, VLTrader, and LexiCom - Arbitrary Command Execution via Autorun Directory | Remote |
| [CVE-2024-56145](agent/exploits/cve_2024_56145.py) | Craft CMS template-path manipulation RCE (CVE-2024-56145) | Remote |
| [CVE-2024-57726](agent/exploits/cve_2024_57726.py) | SimpleHelp CVE-2024-57726 technician privilege escalation | Remote |
| [CVE-2024-57727](agent/exploits/cve_2024_57727.py) | SimpleHelp unauthenticated path traversal file disclosure (CVE-2024-57727) | Remote |

</details>

<details><summary><b>2023 — 33 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2023-1389](agent/exploits/cve_2023_1389.py) | Remote Code Execution in TP-Link AX21. | Remote |
| [CVE-2023-3452](agent/exploits/wordpress_readme_2026.py) | Canto (CVE-2023-3452) | Remote |
| [CVE-2023-4966](agent/exploits/cve_2023_4966.py) | Citrix NetScaler ADC/Gateway sensitive memory disclosure (Citrix Bleed, CVE-2023-4966) | Remote |
| [CVE-2023-5204](agent/exploits/wordpress_readme_2026.py) | AI ChatBot (WPBot) (CVE-2023-5204) | Remote |
| [CVE-2023-6825](agent/exploits/wordpress_readme_2026.py) | File Manager (free edition) (CVE-2023-6825) | Remote |
| [CVE-2023-6895](agent/exploits/cve_2023_6895.py) | Hikvision Intercom Broadcasting System ping.php command injection (CVE-2023-6895) | Remote |
| [CVE-2023-22518](agent/exploits/cve_2023_22518.py) | Improper Authorization Vulnerability In Confluence Data Center and Server | Remote |
| [CVE-2023-24000](agent/exploits/wordpress_readme_2026.py) | GamiPress (CVE-2023-24000) | Remote |
| [CVE-2023-25135](agent/exploits/cve_2023_25135.py) | vBulletin before 5.6.9 PL1 pre-authentication deserialization RCE (CVE-2023-25135) | Remote |
| [CVE-2023-25157](agent/exploits/cve_2023_25157.py) | GeoServer OGC Filter / CQL SQL injection (CVE-2023-25157) | Remote |
| [CVE-2023-25280](agent/exploits/cve_2023_25280.py) | Command Injection in D-Link DIR820LA1 | Remote |
| [CVE-2023-26347](agent/exploits/cve_2023_26347.py) | Adobe ColdFusion admin access-control bypass (CVE-2023-26347) | Remote |
| [CVE-2023-27032](agent/exploits/cve_2023_27032.py) | PrestaShop Advanced Popup Creator SQL injection (CVE-2023-27032) | Remote |
| [CVE-2023-27638](agent/exploits/cve_2023_27638.py) | PrestaShop tshirtecommerce module SQL injection (CVE-2023-27638) | Remote |
| [CVE-2023-27997](agent/exploits/cve_2023_27997.py) | A heap-based buffer overflow vulnerability in FortiOS. | Remote |
| [CVE-2023-28461](agent/exploits/cve_2023_28461.py) | Array Networks Array AG Series and vxAG Remote Code Execution Vulnerability | Remote |
| [CVE-2023-29357](agent/exploits/cve_2023_29357.py) | Microsoft SharePoint Server JWT authentication bypass (CVE-2023-29357) | Remote |
| [CVE-2023-34990](agent/exploits/cve_2023_34990.py) | FortiWLM Directory Traversal | Remote |
| [CVE-2023-35078](agent/exploits/cve_2023_35078.py) | Ivanti EPMM (MobileIron Core) <=11.10 unauthenticated API access (CVE-2023-35078) | Remote |
| [CVE-2023-36845](agent/exploits/cve_2023_36845.py) | Juniper Junos OS EX Series and SRX Series PHP External Variable Modification Vulnerability | Remote |
| [CVE-2023-41892](agent/exploits/cve_2023_41892.py) | Craft CMS before 4.4.15 unauthenticated remote code execution (CVE-2023-41892) | Remote |
| [CVE-2023-42282](agent/exploits/cve_2023_42282.py) | assessment of node-ip CVE-2023-42282 without SSRF probes | Offline inventory |
| [CVE-2023-43770](agent/exploits/cve_2023_43770.py) | Roundcube Webmail Persistent Cross-Site Scripting (XSS) Vulnerability | Remote |
| [CVE-2023-45727](agent/exploits/cve_2023_45727.py) | Proself Enterprise/Standard XXE Vulnerability | Remote |
| [CVE-2023-46805](agent/exploits/cve_2023_46805.py) | Ivanti Connect Secure authentication bypass (CVE-2023-46805) | Remote |
| [CVE-2023-48788](agent/exploits/cve_2023_48788.py) | Fortinet FortiClient EMS SQL Injection Vulnerability | Remote |
| [CVE-2023-49103](agent/exploits/cve_2023_49103.py) | ownCloud graphapi phpinfo disclosure (CVE-2023-49103) | Remote |
| [CVE-2023-49105](agent/exploits/cve_2023_49105.py) | ownCloud CVE-2023-49105 | Remote |
| [CVE-2023-49897](agent/exploits/cve_2023_49897.py) | FXC wireless LAN routers "AE1021PE" and "AE1021" vulnerable to OS command injection. | Remote |
| [CVE-2023-50839](agent/exploits/wordpress_readme_2026.py) | JS Help Desk (CVE-2023-50839) | Remote |
| [CVE-2023-50969](agent/exploits/cve_2023_50969.py) | Imperva SecureSphere WAF Bypass for POST Data Inspection Rules | Remote |
| [CVE-2023-54391](agent/exploits/cve_2023_54391.py) | Proxmox VE authentication bypass via TFA challenge (CVE-2023-54391) | Remote |
| [CVE-2023-54419](agent/exploits/cve_2023_54419.py) | [nginxWebUI deployment version](docs/nginxwebui-2023-54419.md) | Offline inventory |

</details>

<details><summary><b>2022 — 14 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2022-1453](agent/exploits/wordpress_readme_2026.py) | RSVPMaker (CVE-2022-1453) | Remote |
| [CVE-2022-21445](agent/exploits/cve_2022_21445.py) | Oracle Application Development Framework (ADF) Remote Code Execution Vulnerability | Remote |
| [CVE-2022-22965](agent/exploits/cve_2022_22965.py) | Spring4Shell potential package exposure; runtime prerequisites unconfirmed | Remote SBOM / offline inventory |
| [CVE-2022-24223](agent/exploits/cve_2022_24223.py) | Atom CMS v2.0 SQL injection in admin login (CVE-2022-24223) | Remote |
| [CVE-2022-24331](agent/exploits/cve_2022_24331.py) | native GitLab authentication assessment for TeamCity CVE-2022-24331 | Offline inventory |
| [CVE-2022-24816](agent/exploits/cve_2022_24816.py) | GeoServer WPS Remote Code Execution | Remote |
| [CVE-2022-26318](agent/exploits/cve_2022_26318.py) | WatchGuard Firebox and XTM Appliances Arbitrary Code Execution | Remote |
| [CVE-2022-36883](agent/exploits/cve_2022_36883.py) | Jenkins Git plugin <=4.11.3 missing authorization on notifyCommit (CVE-2022-36883) | Remote |
| [CVE-2022-37601](agent/exploits/cve_2022_37601.py) | assessment of loader-utils CVE-2022-37601, without target I/O | Offline inventory |
| [CVE-2022-42889](agent/exploits/cve_2022_42889.py) | Text4Shell potential package exposure; interpolation path unconfirmed | Remote SBOM / offline inventory |
| [CVE-2022-43939](agent/exploits/cve_2022_43939.py) | Pentaho BA Server non-canonical URL authorization bypass (CVE-2022-43939) | Remote |
| [CVE-2022-44588](agent/exploits/wordpress_readme_2026.py) | Cryptocurrency Widgets Pack (CVE-2022-44588) | Remote |
| [CVE-2022-44727](agent/exploits/cve_2022_44727.py) | PrestaShop lgcookieslaw SQL injection via the __lglaw/lgcookieslaw cookie (CVE-2022-44727) | Remote |
| [CVE-2022-47945](agent/exploits/cve_2022_47945.py) | ThinkPHP before 6.0.14 local file inclusion via lang parameter (CVE-2022-47945) | Remote |

</details>

<details><summary><b>2021 — 14 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2021-21311](agent/exploits/cve_2021_21311.py) | Adminer before 4.7.9 server-side request forgery (CVE-2021-21311) | Remote |
| [CVE-2021-22941](agent/exploits/cve_2021_22941.py) | Improper Access Control in Citrix ShareFile storage zones controller. | Remote |
| [CVE-2021-24139](agent/exploits/wordpress_readme_2026.py) | Photo Gallery by 10Web (CVE-2021-24139) | Remote |
| [CVE-2021-26086](agent/exploits/cve_2021_26086.py) | Atlassian Jira limited file read via /WEB-INF/web.xml (CVE-2021-26086) | Remote |
| [CVE-2021-29442](agent/exploits/cve_2021_29442.py) | Nacos before 1.4.1 unauthenticated Derby SQL access (CVE-2021-29442) | Remote |
| [CVE-2021-31316](agent/exploits/cve_2021_31316.py) | CentOS Web Panel unauthenticated SQL injection via idsession (CVE-2021-31316) | Remote |
| [CVE-2021-31914](agent/exploits/cve_2021_31914.py) | server-release and Windows assessment for TeamCity CVE-2021-31914 | Offline inventory |
| [CVE-2021-32648](agent/exploits/cve_2021_32648.py) | October CMS password recovery vulnerability: CVE-2021-32648 | Remote |
| [CVE-2021-33044](agent/exploits/cve_2021_33044.py) | Dahua IPC/VTH/VTO devices auth bypass | Remote |
| [CVE-2021-33045](agent/exploits/cve_2021_33045.py) | Dahua devices authentication bypass via loopback login (CVE-2021-33045) | Remote |
| [CVE-2021-40655](agent/exploits/cve_2021_40655.py) | Information disclosure issue exists in D-LINK-DIR-605 B2 | Remote |
| [CVE-2021-43798](agent/exploits/cve_2021_43798.py) | Grafana plugin static-file path traversal arbitrary file read (CVE-2021-43798) | Remote |
| [CVE-2021-44228](agent/exploits/cve_2021_44228.py) | Log4Shell potential log4j-core package exposure; logging path unconfirmed | Remote SBOM / offline inventory |
| [CVE-2021-45328](agent/exploits/cve_2021_45328.py) | Gitea CVE-2021-45328 POTENTIAL EXPOSURE | Remote |

</details>

<details><summary><b>2020 — 5 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2020-1992](agent/exploits/cve_2020_1992.py) | PAN-OS Varrcvr assessment; no remote daemon probe | Offline inventory |
| [CVE-2020-2551](agent/exploits/cve_2020_2551.py) | Unauthenticated RCE In Oracle WebLogic | Remote |
| [CVE-2020-2555](agent/exploits/cve_2020_2555.py) | Oracle WebLogic Server - T3 Deserialization Remote Code Execution (CVE-2020-2555) | Remote |
| [CVE-2020-14644](agent/exploits/cve_2020_14644.py) | WebLogic Remote Command Execution Vulnerability | Remote |
| [CVE-2020-15415](agent/exploits/cve_2020_15415.py) | Remote Command Execution in DrayTek Vigor Routers | Remote |

</details>

<details><summary><b>2019 — 10 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2019-5418](agent/exploits/cve_2019_5418.py) | Ruby on Rails file content disclosure via Accept header (CVE-2019-5418) | Remote |
| [CVE-2019-7193](agent/exploits/cve_2019_7193.py) | QNAP QTS Improper Input Validation Vulnerability | Remote |
| [CVE-2019-9874](agent/exploits/cve_2019_9874.py) | Sitecore Anti-CSRF Unauthenticated Deserialization | Remote |
| [CVE-2019-9880](agent/exploits/cve_2019_9880.py) | WPGraphQL 0.2.3 unauthenticated WordPress user information disclosure (CVE-2019-9880) | Remote |
| [CVE-2019-12989](agent/exploits/cve_2019_12989.py) | Security Vulnerabilities in Citrix CVE-2019-12989 and CVE-2019-12991 | Remote |
| [CVE-2019-12991](agent/exploits/cve_2019_12989.py) | Security Vulnerabilities in Citrix CVE-2019-12989 and CVE-2019-12991 | Remote |
| [CVE-2019-14793](agent/exploits/wordpress_readme_2026.py) | Meta Box (CVE-2019-14793) | Remote |
| [CVE-2019-16278](agent/exploits/cve_2019_16278.py) | NOSTROMO NHTTPD DIRECTORY TRAVERSAL VULNERABILITY | Remote |
| [CVE-2019-19006](agent/exploits/cve_2019_19006.py) | framework-module inventory for FreePBX CVE-2019-19006 | Offline inventory |
| [CVE-2019-19781](agent/exploits/cve_2019_19781.py) | Citrix ADC and Gateway unauthenticated directory traversal (CVE-2019-19781) | Remote |

</details>

<details><summary><b>2018 — 11 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2018-6789](agent/exploits/cve_2018_6789.py) | Exim < 4.90.1 - Remote Code Execution (base64d one-byte overflow) | Remote |
| [CVE-2018-7841](agent/exploits/cve_2018_7841.py) | Schneider Electric U.motion Builder SQL Injection Vulnerability | Remote |
| [CVE-2018-10561](agent/exploits/cve_2018_10561.py) | Dasan GPON Routers Command Injection Vulnerability. | Remote |
| [CVE-2018-10562](agent/exploits/cve_2018_10561.py) | Dasan GPON Routers Command Injection Vulnerability. | Remote |
| [CVE-2018-13382](agent/exploits/cve_2018_13382.py) | An Improper Authorization vulnerability in Fortinet FortiOS: CVE-2018-13382 | Remote |
| [CVE-2018-14558](agent/exploits/cve_2018_14558.py) | Tenda AC7, AC9, and AC10 Routers Command Injection Vulnerability. | Remote |
| [CVE-2018-14667](agent/exploits/cve_2018_14667.py) | Red Hat JBoss RichFaces Framework Expression Language Injection Vulnerability | Remote |
| [CVE-2018-14933](agent/exploits/cve_2018_14933.py) | Remote Command Execution in NUUO NVRmini devices | Remote |
| [CVE-2018-15133](agent/exploits/cve_2018_15133.py) | PHP Laravel Framework 5.5.40 / 5.6.x < 5.6.30 - token Unserialize Remote Command Execution | Remote |
| [CVE-2018-17254](agent/exploits/cve_2018_17254.py) | Joomla! JCK Editor 6.4.4 SQL injection (CVE-2018-17254) | Remote |
| [CVE-2018-19410](agent/exploits/cve_2018_19410.py) | PRTG Network Monitor Authentication Bypass & Local File Inclusion | Remote |

</details>

<details><summary><b>2017 — 6 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2017-0147](agent/exploits/cve_2017_0148.py) | Microsoft Windows SMBv1 - Remote Code Execution (MS17-010 / EternalBlue) | Remote |
| [CVE-2017-0148](agent/exploits/cve_2017_0148.py) | Microsoft Windows SMBv1 - Remote Code Execution (MS17-010 / EternalBlue) | Remote |
| [CVE-2017-3066](agent/exploits/cve_2017_3066.py) | Java deserialization vulnerability in the Apache BlazeDS library in Adobe ColdFusion | Remote |
| [CVE-2017-7921](agent/exploits/cve_2017_7921.py) | Hikvision IP camera improper authentication (CVE-2017-7921) | Remote |
| [CVE-2017-12637](agent/exploits/cve_2017_12637.py) | SAP NetWeaver AS Java scheduler directory traversal (CVE-2017-12637) | Remote |
| [CVE-2017-1000170](agent/exploits/cve_2017_1000170.py) | jqueryFileTree 2.1.5 and older directory traversal (CVE-2017-1000170) | Remote |

</details>

<details><summary><b>2016 — 3 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2016-2386](agent/exploits/cve_2016_2386.py) | SAP NetWeaver SQL Injection Vulnerability | Remote |
| [CVE-2016-3081](agent/exploits/cve_2016_3081.py) | Apache Struts 2 S2-032 remote code execution via OGNL method prefix (CVE-2016-3081) | Remote |
| [CVE-2016-15043](agent/exploits/wordpress_readme_2026.py) | WP Mobile Detector (CVE-2016-15043) | Remote |

</details>

<details><summary><b>2015 — 2 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2015-4852](agent/exploits/cve_2015_4852.py) | Oracle WebLogic Server - T3 Deserialization Remote Code Execution (CVE-2015-4852) | Remote |
| [CVE-2015-5471](agent/exploits/cve_2015_5471.py) | WordPress Swim Team plugin <= 1.44.10777 arbitrary file read (CVE-2015-5471) | Remote |

</details>

<details><summary><b>2014 — 5 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2014-0780](agent/exploits/cve_2014_0780.py) | Indusoft Web Studio Directory Traversal. | Remote |
| [CVE-2014-2120](agent/exploits/cve_2014_2120.py) | Cisco ASA WebVPN Login Page XSS Vulnerability | Remote |
| [CVE-2014-2383](agent/exploits/cve_2014_2383.py) | dompdf before 0.6.1 local file inclusion via php:// wrapper (CVE-2014-2383) | Remote |
| [CVE-2014-5181](agent/exploits/cve_2014_5181.py) | Last.fm Rotation WordPress plugin local file inclusion (CVE-2014-5181) | Remote |
| [CVE-2014-7169](agent/exploits/cve_2014_7169.py) | GNU Bourne-Again Shell (Bash) Arbitrary Code Execution Vulnerability. | Remote |

</details>

<details><summary><b>2012 — 1 CVE</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2012-1823](agent/exploits/cve_2012_1823.py) | PHP-CGI query string argument injection | Remote |

</details>

<details><summary><b>2010 — 2 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2010-2507](agent/exploits/cve_2010_2507.py) | Joomla Picasa2Gallery component 1.2.8 and earlier directory traversal (CVE-2010-2507) | Remote |
| [CVE-2010-4344](agent/exploits/cve_2010_4344.py) | Exim < 4.70 - Remote Code Execution (string_format heap overflow) | Remote |

</details>

### Non-CVE exposure checks

| Check | Detector |
| --- | --- |
| Unauthenticated Android Debug Bridge (ADB) | [exposed_adb.py](agent/exploits/exposed_adb.py) |
| Exposed Docker Registry API | [exposed_docker_resgistry_api.py](agent/exploits/exposed_docker_resgistry_api.py) |
| Jetpack contact-form data exposure | [jetpack_version_detection.py](agent/exploits/jetpack_version_detection.py) |

### Coverage notes

- A missing finding does not establish that a target is patched. Installed
  hotfixes, backports and effective mitigations may require authenticated
  verification.
- Remote checks use read-only service metadata. Some findings explicitly leave
  exploitability unconfirmed.
- Credential-bypass checks that mint a token from a public in-product secret
  confirm it is accepted using non-sensitive identity or RBAC endpoints. These
  checks do not read user records, API tokens or per-user data and do not
  change state. The inspected bodies are limited to the forged token's own
  echoed claims, the non-sensitive RBAC role listing (checked only for shape
  and never reported), and, for an elevated-role proof, a missing-resource
  response envelope that cannot contain application data. Default-credential
  checks read the affected account's own metadata and are documented in their
  modules.
- Java Shell library checks read the documented public Actuator application
  SBOM when available and also accept owner-supplied offline inventory. Findings
  report potential package exposure with runtime prerequisites unconfirmed. See
  [boundaries and evidence schema](docs/shell-java-libraries.md).
- Inventory assessments cover only the supplied evidence; they do not collect
  inventory, authenticate, or verify operator assertions.
- The list is derived from the detector registry and the inventory assessor
  modules. Add new detectors to both the code and this list.

## Contributing

We welcome contributions from the community. Whether you are submitting bug
reports, feature requests or code contributions, please
[open an issue](https://github.com/Ostorlab/agent_asteroid/issues/new) or
[submit a pull request](https://github.com/Ostorlab/agent_asteroid/pulls).

## Join the Community

Follow us on [Twitter](https://twitter.com/ostorlab) and join the
[Discord server](https://discord.gg/ostorlab).

## License

Apache 2.0. See [LICENSE](LICENSE).
