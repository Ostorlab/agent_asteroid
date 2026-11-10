<h1 align="center">Agent Asteroid</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_asteroid">
<img src="https://img.shields.io/github/stars/ostorlab/agent_asteroid">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

**Agent Asteroid is an open-source scanner for known, remotely exploitable vulnerabilities.**
It checks internet-facing IP addresses, domains and links for the products and
versions associated with those vulnerabilities, using read-only probes that do
not exploit, upload payloads or change configuration. It is also one of the
scanners in the [Ostorlab KEV agent group](https://github.com/Ostorlab/KEV),
which adds Nuclei, Tsunami, Nmap and Metasploit coverage.

A credential-bypass check that confirms a public in-product secret is accepted
submits only locally minted bearer tokens for a fabricated identity — asserting
at most a read-only `user:read` claim — to non-sensitive identity or RBAC
endpoints. Default-credential checks, such as the MLflow CVE-2026-2635 detector,
read the affected account's own metadata and document that in their module.

| Coverage | Count |
| --- | ---: |
| CVEs checked automatically during an `oxo` scan | 374 |
| Additional CVEs assessed from owner-supplied inventory | 85 |
| **Unique CVEs covered** | **459** |
| Non-CVE exposure checks | 3 |

_Coverage snapshot: 10 November 2026._

A finding means the observed evidence matches a known-vulnerable condition. A
clean scan does not prove a target is patched: backports, hotfixes,
configuration and authenticated-only checks can require local verification.

## What it detects

- **Remote checks (374 CVEs).** Version, banner, metadata and behaviour checks
  for exposed services: web applications, VPNs, firewalls, mail servers,
  databases, network appliances and developer tools.
- **Offline inventory assessments (85 CVEs).** For issues that anonymous network
  metadata cannot establish, `python -m agent.utils.inventory` assesses a
  normalized inventory JSON supplied by the owner. It makes no network requests.
- **Non-CVE exposure checks (3).** Unauthenticated ADB, the Docker Registry API,
  and the Jetpack contact-form data exposure.

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

Missing or ambiguous prerequisites produce `inconclusive`. `not_matched`
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

### Detected CVEs

The table combines the 374 remote checks with the 85 inventory-only assessments:
**459 unique CVEs**. The Detector column says whether a CVE runs during a normal
scan or needs the offline inventory assessor.

| Year | Remote | Offline inventory | Total |
| --- | ---: | ---: | ---: |
| 2026 | 179 | 64 | 243 |
| 2025 | 62 | 11 | 73 |
| 2024 | 74 | 4 | 78 |
| 2023 | 18 | 1 | 19 |
| 2022 | 5 | 2 | 7 |
| 2021 | 6 | 1 | 7 |
| 2020 | 4 | 1 | 5 |
| 2019 | 6 | 1 | 7 |
| 2018 | 10 | 0 | 10 |
| 2017 | 3 | 0 | 3 |
| 2016 | 2 | 0 | 2 |
| 2015 | 1 | 0 | 1 |
| 2014 | 3 | 0 | 3 |
| 2010 | 1 | 0 | 1 |
| **Total** | **374** | **85** | **459** |

<details><summary><b>2026 — 243 CVEs</b></summary>

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
| [CVE-2026-0920](agent/exploits/wordpress_readme_2026.py) | LA-Studio Element Kit for Elementor (CVE-2026-0920) | Remote |
| [CVE-2026-0926](agent/exploits/wordpress_readme_2026.py) | Prodigy Commerce (CVE-2026-0926) | Remote |
| [CVE-2026-1306](agent/exploits/wordpress_readme_2026.py) | midi-Synth (CVE-2026-1306) | Remote |
| [CVE-2026-1357](agent/exploits/wordpress_readme_2026.py) | WPvivid Backup & Migration (CVE-2026-1357) | Remote |
| [CVE-2026-1405](agent/exploits/wordpress_readme_2026.py) | Slider Future (CVE-2026-1405) | Remote |
| [CVE-2026-1492](agent/exploits/wordpress_readme_2026.py) | User Registration & Membership (CVE-2026-1492) | Remote |
| [CVE-2026-1830](agent/exploits/wordpress_readme_2026.py) | Quick Playground (CVE-2026-1830) | Remote |
| [CVE-2026-1980](agent/exploits/wordpress_readme_2026.py) | WPBookit (CVE-2026-1980) | Remote |
| [CVE-2026-2416](agent/exploits/wordpress_readme_2026.py) | Geo Mashup (CVE-2026-2416) | Remote |
| [CVE-2026-2635](agent/exploits/cve_2026_2635.py) | MLflow default administrator credential permits account read access | Remote |
| [CVE-2026-3296](agent/exploits/wordpress_readme_2026.py) | Everest Forms – Contact Form, Payment Form, Quiz, Survey & Custom Form Builder (CVE-2026-3296) | Remote |
| [CVE-2026-3584](agent/exploits/wordpress_readme_2026.py) | Kali Forms (CVE-2026-3584) | Remote |
| [CVE-2026-3593](agent/exploits/cve_2026_3593.py) | BIND DoH assessment; no memory-corruption probe | Offline inventory |
| [CVE-2026-3630](agent/exploits/cve_2026_3630.py) | CVE-2026-3630 | Offline inventory |
| [CVE-2026-3844](agent/exploits/wordpress_readme_2026.py) | Breeze Cache (CVE-2026-3844) | Remote |
| [CVE-2026-3891](agent/exploits/wordpress_readme_2026.py) | Pix for WooCommerce (CVE-2026-3891) | Remote |
| [CVE-2026-4060](agent/exploits/wordpress_readme_2026.py) | Geo Mashup (CVE-2026-4060) | Remote |
| [CVE-2026-4257](agent/exploits/wordpress_readme_2026.py) | Contact Form by Supsystic (CVE-2026-4257) | Remote |
| [CVE-2026-4800](agent/exploits/cve_2026_4800.py) | assessment of lodash template imports, without target I/O | Offline inventory |
| [CVE-2026-4858](agent/exploits/cve_2026_4858.py) | Mattermost CVE-2026-4858 (advertised release) | Remote |
| [CVE-2026-6516](agent/exploits/cve_2026_6516.py) | CVE-2026-6516 | Offline inventory |
| [CVE-2026-7873](agent/exploits/cve_2026_7873.py) | Langflow CVE-2026-7873 code-validation RCE | Remote |
| [CVE-2026-8024](agent/exploits/cve_2026_8024.py) | CVE-2026-8024 | Offline inventory |
| [CVE-2026-8181](agent/exploits/wordpress_readme_2026.py) | Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) (CVE-2026-8181) | Remote |
| [CVE-2026-8364](agent/exploits/cve_2026_8364.py) | assessment of Triofox Server Agent CVE-2026-8364 | Offline inventory |
| [CVE-2026-8644](agent/exploits/cve_2026_8644.py) | CVE-2026-8644 | Offline inventory |
| [CVE-2026-8713](agent/exploits/cve_2026_8713.py) | Avada Builder assessment for CVE-2026-8713; no remote probe | Offline inventory |
| [CVE-2026-8763](agent/exploits/cve_2026_8763.py) | assessment of CVE-2026-8763; no remote detector or target I/O | Offline inventory |
| [CVE-2026-9006](agent/exploits/cve_2026_9006.py) | CVE-2026-9006 | Offline inventory |
| [CVE-2026-9103](agent/exploits/cve_2026_9103.py) | Langflow CVE-2026-9103 auto-login token issuance | Remote |
| [CVE-2026-9290](agent/exploits/wordpress_readme_2026.py) | WP User Manager – User Profile Builder & Membership (CVE-2026-9290) | Remote |
| [CVE-2026-9319](agent/exploits/cve_2026_9319.py) | CVE-2026-9319 | Offline inventory |
| [CVE-2026-9848](agent/exploits/wordpress_readme_2026.py) | Customer Support Ticket System & Helpdesk (CVE-2026-9848) | Remote |
| [CVE-2026-10580](agent/exploits/wordpress_readme_2026.py) | Hippoo Mobile App for WooCommerce (CVE-2026-10580) | Remote |
| [CVE-2026-11374](agent/exploits/cve_2026_11374.py) | AD360 predictable SSO tickets | Offline inventory |
| [CVE-2026-11387](agent/exploits/wordpress_readme_2026.py) | SMS Alert (CVE-2026-11387) | Remote |
| [CVE-2026-11541](agent/exploits/cve_2026_11541.py) | CVE-2026-11541 | Offline inventory |
| [CVE-2026-11546](agent/exploits/cve_2026_11546.py) | CVE-2026-11546 | Offline inventory |
| [CVE-2026-11714](agent/exploits/cve_2026_11714.py) | CVE-2026-11714 | Offline inventory |
| [CVE-2026-12394](agent/exploits/wordpress_readme_2026.py) | MemberGlut (CVE-2026-12394) | Remote |
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
| [CVE-2026-20093](agent/exploits/cve_2026_20093.py) | Cisco IMC CVE-2026-20093 owner inventory; no password requests | Offline inventory |
| [CVE-2026-20127](agent/exploits/cve_2026_20127.py) | Cisco Catalyst SD-WAN CVE-2026-20127 | Remote |
| [CVE-2026-20131](agent/exploits/cve_2026_20131.py) | Cisco Secure FMC CVE-2026-20131 | Remote |
| [CVE-2026-20160](agent/exploits/cve_2026_20160.py) | assessment for Cisco SSM On-Prem CVE-2026-20160 | Offline inventory |
| [CVE-2026-20896](agent/exploits/cve_2026_20896.py) | Gitea Docker proxy authentication | Offline inventory |
| [CVE-2026-21445](agent/exploits/cve_2026_21445.py) | Langflow CVE-2026-21445 monitoring authentication bypass | Remote |
| [CVE-2026-21589](agent/exploits/cve_2026_21589.py) | Unauthenticated arbitrary file read in Atlassian Data Center static resources | Remote |
| [CVE-2026-21643](agent/exploits/cve_2026_21643.py) | Fortinet FortiClient EMS CVE-2026-21643 | Remote |
| [CVE-2026-21858](agent/exploits/cve_2026_21858.py) | n8n CVE-2026-21858 unauthenticated file access | Remote |
| [CVE-2026-21877](agent/exploits/cve_2026_21877.py) | n8n CVE-2026-21877 authenticated RCE | Remote |
| [CVE-2026-22769](agent/exploits/cve_2026_22769.py) | CVE-2026-22769 Dell RecoverPoint for Virtual Machines hardcoded credentials | Remote |
| [CVE-2026-22778](agent/exploits/cve_2026_22778.py) | vLLM CVE-2026-22778 video-processing RCE chain | Remote |
| [CVE-2026-23696](agent/exploits/cve_2026_23696.py) | Windmill CVE-2026-23696 folder SQL injection | Remote |
| [CVE-2026-23760](agent/exploits/cve_2026_23760.py) | SmarterTools SmarterMail CVE-2026-23760 | Remote |
| [CVE-2026-24061](agent/exploits/cve_2026_24061.py) | CVE-2026-24061 GNU Inetutils telnetd | Remote |
| [CVE-2026-24423](agent/exploits/cve_2026_24423.py) | SmarterTools SmarterMail CVE-2026-24423 | Remote |
| [CVE-2026-24898](agent/exploits/cve_2026_24898.py) | OpenEMR CVE-2026-24898 MedEx token disclosure | Remote |
| [CVE-2026-25512](agent/exploits/cve_2026_25512.py) | Group-Office CVE-2026-25512 TNEF command injection | Remote |
| [CVE-2026-27464](agent/exploits/cve_2026_27464.py) | Metabase CVE-2026-27464 notification template evaluation | Remote |
| [CVE-2026-27771](agent/exploits/cve_2026_27771.py) | Gitea CVE-2026-27771 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-28323](agent/exploits/cve_2026_28323.py) | SAML applicability for Web Help Desk CVE-2026-28323 | Offline inventory |
| [CVE-2026-29000](agent/exploits/cve_2026_29000.py) | assessment of pac4j-jwt CVE-2026-29000, without target I/O | Offline inventory |
| [CVE-2026-29145](agent/exploits/cve_2026_29145.py) | Tomcat OCSP CVE-2026-29145 | Offline inventory |
| [CVE-2026-32710](agent/exploits/cve_2026_32710.py) | MariaDB JSON_SCHEMA_VALID memory corruption | Remote |
| [CVE-2026-33017](agent/exploits/cve_2026_33017.py) | Langflow CVE-2026-33017 | Remote |
| [CVE-2026-33466](agent/exploits/cve_2026_33466.py) | Logstash GeoIP CVE-2026-33466 (advertised release) | Remote |
| [CVE-2026-33725](agent/exploits/cve_2026_33725.py) | Metabase CVE-2026-33725 Enterprise serialization import code execution | Remote |
| [CVE-2026-34156](agent/exploits/cve_2026_34156.py) | NocoBase CVE-2026-34156 workflow sandbox escape | Remote |
| [CVE-2026-34976](agent/exploits/cve_2026_34976.py) | Dgraph CVE-2026-34976 restoreTenant authorization bypass | Remote |
| [CVE-2026-35616](agent/exploits/cve_2026_35616.py) | Fortinet FortiClient EMS CVE-2026-35616 | Remote |
| [CVE-2026-39468](agent/exploits/wordpress_readme_2026.py) | Meta Box – WordPress Custom Fields Framework (CVE-2026-39468) | Remote |
| [CVE-2026-40281](agent/exploits/cve_2026_40281.py) | Gotenberg CVE-2026-40281 ExifTool argument injection | Remote |
| [CVE-2026-41492](agent/exploits/cve_2026_41492.py) | Dgraph CVE-2026-41492 admin token disclosure | Remote |
| [CVE-2026-41940](agent/exploits/cve_2026_41940.py) | cPanel & WHM CVE-2026-41940 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-42055](agent/exploits/cve_2026_42055.py) | NGINX upstream CVE-2026-42055 | Offline inventory |
| [CVE-2026-42530](agent/exploits/cve_2026_42530.py) | NGINX HTTP/3 CVE-2026-42530 | Offline inventory |
| [CVE-2026-42533](agent/exploits/cve_2026_42533.py) | NGINX map/regex CVE-2026-42533 | Offline inventory |
| [CVE-2026-42589](agent/exploits/cve_2026_42589.py) | Gotenberg CVE-2026-42589 ExifTool metadata-key injection | Remote |
| [CVE-2026-42647](agent/exploits/wordpress_readme_2026.py) | JoomSport (CVE-2026-42647) | Remote |
| [CVE-2026-42796](agent/exploits/cve_2026_42796.py) | Arelle CVE-2026-42796 remote plugin loading | Remote |
| [CVE-2026-42945](agent/exploits/cve_2026_42945.py) | NGINX rewrite CVE-2026-42945 | Offline inventory |
| [CVE-2026-45674](agent/exploits/cve_2026_45674.py) | assessment of Netty DNS CVE-2026-45674, without target I/O | Offline inventory |
| [CVE-2026-45695](agent/exploits/cve_2026_45695.py) | Kopia CVE-2026-45695 SSH command injection | Remote |
| [CVE-2026-46339](agent/exploits/cve_2026_46339.py) | 9Router CVE-2026-46339 MCP command execution | Remote |
| [CVE-2026-46442](agent/exploits/cve_2026_46442.py) | Flowise CVE-2026-46442 authenticated Custom Function RCE | Remote |
| [CVE-2026-48360](agent/exploits/cve_2026_48360.py) | assessment of Adobe Connect clients, CVE-2026-48360 | Offline inventory |
| [CVE-2026-48558](agent/exploits/cve_2026_48558.py) | SimpleHelp CVE-2026-48558 OIDC bypass | Remote |
| [CVE-2026-49772](agent/exploits/wordpress_readme_2026.py) | The Events Calendar (CVE-2026-49772) | Remote |
| [CVE-2026-49869](agent/exploits/cve_2026_49869.py) | Kestra OSS CVE-2026-49869 | Remote |
| [CVE-2026-50751](agent/exploits/cve_2026_50751.py) | Check Point Quantum Security Gateway CVE-2026-50751 | Remote |
| [CVE-2026-52715](agent/exploits/wordpress_readme_2026.py) | GEO my WordPress (CVE-2026-52715) | Remote |
| [CVE-2026-53576](agent/exploits/cve_2026_53576.py) | Kestra OSS CVE-2026-53576 authentication bypass/RCE | Remote |
| [CVE-2026-53753](agent/exploits/cve_2026_53753.py) | Crawl4AI CVE-2026-53753 computed-field sandbox escape | Remote |
| [CVE-2026-54069](agent/exploits/cve_2026_54069.py) | SiYuan CVE-2026-54069 extension-origin authentication bypass | Remote |
| [CVE-2026-54836](agent/exploits/wordpress_readme_2026.py) | YMC Filter / Filter & Grids (CVE-2026-54836) | Remote |
| [CVE-2026-55450](agent/exploits/cve_2026_55450.py) | Langflow CVE-2026-55450 unauthenticated upload | Remote |
| [CVE-2026-56265](agent/exploits/cve_2026_56265.py) | Crawl4AI CVE-2026-56265 default JWT signing key | Remote |
| [CVE-2026-58062](agent/exploits/cve_2026_58062.py) | assessment of CVE-2026-58062; no remote detector or target I/O | Offline inventory |
| [CVE-2026-58138](agent/exploits/cve_2026_58138.py) | Conductor CVE-2026-58138 script evaluation | Remote |
| [CVE-2026-59309](agent/exploits/cve_2026_59309.py) | vCenter CVE-2026-59309 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-59310](agent/exploits/cve_2026_59310.py) | vCenter CVE-2026-59310 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-59650](agent/exploits/cve_2026_59650.py) | assessment of CVE-2026-59650; no remote detector or target I/O | Offline inventory |
| [CVE-2026-59774](agent/exploits/cve_2026_59774.py) | Gitea CVE-2026-59774 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-59822](agent/exploits/cve_2026_59822.py) | LiteLLM CVE-2026-59822 | Remote |
| [CVE-2026-59826](agent/exploits/cve_2026_59826.py) | Metabase CVE-2026-59826 H2 database creation code execution | Remote |
| [CVE-2026-59827](agent/exploits/cve_2026_59827.py) | Metabase CVE-2026-59827 H2 query-result deserialization | Remote |
| [CVE-2026-60004](agent/exploits/cve_2026_60004.py) | Gitea CVE-2026-60004 POTENTIAL EXPOSURE | Remote |
| [CVE-2026-63077](agent/exploits/cve_2026_63077.py) | JetBrains TeamCity CVE-2026-63077 | Remote |
| [CVE-2026-64849](agent/exploits/cve_2026_64849.py) | MLflow CVE-2026-64849 webhook SSRF | Remote |
| [CVE-2026-65182](agent/exploits/cve_2026_65182.py) | Tomcat constraint ordering CVE-2026-65182 | Offline inventory |
| [CVE-2026-65555](agent/exploits/wordpress_readme_2026.py) | Uncanny Toolkit for LearnDash (CVE-2026-65555) | Remote |
| [CVE-2026-65637](agent/exploits/cve_2026_65637.py) | Tomcat HTTP/2 strict-SNI CVE-2026-65637 | Offline inventory |
| [CVE-2026-65905](agent/exploits/cve_2026_65905.py) | Tomcat DIGEST replay CVE-2026-65905 | Offline inventory |
| [CVE-2026-65906](agent/exploits/cve_2026_65906.py) | TeamCity CVE-2026-65906 (advertised release) | Remote |
| [CVE-2026-65907](agent/exploits/cve_2026_65907.py) | TeamCity CVE-2026-65907 (advertised release) | Remote |
| [CVE-2026-67276](agent/exploits/cve_2026_67276.py) | RouterOS SSH RSA CVE-2026-67276 | Offline inventory |
| [CVE-2026-68525](agent/exploits/cve_2026_68525.py) | Tomcat FORM constraints CVE-2026-68525 | Offline inventory |
| [CVE-2026-69084](agent/exploits/cve_2026_69084.py) | SiYuan CVE-2026-69084 publish-mode SQL execution | Remote |
| [CVE-2026-69085](agent/exploits/cve_2026_69085.py) | SiYuan CVE-2026-69085 searchDocs SQL injection | Remote |
| [CVE-2026-69251](agent/exploits/cve_2026_69251.py) | Flowise CVE-2026-69251 TypeORM RCE | Remote |
| [CVE-2026-71495](agent/exploits/cve_2026_71495.py) | Wanderer unauthenticated server-side request forgery (CVE-2026-71495) | Remote |
| [CVE-2026-72898](agent/exploits/cve_2026_72898.py) | Metabase CVE-2026-72898 password-reset SQL injection | Remote |
| [CVE-2026-72899](agent/exploits/cve_2026_72899.py) | Metabase CVE-2026-72899 public-link field-filter SQL injection | Remote |
| [CVE-2026-72900](agent/exploits/cve_2026_72900.py) | Metabase CVE-2026-72900 audit database authorization bypass | Remote |
| [CVE-2026-73453](agent/exploits/cve_2026_73453.py) | Arista EOS P4Runtime CVE-2026-73453 | Offline inventory |
| [CVE-2026-73577](agent/exploits/cve_2026_73577.py) | Apache OFBiz CVE-2026-73577 unauthenticated path-suffix view authorization bypass | Remote |
| [CVE-2026-74849](agent/exploits/cve_2026_74849.py) | CVE-2026-74849 | Offline inventory |
| [CVE-2026-75595](agent/exploits/cve_2026_75595.py) | assessment of Netty SNI CVE-2026-75595, without target I/O | Offline inventory |
| [CVE-2026-76461](agent/exploits/cve_2026_76461.py) | Cisco Secure Email Gateway CVE-2026-76461 | Offline inventory |
| [CVE-2026-76465](agent/exploits/cve_2026_76465.py) | MPLS OAM CVE-2026-76465 owner inventory; no packet probes | Offline inventory |
| [CVE-2026-76471](agent/exploits/cve_2026_76471.py) | NX-API CVE-2026-76471 owner inventory; no crafted HTTP requests | Offline inventory |
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
| [CVE-2026-84411](agent/exploits/cve_2026_84411.py) | RouterOS web-management CVE-2026-84411 | Offline inventory |
| [CVE-2026-85595](agent/exploits/cve_2026_85595.py) | Traefik CVE-2026-85595 digestAuth bypass | Remote |
| [CVE-2026-85714](agent/exploits/cve_2026_85714.py) | Stirling-PDF CVE-2026-85714 H2 import RCE | Remote |
| [CVE-2026-86005](agent/exploits/cve_2026_86005.py) | Chartbrew CVE-2026-86005 unauthenticated BullMQ dashboard | Remote |
| [CVE-2026-87719](agent/exploits/cve_2026_87719.py) | GitLab Duo Chat CVE-2026-87719 | Offline inventory |
| [CVE-2026-88771](agent/exploits/cve_2026_88771.py) | NetScaler CVE-2026-88771 | Remote |
| [CVE-2026-88772](agent/exploits/cve_2026_88772.py) | NetScaler CVE-2026-88772 | Remote |
| [CVE-2026-89078](agent/exploits/cve_2026_89078.py) | CVE-2026-89078 | Offline inventory |
| [CVE-2026-90436](agent/exploits/cve_2026_90436.py) | Apache Axis 1.x CVE-2026-90436 unauthenticated SOAP fault class-loading RCE | Remote |
| [CVE-2026-93479](agent/exploits/cve_2026_93479.py) | NGINX root/access-log CVE-2026-93479 | Offline inventory |
| [CVE-2026-93577](agent/exploits/cve_2026_93577.py) | CVE-2026-93577 | Offline inventory |
| [CVE-2026-93674](agent/exploits/cve_2026_93674.py) | Langflow CVE-2026-93674 import-validation RCE | Remote |
| [CVE-2026-96652](agent/exploits/cve_2026_96652.py) | Plex Media Server CVE-2026-96652/96654/96655/96656 chain | Remote |
| [CVE-2026-96654](agent/exploits/cve_2026_96652.py) | Plex Media Server CVE-2026-96652/96654/96655/96656 chain | Remote |
| [CVE-2026-96655](agent/exploits/cve_2026_96652.py) | Plex Media Server CVE-2026-96652/96654/96655/96656 chain | Remote |
| [CVE-2026-96656](agent/exploits/cve_2026_96652.py) | Plex Media Server CVE-2026-96652/96654/96655/96656 chain | Remote |
| [CVE-2026-97229](agent/exploits/cve_2026_97229.py) | CVE-2026-97229 | Offline inventory |
| [CVE-2026-100109](agent/exploits/wordpress_readme_2026.py) | Security For WooCommerce (CVE-2026-100109) | Remote |
| [CVE-2026-102084](agent/exploits/cve_2026_102084.py) | Junos ADVPN CVE-2026-102084 | Offline inventory |
| [CVE-2026-102610](agent/exploits/cve_2026_102610.py) | fast-agent MCP server unauthenticated remote agent access (CVE-2026-102610) | Remote |
| [CVE-2026-102894](agent/exploits/cve_2026_102894.py) | GPUStack CVE-2026-102894 unauthenticated SAML callback account takeover | Remote |
| [CVE-2026-102895](agent/exploits/cve_2026_102895.py) | GPUStack CVE-2026-102895 unauthenticated administrator bypass | Remote |
| [CVE-2026-103956](agent/exploits/cve_2026_103956.py) | Loom CVE-2026-103956 authentication bypass | Remote |
| [CVE-2026-104203](agent/exploits/cve_2026_104203.py) | Traccar CVE-2026-104203 media authentication bypass via semicolon path parameter | Remote |
| [CVE-2026-104608](agent/exploits/cve_2026_104608.py) | GitHub Enterprise Server CVE-2026-104608 (babeld use-after-free RCE) and CVE-2026-110288 (ChatOps CSRF); exploitability unconfirmed | Remote |
| [CVE-2026-104935](agent/exploits/cve_2026_104935.py) | Ivanti Connect Secure CVE-2026-104935 | Remote |
| [CVE-2026-105740](agent/exploits/cve_2026_105740.py) | Langflow CVE-2026-105740 authenticated MCP RCE | Remote |
| [CVE-2026-107406](agent/exploits/cve_2026_107406.py) | assessment of NetScaler SAML potential exposure | Offline inventory |
| [CVE-2026-107656](agent/exploits/cve_2026_107656.py) | FortiSandbox GUI exposure assessment with edition-specific bounds | Offline inventory |
| [CVE-2026-107861](agent/exploits/kiloview_2026_10.py) | Kiloview E3 October 2026 critical command injection | Remote |
| [CVE-2026-109122](agent/exploits/kiloview_2026_10.py) | Kiloview E3 October 2026 critical command injection | Remote |
| [CVE-2026-109618](agent/exploits/cve_2026_109618.py) | PHP Core CVE-2026-109618 Session Upload Progress Use-After-Free | Remote |
| [CVE-2026-109619](agent/exploits/cve_2026_109619.py) | PHP Core CVE-2026-109619 SAPI Multipart Request Handling | Remote |
| [CVE-2026-110243](agent/exploits/kiloview_2026_10.py) | Kiloview E3 October 2026 critical command injection | Remote |
| [CVE-2026-110264](agent/exploits/cve_2026_110264.py) | CVE-2026-110264 | Offline inventory |
| [CVE-2026-110288](agent/exploits/cve_2026_104608.py) | GitHub Enterprise Server CVE-2026-104608 (babeld use-after-free RCE) and CVE-2026-110288 (ChatOps CSRF); exploitability unconfirmed | Remote |
| [CVE-2026-110447](agent/exploits/cve_2026_110447.py) | Collabora built-in CODE CVE-2026-110447 | Remote |
| [CVE-2026-111497](agent/exploits/cve_2026_111497.py) | Node.js Brotli Decoder Out-of-Bounds Write (Node2Shell) | Remote + inventory |
| [CVE-2026-114612](agent/exploits/cve_2026_114612.py) | LiteLLM CVE-2026-114612 | Remote |
| [CVE-2026-114625](agent/exploits/cve_2026_114625.py) | CVE-2026-114625 | Offline inventory |
| [CVE-2026-115547](agent/exploits/cve_2026_115547.py) | Okta Access Gateway CVE-2026-115547 | Remote |
| [CVE-2026-115560](agent/exploits/cve_2026_115560.py) | CVE-2026-115560 | Offline inventory |
| [CVE-2026-118623](agent/exploits/cve_2026_118623.py) | MLflow CVE-2026-118623 pickle evaluation artifact deserialization RCE | Remote |
| [CVE-2026-118627](agent/exploits/cve_2026_118627.py) | MLflow CVE-2026-118627 SHAP explainer deserialization RCE | Remote |
| [CVE-2026-118628](agent/exploits/cve_2026_118628.py) | MLflow CVE-2026-118628 get-artifacts SSRF information disclosure | Remote |
| [CVE-2026-119481](agent/exploits/wordpress_readme_2026.py) | JetFormBuilder (CVE-2026-119481) | Remote |
| [CVE-2026-119923](agent/exploits/cve_2026_119923.py) | Babelfish for PostgreSQL TDS endpoint (CVE-2026-119923 / CVE-2026-119924; running release not observable) | Remote |
| [CVE-2026-119924](agent/exploits/cve_2026_119923.py) | Babelfish for PostgreSQL TDS endpoint (CVE-2026-119923 / CVE-2026-119924; running release not observable) | Remote |
| [CVE-2026-119977](agent/exploits/cve_2026_119977.py) | WordPress Core CVE-2026-119977 upgrade-window remote code execution | Remote |
| [CVE-2026-120656](agent/exploits/cve_2026_120656.py) | OpenKruise unauthenticated pprof debug endpoint exposed (CVE-2026-120656) | Remote |
| [CVE-2026-123158](agent/exploits/cve_2026_123158.py) | OpenSSH Password Authentication Bypass on musl libc (CVE-2026-123158, 'sshole') | Remote |
| [CVE-2026-123201](agent/exploits/cve_2026_123201.py) | bukuserver unauthenticated server-side request forgery (CVE-2026-123201) | Remote |
| [CVE-2026-125370](agent/exploits/cve_2026_125370.py) | Kubero public fallback JWT secret authentication bypass (CVE-2026-125370) | Remote |

</details>

<details><summary><b>2025 — 73 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2025-0282](agent/exploits/cve_2025_0282.py) | Ivanti Connect Secure Buffer Overflow | Remote |
| [CVE-2025-0674](agent/exploits/cve_2025_0674.py) | Elber ESE DVB-S/S2 Authentication Bypass | Remote |
| [CVE-2025-0890](agent/exploits/cve_2025_0890.py) | Zyxel VMG4325-B10A Default Credentials Leading to RCE | Remote |
| [CVE-2025-2505](agent/exploits/wordpress_readme_2026.py) | Age Gate (CVE-2025-2505) | Remote |
| [CVE-2025-3085](agent/exploits/cve_2025_3085.py) | CVE-2025-3085 | Offline inventory |
| [CVE-2025-3248](agent/exploits/cve_2025_3248.py) | Langflow CVE-2025-3248 | Remote |
| [CVE-2025-4322](agent/exploits/cve_2025_4322.py) | Motors Theme <= 5.6.67 - Unauthenticated Privilege Escalation via Password Update/Account Takeover | Remote |
| [CVE-2025-5777](agent/exploits/cve_2025_5777.py) | NetScaler CVE-2025-5777 | Remote |
| [CVE-2025-7659](agent/exploits/cve_2025_7659.py) | GitLab Web IDE CVE-2025-7659 | Offline inventory |
| [CVE-2025-9209](agent/exploits/wordpress_readme_2026.py) | RestroPress – Online Food Ordering System (CVE-2025-9209) | Remote |
| [CVE-2025-10035](agent/exploits/cve_2025_10035.py) | GoAnywhere MFT License Servlet Deserialization Vulnerability | Remote |
| [CVE-2025-11693](agent/exploits/wordpress_readme_2026.py) | Export WP Page to Static HTML & PDF (CVE-2025-11693) | Remote |
| [CVE-2025-12536](agent/exploits/wordpress_readme_2026.py) | SureForms – Contact Form, Payment Form & Other Custom Form Builder (CVE-2025-12536) | Remote |
| [CVE-2025-12841](agent/exploits/wordpress_readme_2026.py) | Bookit (CVE-2025-12841) | Remote |
| [CVE-2025-13342](agent/exploits/wordpress_readme_2026.py) | Frontend Admin by DynamiApps (CVE-2025-13342) | Remote |
| [CVE-2025-13390](agent/exploits/wordpress_readme_2026.py) | WP Directory Kit (CVE-2025-13390) | Remote |
| [CVE-2025-13761](agent/exploits/cve_2025_13761.py) | GitLab browser CVE-2025-13761 | Offline inventory |
| [CVE-2025-13773](agent/exploits/wordpress_readme_2026.py) | Print Invoice & Delivery Notes for WooCommerce (CVE-2025-13773) | Remote |
| [CVE-2025-13801](agent/exploits/wordpress_readme_2026.py) | Yoco Payments (CVE-2025-13801) | Remote |
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
| [CVE-2025-24893](agent/exploits/cve_2025_24893.py) | XWiki Solr UI CVE-2025-24893 | Remote |
| [CVE-2025-25257](agent/exploits/cve_2025_25257.py) | Fortinet FortiWeb CVE-2025-25257 | Remote |
| [CVE-2025-27364](agent/exploits/cve_2025_27364.py) | MITRE Caldera Agent Dynamic Compilation RCE | Remote |
| [CVE-2025-31161](agent/exploits/cve_2025_31161.py) | CrushFTP CVE-2025-31161 | Remote |
| [CVE-2025-31324](agent/exploits/cve_2025_31324.py) | SAP NetWeaver Visual Composer CVE-2025-31324 | Remote |
| [CVE-2025-32432](agent/exploits/cve_2025_32432.py) | Craft CMS CVE-2025-32432 | Remote |
| [CVE-2025-32433](agent/exploits/cve_2025_32433.py) | Erlang/OTP SSH Pre-Auth Command Execution | Remote |
| [CVE-2025-32756](agent/exploits/cve_2025_32756.py) | Fortinet Multiple Products - Stack-Based Overflow (CVE-2025-32756) | Remote |
| [CVE-2025-32966](agent/exploits/cve_2025_32966.py) | DataEase CVE-2025-32966 JDBC code execution | Remote |
| [CVE-2025-34030](agent/exploits/cve_2025_34030.py) | sar2html CVE-2025-34030 command injection | Remote |
| [CVE-2025-37164](agent/exploits/cve_2025_37164.py) | HPE OneView CVE-2025-37164 | Remote |
| [CVE-2025-40551](agent/exploits/cve_2025_40551.py) | SolarWinds Web Help Desk CVE-2025-40551 | Remote |
| [CVE-2025-47577](agent/exploits/wordpress_readme_2026.py) | TI WooCommerce Wishlist (CVE-2025-47577) | Remote |
| [CVE-2025-47812](agent/exploits/cve_2025_47812.py) | Wing FTP Server CVE-2025-47812 | Remote |
| [CVE-2025-48281](agent/exploits/wordpress_readme_2026.py) | MyStyle Custom Product Designer (CVE-2025-48281) | Remote |
| [CVE-2025-48827](agent/exploits/cve_2025_48827.py) | vBulletin Unauthenticated RCE via ajax/api/ad/replaceAdTemplate (CVE-2025-48827) | Remote |
| [CVE-2025-48828](agent/exploits/cve_2025_48827.py) | vBulletin Unauthenticated RCE via ajax/api/ad/replaceAdTemplate (CVE-2025-48827) | Remote |
| [CVE-2025-52691](agent/exploits/cve_2025_52691.py) | SmarterTools SmarterMail CVE-2025-52691 | Remote |
| [CVE-2025-53521](agent/exploits/cve_2025_53521.py) | F5 BIG-IP APM CVE-2025-53521 | Remote |
| [CVE-2025-53770](agent/exploits/cve_2025_53770.py) | SharePoint Server CVE-2025-53770 | Remote |
| [CVE-2025-54253](agent/exploits/cve_2025_54253.py) | Adobe Experience Manager Forms on JEE CVE-2025-54253 | Remote |
| [CVE-2025-54309](agent/exploits/cve_2025_54309.py) | CrushFTP CVE-2025-54309 | Remote |
| [CVE-2025-54531](agent/exploits/cve_2025_54531.py) | Windows plugin-unpacking assessment for TeamCity CVE-2025-54531 | Offline inventory |
| [CVE-2025-54988](agent/exploits/cve_2025_54988.py) | Apache Tika CVE-2025-54988 PDF/XFA XXE | Remote |
| [CVE-2025-55150](agent/exploits/cve_2025_55150.py) | Stirling-PDF CVE-2025-55150 HTML conversion SSRF | Remote |
| [CVE-2025-55182](agent/exploits/cve_2025_55182.py) | Meta React Server Components CVE-2025-55182 | Remote |
| [CVE-2025-57819](agent/exploits/cve_2025_57819.py) | Sangoma FreePBX endpoint CVE-2025-57819 | Remote |
| [CVE-2025-59287](agent/exploits/cve_2025_59287.py) | Microsoft Windows WSUS CVE-2025-59287 | Remote |
| [CVE-2025-59528](agent/exploits/cve_2025_59528.py) | Flowise CVE-2025-59528 CustomMCP RCE | Remote |
| [CVE-2025-59718](agent/exploits/cve_2025_59718.py) | Fortinet CVE-2025-59718 FortiCloud SSO | Remote |
| [CVE-2025-61757](agent/exploits/cve_2025_61757.py) | Oracle Identity Manager CVE-2025-61757 | Remote |
| [CVE-2025-61882](agent/exploits/cve_2025_61882.py) | Oracle E-Business Suite CVE-2025-61882 | Remote |
| [CVE-2025-62168](agent/exploits/cve_2025_62168.py) | Squid CVE-2025-62168 authentication credential disclosure | Remote |
| [CVE-2025-62581](agent/exploits/cve_2025_62581.py) | CVE-2025-62581 | Offline inventory |
| [CVE-2025-62582](agent/exploits/cve_2025_62582.py) | CVE-2025-62582 | Offline inventory |
| [CVE-2025-62593](agent/exploits/cve_2025_62593.py) | Ray CVE-2025-62593 browser DNS-rebinding RCE | Remote |
| [CVE-2025-64155](agent/exploits/cve_2025_64155.py) | assessment of FortiSIEM phMonitor; no remote probe | Offline inventory |
| [CVE-2025-64446](agent/exploits/cve_2025_64446.py) | Fortinet FortiWeb CVE-2025-64446 | Remote |
| [CVE-2025-67303](agent/exploits/cve_2025_67303.py) | ComfyUI-Manager CVE-2025-67303 configuration integrity | Remote |
| [CVE-2025-69258](agent/exploits/cve_2025_69258.py) | CVE-2025-69258 | Offline inventory |
| [CVE-2025-69411](agent/exploits/wordpress_readme_2026.py) | ionCube tester plus (CVE-2025-69411) | Remote |
| [CVE-2025-71334](agent/exploits/cve_2025_71334.py) | Flowise CVE-2025-71334 storage path traversal | Remote |
| [CVE-2025-71458](agent/exploits/cve_2025_71458.py) | FTS3 Web Monitoring unauthenticated SQL injection in /linkinfo (CVE-2025-71458) | Remote |

</details>

<details><summary><b>2024 — 78 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2024-0692](agent/exploits/cve_2024_0692.py) | SolarWinds Security Event Manager unauthenticated remote code execution | Remote |
| [CVE-2024-2194](agent/exploits/cve_2024_2194.py) | WP Statistics Unauthenticated Stored Cross-Site Scripting | Remote |
| [CVE-2024-2879](agent/exploits/cve_2024_2879.py) | LayerSlider 7.9.11 - 7.10.0 - Unauthenticated SQL Injection | Remote |
| [CVE-2024-3273](agent/exploits/cve_2024_3273.py) | D-Link Multiple NAS Devices Command Injection Vulnerability | Remote |
| [CVE-2024-3408](agent/exploits/cve_2024_3408.py) | D-Tale CVE-2024-3408 authentication bypass/RCE | Remote |
| [CVE-2024-3596](agent/exploits/cve_2024_3596.py) | PAN-OS BlastRADIUS owner inventory; no authentication probes | Offline inventory |
| [CVE-2024-4040](agent/exploits/cve_2024_4040.py) | Unauthenticated arbitrary file read and remote code execution in CrushFTP | Remote |
| [CVE-2024-4439](agent/exploits/cve_2024_4439.py) | Unauthenticated Stored Cross-Site Scripting Vulnerability in WordPress Core | Remote |
| [CVE-2024-5057](agent/exploits/wordpress_readme_2026.py) | Easy Digital Downloads (CVE-2024-5057) | Remote |
| [CVE-2024-5315](agent/exploits/cve_2024_5315.py) | Dolibarr ERP-CRM 9.0.1 - SQL Injection | Remote |
| [CVE-2024-5333](agent/exploits/wordpress_readme_2026.py) | The Events Calendar (CVE-2024-5333) | Remote |
| [CVE-2024-6385](agent/exploits/cve_2024_6385.py) | GitLab Authentication Bypass Vulnerability. | Remote |
| [CVE-2024-6386](agent/exploits/cve_2024_6386.py) | WPML Multilingual CMS Authenticated Contributor+ Remote Code Execution (RCE) via Twig Server-Side Template Injection (SSTI) | Remote |
| [CVE-2024-6387](agent/exploits/cve_2024_6387.py) | OpenSSH Remote Code Execution Vulnerability | Remote |
| [CVE-2024-6633](agent/exploits/cve_2024_6633.py) | Default Credentials in Fortra FileCatalyst Workflow HSQLDB | Remote |
| [CVE-2024-6745](agent/exploits/cve_2024_6745.py) | SQL Injection in Simple Ticket Booking | Remote |
| [CVE-2024-7029](agent/exploits/cve_2024_7029.py) | AVTECH IP camera Devices Command Injection Vulnerability | Remote |
| [CVE-2024-7120](agent/exploits/cve_2024_7120.py) | Command Injection in RAISECOM Gateway Devices | Remote |
| [CVE-2024-7589](agent/exploits/cve_2024_7589.py) | OpenSSH Pre-Authentication Async Signal Safety Issue | Remote |
| [CVE-2024-8522](agent/exploits/cve_2024_8522.py) | Unauthenticated SQL Injection Vulnerability in LearnPress Plugin | Remote |
| [CVE-2024-8672](agent/exploits/cve_2024_8672.py) | Widget Options Plugin <= 4.0.7 - Authenticated Remote Code Execution | Remote |
| [CVE-2024-8956](agent/exploits/cve_2024_8956.py) | ValueHD PTZ Camera Authentication Bypass | Remote |
| [CVE-2024-8957](agent/exploits/cve_2024_8957.py) | ValueHD PTZ Camera Command Injection | Remote |
| [CVE-2024-9164](agent/exploits/cve_2024_9164.py) | Gitlab Run pipelines on arbitrary branches. | Remote |
| [CVE-2024-9487](agent/exploits/cve_2024_9487.py) | GITHUB ENTERPRISE SERVER AUTHENTICATION BYPASS | Remote |
| [CVE-2024-9537](agent/exploits/cve_2024_9537.py) | ScienceLogic SL1 CVE-2024-9537 | Offline inventory |
| [CVE-2024-9634](agent/exploits/cve_2024_9634.py) | PHP Object Injection Vulnerability in GiveWP Plugin | Remote |
| [CVE-2024-10542](agent/exploits/cve_2024_10542.py) | CleanTalk Plugin Arbitrary Plugin Installation (Via Reverse DNS Spoofing) | Remote |
| [CVE-2024-10781](agent/exploits/cve_2024_10781.py) | CleanTalk Unauthorized Arbitrary Plugin Installation | Remote |
| [CVE-2024-10905](agent/exploits/cve_2024_10905.py) | SailPoint IdentityIQ Static File Exposure | Remote |
| [CVE-2024-11205](agent/exploits/cve_2024_11205.py) | WPForms Lite Plugin 1.8.4 - 1.9.2.1 - Missing Authorization to Authenticated (Subscriber+) Payment Refund and Subscription Cancellation | Remote |
| [CVE-2024-11639](agent/exploits/cve_2024_11639.py) | Authentication Bypass in Ivanti CSA Admin Console | Remote |
| [CVE-2024-11667](agent/exploits/cve_2024_11667.py) | Zyxel ATP/USG FLEX/USG FLEX 50(W)/USG20(W)-VPN UP TO 5.38 URL PATH TRAVERSAL | Remote |
| [CVE-2024-11972](agent/exploits/cve_2024_11972.py) | Hunk Companion Plugin Unauthenticated Arbitrary Plugin Installation | Remote |
| [CVE-2024-12084](agent/exploits/cve_2024_12084.py) | Rsync Heap Buffer Overflow | Remote |
| [CVE-2024-20419](agent/exploits/cve_2024_20419.py) | Account Takeover in Cisco Smart Software Manager On-Prem | Remote |
| [CVE-2024-21287](agent/exploits/cve_2024_21287.py) | Oracle Agile PLM Framework Remote File Disclosure | Remote |
| [CVE-2024-21591](agent/exploits/cve_2024_21591.py) | Junos J-Web CVE-2024-21591 | Offline inventory |
| [CVE-2024-21733](agent/exploits/cve_2024_21733.py) | Apache Tomcat HTTP Request Smuggling (Client- Side Desync) | Remote |
| [CVE-2024-21762](agent/exploits/cve_2024_21762.py) | Fortinet FortiOS Out-of-Bound Write SSL VPN Vulnerability | Remote |
| [CVE-2024-23113](agent/exploits/cve_2024_23113.py) | Critical Fortinet Format String Vulnerability | Remote |
| [CVE-2024-23334](agent/exploits/cve_2024_23334.py) | AIOHTTP Path Traversal | Remote |
| [CVE-2024-24882](agent/exploits/wordpress_readme_2026.py) | Masteriyo LMS (CVE-2024-24882) | Remote |
| [CVE-2024-27198](agent/exploits/cve_2024_27198.py) | JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions | Remote |
| [CVE-2024-27497](agent/exploits/cve_2024_27497.py) | Linksys E2000 1.0.06 authentication bypass | Remote |
| [CVE-2024-28890](agent/exploits/cve_2024_28890.py) | Forminator plugin flaw in WordPress sites | Remote |
| [CVE-2024-28986](agent/exploits/cve_2024_28986.py) | SolarWinds Web Help Desk 12.8.3 - Java Deserialization RCE | Remote |
| [CVE-2024-29269](agent/exploits/cve_2024_29269.py) | Telesquare TLR-2005KSH Unauthorized Remote Command Execution Vulnerability | Remote |
| [CVE-2024-30502](agent/exploits/wordpress_readme_2026.py) | WP Travel Engine (CVE-2024-30502) | Remote |
| [CVE-2024-33544](agent/exploits/cve_2024_33544.py) | Unauthenticated SQL Injection Vulnerability in WZone Plugin | Remote |
| [CVE-2024-34470](agent/exploits/cve_2024_34470.py) | HSC MAILINSPECTOR PATH TRAVERSAL | Remote |
| [CVE-2024-37383](agent/exploits/cve_2024_37383.py) | XSS via SVG Animate Attributes in Roundcube Webmail | Remote |
| [CVE-2024-38077](agent/exploits/cve_2024_38077.py) | Windows Remote Desktop Licensing Service RCE | Remote |
| [CVE-2024-38773](agent/exploits/wordpress_readme_2026.py) | FormLift for Infusionsoft Web Forms (CVE-2024-38773) | Remote |
| [CVE-2024-39717](agent/exploits/cve_2024_39717.py) | Versa Director Dangerous File Type Upload Vulnerability | Remote |
| [CVE-2024-40711](agent/exploits/cve_2024_40711.py) | Veeam Backup & Replication Remote Code Execution Vulnerability | Remote |
| [CVE-2024-40725](agent/exploits/cve_2024_40725.py) | Source Code Disclosure in Apache HTTP Server | Remote |
| [CVE-2024-40766](agent/exploits/cve_2024_40766.py) | SonicWall SonicOS Improper Access Control Vulnerability | Remote |
| [CVE-2024-42450](agent/exploits/cve_2024_42450.py) | Versa Director Database exposure | Remote |
| [CVE-2024-42509](agent/exploits/cve_2024_42509.py) | Unauthenticated Command Injection Vulnerability in HPE Aruba Networking Access Points | Remote |
| [CVE-2024-43044](agent/exploits/cve_2024_43044.py) | JENKINS ARBITRARY FILE READ TO RCE | Remote |
| [CVE-2024-43144](agent/exploits/wordpress_readme_2026.py) | Cost Calculator Builder (CVE-2024-43144) | Remote |
| [CVE-2024-43399](agent/exploits/cve_2024_43399.py) | Mobile Security Framework (MobSF) Zip Slip | Remote |
| [CVE-2024-45409](agent/exploits/cve_2024_45409.py) | GitLab SAML Authentication Bypass Vulnerability. | Remote |
| [CVE-2024-47374](agent/exploits/cve_2024_47374.py) | Stored Cross-Site Scripting (XSS) Vulnerability in LiteSpeed Cache for WordPress | Remote |
| [CVE-2024-47533](agent/exploits/cve_2024_47533.py) | Cobbler XMLRPC Interface Authentication Bypass | Remote |
| [CVE-2024-47575](agent/exploits/cve_2024_47575.py) | Missing Authentication for critical function in FortiManager | Remote |
| [CVE-2024-50379](agent/exploits/cve_2024_50379.py) | Apache Tomcat Race Condition Remote Code Execution | Remote |
| [CVE-2024-50550](agent/exploits/cve_2024_50550.py) | LiteSpeed Cache Vulnerability Allowing privilege escalation | Remote |
| [CVE-2024-50623](agent/exploits/cve_2024_50623.py) | Cleo Harmony, VLTrader, and LexiCom - Unrestricted File Upload and Download Leading to Remote Code Execution | Remote |
| [CVE-2024-51378](agent/exploits/cve_2024_51378.py) | CYBERPANEL RCE | Remote |
| [CVE-2024-51479](agent/exploits/cve_2024_51479.py) | Next.js Authorization Bypass via Middleware | Remote |
| [CVE-2024-53298](agent/exploits/cve_2024_53298.py) | CVE-2024-53298 | Offline inventory |
| [CVE-2024-53704](agent/exploits/cve_2024_53704.py) | SonicWall SSLVPN Authentication Bypass | Remote |
| [CVE-2024-54134](agent/exploits/cve_2024_54134.py) | MALICIOUS PACKAGES FOUND IN COMPROMISED @SOLANA/WEB3.JS LIBRARY | Remote |
| [CVE-2024-55591](agent/exploits/cve_2024_55591.py) | Fortinet FortiOS Authentication Bypass | Remote |
| [CVE-2024-55956](agent/exploits/cve_2024_55956.py) | Cleo Harmony, VLTrader, and LexiCom - Arbitrary Command Execution via Autorun Directory | Remote |
| [CVE-2024-57726](agent/exploits/cve_2024_57726.py) | SimpleHelp CVE-2024-57726 technician privilege escalation | Remote |

</details>

<details><summary><b>2023 — 19 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2023-1389](agent/exploits/cve_2023_1389.py) | Remote Code Execution in TP-Link AX21. | Remote |
| [CVE-2023-3452](agent/exploits/wordpress_readme_2026.py) | Canto (CVE-2023-3452) | Remote |
| [CVE-2023-5204](agent/exploits/wordpress_readme_2026.py) | AI ChatBot (WPBot) (CVE-2023-5204) | Remote |
| [CVE-2023-6825](agent/exploits/wordpress_readme_2026.py) | File Manager (free edition) (CVE-2023-6825) | Remote |
| [CVE-2023-22518](agent/exploits/cve_2023_22518.py) | Improper Authorization Vulnerability In Confluence Data Center and Server | Remote |
| [CVE-2023-24000](agent/exploits/wordpress_readme_2026.py) | GamiPress (CVE-2023-24000) | Remote |
| [CVE-2023-25280](agent/exploits/cve_2023_25280.py) | Command Injection in D-Link DIR820LA1 | Remote |
| [CVE-2023-27997](agent/exploits/cve_2023_27997.py) | A heap-based buffer overflow vulnerability in FortiOS. | Remote |
| [CVE-2023-28461](agent/exploits/cve_2023_28461.py) | Array Networks Array AG Series and vxAG Remote Code Execution Vulnerability | Remote |
| [CVE-2023-34990](agent/exploits/cve_2023_34990.py) | FortiWLM Directory Traversal | Remote |
| [CVE-2023-36845](agent/exploits/cve_2023_36845.py) | Juniper Junos OS EX Series and SRX Series PHP External Variable Modification Vulnerability | Remote |
| [CVE-2023-42282](agent/exploits/cve_2023_42282.py) | assessment of node-ip CVE-2023-42282 without SSRF probes | Offline inventory |
| [CVE-2023-43770](agent/exploits/cve_2023_43770.py) | Roundcube Webmail Persistent Cross-Site Scripting (XSS) Vulnerability | Remote |
| [CVE-2023-45727](agent/exploits/cve_2023_45727.py) | Proself Enterprise/Standard XXE Vulnerability | Remote |
| [CVE-2023-48788](agent/exploits/cve_2023_48788.py) | Fortinet FortiClient EMS SQL Injection Vulnerability | Remote |
| [CVE-2023-49105](agent/exploits/cve_2023_49105.py) | ownCloud CVE-2023-49105 | Remote |
| [CVE-2023-49897](agent/exploits/cve_2023_49897.py) | FXC wireless LAN routers "AE1021PE" and "AE1021" vulnerable to OS command injection. | Remote |
| [CVE-2023-50839](agent/exploits/wordpress_readme_2026.py) | JS Help Desk (CVE-2023-50839) | Remote |
| [CVE-2023-50969](agent/exploits/cve_2023_50969.py) | Imperva SecureSphere WAF Bypass for POST Data Inspection Rules | Remote |

</details>

<details><summary><b>2022 — 7 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2022-1453](agent/exploits/wordpress_readme_2026.py) | RSVPMaker (CVE-2022-1453) | Remote |
| [CVE-2022-21445](agent/exploits/cve_2022_21445.py) | Oracle Application Development Framework (ADF) Remote Code Execution Vulnerability | Remote |
| [CVE-2022-24331](agent/exploits/cve_2022_24331.py) | native GitLab authentication assessment for TeamCity CVE-2022-24331 | Offline inventory |
| [CVE-2022-24816](agent/exploits/cve_2022_24816.py) | GeoServer WPS Remote Code Execution | Remote |
| [CVE-2022-26318](agent/exploits/cve_2022_26318.py) | WatchGuard Firebox and XTM Appliances Arbitrary Code Execution | Remote |
| [CVE-2022-37601](agent/exploits/cve_2022_37601.py) | assessment of loader-utils CVE-2022-37601, without target I/O | Offline inventory |
| [CVE-2022-44588](agent/exploits/wordpress_readme_2026.py) | Cryptocurrency Widgets Pack (CVE-2022-44588) | Remote |

</details>

<details><summary><b>2021 — 7 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2021-22941](agent/exploits/cve_2021_22941.py) | Improper Access Control in Citrix ShareFile storage zones controller. | Remote |
| [CVE-2021-24139](agent/exploits/wordpress_readme_2026.py) | Photo Gallery by 10Web (CVE-2021-24139) | Remote |
| [CVE-2021-31914](agent/exploits/cve_2021_31914.py) | server-release and Windows assessment for TeamCity CVE-2021-31914 | Offline inventory |
| [CVE-2021-32648](agent/exploits/cve_2021_32648.py) | October CMS password recovery vulnerability: CVE-2021-32648 | Remote |
| [CVE-2021-33044](agent/exploits/cve_2021_33044.py) | Dahua IPC/VTH/VTO devices auth bypass | Remote |
| [CVE-2021-40655](agent/exploits/cve_2021_40655.py) | Information disclosure issue exists in D-LINK-DIR-605 B2 | Remote |
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

<details><summary><b>2019 — 7 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2019-7193](agent/exploits/cve_2019_7193.py) | QNAP QTS Improper Input Validation Vulnerability | Remote |
| [CVE-2019-9874](agent/exploits/cve_2019_9874.py) | Sitecore Anti-CSRF Unauthenticated Deserialization | Remote |
| [CVE-2019-12989](agent/exploits/cve_2019_12989.py) | Security Vulnerabilities in Citrix CVE-2019-12989 and CVE-2019-12991 | Remote |
| [CVE-2019-12991](agent/exploits/cve_2019_12989.py) | Security Vulnerabilities in Citrix CVE-2019-12989 and CVE-2019-12991 | Remote |
| [CVE-2019-14793](agent/exploits/wordpress_readme_2026.py) | Meta Box (CVE-2019-14793) | Remote |
| [CVE-2019-16278](agent/exploits/cve_2019_16278.py) | NOSTROMO NHTTPD DIRECTORY TRAVERSAL VULNERABILITY | Remote |
| [CVE-2019-19006](agent/exploits/cve_2019_19006.py) | framework-module inventory for FreePBX CVE-2019-19006 | Offline inventory |

</details>

<details><summary><b>2018 — 10 CVEs</b></summary>

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
| [CVE-2018-19410](agent/exploits/cve_2018_19410.py) | PRTG Network Monitor Authentication Bypass & Local File Inclusion | Remote |

</details>

<details><summary><b>2017 — 3 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2017-0147](agent/exploits/cve_2017_0148.py) | Microsoft Windows SMBv1 - Remote Code Execution (MS17-010 / EternalBlue) | Remote |
| [CVE-2017-0148](agent/exploits/cve_2017_0148.py) | Microsoft Windows SMBv1 - Remote Code Execution (MS17-010 / EternalBlue) | Remote |
| [CVE-2017-3066](agent/exploits/cve_2017_3066.py) | Java deserialization vulnerability in the Apache BlazeDS library in Adobe ColdFusion | Remote |

</details>

<details><summary><b>2016 — 2 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2016-2386](agent/exploits/cve_2016_2386.py) | SAP NetWeaver SQL Injection Vulnerability | Remote |
| [CVE-2016-15043](agent/exploits/wordpress_readme_2026.py) | WP Mobile Detector (CVE-2016-15043) | Remote |

</details>

<details><summary><b>2015 — 1 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2015-4852](agent/exploits/cve_2015_4852.py) | Oracle WebLogic Server - T3 Deserialization Remote Code Execution (CVE-2015-4852) | Remote |

</details>

<details><summary><b>2014 — 3 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
| [CVE-2014-0780](agent/exploits/cve_2014_0780.py) | Indusoft Web Studio Directory Traversal. | Remote |
| [CVE-2014-2120](agent/exploits/cve_2014_2120.py) | Cisco ASA WebVPN Login Page XSS Vulnerability | Remote |
| [CVE-2014-7169](agent/exploits/cve_2014_7169.py) | GNU Bourne-Again Shell (Bash) Arbitrary Code Execution Vulnerability. | Remote |

</details>

<details><summary><b>2010 — 1 CVEs</b></summary>

| CVE | What is detected | Detector |
| --- | --- | --- |
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
  change state; beyond the session envelope, the only application payload
  returned is the non-sensitive RBAC role listing, which is checked only for
  shape and never reported. Default-credential checks read the affected
  account's own metadata and are documented in their modules.
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
