<h1 align="center">Discover and Protect Against Remotely Exploitable Vulnerabilities with Agent Asteroid</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_asteroid">
<img src="https://img.shields.io/github/stars/ostorlab/agent_asteroid">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_The Asteroid Agent is a powerful scanner specializing in the detection of vulnerabilities that could be exploited remotely._

---

<p align="center">
<img src="https://github.com/ostorlab/agent_asteroid/blob/main/images/logo.png" alt="agent-asteroid" />
</p>

Agent Asteroid is a powerful open-source security scanner designed to detect vulnerabilities that could be exploited remotely. Developed by security team at Ostorlab, this tool provides a comprehensive solution for identifying critical security risks. At the time of writing, Agent Asteroid can detect nearly 100 critical CVEs.

## Key Features

- **Advanced Vulnerability Detection**: Agent Asteroid utilizes cutting-edge techniques to scan target systems and identify a wide range of vulnerabilities, including misconfigurations, unpatched software, and more.
- **Comprehensive CVE Coverage**: The agent can detect nearly 100 critical CVEs, helping you stay ahead of the latest security threats.
- **Seamless Integration**: The agent can be easily integrated into your existing security workflows, allowing you to incorporate vulnerability detection into your regular testing and deployment processes.
- **Extensible and Customizable**: With support for custom modules and plugins, Agent Asteroid can be tailored to meet your specific security requirements, making it a versatile tool for organizations of all sizes.
- **Open-Source Transparency**: As an open-source project, Agent Asteroid benefits from community contributions and feedback, ensuring continual improvement and the highest standards of security.

## Getting Started

To perform your first scan with Agent Asteroid, simply run the following command:

oxo scan run --install --agent agent/ostorlab/asteroid ip 8.8.8.8

This command will download and install the `agent/ostorlab/asteroid` agent and target the IP address `8.8.8.8`. For more detailed instructions and usage examples, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs).

## Defensive assessment coverage for 2025–2026 CVEs

Agent Asteroid ships defensive exposure checks for 2025–2026 CVEs
registered in Asteroid's remote detector registry. They use read-only service
metadata to assess potential exposure, and positive results explicitly leave
exploitability unconfirmed. None of these checks executes commands, uploads
payloads, resets passwords, dumps memory, or attempts an authentication bypass.

### What do the remote checks detect?

Each check requires unambiguous product and affected version/build evidence,
plus the configuration prerequisites documented in its module. Hidden,
conflicting, unsupported, or incomplete evidence produces no finding. A missing
finding does not establish that a target is patched. Installed hotfixes,
backports, and effective mitigations may require authenticated verification.
Remote checks run automatically on standard `oxo scan run` scans and can be
filtered with the `custom_cve_list` scanner setting.

| CVE | Product | Implementation |
| --- | --- | --- |
| CVE-2026-79844 through CVE-2026-79876 (33 critical CVEs) | HPE AOS-8/AOS-10, scoped to each OS family | [HPESBNW05162 module](agent/exploits/hpe_2026_05162.py) |
| CVE-2026-114612 | LiteLLM proxy | [CVE-2026-114612 module](agent/exploits/cve_2026_114612.py) |
| CVE-2026-110447 | Collabora built-in CODE app for Nextcloud | [CVE-2026-110447 module](agent/exploits/cve_2026_110447.py) |
| CVE-2026-115547 | Okta Access Gateway, when its version footer is exposed | [CVE-2026-115547 module](agent/exploits/cve_2026_115547.py) |
| CVE-2026-107861, CVE-2026-110243, CVE-2026-109122 | Kiloview E3 | [Kiloview module](agent/exploits/kiloview_2026_10.py) |
| CVE-2026-109618 | PHP Core | [CVE-2026-109618 module](agent/exploits/cve_2026_109618.py) |
| CVE-2026-109619 | PHP Core | [CVE-2026-109619 module](agent/exploits/cve_2026_109619.py) |
| CVE-2025-53770 | Microsoft SharePoint | [CVE-2025-53770 module](agent/exploits/cve_2025_53770.py) |
| CVE-2026-41940 | WebPros cPanel & WHM (WP2 excluded) | [CVE-2026-41940 module](agent/exploits/cve_2026_41940.py) |
| CVE-2026-88771 | Citrix NetScaler | [CVE-2026-88771 module](agent/exploits/cve_2026_88771.py) |
| CVE-2026-88772 | Citrix NetScaler | [CVE-2026-88772 module](agent/exploits/cve_2026_88772.py) |
| CVE-2025-3248 | Langflow | [CVE-2025-3248 module](agent/exploits/cve_2025_3248.py) |
| CVE-2025-55182 | Meta React Server Components | [CVE-2025-55182 module](agent/exploits/cve_2025_55182.py) |
| CVE-2025-31324 | SAP NetWeaver | [CVE-2025-31324 module](agent/exploits/cve_2025_31324.py) |
| CVE-2025-5777 | Citrix NetScaler ADC and Gateway | [CVE-2025-5777 module](agent/exploits/cve_2025_5777.py) |
| CVE-2025-31161 | CrushFTP | [CVE-2025-31161 module](agent/exploits/cve_2025_31161.py) |
| CVE-2026-20131 | Cisco Secure Firewall Management Center (FMC) | [CVE-2026-20131 module](agent/exploits/cve_2026_20131.py) |
| CVE-2026-21643 | Fortinet FortiClient EMS | [CVE-2026-21643 module](agent/exploits/cve_2026_21643.py) |
| CVE-2026-35616 | Fortinet FortiClient EMS | [CVE-2026-35616 module](agent/exploits/cve_2026_35616.py) |
| CVE-2025-23006 | SonicWall SMA1000 Appliances | [CVE-2025-23006 module](agent/exploits/cve_2025_23006.py) |
| CVE-2025-37164 | Hewlett Packard Enterprise (HPE) OneView | [CVE-2025-37164 module](agent/exploits/cve_2025_37164.py) |
| CVE-2025-14847 | MongoDB Server | [CVE-2025-14847 module](agent/exploits/cve_2025_14847.py) |
| CVE-2025-24893 | XWiki Platform | [CVE-2025-24893 module](agent/exploits/cve_2025_24893.py) |
| CVE-2025-25257 | Fortinet FortiWeb | [CVE-2025-25257 module](agent/exploits/cve_2025_25257.py) |
| CVE-2025-64446 | Fortinet FortiWeb | [CVE-2025-64446 module](agent/exploits/cve_2025_64446.py) |
| CVE-2025-47812 | Wing FTP Server | [CVE-2025-47812 module](agent/exploits/cve_2025_47812.py) |
| CVE-2025-61882 | Oracle E-Business Suite | [CVE-2025-61882 module](agent/exploits/cve_2025_61882.py) |
| CVE-2025-61757 | Oracle Fusion Middleware | [CVE-2025-61757 module](agent/exploits/cve_2025_61757.py) |
| CVE-2025-54253 | Adobe Experience Manager (AEM) Forms | [CVE-2025-54253 module](agent/exploits/cve_2025_54253.py) |
| CVE-2025-53521 | F5 BIG-IP | [CVE-2025-53521 module](agent/exploits/cve_2025_53521.py) |
| CVE-2025-52691 | SmarterTools SmarterMail | [CVE-2025-52691 module](agent/exploits/cve_2025_52691.py) |
| CVE-2025-40551 | SolarWinds Web Help Desk | [CVE-2025-40551 module](agent/exploits/cve_2025_40551.py) |
| CVE-2025-59287 | Microsoft Windows | [CVE-2025-59287 module](agent/exploits/cve_2025_59287.py) |
| CVE-2025-54309 | CrushFTP | [CVE-2025-54309 module](agent/exploits/cve_2025_54309.py) |
| CVE-2025-57819 | Sangoma FreePBX | [CVE-2025-57819 module](agent/exploits/cve_2025_57819.py) |
| CVE-2025-14733 | WatchGuard Firebox | [CVE-2025-14733 module](agent/exploits/cve_2025_14733.py) |
| CVE-2025-32432 | Craft CMS | [CVE-2025-32432 module](agent/exploits/cve_2025_32432.py) |
| CVE-2025-59718 | Fortinet Multiple Products | [CVE-2025-59718 module](agent/exploits/cve_2025_59718.py) |
| CVE-2026-104935 | Ivanti Connect Secure | [CVE-2026-104935 module](agent/exploits/cve_2026_104935.py) |
| CVE-2026-63077 | JetBrains TeamCity | [CVE-2026-63077 module](agent/exploits/cve_2026_63077.py) |
| CVE-2026-81578 | PaperCut NG/MF | [CVE-2026-81578 module](agent/exploits/cve_2026_81578.py) |
| CVE-2026-82078 | PaperCut NG/MF | [CVE-2026-82078 module](agent/exploits/cve_2026_82078.py) |
| CVE-2026-33017 | Langflow | [CVE-2026-33017 module](agent/exploits/cve_2026_33017.py) |
| CVE-2026-22769 | Dell RecoverPoint for Virtual Machines (RP4VMs) | [CVE-2026-22769 module](agent/exploits/cve_2026_22769.py) |
| CVE-2026-24061 | GNU InetUtils | [CVE-2026-24061 module](agent/exploits/cve_2026_24061.py) |
| CVE-2026-23760 | SmarterTools SmarterMail | [CVE-2026-23760 module](agent/exploits/cve_2026_23760.py) |
| CVE-2026-24423 | SmarterTools SmarterMail | [CVE-2026-24423 module](agent/exploits/cve_2026_24423.py) |
| CVE-2026-20127 | Cisco Catalyst SD-WAN Controller and Manager | [CVE-2026-20127 module](agent/exploits/cve_2026_20127.py) |
| CVE-2026-50751 | Check Point Security Gateway | [CVE-2026-50751 module](agent/exploits/cve_2026_50751.py) |

### October 2026 additions and inventory evidence

The five new remote detectors above cover 39 CVEs using product/version
metadata. HPE uses one SNMP `sysDescr` GET, only for an explicitly supplied
UDP/SNMP service on port 161, with the public community and no retries. The HTTP
checks read only documented metadata resources. Collabora app metadata is
normally denied by Nextcloud, and Okta normally hides its version before
sign-in; those responses remain inconclusive. No login, credential replay,
configuration change, PAPI packet, or code-execution payload is sent.

Some advisories need evidence that anonymous network metadata cannot establish.
Use the separate **offline** inventory assessor for VeloCloud, GitLab, PHP's
new configuration-dependent issue, Envoy's downstream Brotli exposure, and
OpenHands sandbox exposure:

```shell
python -m agent.utils.inventory inventory.json
```

Each CVE owns its inventory policy and prerequisites in its exploit module:

| CVE | Inventory assessment |
| --- | --- |
| CVE-2026-114625 | [VeloCloud Orchestrator](agent/exploits/cve_2026_114625.py) |
| CVE-2026-110264 | [GitLab CE/EE](agent/exploits/cve_2026_110264.py) |
| CVE-2026-115560 | [PHP session configuration](agent/exploits/cve_2026_115560.py) |
| CVE-2026-111497 | [Envoy Brotli decompressor](agent/exploits/cve_2026_111497.py) |
| CVE-2026-112346 | [OpenHands Docker/Apptainer sandbox](agent/exploits/cve_2026_112346.py) |

The CLI dispatches records to those modules. The CLI, shared result types,
version parsing, and bounded HTTP metadata reads live in `agent/utils`.

The input is an array of normalized records collected and verified by the owner.
This is an Asteroid input schema, not a vendor API response. For example:

```json
[
  {
    "product": "VeloCloud Orchestrator",
    "version": "6.4.2.11",
    "deployment": "on-premises"
  },
  {
    "product": "GitLab EE",
    "version": "19.4.2",
    "deployment": "self-managed"
  },
  {
    "product": "PHP",
    "version": "8.4.27",
    "session_upload_progress_enabled": true,
    "configured_serialize_handler": "php_binary",
    "runtime_serialize_handler_before_session_start": "php"
  },
  {
    "product": "Envoy",
    "version": "1.39.2",
    "brotli_decompressor_enabled": true
  }
]
```

This command makes no network requests and executes no target code. It assesses
only the supplied evidence; it does not collect inventory, authenticate, or
verify an operator's assertions. It is separate from the remote detector
registry and `custom_cve_list`. Missing or ambiguous prerequisites are
`inconclusive`; `not_matched` applies only to that check, not the system's overall
security. Positive assessments leave exploitability and backports unconfirmed.

OpenHands requires evidence for the running sandbox's launcher, effective
authentication and untrusted network exposure. Its 1.52.0 Docker fix does not
fix Apptainer. See the [OpenHands input schema and source review](docs/openhands-cve-2026-112346.md)
for runtime-specific prerequisites and conservative result semantics.

For CVE-2026-115560, the initial assessor covers only the four current upstream
releases explicitly contextualized by the 23 October advisory: 8.2.35, 8.3.36,
8.4.27 and 8.5.12. The full affected-version matrix and fix were not yet
published. Earlier and future versions remain inconclusive for this new issue.
The original PHP2Shell fixes are those four releases; their existing detectors
have been corrected accordingly without changing finding identities.

See the [dated advisory audit](docs/critical-advisories-2026-10-24.md) for sources,
the exact reporting window, earlier catch-up items, vendor-mitigated cloud
issues, and the two KSMBD reports requiring deployed-source verification. No
generic open-port check is presented as proof of those kernel vulnerabilities.

## Contributing

We welcome contributions from the community! Whether you're interested in submitting bug reports, feature requests, or code contributions, please feel free to [open an issue](https://github.com/Ostorlab/agent_asteroid/issues/new) or [submit a pull request](https://github.com/Ostorlab/agent_asteroid/pulls). By working together, we can make Agent Asteroid an even more powerful and effective security tool.

## Join the Community

Stay up-to-date with the latest developments and connect with other security professionals by following us on [Twitter](https://twitter.com/ostorlab) and joining our [Discord server](https://discord.gg/ostorlab). We're always eager to hear your feedback and ideas!


### Build directly from the repository

 1. To build the asteroid agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_asteroid.git && cd agent_asteroid
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```

 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
    ```shell
    oxo scan run --agent agent//asteroid ip 8.8.8.8
    ```
	 * If you specified an organization when building the image:
    ```shell
    oxo scan run --agent agent/[ORGANIZATION]/asteroid ip 8.8.8.8
    ```
