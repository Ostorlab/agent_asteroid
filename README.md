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

The additions below use read-only service metadata or trusted inventory to assess
potential exposure. Positive results explicitly leave exploitability unconfirmed;
none of these checks executes commands, uploads payloads, resets passwords, dumps
memory, or attempts an authentication bypass.

### Remote checks

These eight checks register with Asteroid's normal detector registry. They require
unambiguous product and affected version/build evidence and any configuration
prerequisites their modules document. Hidden, conflicting, unsupported, or
incomplete evidence produces no finding. A missing finding does not establish
that a target is patched. Installed hotfixes, backports, and effective mitigations
may require authenticated verification.

| CVE | Product | Implementation |
| --- | --- | --- |
| CVE-2025-53770 | Microsoft SharePoint | [Module](agent/exploits/cve_2025_53770.py) |
| CVE-2026-1731 | BeyondTrust Remote Support (RS) and Privileged Remote Access (PRA) | [Module](agent/exploits/cve_2026_1731.py) |
| CVE-2026-41940 | WebPros cPanel & WHM (WP2 excluded) | [Module](agent/exploits/cve_2026_41940.py) |
| CVE-2026-88771 | Citrix NetScaler | [Module](agent/exploits/cve_2026_88771.py) |
| CVE-2026-88772 | Citrix NetScaler | [Module](agent/exploits/cve_2026_88772.py) |
| CVE-2025-4427 | Ivanti Endpoint Manager Mobile (EPMM) | [Module](agent/exploits/cve_2025_4427.py) |
| CVE-2025-4428 | Ivanti Endpoint Manager Mobile (EPMM) | [Module](agent/exploits/cve_2025_4428.py) |
| CVE-2025-3248 | Langflow | [Module](agent/exploits/cve_2025_3248.py) |

### Inventory assessments

The following 42 modules expose typed, pure `assess_inventory` functions. They
perform no network requests and are deliberately **not registered as remote
checks**. Ordinary IP/domain/URL scans and `custom_cve_list` do not invoke them.
An authenticated inventory integration must supply fresh evidence bound to the
expected target, including the exact product, installed version/build, relevant
configuration, and patch provenance required by each module's input dataclass.
A caller's `trusted`/attestation fields express that integration's responsibility;
these functions do not authenticate the caller or collect inventory themselves.

Most modules return an assessment distinguishing **potential exposure**,
**outside the affected criteria**, and **unknown**. CVE-2025-31161 returns a list
of potential-exposure findings; its empty list combines insufficient evidence
and exclusions. Use each module's declared result type. Unknown versions, missing
or contradictory evidence, and unmapped custom builds or hotfixes remain
inconclusive. Outside the affected criteria is
specific to that CVE and supplied record, rather than a claim that the whole
installation is safe. Each module documents its input and vendor references;
its matching test module contains usage examples. Inventory ingestion and a
common adapter are not included in this change.

| CVE | Product | Assessment API |
| --- | --- | --- |
| CVE-2025-55182 | Meta React Server Components | [assess_inventory](agent/exploits/cve_2025_55182.py) |
| CVE-2025-31324 | SAP NetWeaver | [assess_inventory](agent/exploits/cve_2025_31324.py) |
| CVE-2025-5777 | Citrix NetScaler ADC and Gateway | [assess_inventory](agent/exploits/cve_2025_5777.py) |
| CVE-2025-31161 | CrushFTP | [assess_inventory](agent/exploits/cve_2025_31161.py) |
| CVE-2026-20131 | Cisco Secure Firewall Management Center (FMC) | [assess_inventory](agent/exploits/cve_2026_20131.py) |
| CVE-2026-1281 | Ivanti Endpoint Manager Mobile (EPMM) | [assess_inventory](agent/exploits/cve_2026_1281.py) |
| CVE-2026-1340 | Ivanti Endpoint Manager Mobile (EPMM) | [assess_inventory](agent/exploits/cve_2026_1340.py) |
| CVE-2026-21643 | Fortinet FortiClient EMS | [assess_inventory](agent/exploits/cve_2026_21643.py) |
| CVE-2026-35616 | Fortinet FortiClient EMS | [assess_inventory](agent/exploits/cve_2026_35616.py) |
| CVE-2025-23006 | SonicWall SMA1000 Appliances | [assess_inventory](agent/exploits/cve_2025_23006.py) |
| CVE-2025-37164 | Hewlett Packard Enterprise (HPE) OneView | [assess_inventory](agent/exploits/cve_2025_37164.py) |
| CVE-2025-14847 | MongoDB Server | [assess_inventory](agent/exploits/cve_2025_14847.py) |
| CVE-2025-24813 | Apache Tomcat | [assess_inventory](agent/exploits/cve_2025_24813.py) |
| CVE-2025-24893 | XWiki Platform | [assess_inventory](agent/exploits/cve_2025_24893.py) |
| CVE-2025-25257 | Fortinet FortiWeb | [assess_inventory](agent/exploits/cve_2025_25257.py) |
| CVE-2025-64446 | Fortinet FortiWeb | [assess_inventory](agent/exploits/cve_2025_64446.py) |
| CVE-2025-30406 | Gladinet CentreStack | [assess_inventory](agent/exploits/cve_2025_30406.py) |
| CVE-2025-47812 | Wing FTP Server | [assess_inventory](agent/exploits/cve_2025_47812.py) |
| CVE-2025-61882 | Oracle E-Business Suite | [assess_inventory](agent/exploits/cve_2025_61882.py) |
| CVE-2025-61757 | Oracle Fusion Middleware | [assess_inventory](agent/exploits/cve_2025_61757.py) |
| CVE-2025-54253 | Adobe Experience Manager (AEM) Forms | [assess_inventory](agent/exploits/cve_2025_54253.py) |
| CVE-2025-53521 | F5 BIG-IP | [assess_inventory](agent/exploits/cve_2025_53521.py) |
| CVE-2025-52691 | SmarterTools SmarterMail | [assess_inventory](agent/exploits/cve_2025_52691.py) |
| CVE-2025-40551 | SolarWinds Web Help Desk | [assess_inventory](agent/exploits/cve_2025_40551.py) |
| CVE-2025-59287 | Microsoft Windows | [assess_inventory](agent/exploits/cve_2025_59287.py) |
| CVE-2025-54068 | Laravel Livewire | [assess_inventory](agent/exploits/cve_2025_54068.py) |
| CVE-2025-54309 | CrushFTP | [assess_inventory](agent/exploits/cve_2025_54309.py) |
| CVE-2025-57819 | Sangoma FreePBX | [assess_inventory](agent/exploits/cve_2025_57819.py) |
| CVE-2025-14733 | WatchGuard Firebox | [assess_inventory](agent/exploits/cve_2025_14733.py) |
| CVE-2025-32432 | Craft CMS | [assess_inventory](agent/exploits/cve_2025_32432.py) |
| CVE-2025-59718 | Fortinet Multiple Products | [assess_inventory](agent/exploits/cve_2025_59718.py) |
| CVE-2026-104935 | Ivanti Connect Secure | [assess_inventory](agent/exploits/cve_2026_104935.py) |
| CVE-2026-63077 | JetBrains TeamCity | [assess_inventory](agent/exploits/cve_2026_63077.py) |
| CVE-2026-81578 | PaperCut NG/MF | [assess_inventory](agent/exploits/cve_2026_81578.py) |
| CVE-2026-82078 | PaperCut NG/MF | [assess_inventory](agent/exploits/cve_2026_82078.py) |
| CVE-2026-33017 | Langflow | [assess_inventory](agent/exploits/cve_2026_33017.py) |
| CVE-2026-22769 | Dell RecoverPoint for Virtual Machines (RP4VMs) | [assess_inventory](agent/exploits/cve_2026_22769.py) |
| CVE-2026-24061 | GNU InetUtils | [assess_inventory](agent/exploits/cve_2026_24061.py) |
| CVE-2026-23760 | SmarterTools SmarterMail | [assess_inventory](agent/exploits/cve_2026_23760.py) |
| CVE-2026-24423 | SmarterTools SmarterMail | [assess_inventory](agent/exploits/cve_2026_24423.py) |
| CVE-2026-20127 | Cisco Catalyst SD-WAN Controller and Manager | [assess_inventory](agent/exploits/cve_2026_20127.py) |
| CVE-2026-50751 | Check Point Security Gateway | [assess_inventory](agent/exploits/cve_2026_50751.py) |

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
