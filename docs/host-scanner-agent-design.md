# Host Scanner Agent — Agentless Host Scanning Design for Review

Status: draft for review · Author: Alaeddine Mesbahi · 2026-11-09

## Summary

We propose **Host Scanner** (working name), a new, dedicated Ostorlab agent for agentless, credentialed scanning. It logs in to Linux, Windows and macOS machines over their native management protocols, collects a normalized host inventory, and checks it for missing patches, insecure configuration and indicators of compromise.

It ships as its own agent, `agent/ostorlab/host_scanner`, beside Asteroid rather than inside it. Asteroid stays the remote, unauthenticated scanner. Host Scanner is the authenticated verification that Asteroid's README defers to for installed hotfixes, backports and mitigations.

The design rests on one contract: collectors write a normalized **host inventory**, and every analyzer reads only that inventory, never the host. Target interaction stays small and read-only, analyzers test offline from recorded fixtures, and a new platform arrives as a new collector set without touching vulnerability logic.

Findings leave as `v3.report.vulnerability` messages, aggregated per host and per package or missing update, with a stable DNA so they close when the host is patched.

## Goals and non-goals

Version 1 targets patch level, configuration and compromise on Linux, Windows and macOS hosts, with nothing installed on them and nothing changed.

**Goals**

- Authenticated scanning of Linux, Windows and macOS hosts with no software installed on them.
- Patch-level vulnerability detection that honours distro backports and Windows cumulative updates.
- Configuration audit against a curated rule set mapped to public benchmarks.
- Indicators of compromise: persistence, known-bad hashes, and CVE-specific artefacts for the CVEs Asteroid detects remotely.
- An explicit coverage record per host: what was collected, with which privilege, and what failed.

**Non-goals for version 1**

- Any write on the target: the scanner never patches, restarts or reconfigures.
- EDR-style forensics, memory analysis or continuous monitoring.
- Network devices, hypervisors, containers and language-level packages (later phases).
- Credential discovery or brute force: only customer-provided credentials are used.

**Success criteria**

- Zero state changes on lab targets, verified by before/after file system, service and package diffs.
- Linux findings match a reference scanner (Grype) on the same lab images, every difference explained.
- Every scanned host produces a coverage record, including failed logins.
- A finding closes automatically when the next scan sees the fix.

## The agent

Host Scanner is a new, dedicated Ostorlab agent with its own definition, image and release cycle; it is not a mode of `AsteroidAgent`.

### Why a dedicated agent

- **Execution model.** Asteroid runs every exploit against every target in one thread pool, each a short probe. A host scan is one login session per host, collect then analyze, often minutes long.
- **Credentials.** Asteroid runs on standard `oxo scan run` scans; fleet admin credentials stay out of it.
- **Opt-in.** Credentialed scanning needs change approval and service accounts at most customers. A separate agent is a separate switch in the agent group.
- **Footprint.** The SSH and WinRM clients and the vulnerability source data stay out of an image that every scan runs.
- **Operations.** Releases, scaling and timeouts are tuned without touching Asteroid.

### Definition

```yaml
kind: Agent
name: host_scanner
version: 0.1.0
description: Agentless, credentialed scanner for Linux, Windows and macOS hosts.
in_selectors:
  - v3.asset.ip.v4
  - v3.asset.ip.v6
  - v3.asset.domain_name
out_selectors:
  - v3.report.vulnerability
supported_architectures:
  - linux/arm64/v8
  - linux/x86_64
docker_file_path: Dockerfile
docker_build_root: .
args:
  # SSH: Linux, macOS, Unix
  - name: ssh_username
    type: string
  - name: ssh_password
    type: string
  - name: ssh_private_key
    type: string
    description: PEM-encoded private key; preferred over ssh_password.
  - name: ssh_private_key_passphrase
    type: string
  - name: ssh_become_method
    type: string
    value: sudo
    description: sudo, su, doas, pbrun, dzdo or none.
  - name: ssh_become_password
    type: string
  # Windows: WinRM first, SMB/WMI fallback
  - name: windows_username
    type: string
  - name: windows_password
    type: string
  - name: windows_domain
    type: string
  - name: windows_auth
    type: string
    value: kerberos
    description: kerberos or ntlm.
  # Scan behaviour
  - name: max_parallel_hosts
    type: number
    value: 10
  - name: host_time_budget_seconds
    type: number
    value: 900
  - name: enable_ioc
    type: boolean
    value: true
  - name: allow_state_changes
    type: boolean
    value: false
    description: Allows opt-in actions such as starting RemoteRegistry; state is restored after the scan.
```

The numeric defaults are starting proposals for review. `v3.asset.link` and `v3.asset.file.api_schema`, which Asteroid takes, are left out: URLs and API schemas are not hosts.

Credentials are explicit arguments: one SSH set and one Windows set per scan, applied to every host. SNMP v3 arguments arrive with phase 4. No argument selects or configures vulnerability sources: every source plugin and its data are embedded in the agent (see [Vulnerability matching](#vulnerability-matching)).

### Inputs, outputs and lifecycle

| Direction | Selector | Use |
| --- | --- | --- |
| In | `v3.asset.ip.v4`, `v3.asset.ip.v6` | Hosts and CIDRs to scan; nmap's `port.service` messages arrive under the same prefix and pick the transport |
| In | `v3.asset.domain_name` | Resolved to IPs, then deduplicated by machine ID |
| Out | `v3.report.vulnerability` | Findings and coverage records |

`process()` handles one asset message:

1. Skip the asset if already processed (`AgentPersistMixin`, as in Asteroid); expand CIDRs with Asteroid's limits (/16 for IPv4, /112 for IPv6).
2. Pick the transport from the open ports and the credentials supplied. No usable pair yields an INFO coverage finding and stops there.
3. Open a session, detect the OS and read the machine ID. A machine ID already scanned in this scan stops there.
4. Run the collectors into the inventory, then close the session.
5. Run the analyzers offline, report findings, and mark the host processed.

Hosts from one CIDR run in parallel up to `max_parallel_hosts`; across messages, the platform's agent replicas scale it.

### Repository and code

Recommendation: its own repository, `agent_host_scanner`, with Asteroid's layout and tooling: `agent/`, `tests/`, `ostorlab.yaml`, `Dockerfile`, and the ruff, mypy and pytest workflows. A second definition inside `agent_asteroid` would share one `agent/` package and pull every exploit module into the build context.

Copied from Asteroid, not imported: the `Vulnerability` dataclass, `compute_dna()`, `build_vuln_location()` and the registry decorator pattern. Nothing from Asteroid is imported at runtime.

### Relationship with Asteroid

Both agents sit in the same agent group, read the same asset messages, and never call each other. The platform correlates their findings by asset and CVE ID: Asteroid reports a potential exposure; Host Scanner confirms or rules it out from the installed version.

CVE-specific host checks live in Host Scanner's custom source plugin, written like Asteroid's detector modules, keyed by CVE ID and seeded from Asteroid's CVE list.

```yaml
kind: AgentGroup
description: Remote and credentialed host scan.
agents:
  - key: agent/ostorlab/nmap
  - key: agent/ostorlab/asteroid
  - key: agent/ostorlab/host_scanner
    args:
      - name: ssh_username
        type: string
        value: svc_scan
      - name: ssh_private_key
        type: string
        value: |
          -----BEGIN OPENSSH PRIVATE KEY-----
          ...
          -----END OPENSSH PRIVATE KEY-----
      - name: windows_username
        type: string
        value: svc_scan
      - name: windows_domain
        type: string
        value: CORP
      - name: windows_password
        type: string
        value: <password>
```

### Internal contracts

Sketch, in the style of Asteroid's `definitions.Exploit`:

```python
class Transport(abc.ABC):
    """One authenticated session to one host: SSH, WinRM or SMB/WMI."""

    capabilities: frozenset[Capability]  # EXEC, FILE_READ, REGISTRY, WMI

    def run(self, command: Command, elevate: bool = False) -> CommandResult: ...
    def read_file(self, path: str, max_bytes: int) -> bytes: ...
    def registry_values(self, key: str) -> dict[str, RegistryValue]: ...
    def wmi_query(self, wql: str) -> list[dict[str, object]]: ...


class Collector(abc.ABC):
    """Fills one part of the inventory; never decides what is vulnerable."""

    platforms: frozenset[OsFamily]
    requires: frozenset[Capability]
    requires_root: bool

    def collect(self, transport: Transport, inventory: HostInventory) -> None: ...


class VulnSource(abc.ABC):
    """A vulnerability source plugin: embedded data plus matching logic."""

    name: str  # "debian", "osv", "msrc", "custom", ...
    precedence: Precedence  # CUSTOM > VENDOR > AGGREGATOR > FALLBACK

    def accept(self, inventory: HostInventory) -> bool: ...
    def match(self, inventory: HostInventory) -> list[Match]: ...
    def data_date(self) -> datetime.date: ...


class HostCheck(abc.ABC):
    """One custom check: written like an Asteroid Exploit, but over the inventory."""

    metadata: VulnerabilityMetadata
    requires: HostRequirements  # extra products, paths, registry keys to collect

    def accept(self, inventory: HostInventory) -> bool: ...
    def check(self, inventory: HostInventory) -> list[Match]: ...


class Check(abc.ABC):
    """Config rule or IoC rule; reads the inventory only."""

    def accept(self, inventory: HostInventory) -> bool: ...
    def check(self, inventory: HostInventory) -> list[Vulnerability]: ...
```

## Architecture

Inside its own container, Host Scanner runs one pipeline per host: resolve credentials, open one session, collect into the inventory, analyze offline, report.

```mermaid
flowchart TD
    inputs["Scan bus inputs<br/>v3.asset.ip v4/v6, domain_name, nmap services"]
    args["Agent arguments<br/>ssh_ and windows_ credentials, not on the bus"]

    subgraph agent["Host Scanner agent · own image, opt-in"]
        resolver["Target and credential resolver<br/>matches each host's open management ports to the supplied credentials"]
        session["Session manager<br/>SSH, WinRM, SMB + WMI, SNMP v3 later<br/>authenticates, escalates privilege,<br/>pins SSH host keys, enforces timeouts"]
        collectors["OS detection and collectors<br/>read-only commands per platform"]
        inventory[("Host inventory<br/>machine ID, OS build, packages as purls,<br/>Windows updates, config facts, IoC artefacts, coverage gaps")]
        vuln["Vuln source plugins<br/>distro, OSV, MSRC, NVD, Apple,<br/>custom checks like Asteroid"]
        config["Config audit<br/>YAML rule packs mapped to CIS / STIG IDs"]
        ioc["IoC engine<br/>persistence, hash intel, CVE-linked artefacts"]
        reporter["Reporter<br/>one finding per host and package, update or rule;<br/>stable DNA; KEV-aware risk; coverage findings"]
    end

    out["v3.report.vulnerability"]
    asteroid["Asteroid agent<br/>remote checks, unchanged"]

    inputs --> resolver
    args --> resolver
    resolver --> session
    session --> collectors
    collectors --> inventory
    inventory --> vuln
    inventory --> config
    inventory --> ioc
    vuln --> reporter
    config --> reporter
    ioc --> reporter
    reporter --> out
    asteroid --> out

    classDef contract stroke-width:3px
    class inventory contract
```

Only the session manager and collectors touch the host; everything below the inventory runs offline. Asteroid reads the same asset messages and reports to the same place, unchanged. Vulnerability source plugins and their data are embedded in the agent, so nothing is fetched at scan time.

## Transports and credentials

The session manager picks a transport from the host's open management ports, authenticates with the credentials passed as agent arguments, and escalates privilege only where a collector needs it.

| Transport | Platforms | Ports | Authentication | Privilege | Library (proposed) |
| --- | --- | --- | --- | --- | --- |
| SSH | Linux, Unix, macOS | 22/tcp | Key (default), certificate, password; jump host | `sudo -n`, `su`, `doas`, `pbrun`/`dzdo` | asyncssh or paramiko |
| WinRM | Windows (preferred) | 5986/tcp HTTPS, 5985/tcp HTTP | Kerberos (default), NTLM; CredSSP off | Local admin for full patch data | pypsrp |
| SMB + WMI/DCOM | Windows fallback | 445/tcp, 135/tcp + dynamic RPC | Kerberos, NTLM with SMB signing | Local admin | impacket (also used by Asteroid) |
| SNMP v3 | Network devices (phase 4) | 161/udp | authPriv only | n/a | pysnmp (also used by Asteroid) |

**Selection order.** Ports come from nmap `port.service` messages when present, else from a TCP connect probe of 22, 5986, 5985 and 445. SSH is tried first, then WinRM, then SMB/WMI. The first transport that authenticates wins.

**Credentials.** Credentials are explicit agent arguments, set in the agent group file. One set per protocol applies to every host in the scan; different accounts per subnet mean separate scans in version 1.

| Argument | Transport | Notes |
| --- | --- | --- |
| `ssh_username` | SSH | Required for SSH |
| `ssh_private_key`, `ssh_private_key_passphrase` | SSH | PEM key; the documented default |
| `ssh_password` | SSH | Used only when no key is given |
| `ssh_become_method`, `ssh_become_password` | SSH | `sudo` (default), `su`, `doas`, `pbrun`, `dzdo` or `none` |
| `windows_username`, `windows_password`, `windows_domain` | WinRM, SMB/WMI | Domain or local account |
| `windows_auth` | WinRM, SMB/WMI | `kerberos` (default) or `ntlm` |

**Credential handling rules**

- Credentials reach the agent only through its arguments, never in bus messages, which every agent in the scan can read.
- Secrets never reach logs, findings or exceptions: a redaction filter keyed on the resolved values wraps the logger.
- Each credential is tried once per host and disabled for the rest of the scan after its first lockout-type error, so one domain account cannot be locked fleet-wide.
- SSH host keys are recorded on first use. A changed key on a later scan blocks password authentication to that host and raises a finding.
- SSH password authentication hands the password to the server, so a compromised host can capture it: keys or certificates are the documented default.
- NTLM can be relayed: WinRM over HTTPS with Kerberos is the Windows default, and the SMB fallback requires signing.
- The agent group file now holds secrets: it stays out of version control, and the platform stores these arguments encrypted and shows them masked.

**Least privilege.** Every collector declares whether it needs root or admin. Without it, the collector is skipped and the gap lands in the coverage record. We ship a sudoers snippet allowing only the collectors' commands, and document which Windows collectors work without local admin.

## Collection and the host inventory

After login, OS detection picks a collector set; each collector runs fixed, read-only commands or API queries and writes typed facts into the inventory.

**OS detection.** On SSH, `uname -s` separates Linux, macOS and other Unix; then `/etc/os-release` (Linux) or `sw_vers` (macOS). On Windows, the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` values `ProductName`, `DisplayVersion`, `CurrentBuild` and `UBR` give the exact patch build.

| Area | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Identity | `/etc/machine-id`, hostname, IPs | `IOPlatformUUID` via `ioreg` | `MachineGuid`, SMBIOS UUID |
| OS and patch level | os-release, `uname -r`, pending reboot (`/var/run/reboot-required`, `needs-restarting -r`) | `sw_vers`, `softwareupdate --history` | Build + UBR; `Win32_QuickFixEngineering` as a hint only |
| Packages | `dpkg-query`, `rpm -qa`, `apk info`, `pacman -Q` | `pkgutil`, app `Info.plist`, Homebrew | Uninstall keys (32- and 64-bit), Appx |
| Services and network | `systemctl`, `ss -tulpn` | `launchctl list`, `lsof -i` | `Win32_Service`, `Get-NetTCPConnection` |
| Accounts | `/etc/passwd`, groups, sudoers, `authorized_keys` | `dscl` users and admins | Local users and groups, LAPS |
| Hardening facts | `sshd -T`, `sysctl`, firewall, mounts | SIP, Gatekeeper, FileVault, firewall | SMBv1, LSA protection, Defender, RDP NLA, audit policy, BitLocker |
| IoC artefacts | cron, systemd units, `ld.so.preload`, SUID files, `/proc/*/exe` | LaunchAgents and LaunchDaemons, login items, profiles | Run keys, services, scheduled tasks, WMI subscriptions |

On macOS, SSH sessions are subject to privacy controls (TCC): some paths need the Remote Login "full disk access for remote users" option, which the onboarding guide must cover.

**Inventory model.** One `HostInventory` per host per scan:

- `identity`: machine ID, hostnames, IPs, transport used, privilege obtained.
- `os`: family, distribution, version, build, running and installed kernel, architecture.
- `packages`: name, version, architecture, source manager, and a package URL (purl) with distro qualifiers, such as `pkg:deb/ubuntu/openssl@<version>?distro=ubuntu-22.04`.
- `updates`: Windows build, UBR and installed KBs.
- `facts`: typed hardening facts, such as `ssh.permit_root_login = "no"`.
- `artefacts`: persistence entries, file hashes, processes and listeners for IoC rules.
- `coverage`: each collector's status (ok, skipped for privilege, failed, timed out) with its error.
- `evidence`: the size-capped raw output behind each fact, quoted in findings.

The inventory serialises to versioned JSON, so recorded inventories double as test fixtures and can later export as a CycloneDX SBOM.

**Collector rules**

- Commands are constants in the collector; no value read from the target is interpolated into a command.
- Every command has a timeout and an output cap, so one slow collector never blocks the others.
- Parsers treat output as hostile: no `eval`, bounded sizes, unknown lines ignored and counted.
- Shell commands run with `LC_ALL=C` and no login profile, so output never depends on locale or user aliases.

## Analysis: vulnerabilities, configuration, compromise

Three analyzers read the inventory; none talks to the host, so all three run offline against recorded inventories.

### Vulnerability matching

The matcher is a set of **source plugins**. Each plugin owns its embedded data, its update script and its matching logic. No agent argument configures them: every plugin whose `accept()` takes the host's inventory runs.

Vendor fix data still wins over upstream version ranges. Distros backport fixes without changing the upstream version, so NVD ranges on distro packages produce false positives.

| Plugin | Embedded data | Covers | Version logic | Precedence | Phase |
| --- | --- | --- | --- | --- | --- |
| `custom` | Hand-written checks, one module per CVE | Whatever each check accepts | Per check | Custom | 1 |
| `debian` | Debian Security Tracker | Debian packages | dpkg | Vendor | 1 |
| `ubuntu` | Ubuntu USN / OVAL | Ubuntu packages | dpkg | Vendor | 1 |
| `rhel_family` | Red Hat, Rocky, Alma and Oracle errata (OVAL or CSAF/VEX) | RHEL and its rebuilds | rpm EVR | Vendor | 1 |
| `suse` | SUSE OVAL | SLES, openSUSE | rpm EVR | Vendor | 1 |
| `amazon` | Amazon Linux ALAS | Amazon Linux | rpm EVR | Vendor | 1 |
| `alpine` | Alpine secdb | Alpine | apk | Vendor | 1 |
| `osv` | OSV.dev bulk exports | Distros and language ecosystems OSV covers | Per ecosystem | Aggregator | 1 |
| `endoflife` | endoflife.date | OS and product releases | Release cycle | End-of-life findings only | 1 |
| `msrc` | MSRC security update data | Windows OS | Build + UBR | Vendor | 2 |
| `nvd` | NVD CPE ranges + curated name-to-CPE map | Third-party Windows and macOS apps | Per product | Fallback | 2 |
| `apple` | Apple security release notes | macOS | macOS version | Vendor | 3 |

CISA KEV and FIRST EPSS are embedded too, as enrichment for risk rating rather than as plugins. The `univers` library (aboutcode) implements dpkg, rpm and apk comparison; we adopt it only after it passes each tool's own test vectors.

**Merging.** Each plugin returns matches: package or product, installed version, fixed version, CVE IDs, source and evidence. For one host, package and CVE, the highest precedence wins: custom, then vendor, then aggregator, then fallback. A vendor "fixed" or "not affected" answer drops lower-precedence matches for that CVE.

**Running versus installed.** A patched kernel that is not yet running is still exploitable: plugins match the running kernel version, and pending reboots are reported.

**Plugin layout.** Feed-based plugins share one normalised schema, `(ecosystem, package, affected range, fixed version, CVE, severity)`, and one matcher base class; only their update script differs.

```text
agent/sources/
  debian/
    __init__.py          # DebianSource(VulnSource), registered
    update.py            # downloads and normalises the feed
    data/debian.sqlite.zst
  osv/ ...
  custom/
    __init__.py          # CustomSource: runs every registered HostCheck
    checks/
      cve_2025_53770.py
```

**Embedded data and freshness.** Plugin data ships in the source tree and the image; the agent fetches nothing at scan time. A scheduled CI workflow runs every `update.py`, opens a pull request and cuts a release once tests pass. Each finding records its sources' data dates, and an INFO coverage finding flags data older than an agreed threshold.

**Alternative considered.** Grype or Trivy could later run as one more plugin over a CycloneDX export of the inventory. Neither covers Windows patch levels, so neither replaces the plugin set.

### Custom checks

The `custom` plugin works like Asteroid: one Python module per CVE, registered with a decorator, carrying `VulnerabilityMetadata` with `accept()` and `check()`. It covers what feeds miss:

- Server software without a usable feed, such as SharePoint or Confluence installs.
- CVEs that depend on configuration: vulnerable only when a feature is on or a mitigation is absent.
- Artefacts left by exploitation of one CVE, such as a known web shell.
- Host-side confirmation of the CVEs Asteroid detects remotely, under the same CVE ID.

A check never touches the host. It declares the extra products, paths and registry keys it needs, and a generic collector gathers them during collection.

```python
@checks_registry.register
class SharePoint53770Check(definitions.HostCheck):
    """CVE-2025-53770: SharePoint build below its edition's fixed build, or the known web shell present."""

    metadata = definitions.VulnerabilityMetadata(
        title="Microsoft SharePoint Server remote code execution (CVE-2025-53770)",
        description="...",
        reference="CVE-2025-53770",
        cve_ids=["CVE-2025-53770"],
        risk_rating="CRITICAL",
    )
    requires = definitions.HostRequirements(
        products=["Microsoft SharePoint Server"],
        paths=["<SharePoint LAYOUTS folder>/spinstall0.aspx"],
    )

    def accept(self, inventory: HostInventory) -> bool:
        return inventory.has_product("Microsoft SharePoint Server")

    def check(self, inventory: HostInventory) -> list[Match]:
        ...  # edition build vs. its fixed build; web shell at the declared path
```

### Configuration audit

Rules are YAML files, one per rule, reviewed like code. Conditions are structured data, never evaluated expressions:

```yaml
id: linux-ssh-root-login
title: SSH permits root login
platforms: [linux, macos]
fail_when:
  fact: ssh.permit_root_login
  not_in: ["no", "prohibit-password"]
risk: HARDENING
references: {cis: "<control id>", stig: "<rule id>"}
recommendation: Set PermitRootLogin to no in sshd_config and reload sshd.
```

A missing fact makes the rule "not evaluated" in the coverage record, never a pass or a fail. The starter pack covers the highest-impact areas per platform: remote access (SSH, RDP, SMB), authentication (NTLM, LLMNR, sudo), disk encryption, firewall, endpoint protection status and automatic updates.

### Indicators of compromise

IoC rules read the inventory's `artefacts`, in three confidence tiers:

| Tier | Example | Risk |
| --- | --- | --- |
| Known-bad indicator | File hash listed in a threat-intel feed | CRITICAL |
| CVE-linked artefact, declared by a custom check | For CVE-2025-53770, the `spinstall0.aspx` web shell in SharePoint's `LAYOUTS` folder | CRITICAL |
| Suspicious state | Process running from a deleted binary, a second UID 0 account, an `ld.so.preload` entry, a WMI event subscription | POTENTIALLY |

Collection stays bounded: hashes are computed on the host (`sha256sum`, `Get-FileHash`) only in hot paths such as persistence targets, temp directories and web roots, with size caps. File contents never leave the host unless the customer opts in, for example to run YARA on small web-root scripts. Windows event-log queries (service installs, log clears, new scheduled tasks) arrive in phase 3.

## Reporting

Findings are aggregated so a stale host yields tens of findings rather than thousands, and each one is fixed by a single change.

| Finding family | One finding per | Risk | DNA key |
| --- | --- | --- | --- |
| Missing security update | Host + package | Highest CVE severity; any CVE on CISA KEV lifts it to at least HIGH | Machine ID + package name |
| Missing Windows update | Host + cumulative update family | Same rule | Machine ID + product + update family |
| End-of-life OS or software | Host + product | HIGH | Machine ID + product |
| Insecure configuration | Host + rule | Rule-defined, usually HARDENING | Machine ID + rule ID |
| Indicator of compromise | Host + indicator | CRITICAL or POTENTIALLY by tier | Machine ID + rule ID + path or hash |
| Coverage gap | Host + collector, or failed login | INFO | Machine ID (IP before login) + collector |

Versions stay out of the DNA, so a partial patch updates the same finding and a full patch closes it.

When several source plugins match the same package, the finding merges their CVEs and names each source; the source is not part of the DNA.

**Location.** `vulnerability_location` carries the IP or domain asset plus existing `MetadataType` values: `PACKAGE_NAME` for packages, `FILE_PATH` for artefacts and configuration files, `PORT` for exposed services.

**Technical detail** (shape, placeholder values):

```text
Host: web-01 (10.0.4.12, machine-id 3f9c...), Ubuntu 22.04, via SSH as svc_scan (sudo)
Package: openssl <installed version> (dpkg)
Fixed in: <fixed version> (USN-NNNN-N)
CVEs: CVE-YYYY-NNNNN, CVE-YYYY-NNNNN (1 on CISA KEV)
Evidence: dpkg-query -W openssl -> "openssl <installed version>"
```

The wording differs from Asteroid's remote checks on purpose: a host finding states a **confirmed vulnerable version present**, while a remote check reports a potential exposure.

## Safety, security and operations

The scanner holds privileged credentials to a whole fleet and logs in to hosts that may already be compromised; the design assumes both.

- **Read-only.** Collectors use an allow-list of commands reviewed in code, and a test fails if any other command is sent. No file writes, service changes or package-index refreshes (`apt update` is out).
- **State changes are opt-in.** Remote registry over SMB needs the RemoteRegistry service, often stopped on client editions. Starting it is opt-in, and the scanner restores the original state afterwards.
- **Hostile targets.** A compromised host controls every byte it returns: parsers are bounded and fuzzed, output is never executed, and evidence is quoted as text.
- **Credential exposure.** Key auth over SSH, Kerberos over HTTPS for WinRM, CredSSP off, SMB signing required. The scanner never forwards SSH agents or delegates credentials.
- **Load.** Configurable host concurrency per scan, one session per host, per-command timeouts and a per-host time budget.
- **Noise.** Logins show up in auth logs and EDR telemetry. We document the scanner's source IP, account and command list so SOC teams can allow-list it.
- **Data minimisation.** Inventories hold package and configuration data, not file contents. Evidence is truncated, and a redaction pass masks secrets read by accident, such as a password in a config line.
- **Supply chain.** The new SSH and WinRM clients are pinned and reviewed; embedded source data and custom checks change only through reviewed pull requests.
- **Opt-in agent.** Host Scanner is in no default agent group. It runs only where a customer adds it with credentials, so a standard scan never logs in to anything.

## Testing

Recorded host output is the main fixture, so most tests run in pytest with no network. The repository reuses Asteroid's test layout and its ruff, mypy and pytest CI workflows.

1. **Parsers.** Real outputs of `dpkg-query`, `rpm -qa`, `sw_vers`, registry dumps and WMI results, recorded per OS version, each with a golden inventory.
2. **Version comparison.** dpkg, rpm and apk vectors taken from each tool's own test suite.
3. **Matcher accuracy.** Inventories from old, known-vulnerable distro container images compared with Grype on the same images. Every difference is triaged and either fixed or documented.
4. **Windows matching.** Recorded build, UBR and KB sets from lab VMs checked against MSRC data for known months.
5. **Rules.** Each config rule, IoC rule and custom check ships with a passing and a failing inventory fixture.
6. **Lab integration.** A docker-compose lab of SSH-enabled Debian, Ubuntu, Rocky and Alpine containers with planted misconfigurations and IoC artefacts (fake cron persistence, an `ld.so.preload` entry, the EICAR test file). A Windows Server VM and a macOS runner join in a nightly job.
7. **Safety.** Before/after diffs of file system, services and packages on lab targets must be empty; an allow-list test covers every command sent; parsers are fuzzed with hostile output.
8. **Source merging.** Conflicting plugin answers, such as a vendor "fixed" against an OSV "affected", resolve by precedence; each plugin's update script is tested against a recorded feed sample.

## Delivery plan

Linux ships first because SSH plus distro advisories gives the most coverage for the least new surface; Windows, macOS and IoC detection follow, each behind an exit gate.

```mermaid
flowchart TD
    p0["Phase 0 · Spike<br/>SSH + dpkg demo, plugin contract,<br/>credential flow, repo + skeleton"]
    g0{{"Gate 0: open questions closed in review"}}
    p1["Phase 1 · Linux MVP<br/>SSH + sudo, deb/rpm/apk, source plugins,<br/>EOL + config, coverage records"]
    g1{{"Gate 1: Grype parity on lab images; zero target changes"}}
    p2["Phase 2 · Windows<br/>WinRM, SMB/WMI, build + UBR, MSRC matching,<br/>top apps to CPE, config rules"]
    g2{{"Gate 2: MSRC matches verified on lab Windows builds"}}
    p3["Phase 3 · macOS + IoC<br/>macOS over SSH, persistence, hash intel,<br/>CVE-linked IoCs, event logs"]
    g3{{"Gate 3: IoC false positives reviewed on a clean fleet"}}
    p4["Phase 4 · Breadth<br/>SNMPv3 + CLI, network devices, containers,<br/>language packages, hypervisors"]

    p0 --> g0 --> p1 --> g1 --> p2 --> g2 --> p3 --> g3 --> p4

    classDef mvp stroke-width:3px
    class p1 mvp
```

Phase 1 is the first release customers can enable. Durations are left for the spike to estimate; the gates, not dates, decide when the next phase starts.

## Open questions for reviewers

Decided: Host Scanner is a new, dedicated agent; credentials are explicit agent arguments; vulnerability data comes from embedded source plugins, including Asteroid-style custom checks. Gate 0 closes when each question below has an owner and a decision; the recommendation is stated where there is one.

- [ ] **Repository.** Its own repository, `agent_host_scanner` (recommended), or a second agent definition inside `agent_asteroid`? Also confirm the store publishing flow for whichever we pick.
- [ ] **Credential masking.** Does the platform store agent arguments encrypted and show them masked today? If not, that is a prerequisite for phase 1.
- [ ] **Correlation with Asteroid.** Is platform-side correlation by asset and CVE ID enough, or should Host Scanner also consume Asteroid's findings to confirm or refute them explicitly?
- [ ] **Inventory output.** Emit the inventory as its own message (a new selector) for other agents and the asset graph, or keep it inside findings?
- [ ] **KB entries.** Reuse existing Ostorlab KB entries for outdated software and misconfiguration, or add the six finding families above?
- [ ] **Benchmarks.** May rule IDs map to CIS Benchmarks under CIS licensing terms, or do we map to DISA STIG only?
- [ ] **First plugins.** Which source plugins ship in phase 1? Recommendation: `custom`, `debian`, `ubuntu`, `rhel_family`, `alpine`, `osv` and `endoflife`, with `suse` and `amazon` if the spike shows their feeds are clean.
- [ ] **Feed coverage.** The spike confirms which distros publish complete OSV data and which need OVAL or CSAF.
- [ ] **Windows depth.** Is local admin an acceptable prerequisite for Windows patch data in version 1?
- [ ] **Name.** "Host Scanner" (`agent/ostorlab/host_scanner`) is a working name.
- [ ] **Several credential sets.** Version 1 takes one SSH and one Windows credential per scan. Do customers need per-subnet accounts within one scan?
- [ ] **Plugin data in the repository.** Commit each plugin's compressed data directly, or move large ones to Git LFS? The spike measures the sizes.
