# Gitea coverage: Nuclei templates first published in 2026

This batch adds **four registered remote read-only checks for potential release
exposure** and **one offline owner-inventory assessment**. It covers Gitea-related
Nuclei detections first published in 2026, including the older CVE-2021-45328.
The applicability decisions were verified against upstream advisories and tagged
source on 2026-11-05.

This is one implementation batch from the
[2026 scanner-gap audit (PR #278)](https://github.com/Ostorlab/agent_asteroid/pull/278).
It does not close the remaining coverage backlog identified by that audit.

| CVE | Coverage | Affected interval reported by this check | Fixed release |
| --- | --- | --- | --- |
| CVE-2026-59774 | Registered, read-only release exposure | 1.22.1 through 1.27.0 | 1.27.1 |
| CVE-2026-60004 | Registered, read-only release exposure | 1.17.0 through 1.27.0 | 1.27.1 |
| CVE-2026-27771 | Registered, read-only Composer source-link exposure | 1.24.0 through 1.26.1 (detector start from PR 33502 source-field provenance; advisory states only <=1.26.1) | 1.26.2 |
| CVE-2021-45328 | Registered, read-only release exposure | 1.x before 1.4.3 | 1.4.3 |
| CVE-2026-20896 | Offline owner-inventory assessment only | Official Docker 1.x through 1.26.2, with all effective prerequisites supplied | Image default removed in 1.26.3; verify existing configuration |

These are **potential exposure** findings, not successful exploitation findings.
A negative result does not establish that a target is patched. Hidden metadata,
custom branding, prereleases, development/build suffixes, and conflicting
signals remain inconclusive. Vendor backports cannot be verified remotely.

## Which Nuclei templates back these checks?

The template links below are pinned to the audited Nuclei snapshot
`fef763cd6e1da264eca8668741edef52faa743f6`. Each date links to the original
first-main template revision. These UTC first-parent commit dates are the
audit's reproducible publication proxy, not CVE publication dates.

| Nuclei template ID | First-main date (UTC) |
| --- | --- |
| [CVE-2026-59774](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-59774.yaml) | [2026-08-13](https://github.com/projectdiscovery/nuclei-templates/blob/29f6cd8c9638748c565d8c4a76fc141130c9e130/http/cves/2026/CVE-2026-59774.yaml) |
| [CVE-2026-60004](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-60004.yaml) | [2026-08-03](https://github.com/projectdiscovery/nuclei-templates/blob/984c74d51c2d00293cd03d39b07ab006c6d8eec0/http/cves/2026/CVE-2026-60004.yaml) |
| [CVE-2026-27771](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-27771.yaml) | [2026-05-30](https://github.com/projectdiscovery/nuclei-templates/blob/031cecd5ce87d75fd6488f8247d8b3919050e940/http/cves/2026/CVE-2026-27771.yaml) |
| [CVE-2021-45328](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2021/CVE-2021-45328.yaml) | [2026-04-22](https://github.com/projectdiscovery/nuclei-templates/blob/3005b49e8885e7cea70833a0c9861a2d5ebac71f/http/cves/2021/CVE-2021-45328.yaml) |
| [CVE-2026-20896](https://github.com/projectdiscovery/nuclei-templates/blob/fef763cd6e1da264eca8668741edef52faa743f6/http/cves/2026/CVE-2026-20896.yaml) | [2026-08-19](https://github.com/projectdiscovery/nuclei-templates/blob/48340f699f1021b56b9facef9c4e79dbd9c08137/http/cves/2026/CVE-2026-20896.yaml) |

## What does each remote check request and verify?

The four remote checks load automatically during normal Asteroid scans. To scope
the scan, set the [`custom_cve_list` agent argument](../ostorlab.yaml) to
`CVE-2026-59774`, `CVE-2026-60004`, `CVE-2026-27771` and `CVE-2021-45328`.
See the [scanner usage instructions](../README.md) for installation and invocation.
The offline Docker assessment below is not enabled by that argument.

Each check performs at most two anonymous GETs: `api/v1/version`, then the
homepage, relative to `/` or an explicitly supplied deployment directory ending
in `/` (for example `/git/`). Query strings/fragments are removed. Arbitrary
application paths and unsafe path segments are not probed. Each body is bounded
to 256 KiB with a five-second timeout; credentials and cookies are excluded,
and redirects are never followed. `accept()` and `check()` each obtain fresh
evidence, so the normal scanner lifecycle makes at most four GETs per policy.

The version API response JSON must contain exactly one canonical numeric
`version` field. The homepage must have Gitea's default `meta name="author"` value and an official
Gitea link in its footer. Conflicting author/generator/fork indicators, duplicate
attributes, malformed identity sections, and different footer version labels
are rejected. The finding location and stable deduplication identity use the
observed deployment root.

Sources for these real metadata surfaces:

- [API ServerVersion implementation](https://github.com/go-gitea/gitea/blob/v1.27.0/routers/api/v1/misc/version.go)
- [Head author metadata](https://github.com/go-gitea/gitea/blob/v1.27.0/templates/base/head.tmpl)
- [Default MetaAuthor](https://github.com/go-gitea/gitea/blob/v1.27.0/modules/setting/ui.go)
- [Current footer](https://github.com/go-gitea/gitea/blob/v1.27.0/templates/base/footer_content.tmpl), [1.17 footer](https://github.com/go-gitea/gitea/blob/v1.17.0/templates/base/footer_content.tmpl), and [1.4.2 footer](https://github.com/go-gitea/gitea/blob/v1.4.2/templates/base/footer.tmpl)

## How are affected intervals derived, and where does coverage stop?

Intervals combine the vendor advisory with tagged-source evidence; source-derived
lower bounds are labeled explicitly. A disputed release remains inconclusive
when the available evidence does not establish a consistent boundary.

**CVE-2026-59774:** [The vendor advisory](https://github.com/go-gitea/gitea/security/advisories/GHSA-6v53-hr58-556r)
lists `1.22 < 1.27.1`, but its narrative starts at 1.22.1. The detector uses the
intersection and leaves 1.22.0 inconclusive. Tagged 1.22.0/1.22.1 source uses
`org.New()` and the same go-org dependency; the conservative exclusion avoids
claiming an exact lower boundary that the advisory does not state consistently.

- **Fixed-side evidence:** [the 1.27.1 renderer](https://github.com/go-gitea/gitea/blob/v1.27.1/modules/markup/orgmode/orgmode.go)
  disables `ReadFile`.
- **Not established remotely:** anonymous reachability requires a public
  repository with a readable code unit; the further execution chain depends on
  storage permissions. Neither prerequisite is established by metadata.
- **Not sent:** markup or file-read payloads.

**CVE-2026-60004:** [The vendor advisory](https://github.com/go-gitea/gitea/security/advisories/GHSA-rcr6-4jqh-j84m)
states `>=1.17, <1.27.1`; the
[1.17 API patch handler](https://github.com/go-gitea/gitea/blob/v1.17.0/routers/api/v1/repo/patch.go)
exists. Exploitation requires an authenticated repository writer. The detector
does not authenticate, submit a patch, or modify a repository.

**CVE-2026-27771:** [The vendor advisory](https://github.com/go-gitea/gitea/security/advisories/GHSA-8qw8-rq86-9pc2)
gives `<=1.26.1` and fixed 1.26.2, without a technical narrative.
[The vendor 1.26.2 release](https://blog.gitea.com/release-of-1.26.2/)
explicitly associates this CVE with [PR 37610](https://github.com/go-gitea/gitea/pull/37610),
the Composer source permission check.

- **Detector start 1.24.0:** the source field was added in
  [PR 33502](https://github.com/go-gitea/gitea/pull/33502), appears in
  [1.24.0](https://github.com/go-gitea/gitea/blob/v1.24.0/routers/api/packages/composer/api.go),
  and is absent from
  [1.23.0](https://github.com/go-gitea/gitea/blob/v1.23.0/routers/api/packages/composer/api.go).
- **Not claimed:** private-container access. A nonempty registry catalog alone
  does not establish that private packages were disclosed; the template's other
  cited [PR 37290](https://github.com/go-gitea/gitea/pull/37290) concerns permitting
  normal public registry access.
- **Unverified:** package availability, repository visibility and permissions.

**CVE-2021-45328:** The 2026 publication cohort includes this older CVE.
[The cited vendor release](https://blog.gitea.com/release-of-1.4.3/)
fixes a login redirect in 1.4.3. The other CVE reference,
[issue 4332](https://github.com/go-gitea/gitea/issues/4332), was closed for a later
internal-link fix. This detector uses the CVE's stated pre-1.4.3 release scope;
it does not infer a new affected interval or a behavioral oracle from the later
issue. It sends no redirect payload or login request.

**CVE-2026-20896:** [The Docker advisory](https://github.com/go-gitea/gitea/security/advisories/GHSA-f75j-4cw6-rmx4)
requires enabled reverse-proxy authentication, wildcard trusted proxies, and
access to the container outside the intended authenticating proxy. Binary and
source builds do not inherit the affected image default. Public Gitea version
metadata cannot establish these facts, so this CVE is not registered for remote
scanning and is not selected by `custom_cve_list`.

Use the existing inventory CLI to assess **CVE-2026-20896 on an official Gitea
Docker deployment**, supplying normalized owner evidence for its running version
and effective configuration:

```json
[{"product":"Gitea","version":"1.26.2","deployment":"official-docker","reverse_proxy_authentication":true,"reverse_proxy_trusts_all":true,"direct_container_access":true}]
```

```sh
python -m agent.utils.inventory inventory.json
```

The boolean fields describe effective settings and reachability, not image
default assumptions. Missing or nonboolean evidence is inconclusive; a verified
absent prerequisite is not matched. The
[1.26.2 template](https://github.com/go-gitea/gitea/blob/v1.26.2/docker/root/etc/templates/app.ini)
sets wildcard trust and the
[1.26.3 template](https://github.com/go-gitea/gitea/blob/v1.26.3/docker/root/etc/templates/app.ini)
removes it. A newer version with supplied wildcard trust remains inconclusive
because an upgrade can preserve existing configuration. The assessment never
uses impersonation headers or independently authenticates inventory evidence.
