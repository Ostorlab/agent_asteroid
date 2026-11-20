# Assess nginxWebUI installations for CVE-2023-54419

**CVE-2023-54419 is an authentication bypass** in nginxWebUI 3.0.0 through
3.5.7 that can lead to unauthenticated command execution. The upstream fix
ships in 3.5.8. See the [CVE record](https://www.cve.org/CVERecord?id=CVE-2023-54419)
and the [upstream fix commit](https://github.com/cym1102/nginxWebUI/commit/6b8c9bceb0d210632a35cd324db6b43caf442a23).

## How do I identify potentially affected installations?

Use a deployment manifest or SBOM tied to the running image digest. If the
deployed JAR includes Maven metadata, read its `version` field locally:

```sh
unzip -p nginxWebUI.jar META-INF/maven/com.cym/nginxWebUI/pom.properties
```

The inventory check uses this local evidence to identify affected versions
without contacting the service. Record one entry per installation in a JSON
array using the exact upstream release.

Save this example as `inventory.json` and replace the version with your evidence.

```json
[{"product": "nginxWebUI", "version": "3.4.8"}]
```

```sh
python -m agent.utils.inventory inventory.json
```

The assessment runs locally. An affected upstream release returns
`potential_exposure` based on the supplied version. A missing or ambiguous
release or a custom build returns `inconclusive`.

For a distributor or custom build, record its provenance explicitly.

```json
[{"product": "nginxWebUI", "version": "3.4.8", "build_provenance": "custom"}]
```

Custom builds return `inconclusive` because the upstream version cannot
establish their patch state. Compare the deployed build's patch history
with the [upstream fix commit](https://github.com/cym1102/nginxWebUI/commit/6b8c9bceb0d210632a35cd324db6b43caf442a23).

## Which nginxWebUI versions does the assessment flag?

| Upstream version or build | Expected result |
| --- | --- |
| 2.9.9 | `not_matched` |
| 3.0.0 through 3.5.7 | `potential_exposure` |
| 3.5.8 and 3.10.0 | `not_matched` |
| Missing version, 0.0.0 placeholder or custom build | `inconclusive` |

## How do I verify the upgrade?

Deploy upstream nginxWebUI 3.5.8 or later and restart every instance. Refresh
the inventory from each running instance, then run
`python -m agent.utils.inventory inventory.json` again.
A verified upstream 3.5.8 or later release returns `not_matched` for this CVE.
