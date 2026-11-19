# Java Shell library exposure assessments

Log4Shell (CVE-2021-44228), Spring4Shell (CVE-2022-22965), and Text4Shell
(CVE-2022-42889) support both anonymous remote package evidence and trusted
owner inventory. Neither mode sends exploitation payloads or confirms RCE.

## How does remote SBOM package evidence work?

Each detector makes one anonymous GET to `/actuator/sbom/application`, the
[documented Spring Boot Actuator application SBOM endpoint](https://docs.spring.io/spring-boot/3.5/api/rest/actuator/sbom.html).
Redirects and session credentials are excluded; the streamed body is bounded
to 1 MiB. Only CycloneDX 1.4–1.7 JSON top-level library components with exact
Maven `group`, `name`, and canonical `version` are assessed. A supplied `purl`
must agree (`pkg:maven/GROUP/NAME@VERSION`, optionally `?type=jar`). Different
versions of the same artifact are assessed separately, so a fixed copy does
not hide an affected copy. Metadata descriptions, application names, nested
components and other SBOM formats are not used as package evidence.

Findings say **POTENTIAL SBOM PACKAGE EXPOSURE**. A remotely exposed SBOM can
be stale or customized and does not establish runtime loading, input paths,
backports or effective configuration. Missing, inaccessible, malformed or
ambiguous SBOM evidence yields no finding and does not establish a patched
target. The endpoint is opt-in and typically absent on older applications;
trusted inventory covers deployments that do not expose it.

## How does trusted inventory assessment work?

Collect evidence for the actual loaded artifacts of the same running target.
Dependency declarations or a host application's version alone are insufficient.
Save a JSON array and run:

```shell
python -m agent.utils.inventory inventory.json
```

Usable input examples:

```json
[
  {
    "product": "org.apache.logging.log4j:log4j-core",
    "version": "2.14.1",
    "jndi_lookup_present": true,
    "untrusted_log_input": true,
    "fix_status": "not-applied"
  },
  {
    "product": "org.springframework:spring-webmvc",
    "version": "5.3.17",
    "java_major": 17,
    "packaging": "war",
    "servlet_container": "Apache Tomcat",
    "untrusted_data_binding": true,
    "fix_status": "not-applied"
  },
  {
    "product": "org.apache.commons:commons-text",
    "version": "1.9",
    "string_substitutor_active": true,
    "untrusted_substitution_input": true,
    "dangerous_lookups_enabled": true,
    "fix_status": "not-applied"
  }
]
```

Exact `product` and canonical `version` are required:

- Log4j accepts two- or three-component numeric releases and published
  `2.0-beta1`–`2.0-beta9`, `2.0-rc1`, and `2.0-rc2`.
- Spring accepts three-component releases with optional `.RELEASE` for
  `org.springframework:spring-webmvc` or `org.springframework:spring-webflux`.
  `spring-beans` alone is not a supported product identity for this assessment.
- Commons Text accepts two- or three-component numeric releases.
- Other prerelease, custom, or build suffixes require manual review.

Assessment outcomes are:

- **`potential_exposure`**: an affected release matches; prerequisite and
  backport assertions remain unverified, and exploitation is unconfirmed.
- **`inconclusive`**: identity or version evidence is unsupported or ambiguous,
  supplied configuration fields are malformed, `fix_status` is unsupported,
  or `conflicting_evidence` is true. Spring executable-JAR and non-Tomcat
  evidence also leave other possible exploit paths unresolved.
- **`not_matched`**: the supplied release is outside this CVE's affected ranges,
  the owner reports its verified fix applied, or a required path is explicitly
  absent. This result never establishes blanket safety.

Prerequisite boolean fields may be omitted or `null` when unknown.
`fix_status` may be omitted or `null` when unknown, `not-applied`, or `applied`;
`applied` excludes this CVE only, based on owner evidence. Only assessment fields
are emitted, never supplied secrets or arbitrary record contents. This CLI does
not collect, authenticate, or remotely verify the supplied inventory.

Each assessor consumes only its family's fields; unrelated fields are ignored.

| Evidence fields | Family | Accepted values |
| --- | --- | --- |
| `jndi_lookup_present`, `untrusted_log_input` | Log4Shell | Effective booleans; omit or use `null` when unknown. |
| `untrusted_data_binding` | Spring4Shell | Effective boolean; omit or use `null` when unknown. |
| `string_substitutor_active`, `untrusted_substitution_input`, `dangerous_lookups_enabled` | Text4Shell | Effective booleans; omit or use `null` when unknown. |
| `java_major` | Spring4Shell | Positive integer, or omitted/`null` when unknown; booleans are not integers here. |
| `packaging` | Spring4Shell | `war`, `executable-jar`, or omitted/`null` when unknown. |
| `servlet_container` | Spring4Shell | Nonempty container name, or omitted/`null` when unknown. Only `Apache Tomcat` establishes the demonstrated container prerequisite. |
| `fix_status` | All three | `not-applied`, `applied`, or omitted/`null` when unknown. |
| `conflicting_evidence` | All three | Omitted or `false` means no reported conflict; `true` or a malformed value produces `inconclusive`. |

## Advisory boundaries and prerequisites

| Family | Affected releases | Required path and exclusions |
| --- | --- | --- |
| [Log4Shell](https://logging.apache.org/security.html#CVE-2021-44228) | `[2.0-beta9,2.3.1)`, `[2.4,2.12.2)`, `[2.13.0,2.15.0)` | `log4j-core`, JNDI lookup, untrusted logging input. Verified `jndi_lookup_present: false` excludes this path. `log4j-api` alone is not this component. Original fixes do not settle later Log4j CVEs. |
| [Spring4Shell](https://spring.io/security/cve-2022-22965/) | Through `5.2.19.RELEASE`, plus `5.3.0`–`5.3.17` | JDK 9+ and webmvc/webflux. The demonstrated exploit also needs Tomcat WAR deployment and untrusted data binding. `java_major` below 9 or `untrusted_data_binding: false` excludes this CVE's prerequisite. `packaging: executable-jar` or another container yields `inconclusive`: other possible paths remain unresolved. |
| [Text4Shell](https://blogsarchive.apache.org/security/entry/cve-2022-42889) | `1.5`–`1.9`, fixed in `1.10.0` | Active StringSubstitutor, untrusted substitution input and dangerous lookups must coincide. Any verified false prerequisite excludes this path. The fixed default does not establish safety for explicitly configured dangerous lookups. |

A `not_matched` result is limited to this CVE and supplied evidence, never a
blanket safety claim. Effective prerequisite and backport assertions must cover
all loaded copies. Upgrade to current supported fixed versions.

Spring's [vendor CNA record](https://www.cve.org/CVERecord?id=CVE-2022-22965)
explicitly includes "all old and unsupported versions" alongside the 5.2 and
5.3 ranges. The assessment therefore also reports potential exposure for older
releases such as `4.3.30.RELEASE` and `5.1.20.RELEASE`, with the same JDK and
application prerequisites left explicit.
