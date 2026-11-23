# CVE-2025-66516: Apache Tika XFA XML external entity injection

**CVE-2025-66516 is an XML external entity (XXE) injection** in Apache Tika
(CWE-611, CVSS 3.1 8.4). Tika processes the XFA form inside a crafted PDF
without disabling external entities, so a `file:///` entity in the XFA XML is
resolved during text extraction and its contents are returned.

**Affected:** tika-core 1.13-3.2.1, tika-pdf-module 2.0.0-3.2.1, tika-parsers
1.13-1.28.5

**Fixed:** tika-core >= 3.2.2 (with updated tika-pdf-module and tika-parsers)

**Severity:** CVSS 3.1 8.4 (High) — `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

NVD scores the attack vector as Local (`AV:L`) because exploitation requires a
crafted document to be submitted into Tika's parsing pipeline. Where
`tika-server` is exposed, that document is delivered over HTTP — as this
detector does with `PUT /tika` — but the vector above follows NVD's scoring.

## How does the detector verify it?

This is an **active, non-destructive benign file read**. It submits one PDF to
the stateless `PUT /tika` extraction endpoint whose XFA template declares a
`file:///etc/passwd` SYSTEM entity, and confirms the account listing is
reflected in the extracted text:

```
PUT /tika            Content-Type: application/pdf
  <crafted PDF: <!ENTITY xxe SYSTEM "file:///etc/passwd"> ... &xxe;>
# confirm: response body matches  root:...:0:0:
```

The `/tika` endpoint only parses and returns text; it persists nothing. Only
`/etc/passwd` — a world-readable file with no secret — is read. The passwd
pattern cannot appear by reflection of the request, so a match proves Tika
resolved the external entity and read a local file. No credential or cookie is
sent and redirects are not followed.

## Remediation

Upgrade tika-core to 3.2.2 or later and update tika-pdf-module and tika-parsers
to the latest versions. Do not expose the Tika server extraction endpoint to
untrusted clients, and run it with external entity resolution disabled.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-66516> (published 2025-12-04,
  CWE-611, CVSS 3.1 8.4).
- Write-up and PoC:
  <https://github.com/chasingimpact/CVE-2025-66516-Writeup-POC>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-66516>.
