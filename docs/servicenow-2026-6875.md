# ServiceNow CVE-2026-6875 unauthenticated remote code execution

**CVE-2026-6875** is an unauthenticated remote code execution flaw in the
ServiceNow AI Platform. The unauthenticated `/assessment_thanks.do` endpoint
evaluates the `javascript:` prefix of its `sysparm_assessable_type` filter
inside a script sandbox; a public sandbox escape reaches
`GlideController.evaluateAsObject` and runs arbitrary server-side JavaScript
(CWE-94).

## Which advisory and references confirm the vulnerability?

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-6875> (published
  2026-07-13T19:17Z by the ServiceNow PSIRT, CWE-94, CVSS 4.0 9.5
  `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`).
- ServiceNow advisory:
  <https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB3137947>.
- Technical write-up (Assetnote / SearchLight Cyber, 2026-07-14):
  <https://slcyber.io/research-center/smashing-the-servicenow-sandbox-pre-authentication-rce/>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-6875>.

## Affected and fixed versions

The advisory lists these first fixed points per family release: Australia
Patch 2; Yokohama Patch 12 Hot Fix 1b and Patch 13; Zurich Patch 7b and Patch
9; Brazil EA/GA. ServiceNow updated hosted instances directly and provided
updates to self-hosted customers and partners. ServiceNow stated it was not
aware of exploitation at publication.

## How the detection confirms it, safely

1. **Attribution** — `GET /login.do` must contain one of the markers
   `servicenow`, `glide` or `sysparm` (case-insensitive). The probe is sent
   only to a confirmed ServiceNow instance.
2. **Evidence** — `GET /assessment_thanks.do` with a `sysparm_assessable_type`
   payload that evaluates `gs.addInfoMessage(a*b)`, where `a` and `b` are two
   random integers between 100 and 999 chosen for that single request. The
   finding is reported only when the HTML response reflects the product `a*b`.

Because the expected product is computed from random factors and never appears
in the request, a page that merely echoes request text cannot match it — the
endpoint must have executed the expression. The payload only adds an info
message: it reads no file, creates or modifies no record, sends no credential
or cookie, and follows no redirect. Responses are byte-capped.

The sandbox-escape wrapper (defining `Object.clone`, overriding
`AbstractAjaxProcessor.prototype`, then calling
`ItemViewElementsProvider.prototype()`) is the public proof-of-concept shape;
only the arithmetic inside `gs.addInfoMessage(...)` is varied per request.

## Remediation

Apply the ServiceNow fix for CVE-2026-6875 (KB3137947): hosted instances were
updated by ServiceNow; self-hosted customers and partners should move to a
patched family release or patch listed above. Because the flaw allows
unauthenticated code execution, review the instance for unexpected scripts,
scheduled jobs, service accounts and data access, and rotate instance
credentials and integration secrets.
