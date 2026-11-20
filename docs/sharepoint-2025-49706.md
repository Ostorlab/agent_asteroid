# Microsoft SharePoint CVE-2025-49706 ToolPane authentication bypass

Microsoft SharePoint Server is affected by an authentication bypass / spoofing flaw in `ToolPane.aspx` (CWE-287), the first step of the ToolShell chain, letting an unauthenticated attacker reach the web-part editor.

```text
POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-49706>.
- MSRC update guide: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-49706>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-49706>.

## How the detection confirms it
An anonymous `POST` to the ToolPane editor endpoint, no redirects followed. A finding needs a SharePoint server header and a non-error status (the endpoint processes the request unauthenticated). An empty web-part form is submitted; no state changes.

## Remediation
Apply the SharePoint security update for CVE-2025-49706 and the related ToolShell fixes (CVE-2025-49704 / CVE-2025-53770), enable AMSI, and restrict the `_layouts` endpoints.
