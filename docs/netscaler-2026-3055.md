# NetScaler CVE-2026-3055 SAML IDP memory overread

NetScaler ADC / Gateway configured as a SAML IDP insufficiently bounds a buffer (CWE-125), leaking adjacent process memory in the `NSC_TASS` response cookie.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-3055> (published 2026-03-23, CVSS 3.1 9.8).
- Citrix advisory CTX696300: <https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696300>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-3055>.

## How the detection confirms the SAML memory overread
Confirms NetScaler, then sends the SAML (`/saml/login`) and WS-Federation (`/wsfed/passive`) probes; a finding needs a 302 whose `NSC_TASS` cookie base64-decodes to memory containing a `wctx=` marker (and no parse-failure message). The leaked memory is only inspected for the marker and not kept.

## Remediation
Upgrade per CTX696300 and rotate secrets, since process memory may have leaked.
