# CVE-2026-49777: Product Slider Pro for WooCommerce supply-chain backdoor RCE

**CVE-2026-49777 is a supply-chain-implanted backdoor** (CWE-1284) affecting
builds of Product Slider Pro for WooCommerce before 3.5.4 compromised in the
Smart Slider 3 Pro supply-chain attack. The implant runs an
attacker-chosen shell command decoded from a request header whenever a fixed
marker header is present.

**Affected:** Product Slider Pro for WooCommerce builds compromised before 3.5.4

**Fixed:** 3.5.4 (a clean reinstall from an official source)

**Severity:** CVSS 3.1 10.0 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

## How does the detector verify it?

This is an **active, non-destructive, unforgeable** check. It sends the
backdoor's marker header together with a benign `expr A + B` command for two
random integers, and confirms the computed sum (never the literal command,
which is all the request carries) appears in the response:

```
GET /
X-Cache-Status: <fixed marker>
X-Cache-Key: base64("expr <A> + <B>")
# confirm: HTTP 200 text/plain response contains the computed sum A+B
```

Only a benign arithmetic addition is run — **no file is read or written and
no state is changed**. A server that merely reflects the header would contain
the base64 blob or the literal command, never the sum, so a match proves a
shell evaluated the decoded command. No credential or cookie is sent and
redirects are not followed. The two headers used are outside
`defensive_http`'s metadata-only allow list, so the probe is built and sent
through an isolated, unmerged request rather than the session's
credential-bearing path.

**Limitation:** this check reports a live backdoor on an already-compromised
build; it does not independently verify the plugin's legitimate 3.5.4 release
is otherwise vulnerable. A compromised host whose implant has since been
removed, or that filters the custom headers, is not reported (a conservative
false negative, never a false positive).

## Remediation

Remove the compromised plugin build and reinstall a clean Product Slider Pro
for WooCommerce 3.5.4 or later from an official source. Rotate any secrets
the host could reach and audit the site for further implants.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-49777> (published
  2026-06-05, CWE-1284, CVSS 3.1 10.0).
- Patchstack advisory:
  <https://patchstack.com/database/wordpress/plugin/woo-product-slider-pro/vulnerability/wordpress-product-slider-pro-for-woocommerce-plugin-3-5-2-backdoor-vulnerability>.
- Patchstack malware analysis:
  <https://patchstack.com/articles/critical-supply-chain-compromise-in-smart-slider-3-pro-full-malware-analysis/>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-49777>.
