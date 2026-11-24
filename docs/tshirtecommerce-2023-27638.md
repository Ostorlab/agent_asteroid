# PrestaShop tshirtecommerce CVE-2023-27638 time-based SQL injection

The tshirtecommerce module for PrestaShop does not sanitise the
`tshirtecommerce_design_cart_id` parameter (CWE-89), allowing time-based blind
SQL injection.

```text
GET /module/tshirtecommerce/designer?tshirtecommerce_design_cart_id=1 AND SLEEP(8)
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-27638> (published 2023-03-22, CWE-89, CVSS 3.1 9.8).
- Friends-of-Presta advisory: <https://friends-of-presta.github.io/security-advisories/module/2023/03/21/tshirtecommerce_cwe-89.html>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2023-27638>.

## How the detection confirms it
A home-page fingerprint for PrestaShop + tshirtecommerce, then it times a baseline
request and a `SLEEP(8)` request. A finding needs the injected request to be at
least ~6s slower than the baseline, proving the parameter executes SQL. Only a
timing payload is sent; no data is read or changed.

## Remediation
Update the tshirtecommerce module per the advisory and review the database for
tampering.
