# Really Simple Security CVE-2024-10924 two-factor authentication bypass

The Really Simple Security plugins for WordPress (9.0.0 to 9.1.1.1) mishandle the two-factor `skip_onboarding` REST action (CWE-287), so an anonymous request with a valid login nonce and `user_id=1` is authenticated as that user.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-10924> (published 2024-11-15 by the Wordfence CNA, CVSS 3.1 9.8).
- Wordfence write-up: <https://www.wordfence.com/blog/2024/11/really-simple-security-vulnerability/>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-10924>.

## Affected and fixed versions
Really Simple Security **9.0.0 to 9.1.1.1**; fixed in 9.1.2.

## How the detection confirms it
Reads the login nonce, calls `two_fa/skip_onboarding` with `user_id=1`, and confirms the resulting session reaches `/wp-admin/profile.php` (`Personal Options`). A read-only admin session is established to confirm the bypass; no configuration is changed.

The flow needs session cookies between requests, which the anonymous `defensive_http` transport does not keep, so the scanner session is used directly.

## Remediation
Update to Really Simple Security 9.1.2 or later and review administrator accounts.
