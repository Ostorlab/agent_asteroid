# symfony/runtime CVE-2024-50340 argument-injection profiler exposure

symfony/runtime is affected by an argument-injection flaw: when PHP `register_argc_argv` is enabled, a `?+--env=dev` query argument forces the dev environment and exposes the profiler (CWE-74).

```text
GET /_profiler/phpinfo?+--env=dev
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-50340> (published 2024-11-06, CWE-74).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2024-50340>.

## Affected and fixed versions
symfony/runtime before **5.4.46**, **6.4.14**, **7.1.7**.

## How the detection confirms it
A Symfony fingerprint, then a `GET` of `/_profiler/phpinfo?+--env=dev` (needs `PHP Version` and `PHP Extension`). Only the phpinfo page is read; requests are bounded.

## Remediation
Upgrade symfony/runtime to a fixed release or disable `register_argc_argv`.
