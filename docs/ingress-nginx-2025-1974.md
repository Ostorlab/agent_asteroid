# Kubernetes ingress-nginx CVE-2025-1974 configuration injection (IngressNightmare)

Part of the "IngressNightmare" chain. The Kubernetes ingress-nginx admission
controller renders Ingress fields into an nginx config and validates it with
`nginx -t`, without sanitising them (CWE-653). An attacker who can reach the
admission webhook injects nginx directives through the object `uid` /
mirror-target, which combined with the other IngressNightmare bugs leads to RCE.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-1974> (published 2025-03-25 by the Kubernetes CNA, CWE-653, CVSS 3.1 9.8).
- Kubernetes issue: <https://github.com/kubernetes/kubernetes/issues/131009>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-1974>.

## Affected and fixed versions
ingress-nginx before **v1.12.1** and **v1.11.5**.

## How the detection confirms it
One anonymous dry-run `AdmissionReview` POST to `/`. A finding needs the response
to carry the `nginx -t` parse error for the injected directive (`load_module`,
`directive is specified too late`). No Ingress is created (`dryRun: true`); the
request is bounded and follows no redirect.

## Remediation
Upgrade ingress-nginx to v1.12.1 / v1.11.5 or later. Restrict network access to
the admission webhook so only the API server reaches it, enforced with
NetworkPolicy.
