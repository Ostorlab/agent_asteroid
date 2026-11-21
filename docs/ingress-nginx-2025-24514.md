# Kubernetes ingress-nginx CVE-2025-24514 auth-url configuration injection (IngressNightmare)

Part of "IngressNightmare". The ingress-nginx admission controller does not
sanitise the `auth-url` Ingress annotation before rendering it into the nginx
config (CWE-20), letting an attacker inject nginx directives.

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-24514> (published 2025-03-25 by the Kubernetes CNA, CWE-20, CVSS 3.1 8.8).
- Kubernetes issue: <https://github.com/kubernetes/kubernetes/issues/131006>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2025-24514>.

## Affected and fixed versions
ingress-nginx before **v1.12.1** and **v1.11.5**.

## How the detection confirms it
One anonymous dry-run `AdmissionReview` POST to `/` whose `auth-url` annotation
injects a directive. A finding needs the `nginx -t` parse error (`load_module`,
`directive is not allowed here`). No Ingress is created (`dryRun`); the request is
bounded.

## Remediation
Upgrade ingress-nginx to v1.12.1 / v1.11.5 or later and restrict access to the
admission webhook with NetworkPolicy.
