# Jenkins Git plugin CVE-2022-36883 missing authorization

**CVE-2022-36883** is a missing authorization check in the Jenkins Git plugin
through 4.11.3 (CWE-862). The `/git/notifyCommit` endpoint requires no
authentication, so an attacker can trigger builds of jobs that use an
attacker-specified repository and commit.

```text
GET /git/notifyCommit?url=https://<random>.example.invalid/<random>.git&branches=<random>
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2022-36883> (published 2022-07-27, CWE-862, CVSS 3.1 7.5).
- Jenkins advisory SECURITY-284: <https://www.jenkins.io/security/advisory/2022-07-27/#SECURITY-284>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2022-36883>.

## Affected and fixed versions
Jenkins Git plugin **<= 4.11.3**; fixed in **4.11.4**.

## How the detection confirms it
One anonymous `GET` of `/git/notifyCommit` naming a random, non-existent
repository URL and random branches that no configured job can match, so no build
or SCM polling runs. A finding needs HTTP 200 and the `SCM API plugin`
notification page (`repository:` marker). The request reads only the
notification page; no credential or cookie is sent and redirects are not
followed.

## Remediation
Upgrade the Jenkins Git plugin to 4.11.4 or later and restrict the Jenkins HTTP
endpoint to trusted clients.
