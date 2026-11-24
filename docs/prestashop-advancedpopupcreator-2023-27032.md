# PrestaShop Advanced Popup Creator CVE-2023-27032 SQL injection

**CVE-2023-27032** is an unauthenticated SQL injection in the Idnovate "Advanced
Popup Creator" (`advancedpopupcreator`) module for PrestaShop (CWE-89). A guest
can inject SQL through the module's popup endpoint and extract database contents.

```text
POST /module/advancedpopupcreator/popup
availablePopups=if(now()=sysdate(),sleep(6),0)&...&time=<time>&token=<token>
```

## References
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-27032> (published 2023-04-12, CWE-89, CVSS 3.1 9.8).
- Friends of PrestaShop advisory: <https://security.friendsofpresta.org/modules/2023/04/11/advancedpopupcreator.html>.
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2023-27032>.

## Affected and fixed versions
Idnovate Advanced Popup Creator module for PrestaShop in affected versions;
upgrade to the latest module version from Idnovate.

## How the detection confirms it
It attributes PrestaShop from the `static_token` and `time` values the front page
exposes, then sends to the popup endpoint a baseline `sleep(0)` request and an
injected `sleep(6)` request twice each (order counterbalanced) and reports only
when both injected responses are a threshold slower than both fast controls. The
injected statement is a read-only `SELECT sleep`; no data is extracted and no
state changes.

## Remediation
Upgrade the Advanced Popup Creator module to the latest version from Idnovate.
