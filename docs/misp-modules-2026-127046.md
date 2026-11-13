# CVE-2026-127046: MISP Modules unauthenticated external-tools API-key disclosure

**CVE-2026-127046** is an information disclosure in the website component of
[MISP Modules](https://github.com/MISP/misp-modules). The website's public
`GET /external_tools/list` route returns the configured external enrichment
tools as a JSON array. Before upstream fix commit `61c2789`, the
`ExternalTools.to_json()` serializer in `website/app/models/models.py` included
the stored `api_key` of every tool, so an unauthenticated caller could read the
credential the MISP Modules server uses to authenticate to external analysis
and enrichment services.

**Affected:** MISP Modules website builds before commit `61c2789`
**Fixed:** commit `61c2789` (`fix: [website] keep external tool API keys out of responses`)
**Severity:** CVSS 4.0 9.2 (Critical) — `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`, CWE-200/CWE-522

The list route is public in both builds; the fix removes the credential from
the serializer and makes the edit field write-only. The adjacent
[CVE-2026-127016](https://nvd.nist.gov/vuln/detail/CVE-2026-127016) covers
missing administrator authorization on the external-tool management handlers
(add, delete, status and configuration) and was fixed in the parent commit
`28c27e3`. That is a different issue and this detector does not exercise or
claim it.

A deployment leaks a credential only when at least one external tool is
configured with a non-empty API key. A site with no tools, or with empty API
keys, has nothing to disclose.

## How does the detector verify the disclosure?

1. `GET /` must return the MISP Modules website home page: HTTP 200
   `text/html`, a `<title>` containing `MISP Modules`, and one of the
   product's own static asset paths (`/static/images/misp-modules.svg` or
   `/static/images/misp-modules-icon.svg`) in the page. This attributes the
   website without a banner guess.
2. `GET /external_tools/list` must answer HTTP 200 `application/json` with a
   JSON array in which at least one record carries the product's public tool
   shape: an integer `id`, string `name` and `url`, and boolean `is_active`.
   At least one conforming record must carry a non-empty string `api_key`.
   A list that mixes conforming and non-conforming records still yields a
   finding whenever at least one conforming record carries a non-empty
   `api_key`, instead of discarding the whole response.

A fixed build returns the same records without the `api_key` field. An
authentication challenge (`401`/`403`), a non-JSON or malformed body, a list
with no conforming record, a missing product marker, or a different product
title produces no finding. The response is inspected only for the field's presence:
the key value is never printed, stored or used. The check sends two anonymous
GETs and changes no state.

## What does the finding claim?

The finding confirms that an anonymous client can read a stored external-tool
API key from the public list response. It does **not** claim that the key was
used against the external service, that any external system was accessed, or
that the MISP Modules configuration was modified. The finding recommends
rotating every external-tool API key configured before the upgrade, because a
vulnerable deployment may already have disclosed it.

## What does the detector miss?

- A deployment with no configured external tools, or with empty API keys, has
  nothing to disclose and produces no finding.
- A website mounted under a path prefix (rather than the origin root) is not
  probed.
- A reverse proxy that requires authentication or blocks
  `/external_tools/list` answers `401`/`403` or a non-JSON page and produces
  no finding, even though the underlying website build may still be
  vulnerable.
- Network errors, timeouts, truncated responses and unsupported schemes are
  inconclusive and produce no finding; a missing finding is not proof that the
  disclosure is absent.
- A build that already removed `api_key` from the serializer produces no
  finding even if the public list route remains reachable, which is the fixed
  behavior.

## How to reproduce and remediate

Request the public list and inspect the record keys (do not print the values):

```sh
curl -sS 'http://<target>/external_tools/list' \
  | python3 -c 'import json,sys; print([sorted(r) for r in json.load(sys.stdin)])'
```

A record key list containing `api_key` on a pre-fix build confirms the
disclosure. A vulnerable response record looks like:

```json
{"id": 1, "name": "synthetic-enrichment", "url": "https://enrichment.example/api", "is_active": true, "api_key": "<redacted>"}
```

The fixed build returns the same record without the `api_key` field:

```json
{"id": 1, "name": "synthetic-enrichment", "url": "https://enrichment.example/api", "is_active": true}
```

Upgrade the MISP Modules website to a build containing commit `61c2789`, then
rotate every external-tool API key that was configured before the upgrade.
Confirm the fix by requesting `/external_tools/list` and checking that no
record contains an `api_key` field. If the upgrade cannot be applied
immediately, restrict network access to the website (and in particular
`/external_tools/list`) with authentication or a reverse-proxy allow-list, and
rotate the affected keys. The list route is public in fixed builds too, so
network access control is the interim mitigation. For the agent-side summary,
run `oxo vulnz describe -v CVE-2026-127046`.

## How was the detector validated?

The real upstream website was checked out at the vulnerable parent commit
`28c27e3` and at fix commit `61c2789`, installed from each tree's own
`pyproject.toml` dependencies, and run on loopback with a SQLite database
seeded with a synthetic external tool. An independent standard-library oracle
read the checked-out `models.py` to establish whether the serializer includes
`api_key`, then fetched `/` and `/external_tools/list` directly.

| Case | Version / Product | Seeded tools | Detector | Oracle |
| --- | --- | --- | --- | --- |
| 1 | `28c27e3` | one key | TP | vulnerable |
| 2 | `61c2789` | one key | TN | fixed |
| 3 | `28c27e3` | none | TN | no key exposed |
| 4 | `28c27e3` | one empty key | TN | no key exposed |
| 5 | `28c27e3` | two keys | TP | vulnerable |
| 6 | `61c2789` | none | TN | fixed |
| 7 | lookalike (not MISP Modules) | one key, different product | TN | not the product |

**TP 2 / TN 5 / FP 0 / FN 0 / inconclusive 0.** The detector emitted one
finding each for cases 1 and 5 (CRITICAL, external-tools location) and none for
the fixed, empty, no-tool, or lookalike cases. No API-key value appeared in any
finding or log.

## Sources

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-127046> (published
  2026-11-12T12:18Z, CWE-200/CWE-522, CVSS 4.0 9.2).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-127046>.
- Project: <https://github.com/MISP/misp-modules>.
- Upstream fix commit:
  <https://github.com/MISP/misp-modules/commit/61c27893066cee80d9711649765ebc2bccd0e4af>
  (`fix: [website] keep external tool API keys out of responses`, 2026-11-12).
- Adjacent CVE-2026-127016 fix:
  <https://github.com/MISP/misp-modules/commit/28c27e30f6d3a10e38fe9c54bb52f57ccf70d027>
  (`fix: [website] authorize external tool management`, 2026-11-12).
