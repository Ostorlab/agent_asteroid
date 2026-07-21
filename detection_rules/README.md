# Detection Rules

This directory hosts generic, static-analysis **detection rules** (Semgrep / Opengrep
rule files) for vulnerability classes that are not covered by the network-CVE exploit
modules under `agent/exploits/`.

Each rule is framework- and pattern-oriented: it flags the *class* of bug, not a single
instance, so the same rule catches the vulnerability in any codebase that follows the
matched pattern.

## Layout

```
detection_rules/<language>/<rule_name>.yml      # the rule definition
detection_rules/<language>/examples/           # vulnerable + safe fixtures
```

## Running the rules

```shell
semgrep scan --config detection_rules/python/ <path/to/code>
# or, with Opengrep:
opengrep scan --config detection_rules/python/ <path/to/code>
```

## Validation

The rule behaviour is covered by `tests/detection_rules_test.py`, which runs the rule
against the fixtures under `detection_rules/python/examples/`. The test is skipped
automatically when `semgrep`/`opengrep` is not installed, so it does not affect CI on
runners without the tool.

## Available rules

### `python/django_tenant_scoped_orm_lookup.yml`

Detects **cross-tenant IDOR** (Broken Access Control) in Django/GraphQL resolvers that
resolve a tenant-scoped object (e.g. a `Scan`) from an attacker-controlled id while
omitting the server-derived organisation/tenant scope key from the ORM lookup.

Two checks:

| Rule id | Severity | Matches |
| --- | --- | --- |
| `...missing-organisation-key` | `ERROR` | A filter dict assigned to a variable that contains an `"id"` key but is missing the `"organisation"` (or `tenant`) scope key, inside a resolver that derives the organisation from the authenticated context and passes the dict to `Model.objects.get(**filters)` / `.filter(**filters)`. |
| `...inline-missing-organisation` | `WARNING` | An inline `Model.objects.get(id=<..._id>, ...)` / `.filter(...)` lookup, inside a resolver that derives the organisation from the authenticated context, that omits the `organisation=` scope key. Restricted to `*_id`-named selectors to limit false positives. |

**Why it matters:** a `@authorize`/permission decorator is a *role* gate only — it
performs no object-level scoping on the attacker-supplied `id`. When the resolver also
omits the inline `organisation` filter (or bypasses the canonical object-level gate
`access.get_scan_with_access(...)`), the lookup collapses to a bare
`Model.objects.get(id=<foreign_id>)` with no tenant constraint, enabling cross-tenant
read/write and existence-oracle attacks.

**Remediation:** add `"organisation": organisation` to the filter dict (mirroring every
protected sibling mutation), or route resolution through the canonical object-level gate
and abort on `None`. Also wrap the bare `.get()` in a `try/except <Model>.DoesNotExist`
handler to remove the cross-tenant existence oracle.
