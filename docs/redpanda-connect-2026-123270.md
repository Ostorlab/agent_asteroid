# Redpanda Connect CVE-2026-123270 unauthenticated streams management API

**CVE-2026-123270** is an unauthenticated remote code execution vulnerability in
the streams-mode management API of Redpanda Connect (formerly Benthos). When the
service runs in streams mode it exposes an HTTP management listener on
`0.0.0.0:4195`. Through **v4.110.0** the stream CRUD routes are registered by
default and `http.basic_auth.enabled` defaults to `false`, so an anonymous
client can `POST /streams/{id}` with a pipeline definition. Pipelines may contain
the `command`, `subprocess`, `ffi` or `sql_raw` (with `unsafe_dynamic_query`)
processors, which execute code as the Connect service account.

From **v4.111.0** the CRUD routes are only registered when the operator passes
`--bind-http` (Benthos v4.81.0 gated them behind the flag). That is a
default-off change rather than an authentication fix: enabling the API without
`http.basic_auth` restores the same unauthenticated pipeline-submission path.
CWE-306 leading to CWE-94; CVSS 3.1 9.8
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

## Sources

- CERT/CC-coordinated advisory and public proof of concept:
  <https://github.com/pagvac/redpanda-connect-unauth-rce>
- Full advisory document:
  <https://github.com/pagvac/redpanda-connect-unauth-rce/blob/main/rp_connect_rce_advisory_CVE-2026-123270.md>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-123270> (published
  2026-11-09, CWE-306, CVSS 3.1 9.8).
- CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-123270>.
- Vulnerable route registration in the embedded Benthos v4.80.0 core:
  `internal/stream/manager/api.go`.
- Default-off basic authentication:
  `internal/httpserver/basic_auth.go` (`Enabled: false`).
- Fixed release: <https://github.com/redpanda-data/connect/releases/tag/v4.111.0>.

## How does the detector verify the exposure?

1. `GET /version` must return the management API's own envelope: exactly the
   keys `version` and `built`, with a semantic release label. This attributes
   the Benthos/Redpanda Connect management API rather than a generic service.
2. `GET /endpoints` must return the management API's endpoint map: string keys
   and values, including the exact `Ping me.` and `Returns the service
   version.` descriptions. The `/streams` and `/streams/{id}` descriptions are
   then checked to establish that the CRUD routes are registered.
3. `GET /streams` must answer `200` with `Content-Type: application/json` and
   the stream-status map (each value carrying `active`, `uptime` and
   `uptime_str`; an empty object is accepted once the endpoint map proves the
   route is registered). The advisory itself uses `GET /streams` returning 200,
   rather than 401/403, as the read-only unauthenticated signal.

A release at or above 4.111.0 that still answers the CRUD route is reported as
an explicitly enabled API (`--bind-http`) without authentication; the finding
text says so instead of calling it the default configuration.

All three requests are anonymous GETs. The check never calls `POST /streams`,
`PUT`, `PATCH` or `DELETE`, never submits a pipeline, resource or command, and
changes no state. Existing stream identifiers are counted only for the evidence
line; their names and configurations are not included in the finding.

## What is the finding?

The finding confirms that the streams management API is reachable without
authentication and that its pipeline-upload routes are registered. It does not
claim that command execution was performed: the code-executing step would
require submitting a pipeline, which this read-only check does not do. On a
default **v4.110.0** or earlier instance the advisory establishes that the
submission path is exploitable; on **v4.111.0** and later the presence of the
route is the operator-enabled condition.

## What does the detector miss?

- `http.basic_auth.enabled: true` protects the whole listener, so `/version`
  answers 401 and the target is not attributed or reported. That is the
  authenticated state, not an exposed instance.
- A reverse proxy that mounts the API under a path prefix is not probed; the
  check reads the target origin's root paths.
- A proxy that rewrites `/streams` to a generic 200 does not satisfy the
  endpoint-map or stream-status shape and is not reported.
- A default v4.111.0+ instance does not register the CRUD routes and is not
  reported; a missing finding therefore does not prove that an operator has not
  enabled the API on a non-standard port or behind a proxy.
- Network errors, timeouts and truncated responses are treated as inconclusive
  and produce no finding.
