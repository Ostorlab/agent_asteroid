# KSMBD ZDI owner-inventory assessment

Run `python -m agent.utils.inventory inventory.json` to assess potential exposure
to **ZDI-CAN-33774** and **ZDI-CAN-33549** from build-bound owner evidence.
The offline assessor returns **potential exposure**, **not matched**, or
**inconclusive** per advisory. It sends no traffic and never runs target commands.
SMB negotiation, an open port, a Linux version, Samba, and a loaded KSMBD module
cannot establish these flaws. Research checked 29 October 2026.

## Verified basis and release limits

The starting [Ostorlab article](https://blog.ostorlab.co/linux-ksmbd-preauth-rce-zdi-can-33774.html)
and the [24 October audit](critical-advisories-2026-10-24.md) were followed to
primary reports and patches. The article's broad exposure statement is not the
assessment rule. Its claim about the exact mainline merge date is not inferred
from the fix's commit date.

- **33774:** the [ZDI report](https://lists.openwall.net/linux-kernel/2026/10/21/2694)
  describes per-request selection of a connection-wide dispatch table racing
  with queued work. A short SMB1 buffer can be processed using SMB2 handlers.
  It reports a guest-share prerequisite and an additional security-descriptor
  write path. The public reproducer exercises memory disclosure/crashes;
  it is unsuitable as a safe detection oracle. The tested kernel is 7.3-rc3,
  not a complete affected-version range. We require guest-share evidence for
  a potential result; its absence is inconclusive, not proof the pre-auth
  negotiation path is safe.
- **33549:** the [primary report and attached minimal fix](https://lkml.iu.edu/hypermail/linux/kernel/2610.2/18418.html)
  identify descriptor accounting in `smbdirect_connection_rdma_xmit()`.
  Clamping an oversized descriptor prematurely zeroes the remaining length,
  which then underflows when decremented. The report requires SMB Direct,
  an RDMA device (hardware or software), and a writable share; it also tested
  7.3-rc3. The patch describes both SMB WRITE corruption and SMB READ disclosure.
  This assessor covers the reported writable-share path. No writable share
  therefore gives an inconclusive result rather than excluding the READ path.
  Authenticated access can satisfy the share prerequisite: this result does
  not assert unauthenticated RCE.
- The reports assign **CVSS 9.0**, vector
  `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`. We do not translate that impact rating
  into confirmed exploitability. No verified CVE alias is assigned here.
- **Race fix:** [68f410faedaf6ee74d81e574733c50ebcc1bd8ed](https://github.com/torvalds/linux/commit/68f410faedaf6ee74d81e574733c50ebcc1bd8ed)
  waits for queued work while the connection is new or needs negotiation,
  before reading another PDU. Review equivalent vendor changes semantically;
  a backport need not retain this hash. The patch changes only `server.c` and
  does not introduce a safe network regression test.
- **RDMA fix:** the [23 October maintainer patch](https://lists.openwall.net/linux-kernel/2026/10/23/971)
  removes the premature `buf_len = 0`. Its mail patch object is
  `5b8ce2e5670ebe31970b6718403197ae51d47e43`; this is not a promise that a
  released vendor build contains that object. It supersedes reliance on the
  tentative `for-7.5/smbdirect` branch suggestion. The one-line patch includes
  no regression test. Never run the malformed-descriptor reproducer for this
  assessment.

Release verification on this date:

- [Kernel.org](https://www.kernel.org/) lists mainline release 7.3 and stable
  7.2.13. Inspection of `queue_ksmbd_work()` in
  [7.3](https://raw.githubusercontent.com/torvalds/linux/v7.3/fs/smb/server/server.c)
  and [7.2.13](https://raw.githubusercontent.com/gregkh/linux/v7.2.13/fs/smb/server/server.c)
  found the unsynchronized dispatch path. Their SMB Direct sources retain
  the premature zeroing:
  [7.3](https://raw.githubusercontent.com/torvalds/linux/v7.3/fs/smb/smbdirect/rw.c),
  [7.2.13](https://raw.githubusercontent.com/gregkh/linux/v7.2.13/fs/smb/smbdirect/rw.c).
- The inspected mainline development snapshot
  `c339f4010dea8b0d754f84ace70cd1b089878ef8` contains the
  [race wait](https://github.com/torvalds/linux/blob/c339f4010dea8b0d754f84ace70cd1b089878ef8/fs/smb/server/server.c),
  while its [RDMA accounting](https://github.com/torvalds/linux/blob/c339f4010dea8b0d754f84ace70cd1b089878ef8/fs/smb/smbdirect/rw.c)
  still zeroes and decrements the length.
- The latest stable/LTS changelogs were searched for both patch subjects and
  identifiers: 7.2.13, 6.18.59, 6.12.114, 6.6.160, 6.1.190, 5.15.223,
  and 5.10.272. No match was found. This search is not exhaustive semantic
  backport verification, so no fixed-version table is encoded.
- [Red Hat's bulletin](https://access.redhat.com/security/vulnerabilities/RHSB-2026-014)
  marks supported RHEL unaffected because the necessary modules/features are
  absent. This is not a kernel-version rule for custom builds or other vendors.
  No fixed distribution package boundary was verified. Kernel.org Git endpoints
  returned HTTP 403; primary GitHub/Googlesource mirrors and mailing-list
  archives were used. Unknown vendor builds remain inconclusive.

## How do I assess a deployment for ZDI-CAN-33774 and ZDI-CAN-33549?

Run `python -m agent.utils.inventory inventory.json` with an array of records.
Use **one record per advisory per host**, copying shared runtime evidence but
reviewing code status independently for each advisory. Results preserve input
order. The legacy output field `cve_ids` holds the actual **ZDI** identifier;
it does not imply that ZDI assigned a CVE. No changes to the shared result
schema or remote registry are needed.

All evidence must come from the owner and describe the same running deployment
and assessed peer/network scope. These normalized fields are assertions by the
collector, not remote responses. The assessor checks their types, completeness
and build binding; it does not authenticate evidence or audit source itself.
Keep the underlying review, configuration and provenance in the owner's system.
Do not put secrets or full configuration dumps in inventory.

| Field | Required meaning |
| --- | --- |
| `product` | Exactly `KSMBD`, with service ownership independently verified. |
| `advisory_id` | Exactly `ZDI-CAN-33774` or `ZDI-CAN-33549`. Missing/unknown IDs are inconclusive. |
| `ksmbd_running` | Boolean effective service state, not just installed tools or module presence. False is not matched for current runtime exposure. |
| `running_build_id` | Nonblank artifact/provenance identifier, at most 256 characters. Bind the booted kernel and any separately built/loaded KSMBD module; a generic release string is insufficient. |
| `reviewed_build_id` | Exactly the same artifact identifier as `running_build_id`. An installed but not booted kernel is not the running build. |
| `code_evidence_source` | `source_review` or `vendor_advisory`. |
| `code_evidence` | Nonblank review reference, at most 2048 characters, identifying the advisory-specific source/vendor evidence and its mapping to that artifact. Never fetched or echoed. |
| `code_status` | `affected` only when the flawed control flow is verified in the deployed source/artifact and no equivalent fix is present. `fixed` requires the exact semantic fix or verified vendor backport in the running artifact. Otherwise use `unknown`. Absence of a hash is insufficient for `affected`. |
| `tcp_smb_reachable` | For 33774: boolean effective TCP SMB reachability from assessed peers, bound to the KSMBD listener (including custom ports). |
| `guest_share_accessible` | For 33774: boolean effective guest access to a KSMBD share for those peers. False remains inconclusive. |
| `smb_direct_enabled` | For 33549: boolean effective server SMB Direct support, including `CONFIG_SMB_SERVER_SMBDIRECT` and enabled transport. |
| `rdma_transport_reachable` | For 33549: boolean evidence of a usable RDMA interface and SMB Direct transport reachable/negotiable from assessed peers. TCP 445 and an installed RDMA driver are insufficient. |
| `writable_share_accessible` | For 33549: boolean effective write access to a share for those peers via guest or authorized authenticated access. False remains inconclusive. |

Only explicit JSON booleans count. Missing data, strings such as `"false"`,
numeric booleans, unknown code status and mismatched build provenance are
inconclusive. A verified fixed build is not matched even when share details are
unknown. A disabled required transport is not matched only for that advisory's
assessed path and peers. A positive result is always **potential exposure**,
with exploitability unconfirmed. It never reports successful RCE.

Example input shape (illustrative local fixture; replace with collected facts):

```json
[
  {
    "product": "KSMBD",
    "advisory_id": "ZDI-CAN-33774",
    "ksmbd_running": true,
    "running_build_id": "owner-artifact-identifier",
    "reviewed_build_id": "owner-artifact-identifier",
    "code_status": "affected",
    "code_evidence_source": "source_review",
    "code_evidence": "owner-review/33774: affected dispatch verified in this artifact",
    "tcp_smb_reachable": true,
    "guest_share_accessible": true
  },
  {
    "product": "KSMBD",
    "advisory_id": "ZDI-CAN-33549",
    "ksmbd_running": true,
    "running_build_id": "owner-artifact-identifier",
    "reviewed_build_id": "owner-artifact-identifier",
    "code_status": "affected",
    "code_evidence_source": "source_review",
    "code_evidence": "owner-review/33549: affected descriptor accounting verified",
    "smb_direct_enabled": true,
    "rdma_transport_reachable": true,
    "writable_share_accessible": true
  }
]
```

## What evidence and edge cases do the assessment tests cover?

Local-fixture tests validate the assessment logic, not the truth of owner
assertions or exploitation of a kernel lab.

Tests use local owner-evidence fixtures for both affected paths, independently
patched/backported builds, unknown and malformed evidence, Samba/Linux/version
controls, inactive services, separate TCP/RDMA reachability, missing share
prerequisites, no network I/O, nonmutation and output sanitization. The CLI test
keeps the race fixed and RDMA affected on the same build to catch accidental
cross-advisory suppression and missing registration. No kernel exploit or
public/production target is exercised.
