# Postiz owner-inventory assessment

This is **offline potential-exposure coverage**, not remote exploit detection.
Use `python -m agent.utils.inventory inventory.json` with one normalized record
per CVE. `product` must be `Postiz`; `cve_id` selects exactly one of the three
issues. The module lives in `agent/exploits/cve_2026_115931.py` and is registered
only in the inventory dispatcher, not the remote exploit registry or
`custom_cve_list`.

## Verified release boundaries

Checked 29 October 2026 against the disclosure advisories, vendor patches and
release notes, starting with the
[Ostorlab article](https://blog.ostorlab.co/postiz-full-takeover-any-registered-user-cve-2026-115931.html).

| CVE | Affected upstream releases | First fixed release | Primary evidence |
| --- | --- | --- | --- |
| CVE-2026-115931 | `>=2.23.0,<2.25.2` | 2.25.2 | [PSA-2026-JNXM56](https://gadvisory.org/advisories/PSA-2026-JNXM56), [provider allowlist patch](https://github.com/gitroomhq/postiz-app/commit/9383f5be4d310c346e33a3748a9a7ded64c96fed), [release](https://github.com/gitroomhq/postiz-app/releases/tag/v2.25.2) |
| CVE-2026-115932 | `>=2.23.0,<2.25.3` | 2.25.3 | [PSA-2026-E9AHFV](https://gadvisory.org/advisories/PSA-2026-E9AHFV), [media confinement patch](https://github.com/gitroomhq/postiz-app/commit/12db9bd2f428b628a62809669c3d76297e07750a), [release](https://github.com/gitroomhq/postiz-app/releases/tag/v2.25.3) |
| CVE-2026-115933 | `>=2.15.0,<2.25.3` | 2.25.3 | [PSA-2026-YT2HMH](https://gadvisory.org/advisories/PSA-2026-YT2HMH), [token validation/signing patch](https://github.com/gitroomhq/postiz-app/commit/a5affe62c74e39c1e7ac960d50d8418b807d532c), [release](https://github.com/gitroomhq/postiz-app/releases/tag/v2.25.3) |

The patch diffs and the full v2.25.3 repository tree contain no matching
regression-test files. Validation here tests the assessment policies with local
fixtures, not the vendor application's exploit behavior. The repository GitHub
advisory API URLs returned 404; the public GAdvisory disclosures and vendor
patch/release artifacts were available.

## Evidence contract

The owner must verify evidence against the **same running deployment**. This is
an Asteroid schema, not a vendor API response. Obtain the release from the
deployed immutable image/build and effective configuration from the operator's
inventory. Confirm backend and publishing workers run the stated release; mixed
or unknown versions require separate investigation, not a guessed `version`.
Do not paste secrets, tokens, credential values, or whole environment dumps.
The assessor neither authenticates evidence nor verifies backported fixes.

Common fields:

| Field | Required meaning |
| --- | --- |
| `product` | Exact string `Postiz`, identifying `gitroomhq/postiz-app`. |
| `cve_id` | One of the three CVEs above. Submit three records to assess all three. |
| `version` | Canonical numeric `major.minor.patch` upstream release. Floating tags, prefixes, prereleases and custom builds are inconclusive. |
| `deployment` | Exact string `self-hosted`. Managed deployments are inconclusive, not automatically safe. |
| `authenticated_user_access` | Boolean `true` only when an ordinary user can access the application through an existing account or available self-registration. Closing registration does not exclude existing users. |

Every route field below must be JSON boolean `true`; strings and integers are
not accepted as booleans. Missing/false/invalid route evidence is inconclusive
unless a different route is independently established. An affected version or
enabled provider alone never produces potential exposure.

### CVE-2026-115931: unrestricted provider dispatch

Both fields are required:

- `provider_function_access`: ordinary users can reach provider-method dispatch
  through `/integrations/function` or the vulnerable `/integrations/mentions`
  alias, accounting for effective proxy and application access controls.
- `connectable_channel`: the same user can use or connect a provider channel in
  their organization, including applicable channel-plan restrictions.

The patch restricts dispatch to `@Tool`/`@DashboardFunction` methods and forces
the mentions alias to call `mention`. The assessment does not invoke internal
helpers, read files, retrieve credentials or exercise the process-exit path.

### CVE-2026-115932: media paths

One of three independently established routes is required:

| Route | Required fields and meaning |
| --- | --- |
| Discord publishing with post URL substitution | `post_submission_access`, `discord_provider_configured`, `publishing_worker_enabled`, `connectable_wordpress_channel` |
| Discord publishing with stored local media | `post_submission_access`, `discord_provider_configured`, `publishing_worker_enabled`, `local_storage_enabled`, `cloud_bucket_url_empty`, `save_media_access` |
| Validation-time reads | `post_validation_access`, `validation_channel_available` |

- `post_submission_access`: the ordinary user can submit/schedule posts using
  their own channels under the effective access and plan controls.
- `discord_provider_configured`: all three Discord settings
  (`DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `DISCORD_BOT_TOKEN_ID`) are set
  and the user can connect and publish to a Discord channel they control,
  including outbound connectivity and plan restrictions. Supply the boolean,
  never the settings' values.
- `publishing_worker_enabled`: a running worker can process that user's posts.
- `connectable_wordpress_channel`: the user can connect and publish through a
  WordPress endpoint they control, including outbound connectivity and channel
  limits. This is a conservative prerequisite inferred from the vulnerable
  [WordPress provider](https://github.com/gitroomhq/postiz-app/blob/3a7d28b7ad96/libraries/nestjs-libraries/src/integrations/social/wordpress.provider.ts)
  accepting the returned post link and
  [PostsService.updateTags](https://github.com/gitroomhq/postiz-app/blob/3a7d28b7ad96/libraries/nestjs-libraries/src/database/prisma/posts/posts.service.ts)
  substituting it into serialized media after validation. The fix confines
  substitution to content/settings. Other controllable providers are not assumed.
- `local_storage_enabled`: effective storage provider is local.
- `cloud_bucket_url_empty`: effective `CLOUDFLARE_BUCKET_URL` is explicitly an
  empty string. An unknown or unset value is not evidence for this field.
- `save_media_access`: the user can reach `/media/save-media`. The vulnerable
  [controller](https://github.com/gitroomhq/postiz-app/blob/3a7d28b7ad96/apps/backend/src/api/routes/media.controller.ts)
  stores a caller-supplied name as a path; the patch rejects path separators and
  an empty cloud bucket URL. The advisory documents this alternative to needing
  a WordPress site; Discord delivery is still required by this assessment.
- `post_validation_access`: the user can reach the post validation flow,
  including `/posts/valid` or validation during post submission.
- `validation_channel_available`: the user has a usable connected Dribbble,
  TikTok or Pinterest channel with effective provider/plan access. This route
  assesses path information disclosure and memory-exhaustion exposure, **not**
  successful file exfiltration or full takeover.

Disabling Discord does not rule out validation-time reads. Local storage or an
empty bucket URL alone does not establish a complete file-disclosure path.

### CVE-2026-115933: signing and token confusion

The main route requires all of:

- `extension_refresh_access`: `/integrations/extension-refresh` is reachable by
  the user/channel flow through effective proxy/application controls.
- `skool_api_reachable`: the backend can reach `api2.skool.com`, based on owner
  egress inventory; the assessor does not connect to it.
- `connectable_skool_channel`: the ordinary user can connect/use their own
  Skool account, including a usable account and permission for at least one
  channel when Stripe billing applies.

Alternatively, `team_invitation_access=true` means the user has effective
permission to create team invitations. This narrower signing route is reported
as potential interference with another organization's scheduled posts or plan
limits. It is **not** evidence of full session takeover.

The vendor's target-organization STANDARD-tier restriction concerns the
organization-joining impact. The main assessment describes session/token
forgery; session/password-reset impacts are not subject to that target-tier
restriction. Blocking extension refresh does not close the invitation route.

## Example

This local fixture assesses a 2.25.2 deployment with a usable validation channel
and team-invitation permission. It deliberately makes no claims about the other
routes:

```json
[
  {
    "product": "Postiz",
    "cve_id": "CVE-2026-115931",
    "version": "2.25.2",
    "deployment": "self-hosted"
  },
  {
    "product": "Postiz",
    "cve_id": "CVE-2026-115932",
    "version": "2.25.2",
    "deployment": "self-hosted",
    "authenticated_user_access": true,
    "post_validation_access": true,
    "validation_channel_available": true
  },
  {
    "product": "Postiz",
    "cve_id": "CVE-2026-115933",
    "version": "2.25.2",
    "deployment": "self-hosted",
    "authenticated_user_access": true,
    "team_invitation_access": true
  }
]
```

Expected statuses, in order: `not_matched`, `potential_exposure`,
`potential_exposure`. Findings identify only the selected CVE and matched route.
`not_matched` means outside that CVE's published version interval; it does not
establish freedom from other flaws or historical compromise. For affected
versions without a fully evidenced route, the result remains `inconclusive`.

Upgrade backend and workers to 2.25.3 or later to address all three issues.
Review possible compromise and rotate exposed credentials where appropriate.
No target requests, channel/account changes, signing requests, invitations,
post creation, file reads, outbound deliveries or crash probes are performed.
