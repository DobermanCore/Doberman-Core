# Local companion contract

Doberman exposes a small set of surfaces that another tool on the same machine, run by the same user, may read: a
session viewer, a tray app, an approval panel. This page is the contract for those tools. It names what stays stable,
what may change, and how a consumer tells an older Doberman from a broken one.

Everything here is local-only. The dashboard binds to `127.0.0.1`, the decision log is a file in your repo, and nothing
on this list is reachable from another machine.

## Versioning

The contract has one integer major version, served by the dashboard:

```
GET /api/health
Authorization: Bearer <run token>

{"status": "ok", "contract": 1, "doberman": "<package version>", "features": ["pending", "resolve", "session_id", "needs_totp"]}
```

- `contract` is the major. A dashboard that answers without it (Doberman v0.21.0 and earlier) is **contract 0**: the
  same surfaces as below, unversioned.
- `doberman` is the installed package version, for display. Feature-detect with `features`, never by parsing it.
- `features` lists capability names. A name is only added, never repurposed. Today's names:

| Feature | What it means |
| --- | --- |
| `pending` | `GET /api/pending` lists the approvals waiting for a person. |
| `resolve` | `POST /api/resolve/{id}` answers one of them. |
| `session_id` | Pending rows carry the host session id when the approval came from a host hook (`null` otherwise). |
| `needs_totp` | Pending rows say whether approving needs a 6-digit code, and resolve passes `totp_code` through. |

An addition (a new field, a new feature name, a new column) keeps the major. Renaming, removing, or changing the meaning
of anything pinned below bumps it. `/api/health` needs the bearer token like every other `/api/*` route.

## Pinned surfaces (contract 1)

### 1. Audit webhook

With `.doberman/audit_webhook.yaml` holding `url` (plus optional `auth_env` and `timeout_s`), Doberman POSTs each
decision record as JSON to `url`; a non-loopback `url` must be `https`. The `Authorization` header is the value of the environment variable named by `auth_env`, sent as-is
(include any `Bearer ` prefix in the variable). Delivery is best-effort from a background queue: a failed POST is logged
and dropped, and it never changes a decision.

The body always carries these keys (a value may be `null` when it is not known): `ts`, `action_id`, `final_verdict`,
`reason_codes`, `action_type`, `target_path_class`, `risk`, `session_id`, `auth_result`, `human_confirmed`. Other keys
may appear; a consumer must ignore keys it does not know. The record is redacted before it is built: path classes,
reason codes, and verdicts, never a raw command, path, or secret.

### 2. Decision history

The decision log is the SQLite file `.doberman/doberman.db` in the repo. A consumer opens it **read-only** and may
rely on these columns of table `decisions`:

`id`, `ts`, `action_id`, `final_verdict`, `action_type`, `target_path_class`, `risk`, `reason_codes_json`,
`session_id`, `auth_result`, `human_confirmed`

and on `schema_version.version`, an integer. Doberman adds tables and columns freely; only these eleven columns are
pinned. `schema_version` describes the database, not this contract: read it for display, do not gate on it.

### 3. The dashboard process

`doberman dash --path <repo> --port <port>` prints one stdout line matching

```
^Dashboard: http://127\.0\.0\.1:(\d+)/\?token=([A-Za-z0-9_-]+)$
```

The second group is the run's bearer token; it is new every run. If the optional `dash` extra is not installed the
command exits 1 and stderr contains `requires the optional "dash" extra`. A busy port exits 1 before the line is
printed.

### 4. Pending approvals and resolve

Every route takes `Authorization: Bearer <run token>`. A missing or wrong token is `401 {"error": "unauthorized"}`.

`GET /api/pending` returns a list of rows with these fields: `id`, `created_at`, `expires_at`, `tier`,
`action_type`, `risk`, `reason_codes`, `explanation`, `target_path_class`, `needs_totp`, `session_id`. A later
additive change may add fields; a consumer ignores fields it does not know.

`POST /api/resolve/{id}` takes `{"decision": "approved" | "denied", "totp_code": "<digits>"}` (`totp_code` optional):

| Status | Body |
| --- | --- |
| 200 | `{"status": "resolved"}` |
| 400 | `{"error": "decision must be 'approved' or 'denied'"}` |
| 401 | `{"error": "unauthorized"}` |
| 409 | `{"error": "already resolved or expired"}` |

The dashboard never verifies the code itself and never echoes `totp_code` back; the waiting approval checks it.
A consumer treats an unknown `tier`, or a row without `needs_totp`, as needing a code. In Windows Hello-required mode
an approval that needs proof is never queued to the dashboard at all.

### 5. Hook approvals

A host-hook approval (Claude Code, Codex, Cursor) reaches the dashboard only while the dashboard is running. It is a
surface-4 row whose `session_id` is normally non-null (`null` when the host sent no session id); there is no separate
route.

## When one side is missing or out of date

| Case | A consumer should | Doberman does |
| --- | --- | --- |
| Doberman not installed or not on PATH | Show it as not found; keep working otherwise | - |
| The consumer is not running | - | The webhook POST fails fast on loopback and is logged; the decision is unaffected. Without a live dashboard, hook approvals skip the dashboard and ask elsewhere |
| `contract` missing, or `/api/health` fails while `/api/pending` works | Treat it as contract 0 | - |
| `contract` is a major the consumer knows | Work normally; use `features` for optional parts | - |
| `contract` is newer than the consumer knows | Go read-only: show history and pending rows, refuse to resolve, ask the user to update the consumer | - |
| The consumer is older than an additive change | Ignore unknown fields | - |

## Changing a pinned surface

`tests/unit/test_companion_contract.py` pins every value on this page, so an accidental change fails CI. A pull request
that changes a pinned surface on purpose bumps `contract` when the change is not additive, updates this page, and adds a
`contract:` line to its changelog fragment.
