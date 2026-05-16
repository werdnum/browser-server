# Browser Handoff Standalone Service Plan

Source reviewed: https://github.com/werdnum/family-assistant/pull/838

## Design Review

The PR's core recommendation is sound: browser handoff should be a separate service, not an
extension of the Family Assistant process. The strongest part of the design is the lease model. It
correctly makes the safety property enforceable by the service rather than relying on the agent to
pause voluntarily.

The important security invariant is:

> When a human controls the browser, the agent has no ability to observe or mutate that browser.

That means screenshots, DOM snapshots, accessibility trees, JavaScript execution, console messages,
network bodies, clipboard values, current URL details, and form values must all be blocked or
redacted during human-owned states.

The design doc is directionally complete, but a standalone implementation needs sharper boundaries
in these areas:

- A precise service API split between public authenticated API, Family Assistant service API, and
  worker-internal API.
- A worker lifecycle model that can run locally first but later move to containers or a scheduler.
- A concrete command protocol for browser automation so Family Assistant never receives raw
  Playwright handles.
- A token and websocket authentication model for noVNC.
- A fail-closed policy for crashes, worker loss, stale leases, and unknown session state.
- Operational defaults: timeouts, resource limits, metrics, and audit retention.

## Target System

Build `browser-handoff-service` as an independent service that owns live browser sessions, remote
control, leases, state transitions, and audit events.

Family Assistant becomes a client of this service. It can create sessions, send agent browser
commands, request human handoff, subscribe to lifecycle events, and render or link to the handoff UI.
It must not host the browser, noVNC, Playwright runtime, or sensitive handoff state.

```text
Family Assistant
  - chat, auth, agent orchestration
  - browser tool adapter
  - handoff card / notification surface
        |
        | service auth
        v
Browser Handoff API
  - session lifecycle
  - lease/state machine
  - policy checks
  - audit events
  - remote token minting
        |
        | internal worker protocol
        v
Browser Runtime Worker
  - headed Chromium
  - Playwright server/client
  - virtual display
  - noVNC/websockify endpoint
  - scratch browser profile
        ^
        |
Human Web UI
  - authenticated session detail page
  - noVNC viewport
  - complete/cancel/extend controls
```

## Service Components

### API Server

Recommended stack for a first implementation: Python FastAPI, Pydantic models, an in-memory session
registry, process-local timers, and Playwright in workers. This matches the likely Family Assistant
ecosystem while keeping a clean service boundary.

V1 should assume shared fate between the API process and browser runtime workers: if the service
process or container dies, all live browser sessions are invalid and their browser processes,
virtual displays, noVNC proxies, and scratch profiles are killed or wiped by the same supervisor
boundary. Under that assumption, a database is not required to protect live sessions because there
is no live browser left to protect after process death.

Responsibilities:

- Authenticate Family Assistant service calls.
- Authenticate human UI/API calls.
- Own the browser session state machine.
- Enforce lease checks before every browser command.
- Mint short-lived one-time handoff tokens.
- Proxy or authorize noVNC websocket connections.
- Keep live session metadata in memory without storing page content.
- Emit lifecycle events over SSE/webhook.
- Expire and clean up idle or abandoned sessions.

### Runtime Worker

V1 should support one worker process per browser session locally. The API should hide this so V2 can
move to containers, Kubernetes jobs, or a bounded worker pool.

Runtime responsibilities:

- Start Xvfb or Wayland virtual display.
- Start headed Chromium in a scratch profile directory.
- Expose Playwright control to the service only.
- Expose the browser display through noVNC/websockify.
- Return only structured browser command results.
- Never persist video, screenshots, network bodies, clipboard data, or console payloads by default.
- Tear down browser, display, and scratch profile on close/expiry.

### Human UI

The service should provide a minimal operational UI. Family Assistant can embed it or redirect to it.

Pages:

- `GET /sessions`: list sessions claimable by the signed-in user.
- `GET /sessions/{id}`: status, note, expiry, controls, and remote viewport.
- Remote viewport component backed by authenticated noVNC websocket.

Controls:

- Claim/open session.
- Mark complete with structured outcome.
- Cancel.
- Extend.
- Close browser.
- Mark sensitive.

No sensitive values should be entered into service UI forms. Payment, credentials, and OTPs are typed
only into the remote browser page.

## State Machine

States:

- `agent_active`: agent owns the lease; browser commands allowed.
- `handoff_requested`: handoff created; agent commands denied; waiting for human claim.
- `human_active`: human owns lease; all agent observation and mutation denied.
- `human_sensitive`: human likely entered secrets; default exit is close.
- `sanitize_pending`: service owns lease; closes or replaces human-controlled page.
- `agent_resumable`: agent can resume after policy-approved sanitization.
- `completed`: final successful outcome; runtime closed unless explicitly resumable.
- `cancelled`: final cancelled outcome; runtime closed.
- `expired`: final timeout outcome; runtime closed.
- `failed`: runtime or policy failure; runtime closed or isolated for operator inspection without
  page capture.

Lease owners:

- `agent`
- `human`
- `service`
- `none`

Fail closed:

- Unknown state denies browser commands.
- Missing worker denies browser commands and moves session to `failed` or `expired`.
- Failed state mutation leaves the current in-memory lease unchanged.
- Lost websocket does not return control to the agent automatically.
- Expired handoff token cannot be refreshed by the browser client; the API must re-authorize.
- Service restart invalidates every session; Family Assistant should treat missing sessions as
  `expired` or `failed` and ask the user to restart the browser flow.

## Expiry And Cleanup

Treat live browser sessions as expensive, sensitive, and disposable. Expiry is not just resource
management; it is part of the security boundary. A stale browser may contain authenticated cookies,
checkout state, private account pages, or partially entered sensitive data.

Use separate clocks for different concerns:

- `expires_at`: hard deadline for the live browser runtime.
- `idle_expires_at`: shorter deadline extended by allowed activity.
- `handoff_token_expires_at`: deadline for claiming a handoff URL.
- `remote_connection_expires_at`: deadline for a noVNC websocket authorization.
- `cleanup_started_at`: marker that teardown has begun.
- `cleanup_completed_at`: marker that browser, display, websocket proxy, and scratch files are gone.

In V1 these clocks live in the in-memory session registry. They are not durable. A service restart
means all clocks and sessions disappear, and all browser runtimes should die with the service.

Recommended V1 defaults:

```text
agent_active idle timeout:        15 minutes
research session hard timeout:    60 minutes
handoff_requested claim timeout:  10 minutes
human_active idle timeout:        10 minutes
human_sensitive idle timeout:      5 minutes
payment hard timeout:             20 minutes
remote websocket token TTL:        1 minute
handoff URL token TTL:            10 minutes
cleanup grace period:             30 seconds
failed cleanup retry window:       5 minutes
```

Activity should extend `idle_expires_at` only when the actor currently owns the lease:

- Agent browser commands extend agent idle expiry.
- Human mouse/keyboard websocket activity may extend human idle expiry.
- Polling, status reads, or reconnect attempts should not extend idle expiry by themselves.
- Expiry extension should be capped by `expires_at`.

State-specific expiry behavior:

- `agent_active`: close runtime and mark `expired` when idle or hard timeout is reached.
- `handoff_requested`: if the user does not claim in time, close runtime and mark `expired` unless
  product policy explicitly returns the lease to the agent. V1 should close.
- `human_active`: warn the UI shortly before idle expiry; if no activity resumes, close runtime and
  mark `expired`.
- `human_sensitive`: use a shorter timeout and close on expiry. Never return the lease to the agent.
- `sanitize_pending`: if sanitization exceeds a short deadline, close runtime and mark `failed`.
- `agent_resumable`: if the agent does not resume quickly, close runtime and mark `expired`.
- Terminal states: ensure runtime is closed, revoke tokens, close websocket connections, and remove
  scratch files.

Cleanup phases should be idempotent:

1. Atomically move the session to a closing terminal state or set `cleanup_started_at`.
2. Revoke unconsumed handoff and remote websocket tokens.
3. Stop accepting new agent commands, human actions, and websocket upgrades.
4. Close active noVNC websocket connections.
5. Ask the worker to close Chromium gracefully.
6. Kill the worker process/container if graceful close misses the grace period.
7. Remove scratch browser profile, downloads, temporary display sockets, and proxy state.
8. Clear `worker_id` and write `cleanup_completed_at`.
9. Append an audit event with only coarse cleanup metadata.

The cleanup operation must be safe to retry while the process is alive. After process death, cleanup
is delegated to the process/container supervisor and startup scratch-directory sweeping.

Background jobs:

- `expiry_reaper`: scans non-terminal sessions whose idle or hard expiry has passed.
- `worker_health_reaper`: marks sessions failed when workers miss health checks.
- `cleanup_reaper`: retries sessions with `cleanup_started_at` but no `cleanup_completed_at`.
- `token_reaper`: deletes or invalidates expired handoff and remote tokens.
- `orphan_worker_reaper`: finds live workers with no active in-memory session and terminates them.
- `scratch_sweeper`: removes stale scratch profile directories from previous crashed processes at
  service startup.

Concurrency rules:

- Reapers and request handlers should acquire a per-session in-memory lock before mutating a session.
- API-driven completion/cancellation and reaper-driven expiry must use the same state transition
  library.
- If a human completes at the same time as expiry, whichever transition commits first wins; the other
  call receives the terminal state.
- Websocket reconnect after expiry is denied even if the browser process has not been killed yet.

Crash and restart behavior:

- On API startup, the active session registry is empty.
- Any browser process, virtual display, noVNC proxy, or scratch profile from a previous process is
  considered orphaned and must be terminated or deleted.
- Workers should not resurrect sessions by themselves.
- Family Assistant should map `404 unknown session`, dropped SSE, or websocket closure after restart
  to a terminal `expired` or `failed` handoff outcome.
- Never default an unknown or previously human-owned session back to `agent_active`.

User experience:

- Show countdowns for handoff claim and human active time.
- Warn the user before human-control expiry and offer an explicit `extend` action.
- Require the same authorization checks for `extend` as for `claim`.
- Do not auto-extend payment, credential, or legal-consent sessions in the background.
- After expiry, show a clear terminal status and ask the user to restart the browser flow if needed.

## API Shape

Use three API surfaces.

### Family Assistant Service API

```text
POST /v1/sessions
GET  /v1/sessions/{session_id}
POST /v1/sessions/{session_id}/agent-command
POST /v1/sessions/{session_id}/handoff
POST /v1/sessions/{session_id}/close
GET  /v1/sessions/{session_id}/events
```

`POST /v1/sessions` creates a browser runtime and returns opaque metadata:

```json
{
  "session_id": "bs_...",
  "conversation_id": "conv_...",
  "state": "agent_active",
  "lease_owner": "agent",
  "expires_at": "2026-05-15T10:00:00Z"
}
```

`POST /v1/sessions/{id}/agent-command` accepts a typed browser command. Keep this intentionally
narrow at first:

```json
{
  "command_id": "cmd_...",
  "type": "navigate",
  "args": { "url": "https://example.com" }
}
```

Initial command types:

- `navigate`
- `click`
- `type_text`
- `select`
- `press_key`
- `snapshot`
- `screenshot`
- `current_page`
- `close_page`

Commands are denied unless `state=agent_active` or `state=agent_resumable` and
`lease_owner=agent`. Observation commands are denied in all human or sanitize states.

`POST /v1/sessions/{id}/handoff`:

```json
{
  "reason": "payment",
  "handoff_note": "Review the cart and enter payment details.",
  "expected_origin": "https://merchant.example",
  "allowed_resume": "never",
  "assigned_user_id": "user_..."
}
```

Response:

```json
{
  "session_id": "bs_...",
  "state": "handoff_requested",
  "handoff_url": "https://browser-handoff.example/sessions/bs_...?token=...",
  "expires_at": "2026-05-15T10:10:00Z"
}
```

### Human API

```text
POST /v1/sessions/{session_id}/claim
POST /v1/sessions/{session_id}/complete
POST /v1/sessions/{session_id}/cancel
POST /v1/sessions/{session_id}/extend
POST /v1/sessions/{session_id}/mark-sensitive
GET  /v1/sessions/{session_id}/remote
```

`GET /remote` returns a short-lived websocket authorization envelope or performs an authenticated
websocket upgrade. It must not expose raw worker credentials or internal hostnames.

### Worker Internal API

This can be HTTP, gRPC, or a local process protocol. Keep it private.

```text
POST /internal/workers
GET  /internal/workers/{worker_id}/health
POST /internal/workers/{worker_id}/commands
POST /internal/workers/{worker_id}/close
```

The API server should be the only actor allowed to talk to workers.

## Data Model

V1 should use process-local data structures rather than a database for live handoff state. This is
valid only under the shared-fate deployment assumption: the API process, browser workers, virtual
display, noVNC proxy, and scratch profile directory are all scoped to the same service/container
lifecycle. If that process/container dies, the browser session is invalid by definition.

Core in-memory records:

```text
BrowserSessionRecord(
  id uuid,
  conversation_id text not null,
  interface_type text,
  requested_by_user_id text not null,
  assigned_user_id text,
  state text not null,
  lease_owner text not null,
  worker_id text,
  worker_pid integer,
  scratch_dir text,
  current_origin text,
  current_url_redacted text,
  current_title_redacted text,
  handoff_reason text,
  allowed_resume text not null default 'never',
  handoff_note text,
  sensitive_since timestamptz,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  idle_expires_at timestamptz not null,
  expires_at timestamptz not null,
  cleanup_started_at timestamptz,
  cleanup_completed_at timestamptz,
  closed_at timestamptz,
  lock asyncio.Lock
)

BrowserSessionEvent(
  id uuid,
  browser_session_id uuid,
  event_type text not null,
  actor_type text not null,
  actor_user_id text,
  metadata_json dict,
  created_at timestamptz not null
)

HandoffToken(
  id uuid,
  browser_session_id uuid,
  token_hash text not null,
  assigned_user_id text,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null
)

RemoteConnectionToken(
  id uuid,
  browser_session_id uuid,
  token_hash text not null,
  actor_user_id text not null,
  websocket_connection_id text,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null
)
```

The event list is process-local in V1 and exists to drive SSE/UI behavior while the service is
alive. Durable product history should be written by Family Assistant as high-level conversation
events, for example `handoff_requested`, `handoff_expired`, or `handoff_completed`, without page
content.

Add a database to the handoff service only when one of these becomes true:

- API and browser workers no longer share fate.
- Multiple API replicas can access the same sessions.
- Live workers can survive API restart.
- Handoff-service audit history must survive restarts independently of Family Assistant.
- Cleanup can be partial after process death and needs durable retry state.

If durable state is added later, it should store control-plane metadata only: session ID, owner,
state, expiry, terminal outcome, redacted origin/title, and audit events. It still should not store
browser state, cookies, screenshots, DOM snapshots, network bodies, console payloads, form values,
or secrets.

Never store:

- Screenshots.
- DOM snapshots.
- Accessibility trees from human control.
- Form values.
- Clipboard values.
- Payment data.
- Credentials.
- OTPs.
- Full URLs with sensitive query strings.
- Console logs or network bodies.

## Security Model

Authentication:

- Family Assistant uses service-to-service credentials with scoped permissions.
- Human users use normal web auth, plus one-time handoff tokens for session claim.
- noVNC websocket access requires both authenticated user identity and live session authorization.

Authorization:

- Session claim is limited to `assigned_user_id` unless explicitly configured for family-wide claim.
- Agent commands are allowed only for sessions created by that Family Assistant tenant/client.
- Worker APIs are private network only and require internal auth.

Isolation:

- Runtime worker has no access to Family Assistant database or application secrets.
- Browser profile lives in a per-session scratch directory.
- Runtime filesystem is read-only except scratch.
- Disable browser extensions unless explicitly required.
- Apply CPU, memory, process, and wall-clock limits.

Redaction:

- URL redaction should remove query strings by default.
- Audit metadata should use enums and coarse origins, not page contents.
- Browser command responses should be schema-validated before returning to Family Assistant.

## First Implementation Milestones

### 1. Contract-First Skeleton

- Create service repository/package.
- Add Pydantic models for sessions, leases, states, events, and commands.
- Implement state transition library with unit tests.
- Implement the in-memory session registry and per-session locking.
- Add service auth middleware.
- Add expiry fields and cleanup state to the session model.

Exit criteria:

- Invalid state transitions are rejected.
- Agent command authorization fails closed for non-agent leases.
- Payment handoffs reject `same_page` resume.
- Expired sessions reject commands and transition through the same state library.
- Service restart has no active sessions by design.

### 2. Local Browser Worker

- Implement one local runtime worker per session.
- Launch Xvfb, headed Chromium, and Playwright.
- Implement `navigate`, `click`, `type_text`, `snapshot`, `screenshot`, and `close`.
- Add runtime cleanup on close and expiry.
- Add idempotent worker teardown and scratch directory deletion.

Exit criteria:

- API can create a session, navigate to a fixture page, and close cleanly.
- Runtime loss moves session to failed/closed state without exposing page contents.
- Repeated cleanup calls leave no live worker or scratch profile.

### 3. Handoff Without noVNC

- Implement handoff tokens and claim flow.
- Deny all agent commands after handoff request.
- Add completion, cancellation, extension, and expiry.
- Emit SSE lifecycle events.
- Add the process-local expiry, token, cleanup, and scratch-sweeper jobs.

Exit criteria:

- Family Assistant could show a handoff card and receive completion events.
- Agent browser commands are denied during pending/human states.
- Unclaimed handoffs expire and close the runtime.

### 4. noVNC Remote Control

- Add virtual display websocket proxy.
- Add service-hosted session detail page.
- Implement authenticated remote viewport.
- Add complete/cancel/extend controls.

Exit criteria:

- User can claim and control the same headed browser session.
- Websocket URLs expire and cannot be reused.
- Unauthorized users cannot open the viewport.

### 5. Family Assistant Adapter

- Replace direct browser session creation in browser tools with the service client for handoff-capable
  profiles.
- Add `request_browser_handoff`.
- Render handoff cards in chat.
- Subscribe to service events and write high-level conversation events only.

Exit criteria:

- Agent can browse to a fixture checkout, request handoff, lose access, and receive a structured
  human outcome.

### 6. Sanitized Resume

- Implement `after_sanitize` for low-risk reasons only.
- Close human-controlled page.
- Open a fresh page in the same context at an allowed origin.
- Run simple sensitive-field checks before returning lease.

Exit criteria:

- CAPTCHA/cookie-consent style flows can resume.
- Payment, credential, and legal-consent flows still close by default.

### 7. Hardening

- Add metrics, tracing, structured logs, and operational dashboards.
- Add resource quotas.
- Add background reaper for stale sessions/workers.
- Add security regression tests for no model-visible secrets.
- Document deployment options: local Docker Compose first, container scheduler later.

## Testing Plan

Unit tests:

- State transitions.
- Lease authorization.
- Token hashing, expiry, and one-time consumption.
- URL/event metadata redaction.
- Resume policy matrix.
- Cleanup idempotency and reaper lock behavior.

Functional tests:

- Create session, browse fixture shop, request handoff, deny agent commands.
- Human claim, complete, and close.
- Human cancel.
- Handoff expiry closes runtime.
- Human idle expiry closes runtime.
- Payment handoff expiry never returns lease to the agent.
- Worker crash fails closed.
- API restart returns no active sessions; stale scratch directories are swept on startup.
- Sanitized resume for low-risk flow.

UI tests:

- Session list visibility.
- Detail page status and controls.
- noVNC placeholder/connection state.
- Complete/cancel state updates.
- Unauthorized claim blocked.

Security regression tests:

- Agent cannot snapshot, screenshot, execute JS, or inspect URL during human states.
- Console messages and network bodies are not logged or returned.
- Sensitive fixture values never appear in API responses, audit events, logs, or message payloads.
- noVNC websocket cannot be opened with expired, reused, or wrong-user tokens.
- Expired sessions do not leak final URL, title, screenshot, DOM, console, or network metadata during
  cleanup.

## Key Decisions To Make Before Build

1. Runtime topology for V1: local child process, Docker container per session, or bounded worker pool.
   Start with local child process only if deployment is single-host and controlled. Prefer container
   per session if isolation matters immediately.
2. Human claim policy: assigned user only by default. Family-wide claim can be a later explicit
   policy.
3. noVNC proxy mode: service-side websocket proxy is safer than returning worker URLs to the client.
4. Persistence: for shared-fate V1, keep handoff-service state in memory and let Family Assistant
   persist only high-level conversation events. Add handoff-service persistence later only if workers
   can outlive the API, multiple API replicas share sessions, or durable service audit is required.
5. Resume policy: default `never`; allow `after_sanitize` only for non-payment, non-credential,
   non-legal-consent reasons.

## Recommended V1 Scope

Build the smallest standalone service that proves the hard property:

- Family Assistant can create and drive a hosted headed browser through a narrow command API.
- The service can transfer the lease to a human.
- During human control, every agent browser command is denied.
- The human can control the browser through noVNC and mark an outcome.
- Payment/credential handoffs close the runtime and return only structured outcome metadata.

Defer durable browser profiles, same-page resume, family-wide claim, video recording, WebRTC, and
advanced sanitizer logic until the core lease and no-observation guarantees are proven.
