# Browser Handoff Service MVP

Standalone FastAPI MVP for browser handoff sessions.

Implemented:

- In-memory session registry with per-session locks.
- Explicit state and lease transitions.
- Service-authenticated agent API.
- No human user identity model; handoff URL/control tokens are the human authorization primitive.
- Human claim, complete, cancel, extend, and mark-sensitive flows.
- Human-initiated sessions: a user can start a browser session (`initial_owner: "human"`) and later hand it over to an agent.
- One-time handoff URL tokens; claim returns a separate human control token for remote/actions.
- Optional `expected_origin` validation before minting a handoff URL.
- Fail-closed command authorization after handoff starts.
- Sanitized resume for low-risk handoffs closes the human-controlled page before returning the lease.
- Real Playwright Chromium runtime by default.
- Headed Chromium plus Xvfb/x11vnc/noVNC launch path when host binaries are installed.
- Form factor auto-detected from the user's aspect ratio (portrait -> mobile, landscape -> desktop); the noVNC viewport is sized to match.
- Automatic UCP (Universal Commerce Protocol) discovery: on each accessibility `snapshot` the worker probes the current HTTPS origin's `/.well-known/ucp` profile (once per origin, cached), and when a merchant advertises shopping support it attaches a `ucp` hint to the snapshot so the driving agent can use UCP shopping without merchant-specific endpoints being hardcoded.
- noVNC access is exposed through the authenticated service proxy; raw worker noVNC ports stay loopback-only.
- Minimal human UI at `/sessions/{session_id}`.
- SSE lifecycle event stream.
- Agent-side smoke client in `scripts/agent_client_smoke.py`.
- Cookie jars: opt-in, encrypted, scope-filtered persistence of authenticated browser state
  (see "Cookie jars" below).
- Python and Playwright e2e tests.

## Session flows

The session `form_factor` defaults to `"auto"`: the browser UI measures the user's
aspect ratio (`client_viewport`) when starting a session, and the service picks `"mobile"`
for portrait screens (a 412×915 framebuffer with a mobile user agent so sites serve their
mobile layout) or `"desktop"` for landscape (1280×720). With no client measurement (e.g.
agent-created sessions) `"auto"` falls back to mobile. Pass an explicit
`form_factor: "mobile" | "desktop"` to override detection. The human UI sizes its noVNC
viewport to match the session's aspect ratio.

The service supports handing control of a single browser session in either direction:

- **Agent-first (agent → human).** Create a session (the default `initial_owner: "agent"`),
  drive it with agent commands, then `POST /v1/sessions/{id}/handoff` to mint a one-time
  handoff URL. The human opens the URL, claims it, and finishes the task.
- **Human-first (human → agent).** Create a session with `initial_owner: "human"` (the
  "Start a browser session" button on the landing page does this from the
  OAuth-authenticated UI). The response includes a `control_token` and a ready-to-open
  `session_url`; the user drives the browser (e.g. signs in or navigates to the right page).
  When ready, the user clicks "Hand over to agent" (`POST /v1/sessions/{id}/handover` with the
  control token and an optional `handoff_note`). This is the mirror of `handoff`: the session
  is parked in `handover_requested`, the human control token is revoked, and a one-time
  `handover_token` plus `agent_claim_url` are returned for the user to give to their agent.
  The agent — using its existing service credentials — takes over with
  `POST /v1/sessions/{id}/agent-claim` and the `handover_token`, which transitions the session
  to `agent_active` and lets the agent resume with agent commands. Unclaimed handovers expire.

## Cookie jars (persistent authenticated browser state)

A **cookie jar** is a named, durable, encrypted blob of Playwright `storage_state` (cookies +
localStorage + IndexedDB), scope-filtered to a declared set of origins, captured from a session
after a human logs in, and loadable into a fresh session's browser context at creation time. The
canonical flow: a human logs into a site, clicks "Save this login", and the agent picks the
session up later in a fresh session with no one re-entering credentials. This is the single,
opt-in exception to the "never store cookies" rule; jars never persist typed credentials, only
the session artifacts a site grants after login. Full design in `cookie-jar-design.md`.

browser-server provides *mechanism*; policy (confirmation gating, profile placement, taint) lives
in the Family Assistant client. Mechanism enforced here:

- Jar contents (cookie/storage names and values) are never returned by any endpoint, event, or
  log — metadata only.
- Jars are encrypted at rest with AES-256-GCM under an operator key; security-critical metadata is
  bound as AAD, and revocation is rollback-proof via a generation-versioned tombstone.
- Loads happen only at `create_session` and only via the service token, so a session's
  authenticated scope (`jar_origins`/`jar_nav_allowlist`) is immutable and truthfully reported.
- `exec` is denied by default in jar-loaded sessions (opt in with `allow_exec: true`), and
  navigation is confined to the jar's exact origins (`confine_navigation`, default on).
- Save-time scope filtering (default: the session's current origin) keeps IdP/SSO cookies out.

Endpoints: `POST /v1/sessions/{id}/save-jar`, `GET /v1/jars`, `GET`/`DELETE /v1/jars/{id}`,
`POST /v1/jars/{id}/invalidate`, `POST /v1/jars/{id}/probe`, and `jar_id`/`allow_exec`/
`confine_navigation` on `create_session`. A minimal OIDC `/jars` page lets a household audit and
forget saved logins.

The feature fails closed: with no key configured every jar endpoint returns 503 and
`create_session` rejects `jar_id`. Configure it with:

```bash
# 32-byte urlsafe-base64 AES-256 key (comma-separated list rotates: new key first for writes).
export BROWSER_JAR_KEY="$(python -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
export BROWSER_JAR_DIR="/var/lib/browser-handoff/jars"   # optional; default shown
export BROWSER_JAR_MAX_BYTES="5242880"                    # optional; per-jar export cap
export BROWSER_JAR_REQUIRE_SAVE_AUTHORIZATION="0"         # optional; gate human saves behind FA
```

## Setup

```bash
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m playwright install chromium
npm install
npx playwright install chromium
```

For real local Chromium/noVNC e2e, the host also needs browser and display packages:

```bash
sudo bash scripts/install_system_deps.sh
```

After installing those system packages, the real Chromium smoke, headed noVNC runtime smoke, and browser UI e2e can run without the earlier local sysroot workaround.

## Run

Real Chromium runtime:

```bash
export BROWSER_HANDOFF_SERVICE_TOKEN="$(openssl rand -hex 32)"
.venv/bin/python -m uvicorn browser_handoff_service.main:app --host 127.0.0.1 --port 8000
```

### Public URL

Links the service hands to users and agents (the session URL, handoff URL, agent
claim endpoint, and the noVNC viewport) are built from the request host by default,
falling back to `X-Forwarded-Proto`/`-Host`/`-Prefix` when behind a reverse proxy.
In environments where the request host is internal (e.g. a `*.svc.cluster.local`
Service address), set `BROWSER_HANDOFF_PUBLIC_URL` to the externally reachable base
URL so the service never tells a user or agent to visit an unreachable internal
address:

```bash
export BROWSER_HANDOFF_PUBLIC_URL="https://browser.example.com"
# or, when served under a path prefix:
export BROWSER_HANDOFF_PUBLIC_URL="https://example.com/browser"
```

When set, this value always wins over the request host and forwarding headers.

Headed Chromium with noVNC, when Xvfb/x11vnc/noVNC are installed:

```bash
BROWSER_HANDOFF_SERVICE_TOKEN="$BROWSER_HANDOFF_SERVICE_TOKEN" BROWSER_HEADED=1 .venv/bin/python -m uvicorn browser_handoff_service.main:app --host 127.0.0.1 --port 8000
```

Deterministic test runtime:

```bash
BROWSER_HANDOFF_SERVICE_TOKEN="$BROWSER_HANDOFF_SERVICE_TOKEN" BROWSER_RUNTIME=fake .venv/bin/python -m uvicorn browser_handoff_service.main:app --host 127.0.0.1 --port 8000
```

## Test

```bash
.venv/bin/python -m pytest -q
npm run test:user
```

Agent-side smoke against a running service:

```bash
BROWSER_HANDOFF_SERVICE_TOKEN="$BROWSER_HANDOFF_SERVICE_TOKEN" .venv/bin/python scripts/agent_client_smoke.py --base-url http://127.0.0.1:8000
```

## Quality

```bash
.venv/bin/python -m pip install -e '.[dev]'
make lint
make typecheck
make check
.venv/bin/pre-commit install
make pre-commit
```
