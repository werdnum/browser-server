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

## Element refs

`snapshot` stamps each listed element with a `data-fa-ref="eN"` attribute and returns it as the
node's `ref`. Numbers are issued from the caller's own counter: pass `next_ref` (default `1`) with
every snapshot and thread the `next_ref` the result reports into the next one, and no number is
ever issued for two different nodes. A node keeps its ref across snapshots for as long as its role
and accessible name are unchanged; anything else gets a fresh number, and the walker never
allocates below a number already stamped on the document.

`click`, `type_text` and `select` accept a `ref` instead of a `selector`. The ref is checked
against the live page before the action runs — it resolves exactly when a snapshot taken at that
moment would still list that node — so a removed, hidden, relabelled or previous-document ref
returns `{"error": true, "code": "stale_ref", "cause": "missing|hidden|changed", ...}` immediately
rather than waiting out the actionability timeout. A ref that is not of the form `e12` returns
`invalid_ref`. A raw `selector` still works unchanged.

Identity is the stamped attributes (ref, role, name), not the node object: a page that replaces a
stamped node with a clone carrying those attributes produces a look-alike the check cannot tell
apart. This is a deliberate simplification shared with every surveyed harness except Playwright.

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
export BROWSER_JAR_SAVE_AUTHORIZATION_TOKEN="<secret>"    # required only when the gate above is on
export BROWSER_JAR_SESSION_TTL_HOURS="12"                 # optional; bounded retention for session-cookie jars
```

A jar that captured any browser-**session** cookie (`expires == -1`) is loadable only within
`BROWSER_JAR_SESSION_TTL_HOURS` of its last save (default 12h). A session cookie is meant to die on
browser close, so a jar holding one must not become an indefinitely replayable credential; the cap
keys on "contains any session cookie" (not "all cookies are session-only"), since the server cannot
tell which cookie is auth-bearing. Persistent-cookie jars have no TTL — their staleness surfaces via
probing and the human can delete them.

When `BROWSER_JAR_REQUIRE_SAVE_AUTHORIZATION` is enabled, a human save must present
`BROWSER_JAR_SAVE_AUTHORIZATION_TOKEN`. This is a **dedicated** secret, deliberately separate from
`BROWSER_HANDOFF_SERVICE_TOKEN`: the party that relays it to the browser to authorize a save must
not thereby gain the full agent/service API (which can list, load, and delete every jar). If the
gate is on but this token is unset, saves fail closed.

### Durability and multi-process deployment

The jar store is the service's only durable state, and it is deliberately built on plain
filesystem semantics so it works on a **shared directory** — a single RWO volume today, or a
replicated RWX volume (e.g. a Longhorn volume) shared by several pods next. There is no database:

- Each jar is one file, written atomically (temp file + `fsync` + rename).
- The revocation state (tombstone log, signed anchor, audit log, and the cross-process lock) lives
  **inside `BROWSER_JAR_DIR`** alongside the jars — mounting that one directory carries both the
  encrypted logins and their kill-switch, so a revoke cannot be stranded off the shared volume.
- Revocation is an append-only, HMAC-authenticated tombstone log, `fsync`'d on write and re-read
  fresh on every check (NFS close-to-open consistency), so one pod's kill-switch is visible to
  the others without a restart.
- Tombstone-mutating operations serialize across processes with a POSIX file lock (`fcntl.lockf`,
  chosen for NFS reliability); within a process they are already serialized by synchronous
  execution.
- Live sessions recheck the shared tombstone before every agent command and every noVNC/human
  authorization, so a revoke tears down running contexts, not just future loads.

Honest residual: the **session registry itself is still in-memory and process-lifetime** (a
session created on one pod is not visible to another). Persisting it onto the same shared jar
directory is a natural, self-contained follow-up; nothing in the jar design assumes a single
process. The one bound to know about today is a whole-filesystem rollback that also truncates the
tombstone log — set an external monotonic anchor (`jar-anchor.json`, or a KMS/DB/WORM export) to
close it.

## Authenticated-site sessions and credential autofill

A jar is one way to reach a logged-in page; the other is to let the operator's stored password be
**filled** into a login form without it ever passing through the agent. Both live inside the same
session type, created with `authenticated_site: true` on `create_session` (service token only,
like `jar_id`):

```jsonc
POST /v1/sessions
{
  "conversation_id": "…",
  "authenticated_site": true,
  "jar_id": "jar_…",                                   // optional
  "confine_origins": ["https://shop.example.com"],     // required when there is no jar
  "credential_alias": "shop-login"                     // optional; no alias, no autofill
}
```

What the session type fixes, deterministically and regardless of what else the caller asked for:

- `exec` and `extract` are denied outright, and clipboard/transfer chords (`Control`/`Meta` with
  `c`/`x`/`v`/`Insert`, and `Shift+Insert/Delete`) are refused. Typing *into* a protected control is
  still fine — writing is not leaking.
- Navigation confinement is always on (`confine_navigation: false` is a 400, as is `allow_exec`),
  and a **jarless** session supplies the set explicitly and is confined by the same route guard a
  jar-loaded one uses. Stating both a `jar_id` and `confine_origins` requires the two to be equal;
  otherwise the call is a 400, so a caller can never verify one set while the session enforces
  another. The session record echoes `confine_origins` as actually enforced.
- Every `input[type=password]`, plus every control a fill touched, is **protected**: the snapshot
  walker stamps `data-fa-protected`, omits the value, and reports `value_masked` with
  `has_value` instead; screenshots mask the same selector. Tracking is per element, so a "show
  password" toggle cannot turn a protected control back into a readable one.

`POST /v1/sessions/{id}/autofill` then fills the pinned credential into the login form on the
current HTTPS page. Plaintext HTTP documents are refused before a credential request is made.
Policy outcomes are a 200 with a typed status, not an HTTP code:

```jsonc
// request
{"step_key": "password", "fields": [{"ref": "e12", "kind": "password"}], "wait_seconds": 25,
 "context": {"site": "shop", "acting_user": "andrew"}}

// responses
{"status": "filled", "filled": [{"ref": "e12", "kind": "password"}], "origin": "https://shop.example.com"}
{"status": "approval_pending", "request_id": "…", "origin": "…"}
{"status": "refused", "reason": "new_password_field", "detail": "…"}
```

`fields` may be omitted, in which case browser-server auto-detects on the main-frame document (a
second visible password field is `ambiguous_fields`, not a guess). A kind-only entry such as
`{"kind": "password"}` auto-detects just that kind. Refusal reasons:
`not_authenticated_site`, `no_alias`, `wrong_origin`, `no_eligible_field`, `ambiguous_fields`,
`new_password_field`, `in_iframe`, `target_invalidated`, `policy_denied`, `request_expired`,
`grant_invalid`, `bad_password_recorded`, `fill_cap_reached`, `keychute_unavailable`, `stale_ref`,
`invalid_ref`.

`POST /v1/sessions/{id}/autofill/outcome` with `{"outcome": "bad_password"}` latches the session:
every later fill is refused. A per-session cap of 6 credential reads is the deterministic backstop behind it, including reads
whose subsequent fill fails.

### Handing out to a human and back

A challenge a human can finish in the live session — an MFA code, a captcha, a "verify it's you"
click — is a detour, not an ending, so the handoff has to be a round trip. `POST .../handoff` parks
the session under human control as usual (it stays origin-confined and fail-closed for agent
commands throughout; confinement is **never** lifted for an authenticated-site session, which is
why the agent may inherit the context afterwards — the human cannot have widened it). When the
human is done they `POST .../handover`, which for an authenticated-site session forces sanitized
resume: the human-controlled page is closed and a fresh one opened inside the confinement set, so
the authenticated cookies survive but the exact page and any in-progress form state do not.

Trusted orchestration then takes the lease back with `POST .../agent-claim` **and no body**. The
human's handover POST is the signal and the service token is the authority (it already creates
and drives these sessions). No handover token is minted for an authenticated-site session; the
page asks the human to tell their assistant to resume the task. Claiming revokes the human's
control token. Ordinary sessions still require a one-time handover token, and a jar-loaded
session that is *not* an authenticated-site session cannot be handed to an agent at all.

Poll `GET /v1/sessions/{id}` for `state` and `lease_owner`; the handback is ready when `state` is
`handover_requested`. A token-less claim in any other state is a 409, and in a non-authenticated-site
session it is a 403.

Each call is one [Keychute](https://github.com/werdnum/keychute) access request and one single-use
grant read, and the destination is decided here rather than taken on trust:

1. The request's origin constraint is the origin of the **document actually on screen**, never
   anything the caller supplied, and the idempotency key is `"{session_id}:{step_key}"` — so an
   `approval_pending` retry of the same step resumes the same decision instead of opening a second
   one.
2. The fill-time check is against the **granted** constraints, which an approval may have narrowed
   below what was asked for. An origin the session may *navigate* is not thereby an origin a fill
   may *target*.
3. Resolve, verify and fill are one serialized operation under the session lock, and the target
   document is pinned with a nonce; a navigation in between — including one the site starts while
   an approval is pending — is `target_invalidated` rather than a fill into whatever is there now.
4. Element checks refuse rather than guess: a password only into `input[type=password]` (or an
   already-protected control), never into an `autocomplete=new-password` field, an identifier only
   into text/email/tel, and main frame only.

browser-server **stores no credential**: it holds the released plaintext only long enough to place
it in the field, zeroes the returned mutable secret buffer, and puts it in no response, event,
log or exception. HTTP response bytes and parsed Python strings are not zeroed; memory erasure
is not guaranteed. Configure
the broker (unconfigured ⇒ autofill returns `refused(keychute_unavailable)`):

```bash
export BROWSER_KEYCHUTE_URL="https://keychute.keychute.svc.cluster.local"
export BROWSER_KEYCHUTE_TOKEN_FILE="/var/run/secrets/keychute/token"   # re-read per request
export BROWSER_KEYCHUTE_TOKEN="<secret>"                               # alternative to the file
export BROWSER_KEYCHUTE_CA_BUNDLE="/etc/ssl/internal-ca/ca.crt"        # internal CA, optional
export BROWSER_KEYCHUTE_EXTERNAL_URL="https://keychute.example.com"    # approval links, optional
```

Release authority lives in Keychute's policy rows, not here: which secret may be released to
client `browser-server` for mechanism `autofill`, for which page origins, with which outcome. The
alias on the session is routing — it decides *which* secret this run may ask for — and authorizes
nothing on its own.

Read-back protection is best-effort by design, and the design says so: a browser is an open-ended
rendering surface, and once a value is in the field the approved origin's own JavaScript can read
it, exactly as with any password manager. What is mechanical is the destination check, the
serialized target binding, and the absence of `exec`/`extract`.

## Setup

```bash
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m patchright install chromium
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

### Timezone

Each `POST /v1/sessions` request may include a `timezone_id` (an IANA name such as
`Australia/Sydney`), which is applied to the browser context so in-page JavaScript
(`new Date()`, `Intl.DateTimeFormat`) reports that local time. When a request omits
`timezone_id`, the service falls back to the `BROWSER_TIMEZONE` environment variable;
when neither is set, Chromium's host default is used.

```bash
export BROWSER_TIMEZONE="Australia/Sydney"
```

### Stealth hardening

Chromium sessions are hardened against bot detection by default: Playwright's
`--enable-automation` default flag is dropped, the context matches its viewport to
`window.screen`, and an init script in every frame patches the cheap JS-level tells
(`navigator.webdriver`, a missing `window.chrome` object, empty plugins/mimeTypes
arrays, the permissions-query inconsistency, software-renderer WebGL strings). Input
is humanized too — short text is delivered per-key at a jittered cadence instead of an
instantaneous `fill()`, and clicks carry a randomized mousedown→mouseup hold. Set
`BROWSER_STEALTH=0` for a plain vanilla browser (e.g. when debugging a site that
misbehaves under the patched surfaces), and `BROWSER_LOCALE` to override the default
`en-US` locale.

This is not a full anti-fingerprinting layer: CDP-protocol and TLS-level detection are
out of scope. Headed mode (`BROWSER_HEADED=1`) remains meaningfully harder to detect
than headless, and a hard Cloudflare-class interstitial may still need to be solved
manually through the noVNC handoff view.

### OIDC clock skew

Humans authenticate with an OIDC JWT (`BROWSER_HANDOFF_OIDC_JWKS_URL`,
`BROWSER_HANDOFF_OIDC_ISSUER`, `BROWSER_HANDOFF_OIDC_AUDIENCE`); agents use the opaque
`BROWSER_HANDOFF_SERVICE_TOKEN`. JWT `iat`/`nbf`/`exp` are checked against the local
clock, so a token minted on a host whose clock runs marginally ahead can arrive before
it is nominally valid. `BROWSER_HANDOFF_OIDC_LEEWAY_SECONDS` sets the tolerance
(default `60`); set it to `0` to require exact agreement.

```bash
export BROWSER_HANDOFF_OIDC_LEEWAY_SECONDS=60
```

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
