# Cookie Jars: Persistent Authenticated Browser State

## Status

Proposed. Design only — no implementation in this change.

Companion document: `docs/design/browser-cookie-jars.md` in the family-assistant repository, which
specifies the Family Assistant tool surface and policy gating built on the mechanism described here.

## Context

Family Assistant's July 2026 project assessment resequenced the authenticated-browsing roadmap
(originally family-assistant PR #833, the credential broker design). The first deliverable is no
longer a credential broker but the much smaller primitive that unlocks the household site list:

> First: persistent per-origin browser contexts, human-performed login via the existing warm-session
> handoff, and session-expiry detection.

This document designs that primitive for browser-server: a way to **save a "cookie jar"** — the
authenticated browser state a human establishes by logging in through the existing human-first /
handoff flows — and later **load it into a fresh session** so the agent can browse the site as the
logged-in user without anyone re-entering credentials.

The design goal is to be **security compatible**, not to implement security policy here.
browser-server provides mechanism, metadata, and audit; Family Assistant's tool-policy engine
provides policy (confirmation gating on a `load_saved_session` tool, profile placement, taint
labelling). The dividing line is spelled out in "Mechanism/policy split" below.

### Amendment to the data-minimization doctrine

The standalone-service plan states "Never store … cookies … credentials" and defers "durable browser
profiles". Cookie jars are a **deliberate, explicit exception** to that rule, and the only one:

- Jars are opt-in twice over: the operator must configure an encryption key, and each jar is created
  by an explicit save action tied to a session and an actor.
- Jars store only Playwright `storage_state` (cookies + origin storage), filtered to a declared
  scope, encrypted at rest.
- Everything else on the never-store list stays never-stored: screenshots, DOM snapshots,
  accessibility trees from human control, form values, clipboard, payment data, typed credentials,
  OTPs, full URLs with sensitive query strings.

Note the distinction this preserves: a jar contains **session artifacts** (cookies granted after
login), never the **credentials** themselves. Passwords and OTPs are typed by the human into the
page during handoff and are never captured — that is the existing warm-handoff guarantee, unchanged.

## Terminology

- **Cookie jar (jar)**: a named, durable, encrypted blob of Playwright `storage_state` (cookies plus
  localStorage; optionally IndexedDB where the Playwright version supports
  `storage_state(indexed_db=True)`), scoped to a declared set of origins, plus cleartext metadata.
- **Scope**: the set of origins (and their registrable domains) whose state a jar may contain.
- **Jar-loaded session**: a browser session created with `jar_id` set, whose context was seeded from
  that jar at creation time.

## Threat model

The realistic adversary (per the assessment) is scalable prompt injection embedded in web content —
not a targeted attacker against this deployment. What a jar protects, and against what:

1. **Jar theft is account takeover.** A session cookie is a bearer credential for the account.
   Mitigations: encryption at rest with an operator-held key; contents never leave the service
   except into a browser context; strict scope minimization at save time.
2. **The model is untrusted with jar contents.** A prompt-injected agent must not be able to read
   cookie values and exfiltrate them (e.g. paste them into a form on an attacker page).
   Mitigations: no API response, event, or log ever contains cookie values or storage values —
   metadata only; `exec` is denied by default in jar-loaded sessions (see below) because
   `document.cookie` exposes non-HttpOnly cookies to the model.
3. **A prompt-injected agent can still act as the user on the authenticated site.** This is
   inherent to authenticated browsing and is exactly the risk Family Assistant's policy layer
   (confirmation gating today, origin-scoped taint-by-sink policy later) exists to manage.
   browser-server's job is to make the authentication state of every session **visible and
   immutable** (declared at creation, exposed in session metadata) so policy has something solid to
   attach to.
4. **Cross-origin bleed.** Without scoping, saving a jar after a "Sign in with Google" flow would
   vacuum up google.com cookies — a far more valuable credential than the target site's. Save-time
   scope filtering (default: the session's current origin) keeps IdP cookies out unless explicitly
   requested.
5. **Jar poisoning.** A malicious page can set cookies that get saved into a refreshed jar. Impact
   is low (the cookies are scoped to the jar's own domains and would affect only future sessions on
   those domains), and refresh is an explicit action; accepted residual.

## Mechanism/policy split

What browser-server enforces (mechanism — things that must hold regardless of client behavior):

- Jar contents (cookie/storage names and values) are never returned by any endpoint, never included
  in events, never logged.
- Jars are encrypted at rest; without the configured key the feature is disabled fail-closed.
- Save is only possible from a live session by an actor who holds that session's lease (agent) or
  control token (human), and only captures state within the declared scope.
- Load happens only at session creation. A session's authenticated scope is therefore immutable and
  truthfully reported in session metadata for its whole lifetime.
- `exec` (and any future command that can read cookie values) is denied in jar-loaded sessions
  unless the creator explicitly opted in.
- Every jar operation is an audited session/service event.
- The existing no-observation-during-human-control invariant is unchanged; jar endpoints follow the
  same fail-closed authorization as agent commands.

What Family Assistant decides (policy — deliberately **not** implemented here):

- Whether loading a saved session requires user confirmation (`load_saved_session` behind the
  tool-policy engine's durable confirmations).
- Which profiles may save/list/load/delete jars at all.
- Whether snapshots from jar-loaded sessions carry different taint, and what the taint-by-sink
  matrix allows in an authenticated session (the "browser cell", per the assessment).
- Whether to keep `exec`/`extract` enabled in authenticated sessions.
- When to probe for expiry, and how to orchestrate re-login (a handoff) when a jar goes stale.

This split is the whole point: adding confirmation gating, taint rules, or per-origin policy later
must require **zero** browser-server changes.

## Data model

```python
class CookieJarMeta(BaseModel):
    jar_id: str                      # "jar_" + uuid4().hex
    label: str                       # human-readable, e.g. "Woolworths (Andrew)"
    origins: list[str]               # exact origins in scope, e.g. ["https://www.example.com"]
    registrable_domains: list[str]   # derived, e.g. ["example.com"]
    created_at: datetime
    updated_at: datetime             # bumped on refresh
    last_loaded_at: datetime | None
    version: int                     # increments on refresh
    saved_by: Literal["agent", "human"]
    created_session_id: str          # provenance: session the state came from
    conversation_id: str             # provenance only; jars are not conversation-scoped
    cookie_count: int
    origin_storage_count: int        # number of origins with localStorage/IndexedDB entries
    earliest_cookie_expiry: datetime | None   # min over persistent cookies; None if all session-cookies
    probe: JarProbeConfig | None
    last_probe_at: datetime | None
    last_probe_result: Literal["fresh", "stale", "error"] | None
    invalidated_at: datetime | None  # set by explicit invalidation; cleared on refresh


class JarProbeConfig(BaseModel):
    url: HttpUrl                     # must be within jar scope
    # Exactly one success indicator:
    logged_in_selector: str | None = None      # selector present => fresh
    logged_out_url_prefix: str | None = None   # final URL under this prefix => stale
```

Metadata is cleartext (needed for listing); it contains **no cookie names and no values** — only
counts and expiry aggregates. Names live inside the encrypted blob with the values.

### Storage and encryption

- New `JarStore` component with its own lock; storage is one file per jar under
  `BROWSER_JAR_DIR` (default `<data dir>/jars`), mode `0600`, written atomically
  (temp file + rename): `{"meta": {...}, "blob": "<base64>"}`.
- `blob` is the scope-filtered Playwright `storage_state` JSON encrypted with AES-256-GCM (Fernet is
  acceptable) under `BROWSER_JAR_KEY` (urlsafe-base64, 32 bytes; generated by the operator, injected
  as a secret alongside `BROWSER_HANDOFF_SERVICE_TOKEN`).
- **Fail closed**: if `BROWSER_JAR_KEY` is unset, every jar endpoint returns 503 and
  `create_session` rejects `jar_id`. If the key changes, existing blobs fail decryption and load
  returns a clear error; jars are then only deletable. No plaintext fallback, ever.
- This is browser-server's first durable state. It is deliberately kept out of the in-memory
  `SessionRegistry`: sessions stay ephemeral and shared-fate with the process; jars survive
  restarts. No database is introduced.

### Scope semantics

Cookies are domain-scoped, not origin-scoped, so scope filtering works at two levels:

- The jar declares exact `origins` (for display and for future navigation policy) and derives
  `registrable_domains` from them using the public suffix list (`tldextract`, offline mode — a new
  dependency; naive suffix matching is wrong for `co.uk`-style domains).
- At save, a cookie is included iff its domain (leading dot stripped) falls under one of the jar's
  registrable domains. localStorage/IndexedDB entries are included iff their origin's host falls
  under a scoped registrable domain.
- Default scope when the caller does not pass `origins`: the session's **current origin** at save
  time. This is the minimization default that keeps IdP cookies (google.com etc.) out of the jar
  after an SSO login — capturing IdP state requires explicitly listing the IdP origin, which
  Family Assistant policy can gate harder or simply never do. (Deliberate consequence: SSO-backed
  logins re-require the IdP dance when the target site's own session expires. The IdP question is
  the credential broker's deferred problem, not this feature's.)

## API surface

All endpoints follow existing auth conventions: service token (`require_agent_auth`) for
agent-facing calls, `require_service_auth` (service token or OIDC human) for management, human
control token for human-initiated save. Every operation emits an audit event.

### Save

`POST /v1/sessions/{session_id}/save-jar`

```json
{
  "label": "Woolworths (Andrew)",
  "jar_id": null,
  "origins": null,
  "probe": {"url": "https://www.example.com/account", "logged_in_selector": "[data-testid=logout]"},
  "token": null
}
```

- `jar_id: null` creates a new jar; a jar_id refreshes an existing jar in place (version bump,
  `invalidated_at` cleared). Refresh re-filters against the **stored** jar scope — a refresh cannot
  silently widen scope; widening requires creating a new jar.
- `origins: null` defaults to the session's current origin (see scope semantics).
- Authorization mirrors agent commands, fail closed:
  - **Agent save** (no `token`, service auth): allowed only in `AGENT_COMMAND_STATES` with
    `lease_owner == agent` — the agent cannot harvest state from a human-controlled browser.
    Typical flow: human-first login → handover → agent claims → agent saves.
  - **Human save** (`token` = control token): allowed in `human_active`. Surfaced in the session UI
    as a "Save this login for the assistant" action (and as a checkbox on the handover form, which
    performs save-then-handover). `saved_by: "human"` is recorded, giving Family Assistant a
    provenance signal ("human explicitly consented at save time") policy can distinguish.
- Response is `CookieJarMeta` only. Never the blob.
- Event: `jar_saved` (metadata: jar_id, origins, actor, refresh or create).

### Manage

- `GET /v1/jars` → `list[CookieJarMeta]` (service auth). This is what the FA `list_saved_sessions`
  tool renders; it is safe to show to the model verbatim.
- `GET /v1/jars/{jar_id}` → `CookieJarMeta`.
- `DELETE /v1/jars/{jar_id}` → tombstone metadata; blob file destroyed. Event: `jar_deleted`.
- `POST /v1/jars/{jar_id}/invalidate` → marks `invalidated_at` (agent noticed a login wall; FA calls
  this so listings show the jar needs re-login). Event: `jar_invalidated`.
- Human UI: a minimal `/jars` page (OIDC) listing jars with delete buttons, so the household can
  audit and revoke saved logins without going through the assistant.

### Load

`POST /v1/sessions` gains two optional fields:

```json
{"conversation_id": "...", "jar_id": "jar_...", "allow_exec": false}
```

- The worker seeds its context from the decrypted jar at creation
  (`browser.new_context(storage_state=...)`). Load-at-creation-only is a deliberate invariant:
  there is no "inject jar into running session" endpoint, so a session's authentication scope never
  changes after the create call that policy gated.
- One jar per session (V1). One authenticated identity per session keeps the policy story simple.
- The session record and all session responses gain `jar_id`, `jar_origins`, and
  `jar_registrable_domains` so the Family Assistant side always knows it is operating an
  authenticated session and at which origins — the anchor for origin-scoped policy.
- `last_loaded_at` is bumped; event `jar_loaded` is emitted on the new session.
- **`exec` default-deny**: in a jar-loaded session, the `exec` agent command is rejected unless the
  session was created with `allow_exec: true`. Rationale: `page.evaluate` can read `document.cookie`
  and origin storage, handing non-HttpOnly session tokens to the model — the one agent-reachable
  path from "use the login" to "read the credential". Fail-closed server default, explicit opt-in
  keeps the decision with Family Assistant policy. (`extract`/`snapshot` return page content, which
  is the point of authenticated browsing; they stay allowed. The assessment's parallel
  snapshot-redaction milestone is complementary and out of scope here.)
- Handoff/handover interplay is unchanged. In particular the **re-login flow** composes from
  existing pieces: create session with stale jar → `handoff` with reason `credentials` → human logs
  in → human completes (sensitive handoffs never resume) or hands the session back via the
  human-first flow → agent refreshes the jar with `save-jar {jar_id}`.

### Expiry detection

Three layers, cheapest first — browser-server provides signals, Family Assistant decides when to act:

1. **Static metadata**: `earliest_cookie_expiry` computed at save; listings can flag jars whose
   persistent cookies have lapsed. (Necessary but weak — servers revoke sessions server-side too.)
2. **Active probe**: `POST /v1/jars/{jar_id}/probe` (service auth). Loads the jar into a throwaway
   headless context (no session, no worker, no noVNC), navigates to `probe.url`, applies the success
   indicator, tears the context down. Returns `{"result": "fresh" | "stale" | "error",
   "final_origin": "..."}` — never page content. Updates `last_probe_*`. Rate-limited per jar
   (minimum interval, e.g. 15 minutes) so a confused caller cannot hammer a site. Probing is only
   possible when the jar has probe config, which is captured at save (optionally supplied by the
   caller, who has just seen the logged-in page and knows what "logged in" looks like).
3. **In-use signal**: the agent hits a login wall mid-task → FA calls `invalidate`, then runs the
   re-login flow above. No browser-server machinery needed beyond the invalidate endpoint.

Family Assistant owns scheduling (e.g. a cron automation probing household-critical jars and raising
a "please re-login" task) — browser-server never probes on its own initiative.

## Runtime changes

- `PlaywrightBrowserWorker` moves from implicit context (`browser.new_page(**kwargs)`) to explicit
  `browser.new_context(**kwargs)` + `context.new_page()` so that:
  - `storage_state` can be passed at context creation (load), and
  - `context.storage_state()` can be exported (save), then scope-filtered service-side.
- New worker methods: `export_storage_state() -> dict` and a `storage_state` constructor argument.
  Scope filtering lives in `JarStore`, not the worker, so it is unit-testable without a browser and
  identical across runtimes.
- `FakeBrowserWorker` gets a settable in-memory storage_state fixture so the full save/load/probe
  flow is testable in the fake runtime.
- `models.py`: `CreateSessionRequest` gains `jar_id`/`allow_exec`; `BrowserSession` gains
  `jar_id`/`jar_origins`/`jar_registrable_domains`; new jar request/response models.
- New module `jars.py`: `JarStore` (encrypt/decrypt, scope filter, atomic persistence, probe
  rate-limit state) injected into the app like the registry.

## What this deliberately does not do

- No credential storage, no password vault, no IdP integration (credential broker remains deferred
  and optional per the assessment).
- No confirmation prompts, profile checks, or taint decisions in browser-server — see
  mechanism/policy split.
- No multi-jar sessions, no jar sharing/export API (a jar can never be read back out, only loaded
  into a context or deleted).
- No automatic jar refresh on session close (an explicit save keeps the audit trail honest; may be
  revisited once usage shows the refresh nag is real friction).
- No per-jar navigation confinement in V1. Top-level-navigation confinement to jar origins is
  feasible via route interception and is sketched as a follow-up (it is the server-side backstop for
  the taint matrix's "browser cell"), but redirects, SSO bounces, and CDN subresources make a
  correct implementation non-trivial; policy-side enforcement in FA comes first. The session
  metadata exposure (`jar_origins`) is designed so this can be added without API changes.

## Milestones

Each independently testable; browser-server first, family-assistant integration last (tracked in the
companion doc).

1. **JarStore**: models, encryption round-trip, scope filtering (PSL matching), atomic persistence,
   fail-closed keyless mode. Pure unit tests, no browser.
2. **Save path**: explicit-context worker refactor + `export_storage_state`, `save-jar` endpoint
   with agent/human authorization matrix, handover-form checkbox + session-UI action, events. Fake
   runtime + one real-Chromium test asserting a fixture login survives export.
3. **Load path**: `create_session.jar_id` + `allow_exec`, session metadata exposure, `jar_loaded`
   event, `exec` default-deny in jar-loaded sessions, jar management endpoints + `/jars` UI page.
   Real-runtime test: log in on fixture site, save, new session with jar, fixture shows logged-in.
4. **Expiry**: expiry metadata, probe endpoint with rate limiting, invalidate endpoint.
5. **family-assistant adapter** (other repo): `save_browser_session` / `list_saved_sessions` /
   `load_saved_session` / `forget_saved_session` tools, policy + confirmation gating, prompts and
   user guide.

## Testing plan (security regressions, beyond per-milestone tests)

- Grep-style assertion helpers: cookie names/values from a fixture login never appear in any API
  response body, SSE event, or captured log line across the full save→list→load→probe→delete flow.
- Agent `save-jar` denied in every human-controlled and terminal state (parametrized over the state
  machine, like existing command-authorization tests).
- `exec` denied in jar-loaded session by default; allowed with `allow_exec: true`; unaffected in
  jarless sessions.
- Scope filter property tests: IdP-style third-origin cookies excluded under default scope;
  `co.uk` registrable-domain handling; refresh cannot widen scope.
- Keyless mode: all jar endpoints 503, `create_session` with `jar_id` rejected, no plaintext ever
  written.
- Wrong/rotated key: load fails with explicit error, delete still works.

## Open questions

1. **Retention**: jars currently live until deleted or invalidated. Is a `BROWSER_JAR_TTL_DAYS`
   reaper worth it, or is the staleness surfaced in listings (+ human UI delete) enough for a
   household deployment? Leaning: no TTL; expiry probing already surfaces dead jars.
2. **IndexedDB**: include `indexed_db=True` in the export when available? Some sites keep auth
   tokens there; it also bloats jars. Leaning: include, since the scope filter applies equally.
3. **Probe success heuristics**: is selector-or-URL-prefix enough, or do real household sites need a
   "either of N indicators" list? Decide after milestone 4 contact with reality.
4. **`saved_by` policy leverage**: should Family Assistant require `saved_by == "human"` for some
   uses (e.g. loading into less-trusted profiles)? Pure FA policy question; the metadata is there.
