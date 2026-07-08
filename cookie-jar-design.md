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
- Jars store only Playwright `storage_state` (cookies + origin storage — localStorage/IndexedDB),
  filtered to a declared scope, encrypted at rest.
- Everything else on the never-store list stays never-stored: screenshots, DOM snapshots,
  accessibility trees from human control, transient form-field values captured during handoff,
  clipboard, payment data, typed credentials, OTPs, full URLs with sensitive query strings.

**Origin storage is persisted jar content, and is treated as such.** localStorage and IndexedDB can
hold more than session tokens — a site may keep profile details, cart/checkout metadata, or form
drafts there, and `storage_state` captures whatever is present within scope. This does **not**
contradict the never-store list: that list bars browser-server from capturing the *transient* page
DOM and form fields a human types during handoff. What origin storage contains is data the *site
itself* chose to persist client-side, which is inseparable from the authenticated session and is
exactly what must be restored for a reload to work. It therefore gets the same protections as
cookies — encryption at rest, scope filtering, never returned/logged, the same retention and audit
treatment, and the same disclosure to the user ("saved logins keep the site's session data"). A
caller that wants to exclude origin storage entirely can pass `storage: "cookies_only"` at save
(see API), accepting that some sites will then reload logged-out.

Note the distinction this preserves: a jar contains **session artifacts** (cookies and the site's
own client-side session data), never the **credentials** themselves. Passwords and OTPs are typed by
the human into the page during handoff and are never captured — that is the existing warm-handoff
guarantee, unchanged.

## Terminology

- **Cookie jar (jar)**: a named, durable, encrypted blob of Playwright `storage_state` (cookies,
  localStorage, and IndexedDB via `storage_state(indexed_db=True)` where the Playwright version
  supports it), scoped to a declared set of origins, plus cleartext metadata. IndexedDB is captured
  by default: a growing number of sites keep their auth/session token there rather than in a cookie,
  and omitting it would silently produce jars that load into a logged-out session — the worst
  possible failure for this feature. As origin storage, IndexedDB is scope-filtered by **exact
  origin** (like localStorage), so including it does not widen what a jar can capture.
- **Scope**: the exact set of origins whose state a jar may contain (cookies are additionally kept by
  cookie-send semantics — see Scope semantics; registrable domains are informational only and never
  widen capture).
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
- Load happens only at session creation, and **only via service auth** — a direct OIDC human
  `create_session` cannot pass `jar_id`, so FA stays the load-authorization chokepoint. A session's
  authenticated scope is therefore immutable and truthfully reported in session metadata for its
  whole lifetime.
- An **invalidated jar is unloadable** until a refresh replaces its blob and clears the flag.
- `exec` (and any future command that can read cookie values) is denied in jar-loaded sessions
  unless the creator explicitly opted in.
- Top-level document confinement is available (`confine_navigation`, default on for jar-loaded
  sessions): the mechanism keeps an authenticated session from issuing an off-scope document/form
  request in **any** frame (main, child, popup) off its **exact** jar origins, so the client can rely
  on it rather than reimplement egress control.
- Caller-supplied `label` is normalized at save, and probe internals (`logged_in_selector`, urls) are
  never returned in listable metadata — neither can carry markup or become durable prompt-injection
  content in later listings.
- Revocation (delete/invalidate) closes any live session seeded from *or that produced* the jar, not
  just the stored blob — so "forget this login" is a real-time kill-switch, not a deferred cleanup.
- Captured origin-storage size is bounded (oversized saves rejected) so the durable write path cannot
  be used to exhaust memory/disk.
- Every jar operation is a **durably** audited event (jars outlive the in-memory session-event
  stream).
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
    label: str                       # human-readable, normalized at save (see Manage), e.g. "Woolworths (Andrew)"
    origins: list[str]               # exact origins in scope, e.g. ["https://www.example.com"]
    nav_allowlist: list[str]         # extra exact origins reachable under confinement (default [])
    registrable_domains: list[str]   # informational display only; NOT the confinement boundary
    created_at: datetime
    updated_at: datetime             # bumped on refresh
    last_loaded_at: datetime | None
    version: int                     # increments on refresh
    saved_by: Literal["agent", "human"]
    form_factor: str                 # producing session's form factor/UA; jar loads default to it (below)
    storage_mode: Literal["all", "cookies_only"]   # preserved across refresh unless explicitly changed
    created_session_id: str          # provenance: session the state came from
    conversation_id: str             # provenance only; jars are not conversation-scoped
    cookie_count: int
    origin_storage_count: int        # number of origins with localStorage/IndexedDB entries
    earliest_cookie_expiry: datetime | None   # min over persistent cookies; None if none are persistent
    session_cookies_only: bool       # True when the jar holds no persistent cookies (see expiry)
    has_probe: bool                  # a freshness probe is mandatory; internals are NOT listed (below)
    last_probe_at: datetime | None
    last_probe_result: Literal["fresh", "stale", "uncertain", "error"] | None
    invalidated_at: datetime | None  # set by explicit invalidation; cleared on refresh


class JarProbeConfig(BaseModel):     # stored inside the encrypted blob, NOT in listable metadata
    url: HttpUrl                     # scheme+host+path only (query/fragment stripped); within origins+nav_allowlist
    # At least one indicator required; BOTH may be set (selector proves fresh, prefix classifies stale):
    logged_in_selector: str | None = None      # authenticated-only selector present => fresh
    logged_out_url_prefix: str | None = None   # scheme+host+path only; MAY be off-scope (login/IdP); match => stale
```

Metadata is cleartext (needed for listing); it contains **no cookie names and no values** — only
counts and expiry aggregates. Names live inside the encrypted blob with the values. **The probe
config is not part of listable metadata**: `logged_in_selector` can contain user-specific or
page-influenced text, so returning it through `GET /v1/jars` → `list_saved_sessions` would leak page
data and create another durable prompt-injection field. The probe config is stored alongside the
encrypted blob; listings expose only `has_probe` + `last_probe_result`.

**Probes must be safe/idempotent reads, not action URLs.** The scheduled freshness automation
replays `probe.url` under the saved login, so an in-scope but side-effecting target — `/logout`, a
"delete session" GET, any state-changing endpoint injected content asked to store — would end or
corrupt the very session the probe is meant to check. A probe is therefore a plain **GET navigation
followed by a check**, and the required form is a `logged_in_selector` (or `logged_out_url_prefix`)
on a **stable read-only page** (the account/home page), not an action endpoint. Same-origin alone is
insufficient; the target must be idempotent. The probe navigation issues no form submits and, like a
jar-loaded session, aborts off-scope redirects pre-request — but it still **classifies** a
redirect-toward-login as stale by matching the redirect `Location` against `logged_out_url_prefix`
*before* aborting.

- **`probe.url` scope**: validated against the **same `origins + nav_allowlist`** boundary the load
  guard uses, not just captured `origins` — otherwise a jar that reaches a second first-party origin
  only via `nav_allowlist` (without capturing its storage) could have no valid probe target.
- **`logged_out_url_prefix` may be off-scope.** It is a *classification pattern*, not a navigation
  target: expired sessions commonly redirect to an IdP or `login.` subdomain outside the jar scope.
  Constraining it to in-scope would make those flows report `error` instead of `stale` and never
  trigger re-login. So it is exempt from the in-scope rule (query/fragment still stripped).
- **The success signal must be authenticated-only, and both indicators may combine.** A
  `logged_in_selector` that matches chrome present on *both* the login wall and the authed page (logo,
  footer) is a false-positive that keeps reporting a dead jar as fresh; it must distinguish logged-in
  from logged-out (a logout control, account-name element). For the common SSO case — the account page
  is a 200 with an authenticated-only selector, but an expired session redirects to a separate
  login/IdP origin — a probe sets **both**: the selector proves fresh, and `logged_out_url_prefix`
  classifies the off-scope redirect as stale (rather than `error`). At least one indicator is required.
- **No selector ⇒ `uncertain`, not `fresh`.** The "final origin still in scope" heuristic is not a
  freshness proof (a site can render a logged-out wall at the same origin+path with a 200). A save
  must capture a concrete authenticated-only signal; if the non-technical human path genuinely cannot
  derive one, the probe result is `uncertain` (surfaced as needing attention), never silently `fresh`.
- **Human default targets a stable page, not the raw current page.** Deriving `probe.url` from
  whatever page is active would persist a one-time/side-effecting URL (OAuth callback `?code=&state=`,
  checkout confirmation). The human-UI default navigates to a known stable account/home page (and
  strips query/fragment) before saving.

**URL redaction.** `probe.url` and `logged_out_url_prefix` have query and fragment **stripped** on
save (scheme + host + path retained) so neither becomes a back door around the
never-store-sensitive-full-URLs guarantee (`?token=…`, `#access_token=…`, `return_to`, account ids).

### Storage and encryption

- New `JarStore` component with its own lock; storage is one file per jar under
  `BROWSER_JAR_DIR` (default `<data dir>/jars`), mode `0600`, written atomically
  (temp file + rename): `{"meta": {...}, "key_id": "<id>", "blob": "<base64>"}`.
- `blob` is the AEAD ciphertext of a JSON object `{"storage_state": {...}, "probe": {...}}` — i.e. it
  wraps **both** the scope-filtered Playwright `storage_state` **and** the mandatory probe config, so
  the probe survives restarts and can drive `/probe` without ever appearing in listable metadata (the
  selector/urls are sensitive; see the data model). Encryption is **AES-256-GCM** (an authenticated
  AEAD construction) under `BROWSER_JAR_KEY` (urlsafe-base64, 32 bytes; generated by the operator,
  injected as a secret alongside `BROWSER_HANDOFF_SERVICE_TOKEN`). (The format is fixed as AES-256-GCM,
  not "AES-GCM or Fernet" — Fernet is AES-CBC+HMAC, a different construction, and naming both would
  make the on-disk format and rotation/interop tests ambiguous.) Each blob records the `key_id` (a
  short fingerprint of the key that encrypted it) so the service can distinguish "operator rotated the
  key" from "blob corrupted", and so rotation can be handled deliberately.
- **Key rotation**: rotating `BROWSER_JAR_KEY` does not silently orphan jars into indistinguishable
  decrypt failures. A `key_id` mismatch on load is reported as "needs re-login after key rotation"
  (distinct from a corruption error), and the simplest supported runbook is **rotate ⇒ re-login**
  (jars are re-creatable by design; no secret is irreplaceable). A rewrap-on-successful-load path
  (decrypt with old key, re-encrypt under new) is a possible future convenience but not required for
  V1. `BROWSER_JAR_KEY` may accept a comma-separated list (new key first for writes, old keys still
  accepted for reads) to make rotation non-disruptive if that runbook proves too blunt.
- **Fail closed**: if `BROWSER_JAR_KEY` is unset, every jar endpoint returns 503 and
  `create_session` rejects `jar_id`. If a blob cannot be decrypted under any configured key, load
  returns a clear error (rotation vs corruption distinguished by `key_id`); such jars are only
  deletable. No plaintext fallback, ever.
- This is browser-server's first durable state. It is deliberately kept out of the in-memory
  `SessionRegistry`: sessions stay ephemeral and shared-fate with the process; jars survive
  restarts. No database is introduced.
- **Jar audit is durable, unlike session events.** The existing `SessionEvent` stream is in-memory
  and per-session, so it evaporates on restart and when the source session is cleaned up — but jars
  are durable credentials whose management (`jar_saved`/`jar_loaded`/`jar_refreshed`/`jar_deleted`/
  `jar_invalidated`) can happen long after any session is gone. Those jar events are therefore also
  written to a durable, structured audit sink (an append-only jar-audit log next to `BROWSER_JAR_DIR`,
  and/or structured service logs) so the credential audit trail outlives sessions and restarts. Jar
  audit records carry only non-secret metadata (jar_id, origins, actor, op) — never cookie/storage
  material or probe internals.

### Scope semantics

Cookies are domain/path-scoped and origin storage is origin-scoped, so the filter is defined by
**what the declared origins would actually see**, not by registrable-domain membership. The latter
would over-capture: a jar scoped to `https://shop.example.com` must not silently persist a host-only
cookie or the localStorage of a sibling app like `accounts.example.com` that the login flow happened
to touch — that would make the jar hold credentials for origins outside its declared scope and make
the reported `jar_origins` understate the true authenticated scope that policy relies on.

- The jar declares exact `origins`. It also derives `registrable_domains` (public suffix list via
  `tldextract`, offline mode — a new dependency; naive suffix matching is wrong for `co.uk`-style
  domains) purely as **informational** display metadata; it is **not** used to widen capture, and it
  is **not** the confinement boundary (see the note below on why confinement uses exact origins).
- **Cookies**: at save, a cookie is included iff it would actually be sent to at least one declared
  origin under that origin's host and scheme — domain match honoring the `Domain` attribute and
  host-only cookies, plus `Secure`/scheme. A `Domain=.example.com` cookie is kept because it *is*
  sent to `shop.example.com`; a host-only `accounts.example.com` cookie is dropped because it is not.
  **Path is deliberately not used to exclude cookies**: declared `origins` carry no path, and a
  cookie with `Path=/account` is still needed for URLs under the same origin, so path-filtering it
  out would make the reloaded jar appear logged out. All otherwise-matching cookies for a declared
  origin are kept regardless of their `Path`.
- **Origin storage** (localStorage/IndexedDB): included iff its origin is **exactly** one of the
  declared `origins`. No registrable-domain widening — origin storage is not shared across origins,
  so nothing else is in scope.
- **Confinement uses exact origins, not registrable domains.** Navigation confinement (below) keeps
  a loaded session to the jar's exact `origins` (scheme + host + port), optionally plus an explicit
  `nav_allowlist` of additional origins captured at save. Registrable-domain confinement would be
  strictly wider: a jar for `https://app.example.com` would let an injected authenticated page
  navigate/submit to a user-controlled or attacker-controlled sibling like `evil.example.com` (both
  share `example.com`, and a `Domain=.example.com` cookie rides along), which is exactly the
  cross-origin egress the confinement is meant to block. Exact origins are the boundary.
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
  "nav_allowlist": null,
  "storage": "all",
  "probe": {"url": "https://www.example.com/account", "logged_in_selector": "[data-testid=logout]"},
  "token": null
}
```

- `jar_id: null` creates a new jar; a jar_id refreshes an existing jar in place (version bump,
  `invalidated_at` cleared). Refresh re-filters against the **stored** jar scope — a refresh cannot
  silently widen scope; widening requires creating a new jar. **This applies to `nav_allowlist` too**:
  since the confinement boundary is `origins + nav_allowlist`, a refresh may only *preserve or narrow*
  the stored allowlist — adding a reachable origin is a widening that requires a new jar (and its own
  elevated approval), not a quiet expansion under the existing `jar_id` that policy already approved.
  Refresh likewise **preserves the stored `storage_mode`** unless the caller explicitly narrows it: a
  bare-`jar_id` refresh must not silently flip a `cookies_only` jar back to `all` (adding origin
  storage the creator opted out of), so omitted fields inherit the stored jar's settings.
- `origins: null` defaults to the session's current origin (see scope semantics). For a **human
  save**, "current origin" is read from the **live page under the human control token** at save time
  (the registry only updates `current_origin` from *agent* command results, which never run while
  the human is browsing, so it would otherwise be stale/`None`) — resolved server-side and never
  returned to the agent. If it still cannot be resolved, the save is rejected asking the UI for an
  explicit origin rather than saving an empty/stale scope.
- `nav_allowlist: null` → `[]`. Extra **exact** origins a confined jar-loaded session may navigate
  to without capturing their storage (e.g. a second first-party origin the app legitimately spans).
  Validated and audited like `origins`; this is the only way to widen navigation reachability, and
  it is set at save (refresh preserves it unless overridden) — `load` never invents allowlist
  entries.
- `storage: "all"` (default) captures cookies plus in-scope origin storage; `"cookies_only"` skips
  localStorage/IndexedDB for a caller that wants to avoid persisting site-side client storage,
  accepting that some sites reload logged-out. Recorded as `storage_mode` and preserved across
  refresh (above).
- `probe` is **required on every save** (create and refresh) — save is rejected without it. The
  earlier idea of skipping the probe when "a persistent cookie exists" is unsound: Playwright cookie
  state carries no marker for *which* cookie is auth-bearing, so the server cannot prove that the
  earliest-expiring persistent cookie is the login (it is often an unrelated analytics/consent
  cookie). Rather than guess, a live freshness probe is mandatory for all jars; `earliest_cookie_expiry`
  and `session_cookies_only` remain as weak supplementary hints, not a substitute for the probe.
  **A non-technical human never hand-authors a probe.** For a human save the UI derives a default
  probe automatically — `probe.url` = the current live page URL (redacted to origin+path), and the
  success indicator defaults to a generic "did not land on a login page" heuristic (final origin
  still within jar scope ⇒ fresh; redirected to a sign-in URL ⇒ stale) — so the mandatory-probe rule
  is satisfied without asking the user anything. An agent save, which has observed the page, can
  supply a precise selector instead. The mandatory-probe requirement is thus a *server default is
  always producible*, not a *caller must know CSS selectors*.
- **Refresh resets `last_probe_*`.** Replacing a jar's blob (refresh after re-login) clears
  `last_probe_at`/`last_probe_result` and `invalidated_at`, so a jar that was `stale`/invalidated
  does not keep showing expired in listings after a successful refresh; freshness is re-established by
  the next probe.
- Authorization mirrors agent commands, fail closed. Two paths, human-save being the canonical one:
  - **Human save** (`token` = control token): allowed in `human_active` **and `human_sensitive`** —
    a careful user who marked the session sensitive *before* typing credentials must still be able to
    click "Save this login" afterward; rejecting the sensitive state would break save for exactly the
    most safety-conscious flow. This is the primary path — the human logs into a site and clicks
    "Save this login for the assistant"; the agent later picks the jar up in a fresh session with no
    handover involved. Also surfaced as a checkbox on the handover form (save-then-handover).
    `saved_by: "human"` is recorded, giving Family Assistant a provenance signal ("human explicitly
    consented at save time") policy can distinguish.
  - **Agent save** (no `token`, service auth): allowed only in `AGENT_COMMAND_STATES` with
    `lease_owner == agent`. This falls out of the existing agent-command authorization (the agent
    can save only what it is already driving) rather than being a special restriction — it is not a
    security wall around a valuable secret, just the same lease check every agent command uses.
    Typical flow: human-first login → handover → agent claims → agent saves. Nothing stops the human
    from taking the low-friction human-save path instead.
- **Scope/probe constraints are enforced server-side for *every* save path, including the handover
  checkbox.** The minimization default (scope = current origin), the requirement that any off-current-origin
  capture be explicitly listed, the in-scope probe target, and the mandatory probe are browser-server
  mechanism — not just FA policy — so the human-checkbox save (which never passes through FA's
  `save_browser_session` wrapper) still gets them. The browser-server UI enumerates the exact origins
  a save will capture and requires an explicit action to add any beyond the current one. FA's wrapper
  adds the *model-facing* confirmation on top for agent-initiated saves.
- **Human save is intentionally human-authorized, and FA-profile gating on it is an operator option,
  not a default.** The whole point of human-save-in-place is that a human can log in and persist
  *their own* login without the agent/policy loop, so browser-server does not by default require an
  FA save-authorization for the checkbox path (only the human control token + the mechanism
  constraints above). For locked-down deployments where FA profile policy must forbid credential
  persistence for some users/profiles even on the human path, browser-server supports an optional
  config requiring an **FA-issued save-authorization token** for `save-jar` (carrying the profile
  decision into the UI path); when enabled, an un-authorized human checkbox save is rejected. Default
  off, because it re-couples the deliberately-decoupled human path to FA.
- **The saving session records the jar in a `produced_jar_ids` set** (not by overwriting
  `session.jar_id`). This is a **separate provenance field**, for two reasons. (1) A single session
  can save/refresh more than one jar; a scalar tag would be overwritten and revocation of the earlier
  jar would no longer find the source context — a set tracks all of them. (2) The producing context is
  **not** a jar-loaded session: it holds the *full, unfiltered* login state (including the IdP /
  off-scope cookies the jar's scope filter deliberately dropped), so it must not be labelled with the
  jar's `jar_id`/`jar_origins` — doing so would make session metadata and confinement policy treat an
  unfiltered, broader-credential context as if it had the jar's narrow immutable scope. `jar_id` keeps
  its single meaning "seeded from (and scope-filtered to) this jar"; `produced_jar_ids` is provenance
  only, used by revocation to also close the origin context.
- **Origin-storage size cap.** Because localStorage/IndexedDB are captured by default, a
  compromised/injected in-scope page could stuff IndexedDB before save so `JarStore` serializes,
  encrypts, and writes an enormous blob (memory/disk DoS). The export is bounded by a per-jar
  storage-state size limit; a save exceeding it is rejected rather than written.
- Response is `CookieJarMeta` only. Never the blob (or probe internals).
- Event: `jar_saved` (metadata: jar_id, origins, actor, refresh or create).

### Manage

- `GET /v1/jars` → `list[CookieJarMeta]` (service auth). This is what the FA `list_saved_sessions`
  tool renders. It carries no cookie material, but `label` is **caller-supplied**, and an agent save
  can happen after a page-driven session — so a malicious page could try to plant instruction-like
  text in a label that later resurfaces via `list_saved_sessions` as durable prompt injection. Two
  defenses: browser-server **normalizes labels at save** (trim, cap length ~80 chars, strip control
  characters and newlines, plain text only — no markup), and the FA side renders jar metadata as
  **untrusted data**, not as instructions (see the companion doc). So it is safe to *display*, but
  not to *obey*.
- `GET /v1/jars/{jar_id}` → `CookieJarMeta`.
- `DELETE /v1/jars/{jar_id}` → tombstone metadata; blob file destroyed; **and every live session
  whose `jar_id` matches is closed** (see revocation-terminates-live-sessions below). Event:
  `jar_deleted`.
- `POST /v1/jars/{jar_id}/invalidate` → marks `invalidated_at` (agent noticed a login wall; FA calls
  this so listings show the jar needs re-login) **and closes matching live sessions**, since a jar
  that needs re-login should not keep serving an authenticated context. Event: `jar_invalidated`.
- **Revocation terminates live sessions.** Load seeds the decrypted `storage_state` into a running
  browser context that then holds those cookies for the session's whole lifetime — so acting only on
  the stored blob would leave the live authenticated session running after the user "revoked" it.
  Because delete/invalidate is the user's real-time kill-switch for an in-progress abuse (an injected
  page driving same-origin actions under the login — residual #1 that the taint matrix only tightens
  later), both endpoints close **every live session related to the jar**: jar-*loaded* sessions
  (`session.jar_id` matches) **and** any source session that produced it (`jar_id ∈
  session.produced_jar_ids`), via the normal cleanup path. Revocation is not complete until the live
  context is gone, not just the file.
- **An invalidated jar cannot be loaded, and load races with revocation are closed.** `invalidate` is
  a kill-switch/stale marker, so `create_session` with a `jar_id` whose `invalidated_at` is set is
  **rejected** — otherwise a client could re-create a session from the still-stored blob right after
  invalidation. Because a load can race a concurrent `DELETE`/`invalidate` (it may pass the
  invalidation check and decrypt the blob *before* it registers the new session, so the revocation
  scan doesn't see it yet), the two are serialized by a **per-jar lock**, and the load performs a
  **post-registration recheck**: after registering the session it re-reads `invalidated_at`/existence
  and, if the jar was revoked in the window, immediately closes the just-created context. Revocation
  is not defeated by an in-flight load. The jar becomes loadable again only when a refresh replaces
  the blob and clears `invalidated_at`.
- Human UI: a minimal `/jars` page (OIDC) listing jars with delete buttons, so the household can
  audit and revoke saved logins without going through the assistant.

### Load

`POST /v1/sessions` gains optional fields:

```json
{"conversation_id": "...", "jar_id": "jar_...", "allow_exec": false, "confine_navigation": true}
```

- **`jar_id` is accepted only on service-authenticated `create_session`, never on a direct OIDC
  human `create_session`.** Family Assistant is the load-authorization chokepoint (the
  `load_saved_session` confirmation + profile policy). On deployments that expose browser-server's
  OIDC-authenticated API/UI directly, an OIDC human must not be able to seed a human-owned context
  with any saved jar and bypass that gate — so a direct OIDC create with `jar_id` is rejected. Jar
  loads happen through the service token (the FA path) or a FA-issued load authorization; the OIDC
  human path stays limited to jarless human-owned sessions (and the `/jars` UI, which only lists and
  deletes).
- The worker seeds its context from the decrypted jar at creation
  (`browser.new_context(storage_state=...)`). Load-at-creation-only is a deliberate invariant:
  there is no "inject jar into running session" endpoint, so a session's authentication scope never
  changes after the create call that policy gated.
- One jar per session (V1). One authenticated identity per session keeps the policy story simple.
- **Jar loads default to the producing session's form factor/UA.** `storage_state` alone does not
  carry the device profile, and an agent-created session with no client viewport otherwise defaults to
  mobile — so a jar saved from a desktop OIDC session, reloaded under a mobile UA, can trip
  device/UA-bound risk scoring (forced MFA, or an apparently logged-out session). The jar records its
  producing `form_factor`, and a load uses it unless the create call explicitly overrides.
- The session record and all session responses gain `jar_id`, `jar_origins`, `jar_nav_allowlist`,
  and `jar_registrable_domains` so the Family Assistant side always knows it is operating an
  authenticated session and the full set of origins it can reach — the anchor for origin-scoped
  policy. Exposing `jar_nav_allowlist` (not just `jar_origins`) matters: a policy client that saw
  only `jar_origins` would understate where the confined session can navigate and where broad-domain
  cookies may be sent.
- `last_loaded_at` is bumped; event `jar_loaded` is emitted on the new session.
- **`confine_navigation`** (default `true` for jar-loaded sessions): restricts **document/form
  requests in every frame** (main frame, child iframes, and popups) to the jar's exact `origins`
  (plus any saved `nav_allowlist`), not its registrable domains (see "top-level navigation
  confinement" below). Filtering on request type (`document`) means a hidden-iframe form POST to a
  sibling origin is blocked just like a main-frame navigation, while ordinary subresources still
  render. "Exact origin" means **scheme + host + port** (per the web origin definition) — a jar for
  `https://example.com` does not reach `https://example.com:8443`. The Family Assistant side requires
  this
  before it will enable `load_saved_session`, so cross-origin egress from an authenticated session is
  blocked from day one rather than deferred to the taint matrix. A caller can pass `false` to opt
  out, which is a policy decision that belongs to FA.
- **`exec` default-deny**: in a jar-loaded session, the `exec` agent command is rejected unless the
  session was created with `allow_exec: true`. Rationale: `page.evaluate` can read `document.cookie`
  and origin storage, handing non-HttpOnly session tokens to the model — the one agent-reachable
  path from "use the login" to "read the credential". Fail-closed server default, explicit opt-in
  keeps the decision with Family Assistant policy. (`extract`/`snapshot` return page content, which
  is the point of authenticated browsing; they stay allowed. The assessment's parallel
  snapshot-redaction milestone is complementary and out of scope here.)
- Handoff/handover interplay is unchanged, but **confinement never traps a human re-login**, and the
  re-login path is chosen so a live browser context still exists to export from. `confine_navigation`
  restricts *agent-driven* navigation in a jar-loaded session; it does not apply while a human holds
  the control token. Re-login runs in a **fresh session with no jar loaded**, and the refresh happens
  **while the browser is still alive**, via one of two paths:
  - **Human-save-in-place** (canonical): human-first session → human logs in (off-origin IdP/SSO
    bounce unconfined) → human clicks "Save this login", which refreshes `jar_id` from the live page
    *before* completing → then completes. The save happens while the context is live.
  - **Handover-then-agent-save**: human logs in → hands the session over to the agent (browser stays
    alive) → agent refreshes `jar_id`.
  Note the **`credentials` agent→human handoff does not work for this**: sensitive handoffs are
  non-resumable and `human_complete` transitions them to `COMPLETED`, tearing down the worker — so
  there would be no live context left for `save-jar` to export. The re-login flow therefore uses the
  human-first / handover paths above, not a resumable `credentials` handoff. Loading the stale jar
  *before* re-login would also confine the human and block the SSO bounce, so the flow avoids that
  too. **A jar-loaded session that passes to human control is not resumed by the agent as the same
  context.** If a jar-loaded session enters a resumable human handoff, the human can visit off-scope
  login/payment/SSO origins and accumulate cookies/storage the jar scope never contained — so its
  live context now holds *broader* credentials than its `jar_origins` metadata reports. The agent
  therefore never resumes that exact context: either confinement stays enforced for the whole
  jar-loaded lifetime (no off-scope human excursion), or the agent resumes only via a **fresh,
  re-filtered** jar-loaded session (reload from the jar's stored scope), never inheriting the
  human-widened context. Metadata never under-reports the scope the agent actually operates.

### Expiry detection

Three layers, cheapest first — browser-server provides signals, Family Assistant decides when to act:

1. **Static metadata** (weak hint only): `earliest_cookie_expiry` and `session_cookies_only` computed
   at save; listings can flag jars whose persistent cookies have lapsed. This is *only* a hint —
   servers revoke sessions server-side, the earliest-expiring cookie is often an unrelated
   analytics/consent cookie rather than the auth token, and Playwright cookie state has no marker for
   which cookie is auth-bearing, so the server cannot prove a persistent cookie represents the login.
   Because the static signal can never be trusted to establish freshness, it does **not** gate
   anything on its own — a live probe is mandatory for every jar (below).
2. **Active probe (mandatory)**: `POST /v1/jars/{jar_id}/probe` (service auth). Every jar carries a
   `probe` config (required at save), so freshness is always checkable. Loads the jar into a
   throwaway headless context (no session, no worker, no noVNC), navigates to `probe.url` **under the
   same exact-origin navigation guard as a jar-loaded session** — an off-scope redirect (a stale or
   compromised probe endpoint 302-ing to `evil.example.com` to harvest a `Domain=.example.com`
   cookie) is aborted before any request carries jar credentials off-scope — applies the success
   indicator, and tears the context down. Returns `{"result": "fresh" | "stale" | "uncertain" |
   "error", "final_origin": "..."}` — never page content; `uncertain` is returned (and persisted to
   `last_probe_result`) when the configured signal cannot actually prove logged-in state, so FA can
   flag it for attention rather than trust a possibly-dead jar. Updates `last_probe_*`. Rate-limited per jar
   (minimum interval, e.g. 15 minutes) so a confused caller cannot hammer a site. Every jar has a
   probe config (mandatory at save), supplied by the caller who has just seen the logged-in page and
   knows what "logged in" looks like.
3. **In-use signal**: the agent hits a login wall mid-task → FA calls `invalidate`, then runs the
   re-login flow above. No browser-server machinery needed beyond the invalidate endpoint.

Family Assistant owns scheduling (e.g. a cron automation probing household-critical jars and raising
a "please re-login" task) — browser-server never probes on its own initiative.

## Runtime changes

- `PlaywrightBrowserWorker` moves from implicit context (`browser.new_page(**kwargs)`) to explicit
  `browser.new_context(**kwargs)` + `context.new_page()` so that:
  - `storage_state` can be passed at context creation (load), and
  - `context.storage_state(indexed_db=True)` can be exported (save), then scope-filtered
    service-side. The **`indexed_db=True` argument is required** — a bare `context.storage_state()`
    returns only cookies + localStorage, so omitting it would silently drop the IndexedDB the design
    promises to capture (and metadata would claim IndexedDB-backed auth was preserved while the
    reloaded jar shows logged-out). For `storage: "cookies_only"` the export still passes the flag
    and `JarStore` drops origin storage during filtering, keeping the capture/filter split clean.
- New worker methods: `export_storage_state() -> dict` (calling `storage_state(indexed_db=True)`) and
  a `storage_state` constructor argument. Scope filtering lives in `JarStore`, not the worker, so it
  is unit-testable without a browser and identical across runtimes.
- `FakeBrowserWorker` gets a settable in-memory storage_state fixture so the full save/load/probe
  flow is testable in the fake runtime.
- `models.py`: `CreateSessionRequest` gains `jar_id`/`allow_exec`/`confine_navigation`;
  `BrowserSession` gains `jar_id`/`jar_origins`/`jar_nav_allowlist`/`jar_registrable_domains` (for a
  jar-*loaded* session) plus a separate `produced_jar_ids: set[str]` provenance field (for a session
  that *saved* one or more jars); new jar request/response models (the save request carries
  `nav_allowlist`/`storage`/`probe`). **The
  confinement guard is pre-request and covers every top-level document in the context**, not just the
  first navigation the agent asks for: it intercepts via Playwright routing so an **off-scope
  redirect is aborted before the request is sent** (a 302 from an in-scope page to
  `evil.example.com` must not get the chance to carry a `Domain=.example.com` cookie off-scope — the
  same pre-request guard the freshness probe uses), and it applies to **popups / `window.open` /
  `target=_blank` new pages** (a new top-level document off-scope is blocked or closed, not a hole
  around main-frame confinement). `JarStore` normalizes labels, redacts probe/logged-out URL
  query/fragment on save, records `storage_mode`, and preserves `storage_mode`/`nav_allowlist` across
  refresh unless overridden; refresh also resets `last_probe_*`/`invalidated_at`.
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
- **Top-level navigation confinement is in scope for the load milestone** (moved up from a
  follow-up; default-on for jar-loaded sessions, opt-out via `confine_navigation: false`). Because the
  Family Assistant side treats egress confinement as a prerequisite for enabling `load_saved_session`
  (a load-time confirmation alone does not gate what the authenticated session does afterward), a
  jar-loaded session created with `confine_navigation: true` restricts **every top-level document in
  the context** — main-frame navigations, redirect chains (aborted pre-request), and
  popup/`window.open`/`target=_blank` new pages — to the jar's exact `origins` (scheme + host + port,
  plus any saved `nav_allowlist`) via route interception; an attempt outside scope is blocked and
  surfaced as a structured result, not followed. The boundary is exact origins, not registrable
  domains, so a sibling subdomain that shares the registrable domain is *not* reachable.
  This is the server-side backstop for the taint matrix's "browser cell" and directly blocks
  agent-driven cross-origin-egress-under-auth.
- **Deliberately *not* covered in this first cut** (documented residual, deferred to the assessment's
  egress-proxy / CSP layer under the taint matrix, **not** a per-jar hack here): **page-JavaScript
  subresource egress** — a script on a jar-origin page issuing `fetch`/beacon/`<img>` requests to an
  off-scope host, including a same-registrable-domain sibling like `evil.example.com` that a retained
  `Domain=.example.com` cookie would be attached to. Blocking all off-scope subresource requests
  would break normal rendering (CDNs, fonts, third-party widgets legitimate sites depend on) to close
  a low-bandwidth channel the realistic spray-and-pray adversary is unlikely to weaponize per-site;
  it is bounded meanwhile by `exec` default-deny (the model itself cannot read cookie/storage values
  to feed such a script). Also deferred: full SSO-bounce hardening for the *agent* path (login
  bounces run in the human re-login path, which is unconfined by design — see below). `jar_origins`
  /`jar_nav_allowlist` in session metadata let all of this tighten later without API changes.

## Milestones

Each independently testable; browser-server first, family-assistant integration last (tracked in the
companion doc).

1. **JarStore**: models, encryption round-trip, scope filtering (PSL matching), atomic persistence,
   fail-closed keyless mode. Pure unit tests, no browser.
2. **Save path**: explicit-context worker refactor + `export_storage_state`, `save-jar` endpoint
   with agent/human authorization matrix, handover-form checkbox + session-UI action, events. Fake
   runtime + one real-Chromium test asserting a fixture login survives export.
3. **Load path**: `create_session.jar_id` + `allow_exec` + `confine_navigation`, session metadata
   exposure, `jar_loaded` event, `exec` default-deny and top-level navigation confinement in
   jar-loaded sessions, jar management endpoints + `/jars` UI page. Real-runtime test: log in on
   fixture site, save, new session with jar, fixture shows logged-in; a navigation to an off-scope
   origin is blocked.
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
- Navigation confinement: in a jar-loaded session with `confine_navigation: true`, a `navigate` to
  an off-scope origin is blocked and reported structurally; a **sibling subdomain sharing the
  registrable domain** (`accounts.example.com` for a `shop.example.com` jar) and a **different port**
  (`example.com:8443` for an `example.com` jar) are also blocked (confinement is exact scheme+host+port,
  not registrable-domain); an **off-scope redirect** from an in-scope page is aborted pre-request; an
  off-scope **popup/`window.open`** and an **off-scope child-frame document/form POST** are blocked;
  in-scope navigation and saved `nav_allowlist` origins proceed; a jarless or opted-out session is
  unaffected.
- Invalidated jar unloadable: `create_session` with an invalidated `jar_id` is rejected; a refresh
  clears `invalidated_at` and re-enables load.
- Load/revocation race: a load interleaved with `invalidate`/`DELETE` on the same jar does not leave
  a live authenticated context (per-jar lock + post-registration recheck closes the in-flight load).
- Refresh cannot widen `nav_allowlist`: a refresh adding a new allowlist origin is rejected
  (narrowing/preserving allowed); widening requires a new jar.
- Jar load form factor: a jar saved from a desktop session reloads under the desktop UA by default,
  not the mobile agent default.
- Direct-OIDC load gate: an OIDC human `create_session` with `jar_id` is rejected; the service-auth
  (FA) path succeeds.
- Revocation closes the source session: after a save-then-handover flow, `DELETE`/`invalidate` closes
  the still-live session that produced the jar (found via `produced_jar_ids`), not only jar-loaded
  ones; a session that produced two jars is closed when *either* is revoked, and its metadata never
  claims the jar's `jar_origins`.
- Probe internals hidden: `logged_in_selector`/probe urls never appear in `GET /v1/jars` output.
- Probe scope: `probe.url` is accepted within `origins + nav_allowlist`; `logged_out_url_prefix` may
  be off-scope; a probe with no authenticated-only signal yields `uncertain`, not `fresh`.
- Origin-storage size cap: a save whose exported storage_state exceeds the limit is rejected.
- Durable audit: `jar_*` events survive a simulated service restart (written to the durable sink).
- Freshness probe required at save: every save (create and refresh) rejected without a `probe`; a
  human save auto-derives a default probe from the live page so it is never rejected for lack of a
  hand-authored selector.
- Human save allowed in `human_active` and `human_sensitive`; refresh resets `last_probe_*` and
  `invalidated_at` so a refreshed jar no longer reads stale.
- Revocation teardown: `DELETE`/`invalidate` on a jar with a live jar-loaded session closes that
  session; a follow-up agent command on it fails.
- Probe URL redaction: a probe URL with query/fragment is persisted as scheme+host+path only; the
  stripped parameters never appear in metadata, listings, or logs.
- Scope filter property tests: IdP-style third-origin cookies excluded under default scope; a
  host-only sibling cookie (`accounts.example.com`) and sibling-origin localStorage excluded from a
  jar scoped to `shop.example.com`; a `Domain=.example.com` cookie included; a `Path=/account`
  cookie for a declared origin **retained** (path is not used to exclude); `co.uk` handling for the
  informational registrable-domain field; refresh cannot widen scope.
- Label normalization: a save label containing newlines/control characters/markup is stored
  trimmed, length-capped, and plain-text; `list` never emits the raw injected label.
- IndexedDB capture: a fixture login that stores its token in IndexedDB survives export→load (the
  export passes `indexed_db=True`); a `cookies_only` jar drops it.
- Refresh preservation: a bare-`jar_id` refresh of a `cookies_only` jar does not re-add origin
  storage, and preserves `nav_allowlist`; explicit override still works.
- Probe redirect confinement: a probe whose endpoint 302s to an off-scope origin is aborted before
  any request carries a jar cookie off-scope; an in-scope probe resolves normally.
- Mandatory probe: every save (create and refresh) is rejected without a `probe` config.
- Human-save origin: with no agent command having run, a human save resolves default scope from the
  live page under the control token (not a stale/`None` `current_origin`).
- Revocation teardown: `DELETE` and `invalidate` on a jar with a live jar-loaded session close that
  session; a subsequent agent command on it fails (session gone), and no further authenticated
  browsing is possible under the revoked jar.
- Keyless mode: all jar endpoints 503, `create_session` with `jar_id` rejected, no plaintext ever
  written.
- Wrong/rotated key: load fails with explicit error, delete still works.

## Open questions

1. **Retention**: persistent-cookie jars live until deleted or invalidated. Is a `BROWSER_JAR_TTL_DAYS`
   reaper worth it, or is the staleness surfaced in listings (+ human UI delete) enough for a
   household deployment? Leaning: no global TTL for jars with persistent-cookie expiry (probing
   surfaces dead ones), **but** session-cookie-only jars — which carry no intrinsic expiry — are the
   case that most wants a bounded TTL on top of their mandatory probe; a shorter default max age for
   just those is likely worth it. Decide alongside the probe-heuristics work.
2. **Probe success heuristics**: is selector-or-URL-prefix enough, or do real household sites need a
   "either of N indicators" list? Decide after milestone 4 contact with reality.
3. **`saved_by` policy leverage**: should Family Assistant require `saved_by == "human"` for some
   uses (e.g. loading into less-trusted profiles)? Pure FA policy question; the metadata is there.
