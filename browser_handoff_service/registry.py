from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, cast
from uuid import uuid4

from .jars import (
    JarRevokedError,
    JarStore,
    JarValidationError,
    jar_store_from_env,
    normalize_origin,
    validate_jar_id,
)
from .keychute import KeychuteClient, KeychuteError, KeychuteNotConfigured
from .keychute import zero as zero_secret
from .models import (
    AGENT_COMMAND_STATES,
    AUTOFILL_FILL_CAP,
    OBSERVATION_COMMANDS,
    TERMINAL_STATES,
    AgentCommandRequest,
    AgentCommandResponse,
    AutofillRefusal,
    AutofillRequest,
    AutofillResponse,
    BrowserSession,
    CookieJarMeta,
    CreateSessionRequest,
    FilledField,
    HandoffRequest,
    JarProbeConfig,
    LeaseOwner,
    ProbeResult,
    ProbeResultName,
    SaveJarRequest,
    SessionEvent,
    SessionState,
    autofill_refused,
    form_factor_profile,
    new_session,
    now_utc,
)
from .runtime import BrowserRuntime, RuntimeUnavailable, StorageTooLarge, make_worker
from .security import hash_token, mint_token, redact_url
from .transitions import transition

logger = logging.getLogger(__name__)


class NotFoundError(KeyError):
    pass


class AuthorizationError(PermissionError):
    pass


class ConflictError(RuntimeError):
    pass


class SessionInactiveError(ConflictError):
    """The target session has expired or reached a terminal state.

    Subclasses ConflictError so existing conflict handling still applies, but is
    distinct so callers can tell "this session is gone, start a new one" apart
    from "you do not own the lease" (which stays an AuthorizationError). The HTTP
    layer maps this to 410 Gone.
    """


PAGE_STATE_COMMANDS = {
    "navigate",
    "click",
    "type_text",
    "select",
    "press_key",
    "current_page",
    "close_page",
    "wait",
    "exec",
    "extract",
    "mouse_click",
    "mouse_move",
    "mouse_down",
    "mouse_up",
    "mouse_wheel",
    "keyboard_type",
    "keyboard_press",
    "navigate_back",
    "navigate_forward",
}


# Denied outright in an authenticated-site session: both read page content as raw values.
AUTHENTICATED_SITE_DENIED_COMMANDS = {"exec", "extract"}

# Key-chord fences for an authenticated-site session. Writing into a protected control is fine;
# what is denied is every chord that MOVES a value out of one into somewhere observable.
_TRANSFER_KEYS = {"c", "x", "v", "insert"}
# Playwright resolves ControlOrMeta per platform, so it is a third spelling of the same chord.
_TRANSFER_MODIFIERS = {"control", "meta", "controlormeta"}


def _pressed_key(req: AgentCommandRequest) -> str | None:
    """The key string the runtime will actually press, or None for a non-key command.

    Read exactly as ``_dispatch_command`` reads it — ``press_key`` presses ``key`` and ignores
    ``keys``, ``keyboard_press`` prefers ``keys``. A guard that inspected the other argument
    would be a fence around a key the browser never receives, and the key it does receive would
    go unchecked."""
    if req.type == "press_key":
        raw = req.args.get("key")
    elif req.type == "keyboard_press":
        raw = req.args.get("keys", req.args.get("key"))
    else:
        return None
    return raw if isinstance(raw, str) else None


def _is_transfer_chord(req: AgentCommandRequest) -> bool:
    """Whether a key command is a copy/cut/paste chord (Ctrl/Cmd+C/X/V/Insert, Shift+Insert)."""
    raw = _pressed_key(req)
    if raw is None:
        return False
    parts = [part.strip().lower() for part in raw.split("+") if part.strip()]
    if not parts:
        return False
    base, modifiers = parts[-1], set(parts[:-1])
    if base in {"keyc", "keyx", "keyv"}:
        base = base[-1]
    if base not in _TRANSFER_KEYS:
        return False
    if modifiers & _TRANSFER_MODIFIERS:
        return True
    return base == "insert" and "shift" in modifiers


# Every access request's TTL. Long enough for a human approval to land inside the park window,
# short enough that an approved-but-unused grant is not a standing capability.
AUTOFILL_REQUEST_TTL_SECONDS = 600

# What each page-side refusal means, in words the agent can act on.
_AUTOFILL_DETAILS = {
    "no_eligible_field": "no visible login field on this page can take that fill",
    "ambiguous_fields": "more than one password field is visible; address one by ref",
    "new_password_field": "that field is a new-password/confirm field",
    "in_iframe": "the field is inside an iframe; only the main frame can be filled",
    "stale_ref": "that ref no longer names a field on this page",
    "invalid_ref": "a ref looks like e12",
    "target_invalidated": "the page changed under the request",
}


def _origin_host_port(origin: str) -> tuple[str, int]:
    """Split a normalized origin into the host and effective port Keychute constrains on."""
    from urllib.parse import urlsplit

    parts = urlsplit(origin)
    return (parts.hostname or "").lower(), parts.port if parts.port is not None else (
        80 if parts.scheme == "http" else 443
    )


def _parse_secret(secret: bytearray) -> dict[str, str]:
    """Interpret a released payload: a JSON object with username/password, or a bare password.

    Anything that is not a JSON object carrying those keys IS the password, verbatim — not
    trimmed, not normalized. A stored password may legitimately begin or end with whitespace, and
    a fill that quietly altered it would look like a wrong password at the site rather than like
    the bug it is.

    The plaintext only becomes a str here, at the point of the fill, and the caller drops it
    immediately afterwards."""
    try:
        decoded = json.loads(bytes(secret))
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = None
    if isinstance(decoded, dict):
        values: dict[str, str] = {}
        for kind in ("username", "password"):
            value = decoded.get(kind)
            if isinstance(value, str) and value:
                values[kind] = value
        if values:
            return values
    if not secret:
        # An empty release is a broken secret, not a password; the caller refuses it.
        return {}
    return {"password": bytes(secret).decode("utf-8", errors="replace")}


def _normalized_confine_origins(values: list[str] | None) -> list[str] | None:
    """Normalize an explicit confinement set with the canonical origin normalizer.

    Uses the same function the route guard compares against, so an accepted set cannot mean
    one thing at validation and another at enforcement."""
    if values is None:
        return None
    normalized: list[str] = []
    for value in values:
        origin = normalize_origin(value)
        if origin is None:
            raise JarValidationError(f"confine_origins entry is not an exact origin: {value!r}")
        if origin not in normalized:
            normalized.append(origin)
    return normalized


@dataclass
class TokenRecord:
    session_id: str
    token_hash: str
    token_type: str
    expires_at: Any
    consumed_at: Any = None


class SessionRegistry:
    def __init__(self, jar_store: JarStore | None = None) -> None:
        self.sessions: dict[str, BrowserSession] = {}
        self.locks: dict[str, asyncio.Lock] = {}
        self.events: dict[str, list[SessionEvent]] = {}
        self.tokens: dict[str, TokenRecord] = {}
        self.workers: dict[str, BrowserRuntime] = {}
        # Durable, encrypted cookie-jar store (browser-server's only durable state). Built from
        # env by default; injectable for tests. Keyless => the whole feature is fail-closed.
        self.jar_store: JarStore = jar_store if jar_store is not None else jar_store_from_env()
        # Per-jar locks serialize load against invalidate/delete so a load cannot race a
        # concurrent revocation (see create_session's post-registration recheck).
        self.jar_locks: dict[str, asyncio.Lock] = {}
        # Credential broker for autofill. Unconfigured => autofill refuses; injectable for tests.
        self.keychute = KeychuteClient()

    def list_sessions(self) -> list[BrowserSession]:
        return sorted(self.sessions.values(), key=lambda item: item.created_at)

    def _jar_lock(self, jar_id: str) -> asyncio.Lock:
        return self.jar_locks.setdefault(jar_id, asyncio.Lock())

    async def create_session(
        self, req: CreateSessionRequest, *, owner_subject: str | None = None
    ) -> tuple[BrowserSession, str | None]:
        return await self._create_session_locked(req, owner_subject=owner_subject)

    async def _create_session_locked(
        self, req: CreateSessionRequest, *, owner_subject: str | None
    ) -> tuple[BrowserSession, str | None]:
        session = new_session(req)
        # Record the owning OIDC subject for a human-owned session so a later control-token
        # save-jar (which carries no OIDC bearer) can stamp a non-null owner_subject.
        if session.lease_owner == LeaseOwner.HUMAN:
            session.owner_subject = owner_subject

        storage_state: dict | None = None
        confine_origins: list[str] | None = None
        jar_scope: list[str] = []
        explicit_origins = _normalized_confine_origins(req.confine_origins)
        loaded = None
        if req.jar_id is not None:
            # Validate the id BEFORE allocating a per-jar lock, so a caller passing malformed/random
            # ids cannot leave permanent self.jar_locks entries per failed create (as the save path
            # already guards).
            validate_jar_id(req.jar_id)
            # Take the jar lock only for the load (serialize it against a concurrent invalidate/
            # delete), then release it before the slow worker.start() below so a same-process
            # revocation is not queued behind browser startup. The post-start recheck re-verifies
            # the seeded generation against the tombstone, and a racing invalidate's
            # _close_sessions_for_jar also tears down this (already-registered) session.
            async with self._jar_lock(req.jar_id):
                loaded = self.jar_store.load(req.jar_id)  # raises JarError on disabled/missing/revoked
            storage_state = loaded.storage_state
            # A jar load defaults to the producing session's form factor/UA unless the create
            # call explicitly overrode it (storage_state does not carry the device profile).
            if req.form_factor == "auto" and req.client_viewport is None:
                session.form_factor = loaded.meta.form_factor
            # An authenticated-site session is confined unconditionally; the opt-out is a 400
            # at the HTTP layer, and honouring it here would be the silent widening that layer
            # exists to prevent.
            confine = True if req.authenticated_site else (req.confine_navigation is not False)
            jar_scope = [*loaded.meta.origins, *loaded.meta.nav_allowlist]
            if confine:
                confine_origins = list(jar_scope)
            session.jar_id = loaded.meta.jar_id
            session.jar_generation = loaded.meta.generation
            session.jar_origins = list(loaded.meta.origins)
            session.jar_nav_allowlist = list(loaded.meta.nav_allowlist)
            session.jar_registrable_domains = list(loaded.meta.registrable_domains)
            session.allow_exec = False if req.authenticated_site else req.allow_exec
            session.confine_navigation = confine

        if req.authenticated_site:
            if loaded is not None:
                # The session-creation chokepoint: when the caller states the confinement set AND
                # loads a jar, the two must agree exactly. A silent preference for either one is
                # how a session ends up confined to something other than what the caller verified.
                if explicit_origins is not None and set(explicit_origins) != set(jar_scope):
                    raise JarValidationError(
                        "confinement mismatch: confine_origins does not equal the jar's effective origin set"
                    )
            else:
                # Jarless: the explicit set IS the confinement, enforced by the same route guard.
                confine_origins = list(explicit_origins or [])
            session.authenticated_site = True
            session.credential_alias = req.credential_alias
            session.allow_exec = False
            session.confine_navigation = True
        session.confine_origins = list(confine_origins or [])

        self.sessions[session.session_id] = session
        self.locks[session.session_id] = asyncio.Lock()
        self.events[session.session_id] = []
        profile = form_factor_profile(session.form_factor)
        worker = make_worker(
            session.worker_id or "",
            width=profile.width,
            height=profile.height,
            user_agent=profile.user_agent,
            storage_state=storage_state,
            confine_origins=confine_origins,
            timezone_id=session.timezone_id,
            mask_protected=session.authenticated_site,
        )
        self.workers[session.worker_id or ""] = worker
        try:
            await worker.start()
        except RuntimeUnavailable as exc:
            session.state = SessionState.FAILED
            session.lease_owner = LeaseOwner.NONE
            session.closed_at = now_utc()
            self._event(session, "worker_failed", "service", metadata={"reason": str(exc)[:500]})
            return session, None
        if loaded is not None:
            # Close the load/revocation race: after registering the session, re-read the jar and
            # tear the just-created context down if it was revoked in the window. Check the SEEDED
            # generation (the one materialized into this context), not just "is the current file
            # loadable": on a shared volume another pod may have refreshed the jar while
            # worker.start() awaited, tombstoning the seeded generation while the file advanced to a
            # newer loadable one — recheck_loadable alone would pass against that newer generation.
            if not self.jar_store.recheck_loadable(req.jar_id or "") or self.jar_store.is_revoked_generation(
                req.jar_id or "", loaded.meta.generation
            ):
                session.state = SessionState.CANCELLED
                session.lease_owner = LeaseOwner.NONE
                await self._cleanup_locked(session)
                self._event(session, "session_closed", "service", metadata={"reason": "jar_revoked"})
                raise JarRevokedError("jar was revoked during load")
            # Best-effort: last_loaded_at is a non-critical metadata touch. If its write fails (full
            # volume, permissions) it must NOT bubble up here — the session and its seeded worker
            # are already registered, so propagating would leave a live authenticated context alive
            # until expiry while returning an error to the caller.
            try:
                self.jar_store.touch_loaded(req.jar_id or "")
            except Exception:
                logger.warning("touch_loaded failed for jar %s; continuing", req.jar_id, exc_info=True)
            # Confinement gates only agent-driven navigation. If the jar is loaded straight into a
            # human-owned session (service token + initial_owner="human"), the human drives via
            # noVNC and the handoff toggle never runs, so disable confinement now — otherwise the
            # route guard would block the human's off-scope SSO/re-login navigation.
            # An authenticated-site session stays confined even under human control: the design
            # parks it origin-confined, and dropping the guard here would widen it silently.
            if session.lease_owner == LeaseOwner.HUMAN and not session.authenticated_site:
                worker.set_confinement_active(False)
            self._event(
                session,
                "jar_loaded",
                "service",
                metadata={"jar_id": loaded.meta.jar_id, "origins": loaded.meta.origins},
            )
        if session.lease_owner == LeaseOwner.HUMAN:
            control_token = mint_token()
            self.tokens[hash_token(control_token)] = TokenRecord(
                session_id=session.session_id,
                token_hash=hash_token(control_token),
                token_type="control",
                expires_at=session.expires_at,
            )
            self._event(session, "session_created", "human")
            return session, control_token
        self._event(session, "session_created", "agent")
        return session, None

    def get(self, session_id: str) -> BrowserSession:
        try:
            return self.sessions[session_id]
        except KeyError as exc:
            raise NotFoundError(session_id) from exc

    async def handoff(self, session_id: str, req: HandoffRequest, base_url: str) -> tuple[BrowserSession, str]:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            if req.reason in {"payment", "credentials", "otp", "legal_consent"} and req.allowed_resume != "never":
                raise ConflictError("sensitive handoffs cannot resume on the same browser page")
            # A jar-loaded session must never be resumed as the same context after human control:
            # the human can visit off-scope login/payment/SSO origins and accumulate credentials
            # broader than the jar's immutable jar_origins. Force allowed_resume=never so
            # human_complete tears the worker down; the agent resumes only via a fresh,
            # re-filtered jar-loaded session.
            if session.jar_id is not None and req.allowed_resume != "never":
                raise ConflictError("a jar-loaded session cannot request a resumable handoff")
            if req.expected_origin is not None:
                expected_origin = _normalize_origin(req.expected_origin)
                if expected_origin is None:
                    raise ConflictError("expected_origin must include scheme and host")
                if session.current_origin != expected_origin:
                    raise ConflictError("browser is not at the expected handoff origin")
            session.lease_owner = transition(session.state, session.lease_owner, SessionState.HANDOFF_REQUESTED)
            session.state = SessionState.HANDOFF_REQUESTED
            session.handoff_reason = req.reason
            session.allowed_resume = req.allowed_resume
            session.handoff_note = req.handoff_note
            # Navigation confinement gates only agent-driven navigation; once a jar-loaded
            # session is handed to a human, drop confinement so the human is not trapped (e.g. an
            # off-scope SSO/IdP bounce during re-login). The context is torn down at completion
            # and never resumed by the agent (handover and resumable handoff are both refused).
            if session.jar_id is not None and not session.authenticated_site:
                worker = self.workers.get(session.worker_id or "")
                if worker is not None:
                    worker.set_confinement_active(False)
            session.idle_expires_at = min(now_utc() + timedelta(minutes=10), session.expires_at)
            session.updated_at = now_utc()
            token = mint_token()
            self.tokens[hash_token(token)] = TokenRecord(
                session_id=session_id,
                token_hash=hash_token(token),
                token_type="handoff",
                expires_at=session.idle_expires_at,
            )
            self._event(session, "handoff_requested", "agent", metadata={"reason": req.reason})
            return session, f"{base_url.rstrip('/')}/sessions/{session_id}?token={token}"

    async def claim(
        self, session_id: str, token: str, *, owner_subject: str | None = None
    ) -> tuple[BrowserSession, str]:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            handoff_token = self._authorize_token_locked(session, token, token_type="handoff")
            # Record the claiming human's OIDC subject so a save during their control (or after a
            # hand-back for an agent save) lands a non-null owner_subject rather than an
            # ownerless jar invisible in the subject-scoped /jars UI.
            if owner_subject is not None:
                session.owner_subject = owner_subject
            session.lease_owner = transition(session.state, session.lease_owner, SessionState.HUMAN_ACTIVE)
            session.state = SessionState.HUMAN_ACTIVE
            session.idle_expires_at = min(now_utc() + timedelta(minutes=10), session.expires_at)
            session.updated_at = now_utc()
            handoff_token.consumed_at = now_utc()
            control_token = mint_token()
            self.tokens[hash_token(control_token)] = TokenRecord(
                session_id=session_id,
                token_hash=hash_token(control_token),
                token_type="control",
                expires_at=session.expires_at,
            )
            self._event(session, "handoff_claimed", "human")
            return session, control_token

    async def human_complete(self, session_id: str, token: str, outcome: str | None) -> BrowserSession:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._authorize_human_token_locked(session, token)
            self._raise_if_expired(session)
            if session.allowed_resume == "after_sanitize" and session.state == SessionState.HUMAN_ACTIVE:
                session.lease_owner = transition(session.state, session.lease_owner, SessionState.SANITIZE_PENDING)
                session.state = SessionState.SANITIZE_PENDING
                await self._sanitize_for_resume_locked(session)
                session.lease_owner = transition(session.state, session.lease_owner, SessionState.AGENT_RESUMABLE)
                session.state = SessionState.AGENT_RESUMABLE
                session.idle_expires_at = min(now_utc() + timedelta(minutes=5), session.expires_at)
                event_type = "handoff_resumable"
            else:
                session.lease_owner = transition(session.state, session.lease_owner, SessionState.COMPLETED)
                session.state = SessionState.COMPLETED
                await self._cleanup_locked(session)
                event_type = "handoff_completed"
            session.updated_at = now_utc()
            self._event(session, event_type, "human", metadata={"outcome": outcome or "complete"})
            return session

    async def human_cancel(self, session_id: str, token: str, outcome: str | None) -> BrowserSession:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._authorize_human_token_locked(session, token, allow_pending=True)
            self._raise_if_expired(session)
            session.lease_owner = transition(session.state, session.lease_owner, SessionState.CANCELLED)
            session.state = SessionState.CANCELLED
            await self._cleanup_locked(session)
            session.updated_at = now_utc()
            self._event(session, "handoff_cancelled", "human", metadata={"outcome": outcome or "cancelled"})
            return session

    async def handover(self, session_id: str, token: str, handoff_note: str) -> tuple[BrowserSession, str | None]:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            # Keep authorizing with the human control token, but do not consume it: it stays
            # valid through the pending window so the human can still cancel if the agent never
            # claims. State guards block every other human action while in HANDOVER_REQUESTED,
            # and agent_claim revokes it once the agent takes over.
            self._authorize_token_locked(session, token, token_type="control")
            if session.state != SessionState.HUMAN_ACTIVE:
                raise ConflictError("only an active human session can be handed over to an agent")
            # A jar-loaded session that passed to human control must not be resumed by the agent
            # as the same context: during human control the human can visit off-scope
            # login/payment/SSO origins and accumulate credentials broader than the jar's
            # immutable jar_origins. The agent resumes authenticated browsing only by starting a
            # fresh, re-filtered jar-loaded session — never by inheriting the human-widened one.
            #
            # An authenticated-site session is the exception, and only because the premise does
            # not hold for it: confinement is never lifted, not even under human control, so the
            # human cannot have widened it. Without this the handoff is one-way — a run that
            # parks for an MFA code or a captcha could never come back, which is the whole point
            # of parking it.
            if session.jar_id is not None and not session.authenticated_site:
                raise ConflictError(
                    "a jar-loaded session cannot be handed to an agent; start a fresh jar-loaded session"
                )
            session.handoff_reason = None
            session.allowed_resume = "never"
            session.handoff_note = handoff_note
            if session.authenticated_site:
                # Sanitized resume is not an option here, it is the terms: the human-controlled
                # page is closed and a fresh one opened inside the confinement set before the
                # agent can observe anything. Exact page and in-progress form state do not
                # survive; the authenticated cookies do, which is what the handback is for.
                session.allowed_resume = "after_sanitize"
                await self._sanitize_for_resume_locked(session)
                await self._reopen_confined_page_locked(session)
            session.lease_owner = transition(session.state, session.lease_owner, SessionState.HANDOVER_REQUESTED)
            session.state = SessionState.HANDOVER_REQUESTED
            session.idle_expires_at = min(now_utc() + timedelta(minutes=10), session.expires_at)
            session.updated_at = now_utc()
            handover_token = None
            if not session.authenticated_site:
                handover_token = mint_token()
                self.tokens[hash_token(handover_token)] = TokenRecord(
                    session_id=session_id,
                    token_hash=hash_token(handover_token),
                    token_type="handover",
                    expires_at=session.idle_expires_at,
                )
            self._event(session, "handover_requested", "human")
            return session, handover_token

    async def agent_claim(self, session_id: str, token: str | None) -> BrowserSession:
        """Take the lease back after a human handover.

        Ordinarily the one-time handover token is the authority, minted for the human and relayed
        by them. An authenticated-site session cannot work that way: the token is minted for the
        human and the design forbids routing it through the conversation, so trusted orchestration
        would have no way to present it. There the human's handover POST is the signal
        and the service token is the authority, so no handover token is minted."""
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            if session.state != SessionState.HANDOVER_REQUESTED:
                raise ConflictError("session is not awaiting an agent handover")
            await self._enforce_jar_not_revoked_locked(session)
            handover_record = None
            if token or not session.authenticated_site:
                handover_record = self._authorize_token_locked(session, token or "", token_type="handover")
            session.lease_owner = transition(session.state, session.lease_owner, SessionState.AGENT_ACTIVE)
            session.state = SessionState.AGENT_ACTIVE
            session.idle_expires_at = min(now_utc() + timedelta(minutes=15), session.expires_at)
            session.updated_at = now_utc()
            if handover_record is not None:
                handover_record.consumed_at = now_utc()
            else:
                self._revoke_session_tokens_locked(session, token_type="handover")
            self._revoke_session_tokens_locked(session, token_type="control")
            if session.authenticated_site:
                # Confinement is never lifted for these sessions; re-asserting it here means a
                # future change to the human path cannot hand the agent a widened context.
                worker = self.workers.get(session.worker_id or "")
                if worker is not None:
                    worker.set_confinement_active(True)
            self._event(session, "handover_claimed", "agent")
            return session

    async def extend(self, session_id: str, token: str, minutes: int) -> BrowserSession:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._authorize_human_token_locked(session, token)
            self._raise_if_expired(session)
            requested_expiry = min(now_utc() + timedelta(minutes=minutes), session.expires_at)
            session.idle_expires_at = max(session.idle_expires_at, requested_expiry)
            session.updated_at = now_utc()
            self._event(session, "handoff_extended", "human", metadata={"minutes": minutes})
            return session

    async def mark_sensitive(self, session_id: str, token: str) -> BrowserSession:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._authorize_human_token_locked(session, token)
            self._raise_if_expired(session)
            session.lease_owner = transition(session.state, session.lease_owner, SessionState.HUMAN_SENSITIVE)
            session.state = SessionState.HUMAN_SENSITIVE
            session.sensitive_since = now_utc()
            session.idle_expires_at = min(now_utc() + timedelta(minutes=5), session.expires_at)
            session.updated_at = now_utc()
            self._event(session, "human_sensitive", "human")
            return session

    async def authorize_remote(self, session_id: str, token: str) -> BrowserSession:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            self._authorize_human_token_locked(session, token)
            # A jar-loaded session handed to a human keeps a live authenticated context behind
            # noVNC; recheck the shared tombstone so a cross-process revoke tears it down here too.
            await self._enforce_jar_not_revoked_locked(session)
            return session

    async def authorize_handoff_page(self, session_id: str, token: str) -> BrowserSession:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            if session.state == SessionState.HANDOFF_REQUESTED:
                self._authorize_token_locked(session, token, token_type="handoff")
            else:
                # allow_pending lets the page reload while a handover is pending: the human
                # still holds their control token and can see state / cancel from the UI.
                self._authorize_human_token_locked(session, token, allow_pending=True)
            await self._enforce_jar_not_revoked_locked(session)
            return session

    async def agent_command(self, session_id: str, req: AgentCommandRequest) -> AgentCommandResponse:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            if session.state in TERMINAL_STATES:
                raise SessionInactiveError(f"session is no longer active ({session.state})")
            if session.state not in AGENT_COMMAND_STATES or session.lease_owner != LeaseOwner.AGENT:
                raise AuthorizationError("agent commands are denied unless the agent owns the lease")
            if session.state not in AGENT_COMMAND_STATES and req.type in OBSERVATION_COMMANDS:
                raise AuthorizationError("observation denied outside agent-owned states")
            # exec can read document.cookie / origin storage, handing non-HttpOnly session tokens
            # to the model — the one agent-reachable path from "use the login" to "read the
            # credential". Default-deny it in a jar-loaded session unless the creator opted in.
            if req.type == "exec" and session.jar_id is not None and not session.allow_exec:
                raise AuthorizationError("exec is denied in a jar-loaded session unless allow_exec was set")
            # Read-back protection. exec and extract both hand the raw DOM (a filled password
            # field included) straight to the model, so neither exists in an authenticated-site
            # session — jar or no jar, and with no opt-in.
            if session.authenticated_site and req.type in AUTHENTICATED_SITE_DENIED_COMMANDS:
                raise AuthorizationError(f"{req.type} is denied in an authenticated-site session")
            if session.authenticated_site and _is_transfer_chord(req):
                raise AuthorizationError(
                    "clipboard and transfer key chords are denied in an authenticated-site session"
                )
            # Per-command revocation recheck. In a multi-process deployment sharing the jar
            # directory, a revoke in another process cannot reach into this registry's in-memory
            # session set, so a jar-loaded (or jar-producing) session would keep serving an
            # authenticated context until it noticed. Consulting the shared, durable tombstone
            # before each command turns the kill-switch into a near-real-time, cross-process one.
            await self._enforce_jar_not_revoked_locked(session)
            worker = self.workers.get(session.worker_id or "")
            if worker is None or worker.closed:
                session.lease_owner = LeaseOwner.NONE
                session.state = SessionState.FAILED
                session.updated_at = now_utc()
                self._event(session, "worker_failed", "service", metadata={"reason": "missing_worker"})
                raise ConflictError("worker is not available")
            result = await worker.command(req)
            if req.type in PAGE_STATE_COMMANDS and "url" in result:
                self._update_page_metadata(session, result)
            ucp = result.get("ucp")
            if isinstance(ucp, dict) and ucp.get("origin"):
                self._event(
                    session,
                    "ucp_detected",
                    "service",
                    metadata={
                        "origin": ucp.get("origin"),
                        "capabilities": ucp.get("capabilities", []),
                    },
                )
            session.idle_expires_at = min(now_utc() + timedelta(minutes=15), session.expires_at)
            session.updated_at = now_utc()
            self._event(session, "agent_command", "agent", metadata={"type": req.type})
            return AgentCommandResponse(command_id=req.command_id, ok=True, result=result)

    async def close(self, session_id: str) -> BrowserSession:
        session = self.get(session_id)
        async with self.locks[session_id]:
            if session.state not in TERMINAL_STATES:
                session.lease_owner = LeaseOwner.NONE
                session.state = SessionState.CANCELLED
            await self._cleanup_locked(session)
            session.updated_at = now_utc()
            self._event(session, "session_closed", "service")
            return session

    # -- autofill -----------------------------------------------------------

    async def record_autofill_outcome(self, session_id: str, outcome: str) -> BrowserSession:
        """Latch a reported bad password. Every later fill in this session is refused.

        One fill per grant read, and a read is not a login submission: without this latch a model
        that misreads a failed login would keep asking for releases against a password that is
        already known not to work."""
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            if outcome == "bad_password":
                session.autofill_bad_password = True
                session.updated_at = now_utc()
                self._event(session, "autofill_bad_password", "agent")
            return session

    async def autofill(self, session_id: str, req: AutofillRequest) -> AutofillResponse:
        """Fill the session's pinned credential into the login form on the current document.

        The whole resolve -> request -> wait -> verify -> read -> fill sequence holds the session
        command lock, so nothing the agent does can move the page underneath it; the page itself
        still can, which is what the document nonce catches."""
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            if session.state in TERMINAL_STATES:
                raise SessionInactiveError(f"session is no longer active ({session.state})")
            if session.state not in AGENT_COMMAND_STATES or session.lease_owner != LeaseOwner.AGENT:
                raise AuthorizationError("autofill is denied unless the agent owns the lease")
            await self._enforce_jar_not_revoked_locked(session)
            response = await self._autofill_locked(session, req)
            session.updated_at = now_utc()
            session.idle_expires_at = min(now_utc() + timedelta(minutes=15), session.expires_at)
            self._event(
                session,
                "autofill",
                "agent",
                metadata={"status": response.status, "reason": response.reason, "step_key": req.step_key},
            )
            return response

    async def _autofill_locked(self, session: BrowserSession, req: AutofillRequest) -> AutofillResponse:
        if not session.authenticated_site:
            return autofill_refused("not_authenticated_site", "autofill exists only in an authenticated-site session")
        alias = session.credential_alias
        if not alias:
            return autofill_refused("no_alias", "this session has no credential pinned to it")
        if session.autofill_bad_password:
            return autofill_refused("bad_password_recorded", "a bad password was reported for this session")
        if session.autofill_fill_count >= AUTOFILL_FILL_CAP:
            return autofill_refused(
                "fill_cap_reached", f"this session has already consumed {AUTOFILL_FILL_CAP} credential grants"
            )
        worker = self.workers.get(session.worker_id or "")
        if worker is None or worker.closed:
            raise ConflictError("worker is not available")

        # 1. Pin the document and choose the targets. The origin is the document's own, never
        #    anything the caller supplied.
        nonce = uuid4().hex
        fields = [field.model_dump() for field in req.fields] if req.fields else None
        prepared = await worker.autofill_prepare(fields, nonce)
        if prepared.get("error"):
            reason = str(prepared.get("reason") or "no_eligible_field")
            return autofill_refused(
                cast(AutofillRefusal, reason),
                _AUTOFILL_DETAILS.get(reason, "the requested field cannot take a fill"),
                origin=prepared.get("origin"),
            )
        origin = _normalize_origin(str(prepared.get("origin") or ""))
        targets = list(prepared.get("targets") or [])
        if origin is None or origin not in set(session.confine_origins):
            # Cannot happen while the route guard holds, so it is a fail-closed backstop rather
            # than a routine outcome — about:blank reaches it too.
            return autofill_refused(
                "wrong_origin", "the current document is not inside this session's confinement set", origin=origin
            )

        if not self.keychute.configured:
            return autofill_refused("keychute_unavailable", "no credential broker is configured", origin=origin)

        idempotency_key = f"{session.session_id}:{req.step_key}"
        host, port = _origin_host_port(origin)
        site = str((req.context or {}).get("site") or alias)
        acting_user = str((req.context or {}).get("acting_user") or "the configured user")
        try:
            status = await self.keychute.create_access_request(
                idempotency_key=idempotency_key,
                secret_name=alias,
                origin_host=host,
                origin_port=port,
                ttl_seconds=AUTOFILL_REQUEST_TTL_SECONDS,
                # Deterministic for a given (session, step): the reason is part of Keychute's
                # idempotency MAC, so a retry that reworded it would be a different request.
                reason=f"Autofill {site} login on {origin} for {acting_user} (step {req.step_key})",
                structured={
                    **(req.context or {}),
                    "session_id": session.session_id,
                    "step_key": req.step_key,
                    "origin": origin,
                },
            )
            if status.state == "pending" and req.wait_seconds > 0:
                status = await self.keychute.wait(status.request_id, req.wait_seconds)
            if status.state == "pending":
                session.autofill_pending[req.step_key] = status.request_id
                approval_url = self.keychute.approval_url(status.request_id)
                return AutofillResponse(
                    status="approval_pending",
                    request_id=status.request_id,
                    origin=origin,
                    detail=f"awaiting a release decision at {approval_url}"
                    if approval_url
                    else "awaiting a release decision",
                )
            session.autofill_pending.pop(req.step_key, None)
            if status.state == "denied":
                return autofill_refused("policy_denied", "the release was denied", origin=origin)
            if status.state == "expired":
                return autofill_refused("request_expired", "the release request expired", origin=origin)
            if status.grant_id is None:
                return autofill_refused("grant_invalid", "the release was approved without a grant", origin=origin)

            # 2. Check the destination against what was GRANTED, which an approval may have
            #    narrowed below what was asked for.
            info = await self.keychute.grant_info(status.grant_id)
            reference_now = info.server_time or now_utc()
            if (
                info.mechanism != "autofill"
                or info.revoked
                or info.not_after <= reference_now
                or (info.max_uses is not None and info.use_count >= info.max_uses)
            ):
                return autofill_refused("grant_invalid", "the grant is not usable", origin=origin)
            if not any(granted.matches(host, port) for granted in info.origins):
                return autofill_refused(
                    "wrong_origin", "the granted capability does not cover this document's origin", origin=origin
                )

            # 3. Re-verify the pinned document BEFORE spending the grant's single read: a site
            #    can navigate itself while an approval is outstanding.
            verified = await worker.autofill_fill(nonce, origin, targets, {})
            if verified.get("error"):
                return autofill_refused(
                    "target_invalidated", "the page changed while the release was decided", origin=origin
                )

            await self._enforce_jar_not_revoked_locked(session)
            secret = await self.keychute.read_grant(status.grant_id, idempotency_key)
            session.autofill_fill_count += 1
        except KeychuteNotConfigured:
            return autofill_refused("keychute_unavailable", "no credential broker is configured", origin=origin)
        except KeychuteError as exc:
            # str(exc) is built only from Keychute's non-secret error envelope and status codes.
            return autofill_refused("keychute_unavailable", str(exc), origin=origin)

        values: dict[str, str] = {}
        try:
            values = _parse_secret(secret)
            missing = [str(target["kind"]) for target in targets if str(target["kind"]) not in values]
            if missing:
                return autofill_refused(
                    "grant_invalid",
                    f"the released secret carries no {missing[0]}",
                    origin=origin,
                )
            result = await worker.autofill_fill(nonce, origin, targets, values)
        finally:
            zero_secret(secret)
            values.clear()
            del secret

        if result.get("error"):
            return autofill_refused("target_invalidated", "the page changed before the fill landed", origin=origin)
        filled = [
            FilledField(ref=entry.get("ref"), kind=entry["kind"]) for entry in cast(list, result.get("filled") or [])
        ]
        return AutofillResponse(status="filled", filled=filled, origin=origin)

    # -- cookie jars --------------------------------------------------------
    def _require_jars_enabled(self) -> None:
        if not self.jar_store.enabled:
            # Surfaced by the HTTP layer as 503; jars fail closed without a key.
            from .jars import JarDisabledError

            raise JarDisabledError("cookie jars are disabled: no BROWSER_JAR_KEY configured")

    async def save_jar(self, session_id: str, req: SaveJarRequest, *, actor: str) -> CookieJarMeta:
        """Capture the live session's storage_state into a new or refreshed jar.

        ``actor`` is "human" (control-token save) or "agent" (service-auth save); the caller
        (main) establishes it from the auth path. Authorization mirrors agent commands and is
        fail-closed."""
        self._require_jars_enabled()
        # Validate the id, confirm the session exists, and AUTHORIZE before allocating a per-jar
        # lock: _jar_lock caches an asyncio.Lock keyed by jar_id forever, so a caller POSTing
        # malformed/random ids (or ids against a bogus session, or with a bad control token) must not
        # be able to leave permanent entries in self.jar_locks. A malformed id is a 400, an unknown
        # session a 404, and a bad token a 403 — all lock-free. (req.token only *selects* the human
        # path; agent saves are already service-authenticated at the HTTP layer.)
        session = self.get(session_id)
        if req.jar_id is not None:
            validate_jar_id(req.jar_id)
        if actor == "human":
            self._authorize_human_token_locked(session, req.token or "")
        # A refresh mutates an existing durable jar, so it must serialize against
        # invalidate/delete on the same jar (jar lock BEFORE the session lock, matching the
        # jar->session order used by create/revocation) — otherwise an in-flight refresh could
        # write a higher generation over a just-tombstoned one and resurrect a revoked jar.
        if req.jar_id is not None:
            async with self._jar_lock(req.jar_id):
                return await self._save_jar_locked(session_id, req, actor)
        return await self._save_jar_locked(session_id, req, actor)

    async def _save_jar_locked(self, session_id: str, req: SaveJarRequest, actor: str) -> CookieJarMeta:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            # If a jar backing this live session was revoked (possibly by another process), close
            # the session and reject: otherwise the agent could refresh its own jar_id and publish
            # a higher generation with invalidated_at cleared, undoing the kill-switch. A fresh
            # re-login (a jarless session that has not yet produced this jar) is unaffected.
            await self._enforce_jar_not_revoked_locked(session)
            owner_subject, saved_by = self._authorize_save_locked(session, req, actor)

            # Cloning guard: a new-jar save from a jar-loaded session would snapshot the
            # credentials into a second, unlinked blob that revocation of the original never
            # reaches. A jar-loaded session may only refresh its own jar_id.
            if session.jar_id is not None and (req.jar_id is None or req.jar_id != session.jar_id):
                raise ConflictError("a jar-loaded session may only refresh its own jar")

            existing: CookieJarMeta | None = None
            if req.jar_id is not None:
                existing = self.jar_store.get_meta_verified(req.jar_id)
                self._authorize_jar_refresh(session, existing, actor, owner_subject)

            if existing is not None:
                # Refresh: re-filter against the STORED scope. An omitted `origins` must NOT
                # collapse a multi-origin jar to the live page's single origin — pass the
                # caller's (possibly empty) list through and let JarStore keep the stored scope.
                origins = list(req.origins) if req.origins else []
                # Validate the requested scope against the stored jar NOW, before any browser work:
                # otherwise a prompt-injected refresh from an agent-loaded session could point the
                # baseline probe at an arbitrary origin and export the live context, only to have
                # JarStore reject the widening afterward. resolved_origins is the authoritative
                # (subset) scope used for probe derivation.
                effective_nav = (
                    None if actor == "agent" else (list(req.nav_allowlist) if req.nav_allowlist is not None else None)
                )
                scope_origins, _, _ = self.jar_store.resolve_refresh_scope(
                    existing, origins, effective_nav, req.storage
                )
            elif actor == "agent":
                # Agent-supplied origins are untrusted: a prompt-injected page could name an IdP or
                # off-site origin whose cookies are in the live context from a prior human SSO, and
                # persist that credential outside the current site's scope. Capture only the live
                # page's origin, resolved server-side. (Refresh, above, can only narrow stored scope.)
                current = await self._worker_current_origin(session)
                if not current:
                    raise ConflictError("could not resolve save origin from the live page")
                origins = [current]
                scope_origins = origins
            else:
                origins = list(req.origins) if req.origins else None
                if not origins:
                    current = await self._worker_current_origin(session)
                    if not current:
                        raise ConflictError("could not resolve save origin; specify origins explicitly")
                    origins = [current]
                scope_origins = origins

            # An agent may supply the freshness *selector* but not point the replayed probe
            # navigation at an arbitrary path (e.g. /logout). Derive a stable landing page. A
            # human save may supply an explicit stable url; if it omits one we also default to
            # the origin's landing page rather than persist a one-time/side-effecting URL.
            landing_origin = normalize_origin(scope_origins[0]) or scope_origins[0]
            derived_landing = landing_origin + "/"
            if actor == "agent":
                probe_url: str | None = derived_landing
            else:
                probe_url = req.probe.url or derived_landing

            # An agent-supplied freshness selector is not trusted as authenticated-only: an
            # injected page could pick a selector present on the login wall too, so later probes
            # keep reading "fresh" after expiry. Validate it against a logged-out baseline; if it
            # does not discriminate, drop it (the jar then reads "uncertain", never a fake fresh).
            probe_selector = req.probe.logged_in_selector
            if actor == "agent" and probe_selector:
                if not await self._selector_discriminates(
                    scope_origins, session.form_factor, derived_landing, probe_selector
                ):
                    probe_selector = None

            worker = self.workers.get(session.worker_id or "")
            if worker is None or worker.closed:
                raise ConflictError("worker is not available")
            # Export cookies only whenever the STORED result is cookies_only — requested now, or the
            # mode of the jar being refreshed (a cookies_only jar can never widen to "all", so its
            # export is always cookies-only). This also avoids materializing localStorage/IndexedDB
            # for an invalid cookies_only->all widening that JarStore will reject anyway.
            cookies_only_export = req.storage == "cookies_only" or (
                existing is not None and existing.storage_mode == "cookies_only"
            )
            try:
                raw = await worker.export_storage_state(self.jar_store.max_bytes, cookies_only=cookies_only_export)
            except StorageTooLarge as exc:
                raise ConflictError(str(exc)) from exc

            # Re-check revocation AFTER the export await: another process could have revoked the
            # backing jar while the (browser/IndexedDB) export was in flight, and publishing a
            # refreshed higher generation now would undo that kill-switch.
            await self._enforce_jar_not_revoked_locked(session)

            # The generation this live session was seeded from / produced for req.jar_id. Passed as a
            # revoke precondition so JarStore, under its ops lock, rejects the refresh if that
            # generation was revoked in the window between the recheck above and the store's lock —
            # closing the multi-pod refresh-vs-revoke race with stale browser state. A jarless
            # re-login (no captured generation) leaves it None and may legitimately re-enable a jar.
            revoke_precondition: int | None = None
            if req.jar_id is not None:
                if session.jar_id == req.jar_id:
                    revoke_precondition = session.jar_generation
                elif req.jar_id in session.produced_jar_generations:
                    revoke_precondition = session.produced_jar_generations[req.jar_id]

            meta = self.jar_store.save(
                jar_id=req.jar_id,
                label=req.label,
                origins=origins,
                # Agent-supplied nav_allowlist is untrusted: it widens the confinement boundary, so
                # a prompt-injected page could add an attacker sibling origin and later exfiltrate
                # domain-scoped (Domain=.example.com) cookies to it. For an agent, drop it entirely
                # (None => a refresh preserves the trusted stored allowlist; a new jar gets none).
                # For a human/FA save, pass None (omitted) vs [] (explicit) through so a refresh can
                # distinguish "keep the stored allowlist" from "narrow it to no extra origins".
                nav_allowlist=(
                    None if actor == "agent" else (list(req.nav_allowlist) if req.nav_allowlist is not None else None)
                ),
                storage_mode=req.storage,
                raw_storage_state=raw,
                probe_spec_url=probe_url,
                probe_selector=probe_selector,
                # Agent-supplied logged_out_url_prefix is untrusted like the probe url/selector: a
                # prompt-injected page could set it to the landing origin so every future probe reads
                # "stale" before the selector check. Drop it for an agent; only human/FA saves set it.
                probe_logged_out_prefix=(None if actor == "agent" else req.probe.logged_out_url_prefix),
                saved_by=saved_by,
                # New jar => attribute to the authorized owner. Refresh => pass None so JarStore
                # preserves the *target jar's* stored owner; an agent (whose refresh auth is
                # unconditional) must not be able to reassign another human's jar to this session's
                # owner just by refreshing it.
                owner_subject=owner_subject if existing is None else None,
                form_factor=session.form_factor,
                created_session_id=session.session_id,
                conversation_id=session.conversation_id,
                agent_supplied_probe=False,
                revoke_precondition=revoke_precondition,
            )
            # Provenance only: a set, because one session can produce several jars, and the
            # producing context holds the *unfiltered* login state (never tagged with jar_id).
            session.produced_jar_ids.add(meta.jar_id)
            session.produced_jar_generations[meta.jar_id] = meta.generation
            # A jar-loaded session that just refreshed ITS OWN jar has published a new generation
            # and tombstoned the one it was seeded from. Advance the loaded generation (and scope)
            # to the new one, or the very next kill-switch check would see the now-superseded
            # loaded generation as revoked and cancel the session right after a successful refresh.
            if session.jar_id == meta.jar_id:
                session.jar_generation = meta.generation
                session.jar_origins = list(meta.origins)
                session.jar_nav_allowlist = list(meta.nav_allowlist)
                session.jar_registrable_domains = list(meta.registrable_domains)
                # Apply the (possibly NARROWED) scope to the live worker's route guard too, so the
                # running context stops trusting origins the refreshed jar dropped — otherwise the
                # worker would still allow the wider create-time scope while policy readers see the
                # narrowed one. Only for a confined session (a human-driven one runs unconfined).
                if session.confine_navigation and worker is not None and not worker.closed:
                    worker.set_confine_origins([*meta.origins, *meta.nav_allowlist])
                    # The route guard only gates future navigations, so also evict the CURRENT page
                    # if the narrowing dropped its origin — otherwise snapshot/extract/click could
                    # still read the off-scope document that policy readers now consider out of scope.
                    await worker.evict_off_scope_page()
            session.updated_at = now_utc()
            self._event(
                session,
                "jar_saved",
                actor,
                metadata={"jar_id": meta.jar_id, "origins": meta.origins, "refresh": req.jar_id is not None},
            )
            return meta

    async def _selector_discriminates(self, origins: list[str], form_factor: str, url: str, selector: str) -> bool:
        """True iff ``selector`` is ABSENT on the target when logged out (so its presence is a
        real authenticated-only signal). Loads the landing page in a throwaway context with NO
        jar seeded; if the selector is already present logged-out (or the baseline cannot be
        established) it does not discriminate and must not be trusted as proof of freshness."""
        profile = form_factor_profile(form_factor)
        worker = make_worker(
            "baseline_probe",
            width=profile.width,
            height=profile.height,
            user_agent=profile.user_agent,
            confine_origins=[o for o in (normalize_origin(x) for x in origins) if o],
        )
        try:
            await worker.start()
        except RuntimeUnavailable:
            return False
        try:
            nav = await worker.command(AgentCommandRequest(type="navigate", args={"url": url}))
            if nav.get("blocked") or nav.get("error"):
                # No baseline could be established (off-scope block, or an in-scope DNS/TLS/outage
                # error): the selector must NOT be trusted as authenticated-only, or a prompt-injected
                # selector that is absent on a blank/failed page would later read a stale login "fresh".
                return False
            present_when_logged_out = await worker.selector_present(selector)
            if present_when_logged_out is None:
                # The selector could not be evaluated (malformed / transient): not a trustworthy
                # logged-out baseline, so it does not discriminate and must be dropped.
                return False
            return not present_when_logged_out
        except Exception:
            return False
        finally:
            await worker.close()

    def _authorize_save_locked(
        self, session: BrowserSession, req: SaveJarRequest, actor: str
    ) -> tuple[str | None, str]:
        if actor == "human":
            # Allowed in human_active AND human_sensitive: a careful user who marked the session
            # sensitive before typing credentials must still be able to click "Save this login".
            self._authorize_human_token_locked(session, req.token or "")
            if session.owner_subject is None:
                raise AuthorizationError("human save requires an authenticated owner subject")
            if self.jar_store.require_save_authorization and not self._valid_save_authorization(req.save_authorization):
                raise AuthorizationError("an FA save authorization is required for this deployment")
            return session.owner_subject, "human"
        # Agent save falls out of the existing agent-command authorization. Attribute a NEW jar to
        # the session's owner when one exists (a human-created session handed to the agent), so the
        # human can still see and forget a login captured from their own session. The subject is
        # the authenticated one captured at session create/claim — an agent cannot forge it. (On a
        # *refresh* the caller preserves the target jar's stored owner instead; see save().)
        if session.state not in AGENT_COMMAND_STATES or session.lease_owner != LeaseOwner.AGENT:
            raise AuthorizationError("agent save is denied unless the agent owns the lease")
        return session.owner_subject, "agent"

    def _authorize_jar_refresh(
        self, session: BrowserSession, existing: CookieJarMeta, actor: str, owner_subject: str | None
    ) -> None:
        """Refreshing overwrites durable credentials, so it needs ownership of the *target* jar,
        not just control of the live source session. A human may refresh only a jar whose
        owner_subject non-null-equals theirs (None == None is not ownership — ownerless jars are
        service/FA-only). An agent may refresh ONLY the jar currently loaded into its own session:
        a jarless (or differently-loaded) agent session refreshing an arbitrary jar_id is a
        prompt-injection vector — it would filter the live browser state into the victim's jar scope
        and tombstone their generation, emptying or replacing their saved login."""
        if actor == "agent":
            if session.jar_id is None or session.jar_id != existing.jar_id:
                raise AuthorizationError("an agent may only refresh the jar loaded into its own session")
            return
        if existing.owner_subject is None or owner_subject is None or existing.owner_subject != owner_subject:
            raise AuthorizationError("refresh requires ownership of the target jar")

    def _valid_save_authorization(self, token: str | None) -> bool:
        import os

        # A DEDICATED save-authorization secret, deliberately NOT the service bearer: whoever must
        # present this to authorize a human save (e.g. the FA relaying it to the browser) should
        # not thereby gain the full agent/service API (list/load/delete jars). When the gate is
        # enabled but this secret is unset, fail closed rather than fall back to the service token.
        expected = os.environ.get("BROWSER_JAR_SAVE_AUTHORIZATION_TOKEN")
        return bool(token) and bool(expected) and token == expected

    async def _worker_current_origin(self, session: BrowserSession) -> str | None:
        """Resolve the live page's origin server-side (never returned to the agent).

        For a human save the registry only updates current_origin from *agent* command results,
        which never run while the human browses, so read it from the live page instead."""
        worker = self.workers.get(session.worker_id or "")
        if worker is None or worker.closed:
            return session.current_origin
        try:
            result = await worker.command(AgentCommandRequest(type="current_page"))
        except Exception:
            return session.current_origin
        url = result.get("url")
        return redact_url(url)[1] if isinstance(url, str) else session.current_origin

    def list_jars(self) -> list[CookieJarMeta]:
        self._require_jars_enabled()
        return self.jar_store.list_meta()

    def get_jar(self, jar_id: str) -> CookieJarMeta:
        self._require_jars_enabled()
        return self.jar_store.get_meta_verified(jar_id)

    def get_jar_unverified(self, jar_id: str) -> CookieJarMeta:
        """Cleartext metadata without decrypting the blob. Used by service-token management so a
        jar under a rotated/removed key (which can no longer be decrypted) stays deletable."""
        self._require_jars_enabled()
        return self.jar_store.get_meta_unverified(jar_id)

    async def invalidate_jar(self, jar_id: str, *, actor: str = "service") -> CookieJarMeta:
        self._require_jars_enabled()
        async with self._jar_lock(jar_id):
            meta = self.jar_store.invalidate(jar_id, actor=actor)
            await self._close_sessions_for_jar(jar_id, reason="jar_invalidated")
            return meta

    async def delete_jar(self, jar_id: str, *, actor: str = "service") -> CookieJarMeta:
        self._require_jars_enabled()
        async with self._jar_lock(jar_id):
            meta = self.jar_store.delete(jar_id, actor=actor)
            await self._close_sessions_for_jar(jar_id, reason="jar_deleted")
            return meta

    async def _enforce_jar_not_revoked_locked(self, session: BrowserSession) -> None:
        """If a jar backing this session was revoked (possibly by another process), close the
        session and its worker and raise. Called from every path that keeps an authenticated
        context alive — agent commands AND noVNC/human-control authorization — so the kill-switch
        also tears down a live human-driven browser, not just future loads."""
        if session.state in TERMINAL_STATES:
            return
        revoked = self._revoked_jar_for(session)
        if revoked is not None:
            session.lease_owner = LeaseOwner.NONE
            session.state = SessionState.CANCELLED
            await self._cleanup_locked(session)
            session.updated_at = now_utc()
            self._event(session, "session_closed", "service", metadata={"reason": "jar_revoked", "jar_id": revoked})
            raise SessionInactiveError("the jar backing this session was revoked")

    def session_jar_revoked(self, session_id: str) -> bool:
        """Whether a jar backing this session has been revoked (possibly by another process).
        Used to poll during a long-lived noVNC bridge, where no per-command recheck runs."""
        session = self.sessions.get(session_id)
        if session is None or session.state in TERMINAL_STATES:
            return False
        return self._revoked_jar_for(session) is not None

    def _revoked_jar_for(self, session: BrowserSession) -> str | None:
        """Return a jar id backing ``session`` whose *seeded* generation is now revoked
        (invalidated/deleted), consulting the shared durable tombstone — or None. Compares the
        authenticated generation captured at load/produce time, so a later higher-generation
        re-login cannot mask that the running context's own generation was tombstoned. Covers both
        a jar-loaded session and one that produced a jar (which holds the unfiltered login state)."""
        if not self.jar_store.enabled:
            return None
        # Both a produced (source) jar and the loaded jar back a live authenticated context that the
        # kill-switch must be able to tear down. Fail closed on a tombstone of the captured/seeded
        # generation, and also when the current file no longer authenticates (removed, corrupted, or
        # AAD-tampered without a tombstone) — a shared-volume writer must not keep either context
        # alive past its kill-switch by mangling the file.
        for jar_id, generation in session.produced_jar_generations.items():
            if self.jar_store.is_revoked_generation(jar_id, generation) or not self.jar_store.jar_authenticates(jar_id):
                return jar_id
        if session.jar_id is not None:
            if self.jar_store.is_revoked_generation(
                session.jar_id, session.jar_generation
            ) or not self.jar_store.jar_authenticates(session.jar_id):
                return session.jar_id
        return None

    async def _close_sessions_for_jar(self, jar_id: str, *, reason: str) -> None:
        """Revocation is the user's real-time kill-switch: close every live session seeded from
        the jar (jar_id matches) AND any source session that produced it (jar_id in
        produced_jar_ids), so no live authenticated context survives the revoke."""
        for session_id, session in list(self.sessions.items()):
            if session.state in TERMINAL_STATES:
                continue
            if session.jar_id != jar_id and jar_id not in session.produced_jar_ids:
                continue
            async with self.locks[session_id]:
                if session.state in TERMINAL_STATES:
                    continue
                session.lease_owner = LeaseOwner.NONE
                session.state = SessionState.CANCELLED
                await self._cleanup_locked(session)
                session.updated_at = now_utc()
                self._event(session, "session_closed", "service", metadata={"reason": reason, "jar_id": jar_id})

    async def probe_jar(self, jar_id: str) -> ProbeResult:
        """Load the jar into a throwaway context using its recorded form factor, navigate to the
        probe target under the same exact-origin guard as a jar-loaded session, apply the
        success indicator, and tear the context down. Never returns page content. Rate-limited."""
        self._require_jars_enabled()
        # Hold the jar lock only for the load + DURABLE reservation, then release it before the
        # network probe (browser startup + navigation) so a concurrent DELETE/invalidate — the
        # real-time kill-switch — is not blocked behind a slow probe target. reserve_probe stamps
        # last_probe_at under the cross-process ops lock BEFORE the probe runs, so another pod
        # sharing the volume sees the rate-limit and will not run a duplicate authenticated probe.
        async with self._jar_lock(jar_id):
            loaded = self.jar_store.load(jar_id)  # raises if invalidated/revoked/disabled
            if not self.jar_store.reserve_probe(jar_id, loaded.meta.generation):
                raise ConflictError("probe is rate-limited or already in progress; try again later")
        result, final_origin = await self._run_probe(loaded)
        # If the jar was revoked/deleted while the probe ran, skip persisting a stale result. Pass
        # the probed generation so record_probe drops the result if a refresh published a newer
        # generation in the meantime (the old probe must not stamp the fresh login).
        if not self.jar_store.is_revoked_generation(jar_id, loaded.meta.generation):
            self.jar_store.record_probe(jar_id, result, expected_generation=loaded.meta.generation)
        return ProbeResult(result=result, final_origin=final_origin)

    async def _run_probe(self, loaded) -> tuple[ProbeResultName, str | None]:
        return await self._probe_candidate(
            loaded.storage_state,
            loaded.meta.form_factor,
            [*loaded.meta.origins, *loaded.meta.nav_allowlist],
            loaded.probe,
            label=f"probe_{loaded.meta.jar_id}",
        )

    async def _probe_candidate(
        self,
        storage_state: dict[str, Any],
        form_factor: str,
        confine_origins: list[str],
        probe: JarProbeConfig,
        *,
        label: str,
    ) -> tuple[ProbeResultName, str | None]:
        """Seed ``storage_state`` into a throwaway context under the jar's form factor and exact-origin
        confinement, navigate to the probe target, and classify freshness. Shared by the jar freshness
        probe and the save-time verification of a just-captured candidate. Never returns page content."""
        profile = form_factor_profile(form_factor)
        worker = make_worker(
            label,
            width=profile.width,
            height=profile.height,
            user_agent=profile.user_agent,
            storage_state=storage_state,
            confine_origins=confine_origins,
        )
        try:
            await worker.start()
        except RuntimeUnavailable:
            return "error", None
        try:
            if not probe.url:
                # A signal-less / target-less probe can never prove logged-in state.
                return "uncertain", None
            nav = await worker.command(AgentCommandRequest(type="navigate", args={"url": probe.url}))
            if nav.get("error"):
                # An in-scope network failure (DNS/TLS/connection outage of the saved site): not a
                # login-state signal, so do not mark a possibly-valid jar stale.
                return "error", None
            if nav.get("blocked"):
                # An off-scope redirect toward login/IdP was aborted pre-request: classify stale.
                return "stale", nav.get("target_origin")
            final_url = nav.get("url")
            final_origin = redact_url(final_url)[1] if isinstance(final_url, str) else None
            if (
                probe.logged_out_url_prefix
                and isinstance(final_url, str)
                and final_url.startswith(probe.logged_out_url_prefix)
            ):
                return "stale", final_origin
            if probe.logged_in_selector:
                present = await worker.selector_present(probe.logged_in_selector)
                if present is None:
                    # Selector evaluation failed (malformed / transient after navigation): not a
                    # login-state signal, so do not mark a possibly-valid login "stale".
                    return "error", final_origin
                return ("fresh" if present else "stale"), final_origin
            # In scope, no authenticated-only signal: cannot prove logged-in — never "fresh".
            return "uncertain", final_origin
        except Exception:
            return "error", None
        finally:
            await worker.close()

    async def reap_expired(self) -> list[str]:
        expired: list[str] = []
        for session_id, session in list(self.sessions.items()):
            async with self.locks[session_id]:
                if session.state not in TERMINAL_STATES and (
                    session.idle_expires_at <= now_utc() or session.expires_at <= now_utc()
                ):
                    session.state = SessionState.EXPIRED
                    session.lease_owner = LeaseOwner.NONE
                    await self._cleanup_locked(session)
                    session.updated_at = now_utc()
                    self._event(session, "session_expired", "service")
                    expired.append(session_id)
        return expired

    async def _cleanup_locked(self, session: BrowserSession) -> None:
        if session.cleanup_started_at is None:
            session.cleanup_started_at = now_utc()
        for record in self.tokens.values():
            if record.session_id == session.session_id and record.consumed_at is None:
                record.consumed_at = now_utc()
        worker = self.workers.get(session.worker_id or "")
        if worker is not None:
            await worker.close()
        session.closed_at = session.closed_at or now_utc()
        session.cleanup_completed_at = session.cleanup_completed_at or now_utc()

    async def _sanitize_for_resume_locked(self, session: BrowserSession) -> None:
        worker = self.workers.get(session.worker_id or "")
        if worker is None or worker.closed:
            session.lease_owner = LeaseOwner.NONE
            session.state = SessionState.FAILED
            session.updated_at = now_utc()
            self._event(session, "sanitize_failed", "service", metadata={"reason": "missing_worker"})
            raise ConflictError("worker is not available for sanitization")
        await worker.command(AgentCommandRequest(type="close_page"))
        session.current_origin = None
        session.current_url_redacted = None
        session.current_title_redacted = None
        self._event(session, "browser_sanitized", "service")

    async def _reopen_confined_page_locked(self, session: BrowserSession) -> None:
        """Open a fresh page inside the confinement set after sanitization.

        The agent navigates for itself anyway, so a site that is down leaves the page at
        about:blank rather than wedging the handback — a visible, ordinary starting state, not a
        swallowed error."""
        if not session.confine_origins:
            return
        worker = self.workers.get(session.worker_id or "")
        if worker is None or worker.closed:
            return
        result = await worker.command(AgentCommandRequest(type="navigate", args={"url": session.confine_origins[0]}))
        if result.get("blocked") or result.get("error"):
            self._event(session, "resume_page_unavailable", "service", metadata={"reason": "navigation_failed"})
            return
        self._update_page_metadata(session, result)

    def _update_page_metadata(self, session: BrowserSession, result: dict[str, Any]) -> None:
        url = result.get("url")
        session.current_url_redacted = url if isinstance(url, str) else None
        session.current_origin = redact_url(url)[1] if isinstance(url, str) else None
        if "title" in result:
            title = result.get("title")
            session.current_title_redacted = title if isinstance(title, str) else None

    def _raise_if_expired(self, session: BrowserSession) -> None:
        if session.state not in TERMINAL_STATES and (
            session.idle_expires_at <= now_utc() or session.expires_at <= now_utc()
        ):
            raise SessionInactiveError("session has expired")

    def _authorize_human_token_locked(self, session: BrowserSession, token: str, allow_pending: bool = False) -> None:
        allowed_states = {SessionState.HUMAN_ACTIVE, SessionState.HUMAN_SENSITIVE}
        if allow_pending:
            # While a handoff is pending the human authorizes with the one-time handoff token;
            # while a handover is pending they still hold their (unconsumed) control token.
            allowed_states.add(SessionState.HANDOFF_REQUESTED)
            allowed_states.add(SessionState.HANDOVER_REQUESTED)
        if session.state not in allowed_states:
            raise AuthorizationError("session is not human-controlled")
        token_type = "handoff" if allow_pending and session.state == SessionState.HANDOFF_REQUESTED else "control"
        self._authorize_token_locked(session, token, token_type=token_type)

    def _revoke_session_tokens_locked(self, session: BrowserSession, token_type: str) -> None:
        for record in self.tokens.values():
            if (
                record.session_id == session.session_id
                and record.token_type == token_type
                and record.consumed_at is None
            ):
                record.consumed_at = now_utc()

    def _authorize_token_locked(
        self, session: BrowserSession, token: str, token_type: str | None = None
    ) -> TokenRecord:
        record = self.tokens.get(hash_token(token))
        if record is None or record.session_id != session.session_id:
            raise AuthorizationError("invalid token")
        if token_type is not None and record.token_type != token_type:
            raise AuthorizationError("invalid token")
        if record.consumed_at is not None or record.expires_at <= now_utc():
            raise AuthorizationError("expired or revoked token")
        return record

    def _event(
        self,
        session: BrowserSession,
        event_type: str,
        actor_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.events.setdefault(session.session_id, []).append(
            SessionEvent(
                event_id=f"evt_{uuid4().hex}",
                session_id=session.session_id,
                event_type=event_type,
                actor_type=actor_type,
                metadata=metadata or {},
                created_at=now_utc(),
            )
        )


def _normalize_origin(origin: str) -> str | None:
    from urllib.parse import urlsplit

    parsed = urlsplit(origin)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"
