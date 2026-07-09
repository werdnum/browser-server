from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import uuid4

from .jars import (
    JarRevokedError,
    JarStore,
    jar_store_from_env,
    normalize_origin,
)
from .models import (
    AGENT_COMMAND_STATES,
    OBSERVATION_COMMANDS,
    TERMINAL_STATES,
    AgentCommandRequest,
    AgentCommandResponse,
    BrowserSession,
    CookieJarMeta,
    CreateSessionRequest,
    HandoffRequest,
    LeaseOwner,
    ProbeResult,
    ProbeResultName,
    SaveJarRequest,
    SessionEvent,
    SessionState,
    form_factor_profile,
    new_session,
    now_utc,
)
from .runtime import BrowserRuntime, RuntimeUnavailable, StorageTooLarge, make_worker
from .security import hash_token, mint_token, redact_url
from .transitions import transition


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

    def list_sessions(self) -> list[BrowserSession]:
        return sorted(self.sessions.values(), key=lambda item: item.created_at)

    def _jar_lock(self, jar_id: str) -> asyncio.Lock:
        return self.jar_locks.setdefault(jar_id, asyncio.Lock())

    async def create_session(
        self, req: CreateSessionRequest, *, owner_subject: str | None = None
    ) -> tuple[BrowserSession, str | None]:
        if req.jar_id is not None:
            # Serialize the whole jar-load create against revocation on the same jar.
            async with self._jar_lock(req.jar_id):
                return await self._create_session_locked(req, owner_subject=owner_subject)
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
        loaded = None
        if req.jar_id is not None:
            loaded = self.jar_store.load(req.jar_id)  # raises JarError on disabled/missing/revoked
            storage_state = loaded.storage_state
            # A jar load defaults to the producing session's form factor/UA unless the create
            # call explicitly overrode it (storage_state does not carry the device profile).
            if req.form_factor == "auto" and req.client_viewport is None:
                session.form_factor = loaded.meta.form_factor
            confine = req.confine_navigation if req.confine_navigation is not None else True
            if confine:
                confine_origins = [*loaded.meta.origins, *loaded.meta.nav_allowlist]
            session.jar_id = loaded.meta.jar_id
            session.jar_origins = list(loaded.meta.origins)
            session.jar_nav_allowlist = list(loaded.meta.nav_allowlist)
            session.jar_registrable_domains = list(loaded.meta.registrable_domains)
            session.allow_exec = req.allow_exec
            session.confine_navigation = confine

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
            # tear the just-created context down if it was revoked in the window.
            if not self.jar_store.recheck_loadable(req.jar_id or ""):
                session.state = SessionState.CANCELLED
                session.lease_owner = LeaseOwner.NONE
                await self._cleanup_locked(session)
                self._event(session, "session_closed", "service", metadata={"reason": "jar_revoked"})
                raise JarRevokedError("jar was revoked during load")
            self.jar_store.touch_loaded(req.jar_id or "")
            # Confinement gates only agent-driven navigation. If the jar is loaded straight into a
            # human-owned session (service token + initial_owner="human"), the human drives via
            # noVNC and the handoff toggle never runs, so disable confinement now — otherwise the
            # route guard would block the human's off-scope SSO/re-login navigation.
            if session.lease_owner == LeaseOwner.HUMAN:
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
            if session.jar_id is not None:
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

    async def handover(self, session_id: str, token: str, handoff_note: str) -> tuple[BrowserSession, str]:
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
            if session.jar_id is not None:
                raise ConflictError(
                    "a jar-loaded session cannot be handed to an agent; start a fresh jar-loaded session"
                )
            session.lease_owner = transition(session.state, session.lease_owner, SessionState.HANDOVER_REQUESTED)
            session.state = SessionState.HANDOVER_REQUESTED
            session.handoff_reason = None
            session.allowed_resume = "never"
            session.handoff_note = handoff_note
            session.idle_expires_at = min(now_utc() + timedelta(minutes=10), session.expires_at)
            session.updated_at = now_utc()
            handover_token = mint_token()
            self.tokens[hash_token(handover_token)] = TokenRecord(
                session_id=session_id,
                token_hash=hash_token(handover_token),
                token_type="handover",
                expires_at=session.idle_expires_at,
            )
            self._event(session, "handover_requested", "human")
            return session, handover_token

    async def agent_claim(self, session_id: str, token: str) -> BrowserSession:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            if session.state != SessionState.HANDOVER_REQUESTED:
                raise ConflictError("session is not awaiting an agent handover")
            handover_record = self._authorize_token_locked(session, token, token_type="handover")
            session.lease_owner = transition(session.state, session.lease_owner, SessionState.AGENT_ACTIVE)
            session.state = SessionState.AGENT_ACTIVE
            session.idle_expires_at = min(now_utc() + timedelta(minutes=15), session.expires_at)
            session.updated_at = now_utc()
            handover_record.consumed_at = now_utc()
            self._revoke_session_tokens_locked(session, token_type="control")
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
            # Per-command revocation recheck. In a multi-process deployment sharing the jar
            # directory, a revoke in another process cannot reach into this registry's in-memory
            # session set, so a jar-loaded (or jar-producing) session would keep serving an
            # authenticated context until it noticed. Consulting the shared, durable tombstone
            # before each command turns the kill-switch into a near-real-time, cross-process one.
            revoked = self._revoked_jar_for(session)
            if revoked is not None:
                session.lease_owner = LeaseOwner.NONE
                session.state = SessionState.CANCELLED
                await self._cleanup_locked(session)
                session.updated_at = now_utc()
                self._event(session, "session_closed", "service", metadata={"reason": "jar_revoked", "jar_id": revoked})
                raise SessionInactiveError("the jar backing this session was revoked")
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
            owner_subject, saved_by = self._authorize_save_locked(session, req, actor)

            # Cloning guard: a new-jar save from a jar-loaded session would snapshot the
            # credentials into a second, unlinked blob that revocation of the original never
            # reaches. A jar-loaded session may only refresh its own jar_id.
            if session.jar_id is not None and (req.jar_id is None or req.jar_id != session.jar_id):
                raise ConflictError("a jar-loaded session may only refresh its own jar")

            existing: CookieJarMeta | None = None
            if req.jar_id is not None:
                existing = self.jar_store.get_meta_verified(req.jar_id)
                self._authorize_jar_refresh(existing, actor, owner_subject)

            if existing is not None:
                # Refresh: re-filter against the STORED scope. An omitted `origins` must NOT
                # collapse a multi-origin jar to the live page's single origin — pass the
                # caller's (possibly empty) list through and let JarStore keep the stored scope.
                origins = list(req.origins) if req.origins else []
                scope_origins = origins or list(existing.origins)
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
            try:
                raw = await worker.export_storage_state(self.jar_store.max_bytes)
            except StorageTooLarge as exc:
                raise ConflictError(str(exc)) from exc

            meta = self.jar_store.save(
                jar_id=req.jar_id,
                label=req.label,
                origins=origins,
                # Pass None (omitted) vs [] (explicit) through so a refresh can distinguish
                # "keep the stored allowlist" from "narrow it to no extra origins".
                nav_allowlist=list(req.nav_allowlist) if req.nav_allowlist is not None else None,
                storage_mode=req.storage,
                raw_storage_state=raw,
                probe_spec_url=probe_url,
                probe_selector=probe_selector,
                probe_logged_out_prefix=req.probe.logged_out_url_prefix,
                saved_by=saved_by,
                owner_subject=owner_subject,
                form_factor=session.form_factor,
                created_session_id=session.session_id,
                conversation_id=session.conversation_id,
                agent_supplied_probe=False,
            )
            # Provenance only: a set, because one session can produce several jars, and the
            # producing context holds the *unfiltered* login state (never tagged with jar_id).
            session.produced_jar_ids.add(meta.jar_id)
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
            if nav.get("blocked"):
                return False
            present_when_logged_out = await worker.selector_present(selector)
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
        # Agent save falls out of the existing agent-command authorization.
        if session.state not in AGENT_COMMAND_STATES or session.lease_owner != LeaseOwner.AGENT:
            raise AuthorizationError("agent save is denied unless the agent owns the lease")
        return None, "agent"

    def _authorize_jar_refresh(self, existing: CookieJarMeta, actor: str, owner_subject: str | None) -> None:
        """Refreshing overwrites durable credentials, so it needs ownership of the *target* jar,
        not just control of the live source session. Service (FA) may refresh any jar; a human
        may refresh only a jar whose owner_subject non-null-equals theirs (None == None is not
        ownership — ownerless jars are service/FA-only)."""
        if actor == "agent":
            return
        if existing.owner_subject is None or owner_subject is None or existing.owner_subject != owner_subject:
            raise AuthorizationError("refresh requires ownership of the target jar")

    def _valid_save_authorization(self, token: str | None) -> bool:
        import os

        expected = os.environ.get("BROWSER_HANDOFF_SERVICE_TOKEN")
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

    def _revoked_jar_for(self, session: BrowserSession) -> str | None:
        """Return a jar id backing ``session`` that is now revoked (invalidated/deleted/rolled
        back), consulting the shared durable tombstone — or None. Covers both a jar-loaded
        session and one that produced a jar (which holds the unfiltered login state)."""
        if not self.jar_store.enabled:
            return None
        candidates = list(session.produced_jar_ids)
        if session.jar_id is not None:
            candidates.append(session.jar_id)
        for jar_id in candidates:
            if not self.jar_store.recheck_loadable(jar_id):
                return jar_id
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
        async with self._jar_lock(jar_id):
            loaded = self.jar_store.load(jar_id)  # raises if invalidated/revoked/disabled
            next_allowed = self.jar_store.probe_allowed_at(loaded.meta)
            if next_allowed is not None:
                raise ConflictError("probe is rate-limited; try again later")
            result, final_origin = await self._run_probe(loaded)
            self.jar_store.record_probe(jar_id, result)
            return ProbeResult(result=result, final_origin=final_origin)

    async def _run_probe(self, loaded) -> tuple[ProbeResultName, str | None]:
        probe = loaded.probe
        profile = form_factor_profile(loaded.meta.form_factor)
        confine = [*loaded.meta.origins, *loaded.meta.nav_allowlist]
        worker = make_worker(
            f"probe_{loaded.meta.jar_id}",
            width=profile.width,
            height=profile.height,
            user_agent=profile.user_agent,
            storage_state=loaded.storage_state,
            confine_origins=confine,
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
