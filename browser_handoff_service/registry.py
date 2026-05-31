from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import uuid4

from .models import (
    AGENT_COMMAND_STATES,
    OBSERVATION_COMMANDS,
    TERMINAL_STATES,
    AgentCommandRequest,
    AgentCommandResponse,
    BrowserSession,
    CreateSessionRequest,
    HandoffRequest,
    LeaseOwner,
    SessionEvent,
    SessionState,
    form_factor_profile,
    new_session,
    now_utc,
)
from .runtime import BrowserRuntime, RuntimeUnavailable, make_worker
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
    def __init__(self) -> None:
        self.sessions: dict[str, BrowserSession] = {}
        self.locks: dict[str, asyncio.Lock] = {}
        self.events: dict[str, list[SessionEvent]] = {}
        self.tokens: dict[str, TokenRecord] = {}
        self.workers: dict[str, BrowserRuntime] = {}

    def list_sessions(self) -> list[BrowserSession]:
        return sorted(self.sessions.values(), key=lambda item: item.created_at)

    async def create_session(self, req: CreateSessionRequest) -> tuple[BrowserSession, str | None]:
        session = new_session(req)
        self.sessions[session.session_id] = session
        self.locks[session.session_id] = asyncio.Lock()
        self.events[session.session_id] = []
        profile = form_factor_profile(session.form_factor)
        worker = make_worker(
            session.worker_id or "",
            width=profile.width,
            height=profile.height,
            user_agent=profile.user_agent,
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

    async def claim(self, session_id: str, token: str) -> tuple[BrowserSession, str]:
        session = self.get(session_id)
        async with self.locks[session_id]:
            self._raise_if_expired(session)
            handoff_token = self._authorize_token_locked(session, token, token_type="handoff")
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
