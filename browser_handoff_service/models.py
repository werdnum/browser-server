from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl


def now_utc() -> datetime:
    return datetime.now(UTC)


class SessionState(StrEnum):
    AGENT_ACTIVE = "agent_active"
    HANDOFF_REQUESTED = "handoff_requested"
    HUMAN_ACTIVE = "human_active"
    HUMAN_SENSITIVE = "human_sensitive"
    SANITIZE_PENDING = "sanitize_pending"
    AGENT_RESUMABLE = "agent_resumable"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    FAILED = "failed"


class LeaseOwner(StrEnum):
    AGENT = "agent"
    HUMAN = "human"
    SERVICE = "service"
    NONE = "none"


TERMINAL_STATES = {
    SessionState.COMPLETED,
    SessionState.CANCELLED,
    SessionState.EXPIRED,
    SessionState.FAILED,
}

AGENT_COMMAND_STATES = {SessionState.AGENT_ACTIVE, SessionState.AGENT_RESUMABLE}
OBSERVATION_COMMANDS = {"snapshot", "screenshot", "current_page"}


class CreateSessionRequest(BaseModel):
    conversation_id: str = Field(min_length=1)
    interface_type: str = "research"


class HandoffRequest(BaseModel):
    reason: Literal["payment", "credentials", "otp", "legal_consent", "captcha", "cookie_consent", "other"]
    handoff_note: str = Field(default="", max_length=1000)
    expected_origin: str | None = None
    allowed_resume: Literal["never", "after_sanitize"] = "never"


class AgentCommandRequest(BaseModel):
    command_id: str = Field(default_factory=lambda: f"cmd_{uuid4().hex}")
    type: Literal[
        "navigate",
        "click",
        "type_text",
        "select",
        "press_key",
        "snapshot",
        "screenshot",
        "current_page",
        "close_page",
    ]
    args: dict[str, Any] = Field(default_factory=dict)


class ClaimRequest(BaseModel):
    token: str


class HumanActionRequest(BaseModel):
    token: str
    outcome: str | None = None


class ExtendRequest(BaseModel):
    token: str
    minutes: int = Field(default=5, ge=1, le=10)


class BrowserSession(BaseModel):
    session_id: str
    conversation_id: str
    interface_type: str
    state: SessionState
    lease_owner: LeaseOwner
    worker_id: str | None = None
    current_origin: str | None = None
    current_url_redacted: str | None = None
    current_title_redacted: str | None = None
    handoff_reason: str | None = None
    allowed_resume: str = "never"
    handoff_note: str = ""
    sensitive_since: datetime | None = None
    created_at: datetime
    updated_at: datetime
    idle_expires_at: datetime
    expires_at: datetime
    cleanup_started_at: datetime | None = None
    cleanup_completed_at: datetime | None = None
    closed_at: datetime | None = None


class SessionEvent(BaseModel):
    event_id: str
    session_id: str
    event_type: str
    actor_type: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class HandoffResponse(BaseModel):
    session_id: str
    state: SessionState
    handoff_url: HttpUrl
    expires_at: datetime


class AgentCommandResponse(BaseModel):
    command_id: str
    ok: bool
    result: dict[str, Any] = Field(default_factory=dict)


def new_session(req: CreateSessionRequest) -> BrowserSession:
    created = now_utc()
    return BrowserSession(
        session_id=f"bs_{uuid4().hex}",
        conversation_id=req.conversation_id,
        interface_type=req.interface_type,
        state=SessionState.AGENT_ACTIVE,
        lease_owner=LeaseOwner.AGENT,
        worker_id=f"worker_{uuid4().hex}",
        created_at=created,
        updated_at=created,
        idle_expires_at=created + timedelta(minutes=15),
        expires_at=created + timedelta(minutes=60),
    )
