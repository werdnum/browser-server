from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl


def now_utc() -> datetime:
    return datetime.now(UTC)


FormFactorName = Literal["mobile", "desktop"]

# Default new sessions to a mobile-friendly portrait aspect ratio.
DEFAULT_FORM_FACTOR: FormFactorName = "mobile"

# Modern Chrome-on-Android user agent so sites serve their mobile layout.
MOBILE_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
)


@dataclass(frozen=True)
class FormFactor:
    """Display profile for a session: framebuffer size and optional emulation UA."""

    width: int
    height: int
    user_agent: str | None = None


FORM_FACTORS: dict[str, FormFactor] = {
    # Portrait phone (Pixel 7 logical viewport).
    "mobile": FormFactor(width=412, height=915, user_agent=MOBILE_USER_AGENT),
    # Landscape desktop.
    "desktop": FormFactor(width=1280, height=720, user_agent=None),
}


def form_factor_profile(name: str) -> FormFactor:
    """Resolve a form factor name to its display profile, falling back to the default."""
    return FORM_FACTORS.get(name, FORM_FACTORS[DEFAULT_FORM_FACTOR])


class SessionState(StrEnum):
    AGENT_ACTIVE = "agent_active"
    HANDOFF_REQUESTED = "handoff_requested"
    HANDOVER_REQUESTED = "handover_requested"
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
    initial_owner: Literal["agent", "human"] = "agent"
    form_factor: FormFactorName = DEFAULT_FORM_FACTOR


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


class HandoverRequest(BaseModel):
    token: str
    handoff_note: str = Field(default="", max_length=1000)


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
    form_factor: str = DEFAULT_FORM_FACTOR
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
    human_first = req.initial_owner == "human"
    return BrowserSession(
        session_id=f"bs_{uuid4().hex}",
        conversation_id=req.conversation_id,
        interface_type=req.interface_type,
        form_factor=req.form_factor,
        state=SessionState.HUMAN_ACTIVE if human_first else SessionState.AGENT_ACTIVE,
        lease_owner=LeaseOwner.HUMAN if human_first else LeaseOwner.AGENT,
        worker_id=f"worker_{uuid4().hex}",
        created_at=created,
        updated_at=created,
        idle_expires_at=created + timedelta(minutes=15),
        expires_at=created + timedelta(minutes=60),
    )
