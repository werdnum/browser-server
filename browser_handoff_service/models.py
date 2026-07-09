from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl, StringConstraints

# A single origin/allowlist string, length-bounded so a save cannot inflate the cleartext jar
# metadata (which is not covered by the storage/probe byte caps) with megabyte-long entries.
BoundedOriginStr = Annotated[str, StringConstraints(max_length=2048)]
# Max distinct origins / nav_allowlist entries a jar may declare — generous for real multi-origin
# logins, but a hard bound so a caller cannot submit thousands and write an oversized jar file.
MAX_ORIGINS = 64


def now_utc() -> datetime:
    return datetime.now(UTC)


FormFactorName = Literal["mobile", "desktop"]

# Requested form factor: a concrete profile, or "auto" to detect from the client.
RequestedFormFactor = Literal["mobile", "desktop", "auto"]

# Fallback when the form factor is "auto" and no client aspect ratio is available
# (e.g. agent-created sessions with no browser to measure).
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


class ClientViewport(BaseModel):
    """The aspect ratio of the client device, as measured in the browser."""

    width: int = Field(gt=0)
    height: int = Field(gt=0)


def form_factor_for_aspect_ratio(width: int, height: int) -> FormFactorName:
    """Pick a form factor from a client's aspect ratio: portrait -> mobile, landscape -> desktop."""
    return "mobile" if height >= width else "desktop"


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
# Commands that read page content/state. Denied outside agent-owned states so a
# human-controlled session can never be observed by the agent.
OBSERVATION_COMMANDS = {"snapshot", "screenshot", "current_page", "extract", "exec"}


class CreateSessionRequest(BaseModel):
    conversation_id: str = Field(min_length=1)
    interface_type: str = "research"
    initial_owner: Literal["agent", "human"] = "agent"
    # "auto" detects the form factor from client_viewport (the browser UI sends this);
    # an explicit "mobile"/"desktop" always wins.
    form_factor: RequestedFormFactor = "auto"
    client_viewport: ClientViewport | None = None
    # Cookie-jar load (service-token-only; rejected for direct OIDC humans). When set,
    # the worker context is seeded from the jar at creation, exec is default-denied, and
    # navigation is confined to the jar's origins unless the caller opts out.
    jar_id: str | None = None
    allow_exec: bool = False
    # None => default (confine when a jar is loaded); an explicit bool always wins.
    confine_navigation: bool | None = None

    def resolved_form_factor(self) -> FormFactorName:
        if self.form_factor != "auto":
            return self.form_factor
        if self.client_viewport is not None:
            return form_factor_for_aspect_ratio(self.client_viewport.width, self.client_viewport.height)
        return DEFAULT_FORM_FACTOR


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
        "extract",
        "exec",
        "wait",
        "mouse_click",
        "mouse_move",
        "mouse_down",
        "mouse_up",
        "mouse_wheel",
        "keyboard_type",
        "keyboard_press",
        "navigate_back",
        "navigate_forward",
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
    # OIDC subject that owns a human-controlled session. Set when a human-owned session
    # is created and captured on the handoff-claim path so a later human save-jar can
    # record a non-null owner_subject (there is no OIDC bearer on the control-token call).
    owner_subject: str | None = None
    # Cookie-jar provenance and authenticated scope. jar_* fields are set only for a
    # jar-*loaded* session (its authentication scope is immutable for its whole lifetime);
    # produced_jar_ids tracks jars this session *saved* (a source session holds the full,
    # unfiltered login state and is deliberately NOT tagged with the jar's narrow scope).
    jar_id: str | None = None
    # The authenticated generation seeded into a jar-loaded session, captured at load. Live-session
    # kill-switch checks compare THIS immutable generation to the tombstone, so a later re-login
    # publishing a higher generation cannot keep an old, revoked context running.
    jar_generation: int | None = None
    jar_origins: list[str] | None = None
    jar_nav_allowlist: list[str] | None = None
    jar_registrable_domains: list[str] | None = None
    # Effective safety flags persisted at create time so later commands and policy readers
    # (which only see the session record) can tell an opt-in apart from the default.
    allow_exec: bool = False
    confine_navigation: bool = False
    produced_jar_ids: set[str] = Field(default_factory=set)
    # jar_id -> authenticated generation this session produced, for the same generation-scoped
    # kill-switch check on a producing (source) session as on a jar-loaded one.
    produced_jar_generations: dict[str, int] = Field(default_factory=dict)
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


StorageMode = Literal["all", "cookies_only"]
ProbeResultName = Literal["fresh", "stale", "uncertain", "error"]


class JarProbeConfig(BaseModel):
    """Freshness-probe config. Stored *inside* the encrypted blob, never in listable metadata:
    the selector can carry user-/page-influenced text and the urls are sensitive."""

    # scheme+host+port+path only (query/fragment/userinfo stripped on save).
    url: str = Field(max_length=2048)
    # A signal-less probe (both None) is allowed and always resolves to "uncertain".
    logged_in_selector: str | None = Field(default=None, max_length=2048)
    logged_out_url_prefix: str | None = Field(default=None, max_length=2048)


class CookieJarMeta(BaseModel):
    """Cleartext, listable jar metadata: counts and aggregates only — no cookie/storage
    names or values, and no probe internals."""

    jar_id: str
    label: str
    origins: list[str]
    nav_allowlist: list[str] = Field(default_factory=list)
    registrable_domains: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    last_loaded_at: datetime | None = None
    version: int = 1
    # Monotonic; bound in the authenticated envelope. A revocation tombstone rejects any
    # load/probe whose generation is <= the tombstoned generation (rollback-proof kill-switch).
    generation: int = 1
    saved_by: Literal["agent", "human"]
    owner_subject: str | None = None
    form_factor: str = DEFAULT_FORM_FACTOR
    storage_mode: StorageMode = "all"
    created_session_id: str
    conversation_id: str
    cookie_count: int = 0
    origin_storage_count: int = 0
    earliest_cookie_expiry: datetime | None = None
    session_cookies_only: bool = False
    contains_session_cookies: bool = False
    has_probe: bool = True
    last_probe_at: datetime | None = None
    last_probe_result: ProbeResultName | None = None
    invalidated_at: datetime | None = None


class ProbeSpec(BaseModel):
    """Caller-supplied probe on a save request. ``url`` is optional: for an agent save the
    server derives a stable landing page (the agent may only supply the selector)."""

    # Bounded so a control-token save cannot inflate the sealed jar payload past the byte cap.
    url: str | None = Field(default=None, max_length=2048)
    logged_in_selector: str | None = Field(default=None, max_length=2048)
    logged_out_url_prefix: str | None = Field(default=None, max_length=2048)


class SaveJarRequest(BaseModel):
    label: str = Field(min_length=1, max_length=500)
    # None => create a new jar; a jar_id refreshes that jar in place (version/generation bump).
    jar_id: str | None = None
    origins: list[BoundedOriginStr] | None = Field(default=None, max_length=MAX_ORIGINS)
    nav_allowlist: list[BoundedOriginStr] | None = Field(default=None, max_length=MAX_ORIGINS)
    storage: StorageMode | None = None
    # A probe is required on every save (create and refresh); the server can always derive a
    # default (selector on a stable page), so this is "server default is producible", not
    # "caller must know CSS".
    probe: ProbeSpec
    # Human control token (human-save path); absent for an agent (service-auth) save.
    token: str | None = None
    # Optional FA-issued save-authorization, required only when the operator enables the gate.
    save_authorization: str | None = None


class ProbeResult(BaseModel):
    result: ProbeResultName
    final_origin: str | None = None


def new_session(req: CreateSessionRequest) -> BrowserSession:
    created = now_utc()
    human_first = req.initial_owner == "human"
    return BrowserSession(
        session_id=f"bs_{uuid4().hex}",
        conversation_id=req.conversation_id,
        interface_type=req.interface_type,
        form_factor=req.resolved_form_factor(),
        state=SessionState.HUMAN_ACTIVE if human_first else SessionState.AGENT_ACTIVE,
        lease_owner=LeaseOwner.HUMAN if human_first else LeaseOwner.AGENT,
        worker_id=f"worker_{uuid4().hex}",
        created_at=created,
        updated_at=created,
        idle_expires_at=created + timedelta(minutes=15),
        expires_at=created + timedelta(minutes=60),
    )
