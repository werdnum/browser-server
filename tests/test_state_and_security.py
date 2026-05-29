from datetime import timedelta

import pytest
from browser_handoff_service.models import (
    AgentCommandRequest,
    CreateSessionRequest,
    HandoffRequest,
    LeaseOwner,
    SessionState,
    now_utc,
)
from browser_handoff_service.registry import AuthorizationError, ConflictError, SessionRegistry
from browser_handoff_service.runtime import FakeBrowserWorker
from browser_handoff_service.transitions import TransitionError, transition


@pytest.mark.asyncio
async def test_agent_loses_all_command_access_after_handoff_request():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://example.test/path?secret=hidden"}),
    )

    handoff, _ = await registry.handoff(
        session.session_id,
        HandoffRequest(reason="payment", handoff_note="Pay"),
        "http://testserver",
    )

    assert handoff.state == SessionState.HANDOFF_REQUESTED
    assert handoff.current_url_redacted == "https://example.test/path"
    with pytest.raises(AuthorizationError):
        await registry.agent_command(session.session_id, AgentCommandRequest(type="snapshot"))
    with pytest.raises(AuthorizationError):
        await registry.agent_command(session.session_id, AgentCommandRequest(type="click", args={"selector": "button"}))


@pytest.mark.asyncio
async def test_handoff_token_is_one_time():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))
    _, url = await registry.handoff(
        session.session_id,
        HandoffRequest(reason="other", handoff_note="Review"),
        "http://testserver",
    )
    token = url.split("token=", 1)[1]

    with pytest.raises(AuthorizationError):
        await registry.claim(session.session_id, "wrong")

    claimed, control_token = await registry.claim(session.session_id, token)
    assert claimed.state == SessionState.HUMAN_ACTIVE
    with pytest.raises(AuthorizationError):
        await registry.claim(session.session_id, token)
    with pytest.raises(AuthorizationError):
        await registry.authorize_remote(session.session_id, "wrong")
    with pytest.raises(AuthorizationError):
        await registry.authorize_remote(session.session_id, token)
    assert (await registry.authorize_remote(session.session_id, control_token)).session_id == session.session_id


@pytest.mark.asyncio
async def test_pending_handoff_token_cannot_extend_claim_timeout():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))
    _, url = await registry.handoff(
        session.session_id,
        HandoffRequest(reason="other", handoff_note="Review"),
        "http://testserver",
    )
    handoff_token = url.split("token=", 1)[1]
    pending_expiry = session.idle_expires_at

    with pytest.raises(AuthorizationError):
        await registry.extend(session.session_id, handoff_token, 5)
    assert session.idle_expires_at == pending_expiry

    _, control_token = await registry.claim(session.session_id, handoff_token)
    session.idle_expires_at = now_utc() + timedelta(seconds=1)
    claimed_expiry = session.idle_expires_at
    extended = await registry.extend(session.session_id, control_token, 5)
    assert extended.idle_expires_at > claimed_expiry


@pytest.mark.asyncio
async def test_payment_handoff_rejects_resume_policy():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))
    with pytest.raises(ConflictError):
        await registry.handoff(
            session.session_id,
            HandoffRequest(reason="payment", allowed_resume="after_sanitize"),
            "http://testserver",
        )


@pytest.mark.asyncio
async def test_handoff_expected_origin_must_match_current_origin():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))

    with pytest.raises(ConflictError):
        await registry.handoff(
            session.session_id,
            HandoffRequest(reason="payment", expected_origin="https://merchant.test"),
            "http://testserver",
        )

    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://merchant.test/checkout?secret=hidden"}),
    )
    with pytest.raises(ConflictError):
        await registry.handoff(
            session.session_id,
            HandoffRequest(reason="payment", expected_origin="https://evil.test"),
            "http://testserver",
        )

    handoff, _ = await registry.handoff(
        session.session_id,
        HandoffRequest(reason="payment", expected_origin="https://merchant.test/pay"),
        "http://testserver",
    )
    assert handoff.state == SessionState.HANDOFF_REQUESTED


@pytest.mark.asyncio
async def test_low_risk_handoff_can_return_agent_resumable_after_sanitize():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://example.test/captcha?secret=human"}),
    )
    _, url = await registry.handoff(
        session.session_id,
        HandoffRequest(reason="captcha", allowed_resume="after_sanitize"),
        "http://testserver",
    )
    token = url.split("token=", 1)[1]
    _, control_token = await registry.claim(session.session_id, token)
    resumable = await registry.human_complete(session.session_id, control_token, "captcha solved")

    assert resumable.state == SessionState.AGENT_RESUMABLE
    assert resumable.lease_owner == LeaseOwner.AGENT
    response = await registry.agent_command(session.session_id, AgentCommandRequest(type="current_page"))
    assert response.ok is True
    assert response.result == {"url": None, "title": "Blank"}


@pytest.mark.asyncio
async def test_expiry_reaper_closes_runtime_and_denies_commands():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))
    session.idle_expires_at = now_utc() - timedelta(seconds=1)

    expired = await registry.reap_expired()

    assert expired == [session.session_id]
    assert session.state == SessionState.EXPIRED
    assert session.cleanup_completed_at is not None
    with pytest.raises(AuthorizationError):
        await registry.agent_command(session.session_id, AgentCommandRequest(type="current_page"))


@pytest.mark.asyncio
async def test_human_started_session_can_be_handed_over_to_agent():
    registry = SessionRegistry()
    session, control_token = await registry.create_session(
        CreateSessionRequest(conversation_id="conv_1", initial_owner="human")
    )

    assert session.state == SessionState.HUMAN_ACTIVE
    assert session.lease_owner == LeaseOwner.HUMAN
    assert control_token is not None
    # The human owns the lease, so the agent cannot act yet.
    with pytest.raises(AuthorizationError):
        await registry.agent_command(session.session_id, AgentCommandRequest(type="current_page"))

    handed = await registry.handover(session.session_id, control_token, "Finish the booking")

    assert handed.state == SessionState.AGENT_ACTIVE
    assert handed.lease_owner == LeaseOwner.AGENT
    assert handed.handoff_note == "Finish the booking"
    response = await registry.agent_command(session.session_id, AgentCommandRequest(type="current_page"))
    assert response.ok is True


@pytest.mark.asyncio
async def test_handover_revokes_human_control_token():
    registry = SessionRegistry()
    session, control_token = await registry.create_session(
        CreateSessionRequest(conversation_id="conv_1", initial_owner="human")
    )
    assert control_token is not None

    await registry.handover(session.session_id, control_token, "")

    # The consumed control token can no longer drive the session as a human.
    with pytest.raises(AuthorizationError):
        await registry.authorize_remote(session.session_id, control_token)
    with pytest.raises(AuthorizationError):
        await registry.handover(session.session_id, control_token, "")


@pytest.mark.asyncio
async def test_agent_started_session_cannot_be_handed_over():
    registry = SessionRegistry()
    session, control_token = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))

    assert session.state == SessionState.AGENT_ACTIVE
    assert control_token is None
    with pytest.raises(AuthorizationError):
        await registry.handover(session.session_id, "any-token", "")


def test_invalid_state_transitions_are_rejected():
    with pytest.raises(TransitionError):
        transition(SessionState.HUMAN_SENSITIVE, LeaseOwner.HUMAN, SessionState.AGENT_ACTIVE)


@pytest.mark.asyncio
async def test_navigation_origin_tracks_final_worker_url_after_redirect():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))

    class RedirectWorker(FakeBrowserWorker):
        async def command(self, request):
            if request.type == "navigate":
                return {"url": "https://evil.test/landing", "title": "Redirected"}
            return await super().command(request)

    registry.workers[session.worker_id or ""] = RedirectWorker(session.worker_id or "")
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://merchant.test/checkout"}),
    )

    assert session.current_url_redacted == "https://evil.test/landing"
    assert session.current_origin == "https://evil.test"
    with pytest.raises(ConflictError):
        await registry.handoff(
            session.session_id,
            HandoffRequest(reason="payment", expected_origin="https://merchant.test"),
            "http://testserver",
        )


@pytest.mark.asyncio
async def test_location_changing_click_refreshes_current_origin():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_1"))
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://merchant.test/checkout"}),
    )

    class RedirectOnClickWorker(FakeBrowserWorker):
        async def command(self, request):
            if request.type == "click":
                self.url = "https://evil.test/after-click"
                self.title = "Redirected"
                return {"accepted": True, "url": "https://evil.test/after-click", "title": self.title}
            return await super().command(request)

    registry.workers[session.worker_id or ""] = RedirectOnClickWorker(session.worker_id or "")
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="click", args={"selector": "#pay"}),
    )

    assert session.current_origin == "https://evil.test"
    with pytest.raises(ConflictError):
        await registry.handoff(
            session.session_id,
            HandoffRequest(reason="payment", expected_origin="https://merchant.test"),
            "http://testserver",
        )
