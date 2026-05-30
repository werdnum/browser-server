"""Extended agent-command protocol: rich snapshot, screenshot bytes, extract, exec, wait.

These commands let a remote client (the Family Assistant browser-tool adapter) drive
the session with the same rich semantics as a local Playwright page, while keeping the
no-observation-during-human-control invariant intact.
"""

import base64

import pytest
from browser_handoff_service.models import (
    AgentCommandRequest,
    CreateSessionRequest,
    HandoffRequest,
    SessionState,
)
from browser_handoff_service.registry import AuthorizationError, SessionRegistry


@pytest.mark.asyncio
async def test_snapshot_returns_accessibility_tree_shape():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_snap"))
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://example.test/page"}),
    )
    resp = await registry.agent_command(session.session_id, AgentCommandRequest(type="snapshot"))
    assert resp.ok
    for key in ("url", "title", "forms", "elements", "roots"):
        assert key in resp.result
    assert isinstance(resp.result["roots"], list)


@pytest.mark.asyncio
async def test_screenshot_returns_decodable_png_bytes():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_shot"))
    resp = await registry.agent_command(session.session_id, AgentCommandRequest(type="screenshot"))
    assert resp.result["mime_type"] == "image/png"
    decoded = base64.b64decode(resp.result["image_base64"])
    assert decoded[:8] == b"\x89PNG\r\n\x1a\n"


@pytest.mark.asyncio
async def test_extract_and_exec_and_wait_are_supported():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_cmds"))
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://example.test/page"}),
    )
    extract = await registry.agent_command(session.session_id, AgentCommandRequest(type="extract"))
    assert "html" in extract.result
    executed = await registry.agent_command(session.session_id, AgentCommandRequest(type="exec", args={"code": "1"}))
    assert "result" in executed.result
    waited = await registry.agent_command(session.session_id, AgentCommandRequest(type="wait"))
    assert waited.ok


@pytest.mark.asyncio
async def test_extended_observation_commands_denied_during_human_control():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_human"))
    _, url = await registry.handoff(
        session.session_id,
        HandoffRequest(reason="other", handoff_note="take over"),
        "http://testserver",
    )
    token = url.split("token=", 1)[1]
    await registry.claim(session.session_id, token)
    assert registry.get(session.session_id).state == SessionState.HUMAN_ACTIVE
    for command in ("snapshot", "screenshot", "extract", "exec"):
        with pytest.raises(AuthorizationError):
            await registry.agent_command(session.session_id, AgentCommandRequest(type=command))
