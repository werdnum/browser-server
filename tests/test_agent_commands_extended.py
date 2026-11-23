"""Extended agent-command protocol: rich snapshot, screenshot bytes, extract, exec, wait, visual controls.

These commands let a remote client (the Family Assistant browser-tool adapter) drive
the session with the same rich semantics as a local Playwright page, while keeping the
no-observation-during-human-control invariant intact.
"""

import base64
from typing import Literal

import pytest
from browser_handoff_service.models import (
    AgentCommandRequest,
    CreateSessionRequest,
    HandoffRequest,
    SessionState,
)
from browser_handoff_service.registry import AuthorizationError, SessionRegistry

VisualCommand = Literal[
    "mouse_move",
    "mouse_click",
    "mouse_down",
    "mouse_up",
    "mouse_wheel",
    "keyboard_type",
    "keyboard_press",
    "navigate_back",
    "navigate_forward",
]


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
    for key in ("url", "title", "forms", "elements", "next_ref", "roots"):
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


@pytest.mark.asyncio
async def test_visual_commands_are_accepted_by_api_model_and_registry():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_visual"))

    command_args: list[tuple[VisualCommand, dict[str, object]]] = [
        ("mouse_move", {"x": 10, "y": 20}),
        ("mouse_click", {"x": 10, "y": 20}),
        ("mouse_down", {}),
        ("mouse_up", {}),
        ("mouse_wheel", {"delta_x": 0, "delta_y": 120}),
        ("keyboard_type", {"text": "hello"}),
        ("keyboard_press", {"key": "Enter"}),
        ("navigate_back", {}),
        ("navigate_forward", {}),
    ]
    for command, args in command_args:
        resp = await registry.agent_command(session.session_id, AgentCommandRequest(type=command, args=args))
        assert resp.ok


@pytest.mark.asyncio
async def test_hover_by_ref_validates_refs_and_works_in_credential_sessions():
    registry = SessionRegistry()
    session, _ = await registry.create_session(
        CreateSessionRequest(conversation_id="conv_hover", autofill_enabled=True)
    )
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://example.test/page"}),
    )
    snap = await registry.agent_command(session.session_id, AgentCommandRequest(type="snapshot"))
    ref = snap.result["roots"][0]["ref"]

    ok_resp = await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="hover", args={"ref": ref}),
    )
    assert ok_resp.ok
    assert ok_resp.result["accepted"] is True

    stale = await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="hover", args={"ref": "e999999"}),
    )
    assert stale.result["error"] is True
    assert stale.result["code"] == "stale_ref"

    invalid = await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="hover", args={"ref": "not-a-ref"}),
    )
    assert invalid.result["error"] is True
    assert invalid.result["code"] == "invalid_ref"


@pytest.mark.asyncio
async def test_screenshot_returns_viewport_geometry():
    registry = SessionRegistry()
    session, _ = await registry.create_session(
        CreateSessionRequest(conversation_id="conv_shot_geom", form_factor="desktop")
    )
    resp = await registry.agent_command(session.session_id, AgentCommandRequest(type="screenshot"))
    assert resp.result["viewport_width"] == 1280.0
    assert resp.result["viewport_height"] == 720.0
    assert resp.result["device_pixel_ratio"] == 1.0
    assert resp.result["scroll_x"] == 0.0
    assert resp.result["scroll_y"] == 0.0


@pytest.mark.asyncio
async def test_playwright_worker_hover_and_screenshot_geometry():
    from browser_handoff_service.runtime import PlaywrightBrowserWorker

    class _StubLocator:
        def __init__(self) -> None:
            self.hover_calls: list[dict[str, object]] = []

        async def hover(self, **kwargs: object) -> None:
            self.hover_calls.append(kwargs)

    class _StubPage:
        def __init__(self, *, fail_eval: bool = False) -> None:
            self.url = "https://example.test/model"
            self.locator_stub = _StubLocator()
            self.last_selector: str | None = None
            self.fail_eval = fail_eval

        async def title(self) -> str:
            return "Model"

        async def wait_for_load_state(self, *_args: object, **_kwargs: object) -> None:
            return None

        def locator(self, selector: str) -> _StubLocator:
            self.last_selector = selector
            return self.locator_stub

        async def screenshot(self, **_kwargs: object) -> bytes:
            return base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
            )

        async def evaluate(self, script: str, arg: object = None) -> object:
            if arg is not None:
                return {"ok": True}
            if self.fail_eval:
                raise RuntimeError("navigation race")
            return {
                "viewport_width": 1280,
                "viewport_height": 633,
                "device_pixel_ratio": 2,
                "scroll_x": 10,
                "scroll_y": 420,
            }

    worker = PlaywrightBrowserWorker("w_hover")
    worker.stealth = False
    page = _StubPage()
    worker._page = page

    hover_result = await worker._dispatch_command(AgentCommandRequest(type="hover", args={"ref": "e12"}), page)
    assert hover_result["accepted"] is True
    assert page.last_selector == '[data-fa-ref="e12"]'
    assert len(page.locator_stub.hover_calls) == 1

    shot_result = await worker._dispatch_command(AgentCommandRequest(type="screenshot"), page)
    assert shot_result["viewport_width"] == 1280.0
    assert shot_result["viewport_height"] == 633.0
    assert shot_result["device_pixel_ratio"] == 2.0
    assert shot_result["scroll_x"] == 10.0
    assert shot_result["scroll_y"] == 420.0
    assert shot_result["url"] == "https://example.test/model"

    failing_page = _StubPage(fail_eval=True)
    worker._page = failing_page
    fallback_shot = await worker._dispatch_command(AgentCommandRequest(type="screenshot"), failing_page)
    assert fallback_shot["mime_type"] == "image/png"
    assert "viewport_width" not in fallback_shot


@pytest.mark.asyncio
async def test_playwright_worker_screenshot_omits_unstable_or_non_finite_geometry():
    from browser_handoff_service.runtime import PlaywrightBrowserWorker

    class _DriftingPage:
        def __init__(self) -> None:
            self.url = "https://example.test/page"
            self.eval_calls = 0

        async def screenshot(self, **_kwargs: object) -> bytes:
            return base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
            )

        async def evaluate(self, _script: str, _arg: object = None) -> object:
            self.eval_calls += 1
            return {
                "viewport_width": 1280,
                "viewport_height": 720,
                "device_pixel_ratio": 1,
                "scroll_x": 0,
                "scroll_y": 0 if self.eval_calls == 1 else 300,
            }

    class _NonFinitePage:
        url = "https://example.test/page"

        async def screenshot(self, **_kwargs: object) -> bytes:
            return base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
            )

        async def evaluate(self, _script: str, _arg: object = None) -> object:
            return {
                "viewport_width": 1280,
                "viewport_height": 0,
                "device_pixel_ratio": float("nan"),
                "scroll_x": float("inf"),
                "scroll_y": 50,
            }

    worker = PlaywrightBrowserWorker("w_geom_guard")
    worker.stealth = False

    drifting = _DriftingPage()
    worker._page = drifting
    drift_shot = await worker._dispatch_command(AgentCommandRequest(type="screenshot"), drifting)
    assert drift_shot["mime_type"] == "image/png"
    assert "viewport_width" not in drift_shot
    assert "scroll_y" not in drift_shot

    non_finite = _NonFinitePage()
    worker._page = non_finite
    nf_shot = await worker._dispatch_command(AgentCommandRequest(type="screenshot"), non_finite)
    assert nf_shot["viewport_width"] == 1280.0
    assert nf_shot["scroll_y"] == 50.0
    assert "viewport_height" not in nf_shot
    assert "device_pixel_ratio" not in nf_shot
    assert "scroll_x" not in nf_shot
