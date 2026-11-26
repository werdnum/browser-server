from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from browser_handoff_service import main
from browser_handoff_service.main import app, registry
from browser_handoff_service.models import AgentCommandRequest
from browser_handoff_service.runtime import FakeBrowserWorker, PlaywrightBrowserWorker
from browser_handoff_service.webmcp import (
    WEBMCP_MAX_ARGS_BYTES,
    WEBMCP_MAX_DESCRIPTION_CHARS,
    WEBMCP_MAX_NAME_CHARS,
    WEBMCP_MAX_RESULT_BYTES,
    WEBMCP_MAX_SCHEMA_BYTES,
    WEBMCP_MAX_TITLE_CHARS,
    WEBMCP_MAX_TOOLS,
    WEBMCP_MAX_TOTAL_TOOLS_BYTES,
    bound_webmcp_result,
    sanitize_webmcp_tools,
)
from httpx import ASGITransport, AsyncClient

TEST_SERVICE_TOKEN = "test-service-token"


@pytest.fixture(autouse=True)
def clear_registry():
    for attr in ("sessions", "locks", "events", "tokens", "workers", "jar_locks"):
        getattr(registry, attr).clear()
    main._jwks_client = None
    yield
    for attr in ("sessions", "locks", "events", "tokens", "workers", "jar_locks"):
        getattr(registry, attr).clear()
    main._jwks_client = None


def _headers() -> dict[str, str]:
    return {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


# --- sanitization & bounding unit tests -----------------------------------


def test_sanitize_filters_origin_dedups_and_normalizes_schemas():
    raw = [
        # Valid tool with string-encoded inputSchema (Chromium 151 shape)
        {
            "name": "search_catalog",
            "title": "Search Catalog",
            "description": "Search store products",
            "inputSchema": '{"type":"object","properties":{"query":{"type":"string"}}}',
            "annotations": {
                "readOnlyHint": True,
                "consequentialHint": False,
                "untrustedContentHint": True,
                "evilExtra": "ignored",
            },
            "origin": "https://shop.example.com",
        },
        # Duplicate name -> skipped
        {
            "name": "search_catalog",
            "description": "duplicate should be dropped",
            "origin": "https://shop.example.com",
        },
        # Cross-origin tool -> skipped
        {
            "name": "evil_tool",
            "description": "from third party iframe",
            "origin": "https://evil.example.net",
        },
        # Empty / overlong names -> skipped
        {"name": "   ", "description": "blank"},
        {"name": "x" * (WEBMCP_MAX_NAME_CHARS + 1), "description": "too long"},
        # Malformed entries -> skipped
        "not-a-dict",
        None,
    ]
    tools = sanitize_webmcp_tools(raw, "https://shop.example.com")
    assert len(tools) == 1
    tool = tools[0]
    assert tool["name"] == "search_catalog"
    assert tool["title"] == "Search Catalog"
    assert tool["description"] == "Search store products"
    assert tool["input_schema"] == {"type": "object", "properties": {"query": {"type": "string"}}}
    assert tool["annotations"] == {
        "readOnlyHint": True,
        "consequentialHint": False,
        "untrustedContentHint": True,
    }
    assert tool["origin"] == "https://shop.example.com"


def test_sanitize_truncates_strings_oversized_schemas_and_caps_total():
    big_schema = {"type": "object", "properties": {"x": {"description": "a" * (WEBMCP_MAX_SCHEMA_BYTES + 200)}}}
    raw = [
        {
            "name": "big_tool",
            "title": "T" * (WEBMCP_MAX_TITLE_CHARS + 50),
            "description": "D" * (WEBMCP_MAX_DESCRIPTION_CHARS + 100),
            "input_schema": big_schema,
        }
    ]
    tools = sanitize_webmcp_tools(raw, "https://shop.example.com")
    assert len(tools) == 1
    assert len(tools[0]["title"]) == WEBMCP_MAX_TITLE_CHARS
    assert len(tools[0]["description"]) == WEBMCP_MAX_DESCRIPTION_CHARS
    assert tools[0]["input_schema"] == {"_truncated": True}

    many = [{"name": f"tool_{i}", "description": f"Tool {i}"} for i in range(WEBMCP_MAX_TOOLS + 10)]
    capped = sanitize_webmcp_tools(many, "https://shop.example.com")
    assert len(capped) == WEBMCP_MAX_TOOLS

    # Cumulative byte cap across many medium schemas
    medium_schema = {"type": "object", "properties": {"q": {"type": "string", "description": "z" * 3500}}}
    heavy = [{"name": f"heavy_{i}", "description": "desc", "input_schema": medium_schema} for i in range(25)]
    bounded = sanitize_webmcp_tools(heavy, "https://shop.example.com")
    assert len(json.dumps(bounded, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= (
        WEBMCP_MAX_TOTAL_TOOLS_BYTES
    )


def test_sanitize_non_list_returns_empty():
    assert sanitize_webmcp_tools(None, "https://shop.example.com") == []
    assert sanitize_webmcp_tools({"name": "x"}, "https://shop.example.com") == []


def test_bound_webmcp_result_parses_json_envelope_and_truncates():
    envelope = json.dumps({"content": [{"type": "text", "text": "Cart is empty"}], "structuredContent": {"count": 0}})
    value, truncated = bound_webmcp_result(envelope)
    assert truncated is False
    assert isinstance(value, dict)
    assert value["structuredContent"] == {"count": 0}

    plain, truncated = bound_webmcp_result("plain text answer")
    assert truncated is False
    assert plain == "plain text answer"

    # Multi-byte UTF-8 string truncation must not split codepoints
    huge = "€" * (WEBMCP_MAX_RESULT_BYTES // 2)
    cut, truncated = bound_webmcp_result(huge)
    assert truncated is True
    assert isinstance(cut, str)
    assert len(cut.encode("utf-8")) <= WEBMCP_MAX_RESULT_BYTES

    # Oversized JSON object truncates cleanly to string
    big_obj = {"items": ["x" * 2000 for _ in range(50)]}
    cut_obj, truncated = bound_webmcp_result(big_obj)
    assert truncated is True
    assert isinstance(cut_obj, str)
    assert len(cut_obj.encode("utf-8")) <= WEBMCP_MAX_RESULT_BYTES


# --- FakeBrowserWorker & HTTP endpoint tests ------------------------------


@pytest.mark.asyncio
async def test_snapshot_surfaces_webmcp_tools_and_omits_when_absent():
    worker = FakeBrowserWorker("worker_webmcp")
    await worker.command(AgentCommandRequest(type="navigate", args={"url": "https://shop.example.com/"}))

    empty_snap = await worker.command(AgentCommandRequest(type="snapshot"))
    assert "webmcp_tools" not in empty_snap

    worker.webmcp_tools = [
        {
            "name": "get_cart",
            "description": "Inspect the current shopping cart",
            "input_schema": {"type": "object", "properties": {}},
            "annotations": {"readOnlyHint": True},
        },
        {
            "name": "cross_origin_tool",
            "description": "Should be excluded",
            "origin": "https://evil.example.net",
        },
    ]
    snap = await worker.command(AgentCommandRequest(type="snapshot"))
    assert "webmcp_tools" in snap
    assert [t["name"] for t in snap["webmcp_tools"]] == ["get_cart"]


@pytest.mark.asyncio
async def test_http_webmcp_call_success_navigation_and_events(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post("/v1/sessions", headers=_headers(), json={"conversation_id": "conv_webmcp"})
        assert created.status_code == 200, created.text
        session_id = created.json()["session_id"]
        worker = registry.workers[created.json()["worker_id"]]
        assert isinstance(worker, FakeBrowserWorker)

        await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=_headers(),
            json={"type": "navigate", "args": {"url": "https://shop.example.com/"}},
        )
        worker.webmcp_tools = [
            {"name": "get_cart", "description": "Get cart", "annotations": {"readOnlyHint": True}},
            {"name": "proceed_to_checkout", "description": "Open checkout"},
        ]

        def handler(tool_name: str, args: dict[str, Any]) -> Any:
            if tool_name == "get_cart":
                return json.dumps({"content": [{"type": "text", "text": "2 items"}], "args": args})
            if tool_name == "proceed_to_checkout":
                worker.url = "https://shop.example.com/checkout?token=secret123"
                worker.title = "Checkout"
                return {"checkout": True}
            raise AssertionError(f"unexpected tool {tool_name}")

        worker.webmcp_handler = handler

        # Call get_cart
        res = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "get_cart", "arguments": {"currency": "AUD"}},
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["status"] == "ok"
        assert body["navigated"] is False
        assert body["result"]["args"] == {"currency": "AUD"}
        assert body["url"] == "https://shop.example.com/"

        # Call navigation-causing tool: URL is redacted and session metadata updated
        nav_res = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "proceed_to_checkout", "arguments": {}},
        )
        assert nav_res.status_code == 200, nav_res.text
        nav_body = nav_res.json()
        assert nav_body["status"] == "ok"
        assert nav_body["navigated"] is True
        assert nav_body["url"] == "https://shop.example.com/checkout"
        assert "secret123" not in nav_body["url"]

        session = registry.sessions[session_id]
        assert session.current_url_redacted == "https://shop.example.com/checkout"
        events = [e for e in registry.events[session_id] if e.event_type == "webmcp_call"]
        assert len(events) == 2
        assert events[0].metadata == {
            "tool_name": "get_cart",
            "status": "ok",
            "reason": None,
            "navigated": False,
            "truncated": False,
        }
        # Raw arguments/results must never appear in session events
        assert "AUD" not in json.dumps(events[0].metadata)


@pytest.mark.asyncio
async def test_http_webmcp_call_errors_timeouts_and_arg_cap(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post("/v1/sessions", headers=_headers(), json={"conversation_id": "conv_webmcp_err"})
        session_id = created.json()["session_id"]
        worker = registry.workers[created.json()["worker_id"]]
        assert isinstance(worker, FakeBrowserWorker)
        await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=_headers(),
            json={"type": "navigate", "args": {"url": "https://shop.example.com/"}},
        )

        # Unsupported when no tools registered
        r = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "missing"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "error"
        assert r.json()["reason"] == "unsupported"

        worker.webmcp_tools = [
            {"name": "slow_tool", "description": "Hangs"},
            {"name": "broken_tool", "description": "Throws"},
        ]

        async def handler(tool_name: str, _args: dict[str, Any]) -> Any:
            if tool_name == "slow_tool":
                await asyncio.sleep(5)
                return "late"
            raise RuntimeError("boom from page")

        worker.webmcp_handler = handler

        # Tool not found
        r_missing = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "other_tool"},
        )
        assert r_missing.json()["status"] == "error"
        assert r_missing.json()["reason"] == "tool_not_found"

        # Tool error
        r_err = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "broken_tool"},
        )
        assert r_err.json()["status"] == "error"
        assert r_err.json()["reason"] == "tool_error"
        assert "boom from page" in (r_err.json()["detail"] or "")

        # Timeout
        r_to = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "slow_tool", "timeout_seconds": 1.0},
        )
        assert r_to.json()["status"] == "timeout"
        assert r_to.json()["reason"] == "timeout"

        # Oversized arguments refused before reaching worker
        r_big = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "broken_tool", "arguments": {"blob": "x" * (WEBMCP_MAX_ARGS_BYTES + 100)}},
        )
        assert r_big.status_code == 200
        assert r_big.json()["status"] == "refused"
        assert r_big.json()["reason"] == "arguments_too_large"


@pytest.mark.asyncio
async def test_http_webmcp_call_allowed_in_authenticated_site_and_readback_protected_sessions(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers=_headers(),
            json={
                "conversation_id": "conv_auth_webmcp",
                "authenticated_site": True,
                "confine_origins": ["https://shop.example.com"],
            },
        )
        assert created.status_code == 200, created.text
        session_id = created.json()["session_id"]
        worker = registry.workers[created.json()["worker_id"]]
        assert isinstance(worker, FakeBrowserWorker)

        await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=_headers(),
            json={"type": "navigate", "args": {"url": "https://shop.example.com/"}},
        )

        # exec is denied in authenticated_site / readback_protected sessions...
        exec_res = await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=_headers(),
            json={"type": "exec", "args": {"code": "1 + 1"}},
        )
        assert exec_res.status_code == 403

        # ...but WebMCP calls succeed for page-declared tools...
        worker.webmcp_tools = [
            {"name": "add_to_cart", "description": "Add item"},
            {"name": "off_scope_nav", "description": "Navigate off scope"},
        ]

        def handler(tool_name: str, args: dict[str, Any]) -> Any:
            if tool_name == "off_scope_nav":
                worker.url = "https://evil.example.net/steal"
                return {"ok": True}
            return {"added": args.get("sku")}

        worker.webmcp_handler = handler

        ok_res = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "add_to_cart", "arguments": {"sku": "SHOE-10"}},
        )
        assert ok_res.status_code == 200
        assert ok_res.json()["status"] == "ok"
        assert ok_res.json()["result"] == {"added": "SHOE-10"}

        # ...and origin confinement still blocks off-scope tool navigations!
        blocked = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "off_scope_nav"},
        )
        assert blocked.status_code == 200
        assert blocked.json()["status"] == "refused"
        assert blocked.json()["reason"] == "off_scope_blocked"
        assert blocked.json()["target_origin"] == "https://evil.example.net"


@pytest.mark.asyncio
async def test_http_webmcp_call_denied_during_human_handoff_and_after_close(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Unauthorized without service token
        unauth = await client.post("/v1/sessions/bs_none/webmcp-call", json={"tool_name": "get_cart"})
        assert unauth.status_code in {401, 403}

        created = await client.post("/v1/sessions", headers=_headers(), json={"conversation_id": "conv_handoff"})
        session_id = created.json()["session_id"]

        # Handoff to human -> agent loses lease -> webmcp-call is denied (403)
        handoff = await client.post(
            f"/v1/sessions/{session_id}/handoff",
            headers=_headers(),
            json={"reason": "payment", "handoff_note": "finish checkout"},
        )
        assert handoff.status_code == 200
        denied = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "get_cart"},
        )
        assert denied.status_code == 403

        # Close session -> 410 Gone
        closed = await client.post(f"/v1/sessions/{session_id}/close", headers=_headers())
        assert closed.status_code == 200
        gone = await client.post(
            f"/v1/sessions/{session_id}/webmcp-call",
            headers=_headers(),
            json={"tool_name": "get_cart"},
        )
        assert gone.status_code == 410


# --- PlaywrightBrowserWorker unit tests (stubbed page) --------------------


@pytest.mark.asyncio
async def test_playwright_worker_webmcp_call_context_destroyed_and_off_scope():
    from patchright.async_api import Error as PlaywrightError

    worker = PlaywrightBrowserWorker("worker_pw_webmcp", confine_origins=["https://shop.example.com"])

    class _NavStubPage:
        url = "https://shop.example.com/checkout"

        async def evaluate(self, _script: str, _arg: Any = None) -> Any:
            raise PlaywrightError("Execution context was destroyed, most likely because of a navigation.")

        async def title(self) -> str:
            return "Checkout"

        async def wait_for_load_state(self, _state: str, **_kwargs: Any) -> None:
            return None

    worker._page = _NavStubPage()
    res = await worker.webmcp_call("begin_checkout", {}, timeout_seconds=5.0)
    assert res["status"] == "navigated"
    assert res["navigated"] is True
    assert res["url"] == "https://shop.example.com/checkout"

    # Off-scope abort during tool call surfaces refused(off_scope_blocked)
    class _OffScopeStubPage(_NavStubPage):
        async def evaluate(self, _script: str, _arg: Any = None) -> Any:
            worker._nav_off_scope_block = "https://idp.example.com"
            raise PlaywrightError("net::ERR_ABORTED")

    worker._page = _OffScopeStubPage()
    blocked = await worker.webmcp_call("begin_checkout", {}, timeout_seconds=5.0)
    assert blocked["status"] == "refused"
    assert blocked["reason"] == "off_scope_blocked"
    assert blocked["target_origin"] == "https://idp.example.com"


@pytest.mark.asyncio
async def test_playwright_worker_list_webmcp_swallows_errors():
    from patchright.async_api import Error as PlaywrightError

    worker = PlaywrightBrowserWorker("worker_pw_list_err")

    class _ErrPage:
        async def evaluate(self, _script: str) -> Any:
            raise PlaywrightError("target closed")

    assert await worker._list_webmcp_tools(_ErrPage(), "https://shop.example.com/") == []
