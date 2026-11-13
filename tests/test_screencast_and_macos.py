from __future__ import annotations

import asyncio
import json
import os
import plistlib
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from browser_handoff_service import main
from browser_handoff_service.main import app, registry, screencast_proxy_url
from browser_handoff_service.runtime import (
    CDPScreencastSession,
    PlaywrightBrowserWorker,
    RemoteDisplayStatus,
    RuntimeUnavailable,
    remote_viewport_mode,
)
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from scripts.macos.install_launch_agent import (
    SERVICE_LABEL,
    UPDATER_LABEL,
    _ensure_env_file,
    build_service_plist,
    build_updater_plist,
)

TEST_SERVICE_TOKEN = "test-service-token"


@pytest.fixture(autouse=True)
def reset_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    registry.sessions.clear()
    registry.locks.clear()
    registry.events.clear()
    registry.tokens.clear()
    registry.workers.clear()


class _FakeScreencastSession:
    def __init__(self) -> None:
        self.events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.received_inputs: list[dict[str, Any]] = []
        self.closed = False
        self.events.put_nowait(
            {
                "type": "frame",
                "data": "ZmFrZS1qcGVn",
                "width": 1280,
                "height": 720,
                "url": "https://example.com/",
            }
        )

    async def next_event(self) -> dict[str, Any]:
        return await self.events.get()

    async def dispatch_input(self, message: dict[str, Any]) -> None:
        self.received_inputs.append(message)
        self.events.put_nowait(
            {
                "type": "frame",
                "data": "dXBkYXRlZA==",
                "width": 1280,
                "height": 720,
                "url": "https://example.com/after",
            }
        )

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_health_reports_active_non_terminal_session_count() -> None:
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        initial = await client.get("/healthz")
        assert initial.status_code == 200
        assert initial.json()["active_sessions"] == 0

        created = await client.post("/v1/sessions", headers=headers, json={"conversation_id": "conv_health"})
        assert created.status_code == 200
        session_id = created.json()["session_id"]

        during = await client.get("/health")
        assert during.json()["active_sessions"] == 1

        closed = await client.post(f"/v1/sessions/{session_id}/close", headers=headers)
        assert closed.status_code == 200
        assert session_id in registry.sessions

        after = await client.get("/healthz")
        assert after.json()["active_sessions"] == 0


def test_screencast_proxy_url_preserves_scheme_and_prefix() -> None:
    assert (
        screencast_proxy_url("bs_123", "https://browser.andrewgarrett.dev/app/")
        == "wss://browser.andrewgarrett.dev/app/v1/sessions/bs_123/screencast"
    )
    assert (
        screencast_proxy_url("bs_123", "http://127.0.0.1:8000/") == "ws://127.0.0.1:8000/v1/sessions/bs_123/screencast"
    )


@pytest.mark.asyncio
async def test_remote_falls_back_to_screencast_when_novnc_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "remote_display_status", lambda: RemoteDisplayStatus(available=False, reason="macOS"))
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_macos", "initial_owner": "human"},
        )
        assert created.status_code == 200
        body = created.json()
        session_id = body["session_id"]
        control_token = body["control_token"]
        worker: Any = registry.workers[body["worker_id"]]
        worker.supports_cdp_screencast = True

        remote = await client.get(
            f"/v1/sessions/{session_id}/remote",
            params={"token": control_token},
            headers={
                "x-forwarded-proto": "https",
                "x-forwarded-host": "browser.andrewgarrett.dev",
                "x-forwarded-prefix": "/browser",
            },
        )
        assert remote.status_code == 200, remote.text
        assert remote.json() == {
            "session_id": session_id,
            "mode": "screencast",
            "screencast_url": f"wss://browser.andrewgarrett.dev/browser/v1/sessions/{session_id}/screencast",
        }
        cookie = remote.headers["set-cookie"]
        assert f"screencast_{session_id}=" in cookie
        assert f"Path=/browser/v1/sessions/{session_id}/screencast" in cookie
        assert "secure" in cookie.lower()


@pytest.mark.asyncio
async def test_browser_remote_mode_env_overrides_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "remote_display_status", lambda: RemoteDisplayStatus(available=True))
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_remote_mode", "initial_owner": "human"},
        )
        assert created.status_code == 200
        body = created.json()
        session_id = body["session_id"]
        control_token = body["control_token"]
        worker: Any = registry.workers[body["worker_id"]]
        worker.remote_url = "http://127.0.0.1:6080/vnc.html?autoconnect=1"
        worker.supports_cdp_screencast = True

        # Default (auto) prefers noVNC when both are available.
        monkeypatch.delenv("BROWSER_REMOTE_MODE", raising=False)
        assert remote_viewport_mode() == "auto"
        auto_res = await client.get(f"/v1/sessions/{session_id}/remote", params={"token": control_token})
        assert auto_res.status_code == 200
        assert auto_res.json()["mode"] == "novnc"

        # BROWSER_REMOTE_MODE=screencast forces CDP screencast and blocks noVNC proxy routes.
        monkeypatch.setenv("BROWSER_REMOTE_MODE", "screencast")
        assert remote_viewport_mode() == "screencast"
        sc_res = await client.get(f"/v1/sessions/{session_id}/remote", params={"token": control_token})
        assert sc_res.status_code == 200
        assert sc_res.json()["mode"] == "screencast"
        novnc_blocked = await client.get(f"/v1/sessions/{session_id}/novnc/vnc.html", params={"token": control_token})
        assert novnc_blocked.status_code == 503

        # BROWSER_REMOTE_MODE=novnc disables CDP screencast fallback when noVNC is absent.
        worker.remote_url = None
        monkeypatch.setattr(main, "remote_display_status", lambda: RemoteDisplayStatus(available=False, reason="macOS"))
        monkeypatch.setenv("BROWSER_REMOTE_MODE", "novnc")
        assert remote_viewport_mode() == "novnc"
        novnc_only = await client.get(f"/v1/sessions/{session_id}/remote", params={"token": control_token})
        assert novnc_only.status_code == 503

        # Invalid value fails closed with a clear message.
        monkeypatch.setenv("BROWSER_REMOTE_MODE", "bogus")
        with pytest.raises(RuntimeUnavailable, match="BROWSER_REMOTE_MODE"):
            remote_viewport_mode()
        invalid_res = await client.get(f"/v1/sessions/{session_id}/remote", params={"token": control_token})
        assert invalid_res.status_code == 500


def test_screencast_websocket_auth_streaming_input_and_revocation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "remote_display_status", lambda: RemoteDisplayStatus(available=False, reason="macOS"))
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    fake_sc = _FakeScreencastSession()

    with TestClient(app) as client:
        created = client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_ws", "initial_owner": "human"},
        )
        assert created.status_code == 200
        session_id = created.json()["session_id"]
        control_token = created.json()["control_token"]
        worker: Any = registry.workers[created.json()["worker_id"]]
        worker.supports_cdp_screencast = True

        async def _open() -> _FakeScreencastSession:
            return fake_sc

        worker.open_screencast = _open

        # Wrong token is rejected with 1008.
        with pytest.raises(Exception):
            with client.websocket_connect(f"/v1/sessions/{session_id}/screencast?token=wrong") as ws:
                ws.receive_text()

        # Authorized session streams frames, forwards input, and closes cleanly on completion.
        with client.websocket_connect(f"/v1/sessions/{session_id}/screencast?token={control_token}") as ws:
            first = json.loads(ws.receive_text())
            assert first["type"] == "frame"
            assert first["data"] == "ZmFrZS1qcGVn"

            ws.send_text(json.dumps({"type": "mouse", "action": "click", "x": 42, "y": 84}))
            second = json.loads(ws.receive_text())
            assert second["url"] == "https://example.com/after"
            assert fake_sc.received_inputs == [{"type": "mouse", "action": "click", "x": 42, "y": 84}]

            # Complete the session: the next client message must fail the per-message lease check.
            completed = client.post(
                f"/v1/sessions/{session_id}/complete",
                json={"token": control_token, "outcome": "done"},
            )
            assert completed.status_code == 200
            ws.send_text(json.dumps({"type": "text", "text": "x"}))
            with pytest.raises(Exception):
                ws.receive_text()

        assert fake_sc.closed is True


class _StubMouse:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    async def move(self, x: float, y: float) -> None:
        self.calls.append(("move", x, y))

    async def down(self, *, button: str = "left", click_count: int = 1) -> None:
        self.calls.append(("down", button, click_count))

    async def up(self, *, button: str = "left", click_count: int = 1) -> None:
        self.calls.append(("up", button, click_count))

    async def click(self, x: float, y: float, *, button: str = "left", click_count: int = 1) -> None:
        self.calls.append(("click", x, y, button, click_count))

    async def wheel(self, dx: float, dy: float) -> None:
        self.calls.append(("wheel", dx, dy))


class _StubKeyboard:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def type(self, text: str) -> None:
        self.calls.append(("type", text))

    async def insert_text(self, text: str) -> None:
        self.calls.append(("insert_text", text))

    async def press(self, key: str) -> None:
        self.calls.append(("press", key))


class _StubPage:
    def __init__(self, url: str = "https://allowed.example/start") -> None:
        self.url = url
        self.closed = False
        self.mouse = _StubMouse()
        self.keyboard = _StubKeyboard()
        self.nav_calls: list[tuple[str, str]] = []

    def is_closed(self) -> bool:
        return self.closed

    async def goto(self, url: str, **_kwargs: Any) -> None:
        self.url = url
        self.nav_calls.append(("goto", url))

    async def go_back(self) -> None:
        self.nav_calls.append(("back", ""))

    async def reload(self, **_kwargs: Any) -> None:
        self.nav_calls.append(("reload", ""))


class _StubCDPSession:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any] | None]] = []
        self.handlers: dict[str, Any] = {}
        self.detached = False

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler

    async def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.sent.append((method, params))
        if method == "Page.captureScreenshot":
            return {"data": "c2VlZGVk"}
        return {}

    async def detach(self) -> None:
        self.detached = True


class _StubContext:
    def __init__(self, pages: list[_StubPage]) -> None:
        self.pages = pages
        self.cdp_sessions: list[tuple[_StubPage, _StubCDPSession]] = []

    async def new_cdp_session(self, page: _StubPage) -> _StubCDPSession:
        cdp = _StubCDPSession()
        self.cdp_sessions.append((page, cdp))
        return cdp


@pytest.mark.asyncio
async def test_cdp_screencast_session_never_enables_runtime_and_enforces_confinement() -> None:
    worker = PlaywrightBrowserWorker("w_cdp", width=412, height=915, confine_origins=["https://allowed.example"])
    page1 = _StubPage("https://allowed.example/login?secret=1")
    ctx = _StubContext([page1])
    worker._context = ctx  # type: ignore[assignment]
    worker._page = page1  # type: ignore[assignment]

    sc = CDPScreencastSession(worker)
    await sc.start()
    try:
        _, cdp1 = ctx.cdp_sessions[0]
        methods = [m for m, _ in cdp1.sent]
        assert "Page.startScreencast" in methods
        assert "Runtime.enable" not in methods

        # Emit a frame with a sensitive query string; ensure URL is redacted and frame acked.
        cdp1.handlers["Page.screencastFrame"](
            {
                "data": "amZyYW1l",
                "sessionId": 7,
                "metadata": {"deviceWidth": 412, "deviceHeight": 915},
            }
        )
        frame = await sc.next_event()
        assert frame == {
            "type": "frame",
            "data": "amZyYW1l",
            "width": 412,
            "height": 915,
            "url": "https://allowed.example/login",
        }
        assert ("Page.screencastFrameAck", {"sessionId": 7}) in cdp1.sent

        # Input forwarding: single char uses type(), multi-char paste uses insert_text().
        await sc.dispatch_input({"type": "text", "text": "a"})
        await sc.dispatch_input({"type": "text", "text": "123456"})
        await sc.dispatch_input({"type": "key", "key": "Shift+Tab"})
        await sc.dispatch_input({"type": "key", "key": "DisallowedKey"})
        assert page1.keyboard.calls == [
            ("type", "a"),
            ("insert_text", "123456"),
            ("press", "Shift+Tab"),
        ]

        # Confinement blocks off-scope and non-http(s) URLs while allowing in-scope HTTPS.
        await sc.dispatch_input({"type": "navigate", "action": "goto", "url": "javascript:alert(1)"})
        await sc.dispatch_input({"type": "navigate", "action": "goto", "url": "https://evil.example/phish"})
        await sc.dispatch_input({"type": "navigate", "action": "goto", "url": "https://allowed.example/mfa"})
        assert page1.nav_calls == [("goto", "https://allowed.example/mfa")]

        # Opening a popup rebinds the CDP screencast session to the popup and updates worker._page.
        popup = _StubPage("https://allowed.example/popup")
        ctx.pages.append(popup)
        await sc.dispatch_input({"type": "mouse", "action": "down", "x": 10, "y": 20})
        assert worker._page is popup
        assert cdp1.detached is True
        assert len(ctx.cdp_sessions) == 2
        assert popup.mouse.calls == [("move", 10.0, 20.0), ("down", "left", 1)]
    finally:
        await sc.close()
        assert ctx.cdp_sessions[-1][1].detached is True


def test_macos_launch_agent_plist_generation_and_env_seed(tmp_path: Path) -> None:
    repo_root = tmp_path / "Application Support" / "browser-server"
    log_dir = tmp_path / "Logs"
    svc = plistlib.loads(build_service_plist(repo_root, log_dir))
    upd = plistlib.loads(build_updater_plist(repo_root, log_dir, interval_seconds=300))

    assert svc["Label"] == SERVICE_LABEL
    assert svc["LimitLoadToSessionType"] == "Aqua"
    assert svc["KeepAlive"] is True
    assert svc["RunAtLoad"] is True
    assert svc["ProgramArguments"][1].endswith("scripts/macos/run_service.sh")

    assert upd["Label"] == UPDATER_LABEL
    assert upd["LimitLoadToSessionType"] == "Aqua"
    assert upd["StartInterval"] == 300
    assert upd["ProgramArguments"][1].endswith("scripts/macos/self_update.sh")

    env_file = tmp_path / "cfg" / "env"
    assert _ensure_env_file(env_file) is False
    assert (env_file.stat().st_mode & 0o777) == 0o600
    env_file.write_text("BROWSER_HANDOFF_SERVICE_TOKEN=real-secret-token\n", encoding="utf-8")
    assert _ensure_env_file(env_file) is True


def test_macos_self_update_defers_while_busy_and_updates_when_idle(tmp_path: Path) -> None:
    script_src = Path(__file__).resolve().parents[1] / "scripts" / "macos" / "self_update.sh"

    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(origin)], check=True, capture_output=True)

    seed = tmp_path / "seed"
    subprocess.run(["git", "clone", str(origin), str(seed)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.name", "Test"], check=True)
    (seed / "version.txt").write_text("v1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "add", "version.txt"], check=True)
    subprocess.run(["git", "-C", str(seed), "commit", "-m", "v1"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "push", "-u", "origin", "main"], check=True, capture_output=True)

    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", str(origin), str(clone)], check=True, capture_output=True)
    initial_sha = subprocess.check_output(["git", "-C", str(clone), "rev-parse", "HEAD"], text=True).strip()

    # Push v2 to origin/main.
    (seed / "version.txt").write_text("v2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "commit", "-am", "v2"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "push", "origin", "main"], check=True, capture_output=True)
    new_sha = subprocess.check_output(["git", "-C", str(seed), "rev-parse", "HEAD"], text=True).strip()

    # Stub launchctl so we can observe kickstart calls on Linux too.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    kickstart_log = tmp_path / "launchctl.log"
    launchctl_stub = bin_dir / "launchctl"
    launchctl_stub.write_text(
        f'#!/usr/bin/env bash\necho "$@" >> "{kickstart_log}"\n',
        encoding="utf-8",
    )
    launchctl_stub.chmod(0o755)
    health_responses: list[int] = [1]

    class _HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            count = health_responses.pop(0) if len(health_responses) > 1 else health_responses[0]
            body = json.dumps({"ok": True, "active_sessions": count}).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            del format, args
            return

    server = HTTPServer(("127.0.0.1", 0), _HealthHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "BROWSER_SERVER_REPO_ROOT": str(clone),
            "BROWSER_SERVER_STATE_DIR": str(tmp_path / "state"),
            "BROWSER_SERVER_ENV_FILE": str(tmp_path / "nonexistent.env"),
            "BROWSER_SERVER_HEALTH_URL": f"http://127.0.0.1:{port}/healthz",
            "BROWSER_SERVER_SKIP_DEP_SYNC": "1",
        }
        # 1. Busy session before merge: must defer without advancing HEAD or restarting.
        busy_run = subprocess.run(["bash", str(script_src)], env=env, check=True, capture_output=True, text=True)
        assert "deferring update" in busy_run.stdout
        assert subprocess.check_output(["git", "-C", str(clone), "rev-parse", "HEAD"], text=True).strip() == initial_sha
        assert not kickstart_log.exists()

        # 2. Session becomes active while sync_deps runs (0 pre-merge -> 1 pre-restart):
        #    must roll back HEAD and skip restart.
        health_responses[:] = [0, 1]
        race_run = subprocess.run(["bash", str(script_src)], env=env, check=True, capture_output=True, text=True)
        assert "session became active during sync" in race_run.stdout
        assert subprocess.check_output(["git", "-C", str(clone), "rev-parse", "HEAD"], text=True).strip() == initial_sha
        assert not kickstart_log.exists()

        # 3. Idle throughout sync (0 pre-merge -> 0 pre-restart): must fast-forward HEAD and kickstart.
        health_responses[:] = [0, 0]
        idle_run = subprocess.run(["bash", str(script_src)], env=env, check=True, capture_output=True, text=True)
        assert "restarted" in idle_run.stdout
        assert subprocess.check_output(["git", "-C", str(clone), "rev-parse", "HEAD"], text=True).strip() == new_sha
        assert "kickstart -k" in kickstart_log.read_text(encoding="utf-8")
    finally:
        server.shutdown()
        thread.join(timeout=5)
