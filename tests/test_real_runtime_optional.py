import base64
import os
import shutil
import subprocess
import time
import urllib.parse
from collections.abc import Generator

import pytest
from browser_handoff_service.main import app, registry
from browser_handoff_service.models import AgentCommandRequest
from browser_handoff_service.runtime import (
    PlaywrightBrowserWorker,
    RuntimeUnavailable,
    StorageTooLarge,
    _free_display_number,
    remote_display_status,
)
from httpx import ASGITransport, AsyncClient

TEST_SERVICE_TOKEN = "test-service-token"

_WEBGL_FIXTURE_HTML = """<!doctype html>
<html><body><script>
(() => {
  let lostCount = 0;
  const probe = (kind) => {
    const c = document.createElement('canvas');
    c.width = 16;
    c.height = 16;
    c.addEventListener('webglcontextlost', () => { lostCount += 1; });
    const gl = c.getContext(kind);
    if (!gl) return { ok: false };
    gl.clearColor(1.0, 0.0, 0.5, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    const px = new Uint8Array(4);
    gl.readPixels(8, 8, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px);
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    return {
      ok: !gl.isContextLost(),
      pixel: Array.from(px),
      vendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
      renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
      ref: { c, gl },
    };
  };
  const w1 = probe('webgl');
  const w2 = probe('webgl2');
  window.__glRefs = [w1, w2];
  const report = () => {
    document.body.dataset.webgl = JSON.stringify({
      lostCount,
      webgl: {
        ok: Boolean(w1.ok && w1.ref && !w1.ref.gl.isContextLost()),
        pixel: w1.pixel || null,
        vendor: w1.vendor || '',
        renderer: w1.renderer || '',
      },
      webgl2: {
        ok: Boolean(w2.ok && w2.ref && !w2.ref.gl.isContextLost()),
        pixel: w2.pixel || null,
        vendor: w2.vendor || '',
        renderer: w2.renderer || '',
      },
    });
  };
  report();
  setTimeout(report, 150);
})();
</script></body></html>"""


@pytest.fixture
def xvfb_display() -> Generator[str, None, None]:
    xvfb_path = shutil.which("Xvfb")
    if xvfb_path is None:
        pytest.skip("Xvfb unavailable on this host")
    display_number = _free_display_number()
    display = f":{display_number}"
    socket_path = f"/tmp/.X11-unix/X{display_number}"
    proc = subprocess.Popen(
        [xvfb_path, display, "-screen", "0", "1280x720x24", "+extension", "GLX", "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not os.path.exists(socket_path):
            if proc.poll() is not None:
                pytest.fail(f"Xvfb exited early with code {proc.returncode}")
            if time.monotonic() >= deadline:
                pytest.fail(f"Xvfb socket {socket_path} did not appear within 5s")
            time.sleep(0.05)
        yield display
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


async def _assert_worker_webgl_renders(worker: PlaywrightBrowserWorker) -> None:
    data_url = "data:text/html," + urllib.parse.quote(_WEBGL_FIXTURE_HTML)
    await worker.command(AgentCommandRequest(type="navigate", args={"url": data_url}))
    executed = await worker.command(
        AgentCommandRequest(
            type="exec",
            args={
                "code": (
                    "new Promise((resolve) => setTimeout(() => resolve(JSON.parse(document.body.dataset.webgl)), 200))"
                )
            },
        )
    )
    report = executed["result"]
    assert report["lostCount"] == 0, report
    for kind in ("webgl", "webgl2"):
        info = report[kind]
        assert info["ok"] is True, (kind, report)
        r, g, b, a = info["pixel"]
        assert abs(r - 255) <= 2 and abs(g - 0) <= 2 and abs(b - 128) <= 2 and a == 255, (kind, info)
        assert info["vendor"], (kind, info)
        assert info["renderer"], (kind, info)


@pytest.mark.asyncio
async def test_real_local_chromium_runtime_smoke(monkeypatch):
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    worker = PlaywrightBrowserWorker("worker_real_smoke")
    try:
        await worker.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real local Chromium unavailable on this host: {exc}")
    try:
        result = await worker.command(
            AgentCommandRequest(
                type="navigate",
                args={
                    "url": "data:text/html,%3Chtml%3E%3Chead%3E%3Ctitle%3Efixture%3C/title%3E%3C/head%3E%3Cbody%3E%3Ch1%3ECheckout%3C/h1%3E%3C/body%3E%3C/html%3E"
                },
            )
        )
        assert result["title"] == "fixture"
        snapshot = await worker.command(AgentCommandRequest(type="snapshot"))
        assert snapshot["title"] == "fixture"
        assert snapshot["elements"] >= 1
        names = _collect_names(snapshot["roots"])
        assert any("Checkout" in name for name in names)
        assert all(node["ref"].startswith("e") for node in snapshot["roots"])

        screenshot = await worker.command(AgentCommandRequest(type="screenshot"))
        assert screenshot["mime_type"] == "image/png"
        assert base64.b64decode(screenshot["image_base64"])[:8] == b"\x89PNG\r\n\x1a\n"

        extracted = await worker.command(AgentCommandRequest(type="extract"))
        assert "Checkout" in extracted["html"]

        executed = await worker.command(AgentCommandRequest(type="exec", args={"code": "document.title"}))
        assert executed["result"] == "fixture"
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_real_chromium_webgl_available(monkeypatch):
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    worker = PlaywrightBrowserWorker("worker_real_webgl")
    try:
        await worker.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real local Chromium unavailable on this host: {exc}")
    try:
        await _assert_worker_webgl_renders(worker)
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_headed_xvfb_persistent_webgl_available(monkeypatch, xvfb_display):
    """Exercise the production GPU-less Xvfb path (headed persistent context): WebGL1 and
    WebGL2 must initialize, render pixels, and stay live without an async GPU-channel
    context-loss fallback race."""
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", "1")
    monkeypatch.setenv("DISPLAY", xvfb_display)
    worker = PlaywrightBrowserWorker("worker_headed_webgl", headed=True)
    try:
        await worker.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real local Chromium unavailable on this host: {exc}")
    try:
        await _assert_worker_webgl_renders(worker)
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_real_chromium_jar_seed_export_and_confinement(monkeypatch):
    """Exercise the real Playwright explicit-context path the fake runtime can't: seed a
    storage_state at context creation, export it back out, and confine navigation. No network
    is needed — the seeded cookie is accepted at context creation and confinement aborts an
    off-scope navigation pre-request."""
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    seed = {
        "cookies": [
            {
                "name": "sid",
                "value": "SEEDEDSESSIONVALUE",
                "domain": "allowed.example",
                "path": "/",
                "expires": -1,
                "httpOnly": False,
                "secure": True,
                "sameSite": "Lax",
            }
        ],
        "origins": [],
    }
    worker = PlaywrightBrowserWorker("worker_jar_real", storage_state=seed, confine_origins=["https://allowed.example"])
    try:
        await worker.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real local Chromium unavailable on this host: {exc}")
    try:
        # The seeded cookie survives a real new_context + storage_state export round-trip.
        state = await worker.export_storage_state(5 * 1024 * 1024)
        assert "cookies" in state and "origins" in state
        assert any(c["name"] == "sid" and c["value"] == "SEEDEDSESSIONVALUE" for c in state["cookies"])

        # A tiny budget makes the bounded export raise rather than materialize.
        with pytest.raises(StorageTooLarge):
            await worker.export_storage_state(1)

        # Confinement aborts an off-scope top-level navigation before any request is sent.
        blocked = await worker.command(AgentCommandRequest(type="navigate", args={"url": "https://blocked.example/"}))
        assert blocked.get("blocked") is True
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_headless_desktop_session_does_not_advertise_headless_chrome(monkeypatch):
    """A headless desktop session must not leak the "HeadlessChrome" product token, and must
    still report the running build's own version rather than a pinned literal."""
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    worker = PlaywrightBrowserWorker("worker_real_ua", headed=False)
    try:
        await worker.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real local Chromium unavailable on this host: {exc}")
    try:
        result = await worker.command(AgentCommandRequest(type="exec", args={"code": "navigator.userAgent"}))
        user_agent = result["result"]
        assert "HeadlessChrome" not in user_agent
        assert "Chrome/" in user_agent

        # The UA must match the browser actually running, not a frozen string.
        assert worker._browser is not None
        major = worker._browser.version.split(".")[0]
        assert f"Chrome/{major}." in user_agent
    finally:
        await worker.close()


def _collect_names(nodes: list[dict]) -> list[str]:
    names: list[str] = []
    for node in nodes:
        names.append(node.get("name", ""))
        names.extend(_collect_names(node.get("children", [])))
    return names


def test_novnc_stack_readiness_is_reported_from_real_binaries():
    status = remote_display_status()
    if os.environ.get("REQUIRE_NOVNC") == "1":
        assert status.available, status.reason
    else:
        assert isinstance(status.available, bool)
        if status.available:
            assert status.novnc_path and status.websockify_path and status.xvfb_path and status.x11vnc_path


@pytest.mark.asyncio
async def test_headed_novnc_assets_are_served_through_authenticated_service_proxy(monkeypatch):
    status = remote_display_status()
    if not status.available:
        if os.environ.get("REQUIRE_NOVNC") == "1":
            pytest.fail(status.reason or "noVNC stack unavailable")
        pytest.skip(f"noVNC stack unavailable on this host: {status.reason}")

    registry.sessions.clear()
    registry.locks.clear()
    registry.events.clear()
    registry.tokens.clear()
    registry.workers.clear()
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    monkeypatch.setenv("BROWSER_HEADED", "1")
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post("/v1/sessions", headers=headers, json={"conversation_id": "conv_novnc_real"})
        if created.status_code == 503 and os.environ.get("REQUIRE_NOVNC") != "1":
            pytest.skip(f"headed Playwright/noVNC runtime unavailable: {created.text}")
        assert created.status_code == 200, created.text
        session_id = created.json()["session_id"]
        handoff = await client.post(
            f"/v1/sessions/{session_id}/handoff",
            headers=headers,
            json={"reason": "other", "handoff_note": "Review"},
        )
        handoff.raise_for_status()
        handoff_token = handoff.json()["handoff_url"].split("token=", 1)[1]
        claimed = await client.post(f"/v1/sessions/{session_id}/claim", json={"token": handoff_token})
        claimed.raise_for_status()
        remote = await client.get(
            f"/v1/sessions/{session_id}/remote", params={"token": claimed.json()["control_token"]}
        )
        remote.raise_for_status()
        novnc_url = remote.json()["novnc_url"]
        assert f"/v1/sessions/{session_id}/novnc/vnc.html" in novnc_url
        assert "127.0.0.1" not in novnc_url
        asset = await client.get(novnc_url)
        assert asset.status_code == 200, asset.text[:200]
        assert "noVNC" in asset.text

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        denied = await client.get(novnc_url)
    assert denied.status_code == 403
    await registry.close(session_id)


@pytest.mark.asyncio
async def test_real_chromium_cdp_screencast_streams_jpeg_and_dispatches_input(monkeypatch):
    import asyncio

    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    worker = PlaywrightBrowserWorker("real_screencast_test", headed=False, width=800, height=600)
    try:
        await worker.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real local Chromium unavailable on this host: {exc}")

    screencast = None
    try:
        html = (
            "<!doctype html><html><body style='margin:0;background:#1d4ed8'>"
            "<input id='box' style='position:absolute;left:20px;top:20px;width:240px;height:48px;font-size:20px' />"
            "</body></html>"
        )
        data_url = "data:text/html," + urllib.parse.quote(html)
        await worker.command(AgentCommandRequest(type="navigate", args={"url": data_url}))

        screencast = await worker.open_screencast()
        frame = await asyncio.wait_for(screencast.next_event(), timeout=5.0)
        assert frame["type"] == "frame"
        raw = base64.b64decode(frame["data"])
        assert raw[:3] == b"\xff\xd8\xff"
        assert frame["width"] > 0
        assert frame["height"] > 0

        await screencast.dispatch_input({"type": "mouse", "action": "click", "x": 60, "y": 40, "button": "left"})
        await screencast.dispatch_input({"type": "text", "text": "hello tart"})
        val = await worker.command(
            AgentCommandRequest(type="exec", args={"code": "document.getElementById('box').value"})
        )
        assert val["result"] == "hello tart"
    finally:
        if screencast is not None:
            await screencast.close()
        await worker.close()
