import base64
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from browser_handoff_service.main import app, registry
from browser_handoff_service.models import AgentCommandRequest
from browser_handoff_service.runtime import (
    PlaywrightBrowserWorker,
    RuntimeUnavailable,
    StorageTooLarge,
    remote_display_status,
)
from browser_handoff_service.web_bot_auth import WebBotAuthSigner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient

TEST_SERVICE_TOKEN = "test-service-token"


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


class _RecordingHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, dict[str, str]]]

    def do_GET(self) -> None:
        self.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
        if self.path == "/":
            body = (
                b'<html><head><title>signed</title></head><body><img src="/pixel.gif">'
                b"<script>fetch('/api', {headers: {'Signature': 'app=:AAAA:'}})</script></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=abc; Path=/")
        else:
            body = b"GIF89a"
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


def _verify_web_bot_auth(headers: dict[str, str], authority: str, public_key) -> None:
    signature_input = headers["signature-input"].removeprefix("sig1=")
    assert signature_input.startswith('("@authority" "signature-agent");')
    assert ';tag="web-bot-auth"' in signature_input
    base = "\n".join(
        [
            f'"@authority": {authority}',
            f'"signature-agent": {headers["signature-agent"]}',
            f'"@signature-params": {signature_input}',
        ]
    )
    signature = base64.b64decode(headers["signature"].removeprefix("sig1=:").removesuffix(":"))
    public_key.verify(signature, base.encode("ascii"))


@pytest.mark.asyncio
@pytest.mark.parametrize("confined", [False, True])
async def test_real_chromium_signs_every_request_with_web_bot_auth(monkeypatch, confined):
    """Documents and subresources both carry a verifiable signature, the browser's own cookies
    still go out alongside it, and the confinement guard (which continues the request after the
    signing handler falls back to it) keeps the signed headers."""
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    handler = type("Handler", (_RecordingHandler,), {"requests": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    authority = f"127.0.0.1:{server.server_port}"
    origin = f"http://{authority}"
    key = Ed25519PrivateKey.generate()
    signer = WebBotAuthSigner(key, signature_agent="https://bot.example.com")
    worker = PlaywrightBrowserWorker(
        "worker_web_bot_auth", web_bot_auth=signer, confine_origins=[origin] if confined else None
    )
    try:
        try:
            await worker.start()
        except RuntimeUnavailable as exc:
            pytest.skip(f"real local Chromium unavailable on this host: {exc}")
        for _ in range(2):
            result = await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{origin}/"}))
            assert result["title"] == "signed"
    finally:
        await worker.close()
        server.shutdown()

    paths = [path for path, _ in handler.requests]
    assert "/" in paths and "/pixel.gif" in paths and "/api" in paths
    for path, headers in handler.requests:
        if path == "/api":
            # The page's own RFC 9421 signature goes out untouched and unaccompanied.
            assert headers["signature"] == "app=:AAAA:"
            assert "signature-input" not in headers and "signature-agent" not in headers
            continue
        assert headers["signature-agent"] == '"https://bot.example.com"'
        _verify_web_bot_auth(headers, authority, key.public_key())
    documents = [headers for path, headers in handler.requests if path == "/"]
    assert "session=abc" in documents[-1].get("cookie", "")
