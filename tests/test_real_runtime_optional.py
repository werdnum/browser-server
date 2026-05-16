import os

import pytest
from browser_handoff_service.main import app, registry
from browser_handoff_service.models import AgentCommandRequest
from browser_handoff_service.runtime import PlaywrightBrowserWorker, RuntimeUnavailable, remote_display_status
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
        assert "Checkout" in snapshot["nodes"][0]["text"]
    finally:
        await worker.close()


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
