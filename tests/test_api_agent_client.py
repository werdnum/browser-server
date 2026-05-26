import asyncio

import pytest
from browser_handoff_service import main
from browser_handoff_service.main import app, novnc_proxy_url, registry
from browser_handoff_service.runtime import RemoteDisplayStatus
from httpx import ASGITransport, AsyncClient

TEST_SERVICE_TOKEN = "test-service-token"


@pytest.fixture(autouse=True)
def clear_registry():
    registry.sessions.clear()
    registry.locks.clear()
    registry.events.clear()
    registry.tokens.clear()
    registry.workers.clear()


@pytest.mark.asyncio
async def test_landing_page():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/")
        assert response.status_code == 200
        assert "Browser Handoff Service" in response.text
        assert "View Sessions" in response.text


@pytest.mark.asyncio
async def test_agent_side_service_flow_through_http_api(monkeypatch):
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_http"},
        )
        assert created.status_code == 200, created.text
        session_id = created.json()["session_id"]

        nav = await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=headers,
            json={"type": "navigate", "args": {"url": "https://example.test/checkout?token=secret"}},
        )
        assert nav.status_code == 200, nav.text
        assert nav.json()["result"]["url"] == "https://example.test/checkout"

        handoff = await client.post(
            f"/v1/sessions/{session_id}/handoff",
            headers=headers,
            json={"reason": "payment", "handoff_note": "Pay"},
        )
        assert handoff.status_code == 200, handoff.text
        token = handoff.json()["handoff_url"].split("token=", 1)[1]

        denied = await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=headers,
            json={"type": "current_page"},
        )
        assert denied.status_code == 403

        remote_before_claim = await client.get(f"/v1/sessions/{session_id}/remote", params={"token": token})
        assert remote_before_claim.status_code == 403

        claimed = await client.post(f"/v1/sessions/{session_id}/claim", json={"token": token})
        assert claimed.status_code == 200, claimed.text
        control_token = claimed.json()["control_token"]
        duplicate_claim = await client.post(f"/v1/sessions/{session_id}/claim", json={"token": token})
        assert duplicate_claim.status_code == 403
        old_token_remote = await client.get(f"/v1/sessions/{session_id}/remote", params={"token": token})
        assert old_token_remote.status_code == 403
        bad_remote = await client.get(f"/v1/sessions/{session_id}/remote", params={"token": "wrong"})
        assert bad_remote.status_code == 403
        monkeypatch.setattr(main, "remote_display_status", lambda: RemoteDisplayStatus(available=True))
        registry.workers[claimed.json()["worker_id"]].remote_url = "http://127.0.0.1:34147/vnc.html?autoconnect=1"
        remote = await client.get(f"/v1/sessions/{session_id}/remote", params={"token": control_token})
        assert remote.status_code == 200, remote.text
        assert remote.json()["novnc_url"].startswith(f"http://testserver/v1/sessions/{session_id}/novnc/vnc.html?")
        assert "34147" not in remote.json()["novnc_url"]
        assert f"novnc_{session_id}=" in remote.headers["set-cookie"]

        completed = await client.post(
            f"/v1/sessions/{session_id}/complete",
            json={"token": control_token, "outcome": "paid"},
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["state"] == "completed"


@pytest.mark.asyncio
async def test_service_auth_fails_closed_when_token_unset(monkeypatch):
    monkeypatch.delenv("BROWSER_HANDOFF_SERVICE_TOKEN", raising=False)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/sessions",
            headers={"authorization": f"Bearer {TEST_SERVICE_TOKEN}"},
            json={"conversation_id": "conv_auth"},
        )

    assert response.status_code == 503


@pytest.mark.asyncio
async def test_handoff_page_escapes_untrusted_agent_fields():
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_xss"},
        )
        session_id = created.json()["session_id"]
        handoff = await client.post(
            f"/v1/sessions/{session_id}/handoff",
            headers=headers,
            json={
                "reason": "other",
                "handoff_note": '<script>alert("x")</script><b>bold</b>',
            },
        )
        token = handoff.json()["handoff_url"].split("token=", 1)[1]

        no_token_page = await client.get(f"/sessions/{session_id}")
        assert no_token_page.status_code == 403
        bad_token_page = await client.get(f"/sessions/{session_id}", params={"token": "wrong"})
        assert bad_token_page.status_code == 403
        page = await client.get(f"/sessions/{session_id}", params={"token": token})

    assert page.status_code == 200
    assert '<p id="handoff-note"><script>' not in page.text
    assert "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;&lt;b&gt;bold&lt;/b&gt;" in page.text
    assert 'value="\\" autofocus' not in page.text


@pytest.mark.asyncio
async def test_expiry_loop_invokes_registry_reaper(monkeypatch):
    calls = {"sleep": 0, "reap": 0}

    async def fake_sleep(_seconds):
        calls["sleep"] += 1
        if calls["sleep"] > 1:
            raise asyncio.CancelledError()

    async def fake_reap_expired():
        calls["reap"] += 1
        return []

    monkeypatch.setattr(main.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(main.registry, "reap_expired", fake_reap_expired)

    with pytest.raises(asyncio.CancelledError):
        await main._expiry_loop()

    assert calls["reap"] == 1


@pytest.mark.asyncio
async def test_session_list_requires_service_auth():
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        unauthorized = await client.get("/sessions")
        assert unauthorized.status_code == 401

        authorized = await client.get("/sessions", headers=headers)
        assert authorized.status_code == 200


@pytest.mark.asyncio
async def test_events_unknown_session_returns_404():
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/v1/sessions/bs_missing/events", headers=headers)

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_novnc_proxy_rejects_requests_without_human_control_token(monkeypatch):
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post("/v1/sessions", headers=headers, json={"conversation_id": "conv_novnc_auth"})
        session_id = created.json()["session_id"]
        handoff = await client.post(
            f"/v1/sessions/{session_id}/handoff",
            headers=headers,
            json={"reason": "other", "handoff_note": "Review"},
        )
        handoff_token = handoff.json()["handoff_url"].split("token=", 1)[1]
        claimed = await client.post(f"/v1/sessions/{session_id}/claim", json={"token": handoff_token})

    monkeypatch.setattr(main, "remote_display_status", lambda: RemoteDisplayStatus(available=True))
    registry.workers[created.json()["worker_id"]].remote_url = "http://127.0.0.1:34147/vnc.html?autoconnect=1"
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        no_token = await client.get(f"/v1/sessions/{session_id}/novnc/vnc.html")
        old_token = await client.get(f"/v1/sessions/{session_id}/novnc/vnc.html", params={"token": handoff_token})

    assert claimed.status_code == 200
    assert no_token.status_code == 403
    assert old_token.status_code == 403


def test_remote_url_uses_authenticated_service_proxy():
    url = novnc_proxy_url(
        "bs_example",
        "https://handoff.example/base/",
        "http://127.0.0.1:34147/vnc.html?autoconnect=1&resize=remote",
    )

    assert url == (
        "https://handoff.example/v1/sessions/bs_example/novnc/vnc.html?"
        "autoconnect=1&resize=remote&path=%2Fv1%2Fsessions%2Fbs_example%2Fnovnc%2Fwebsockify"
    )
