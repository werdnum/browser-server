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
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        unauthorized = await client.get("/")
        assert unauthorized.status_code == 401

        response = await client.get("/", headers=headers)
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

        forwarded_remote = await client.get(
            f"/v1/sessions/{session_id}/remote",
            params={"token": control_token},
            headers={"x-forwarded-proto": "https,http", "x-forwarded-host": "browser.andrewgarrett.dev"},
        )
        assert forwarded_remote.status_code == 200, forwarded_remote.text
        assert forwarded_remote.json()["novnc_url"].startswith(
            f"https://browser.andrewgarrett.dev/v1/sessions/{session_id}/novnc/vnc.html?"
        )
        assert "secure" in forwarded_remote.headers["set-cookie"].lower()

        forwarded_prefixed_remote = await client.get(
            f"/v1/sessions/{session_id}/remote",
            params={"token": control_token},
            headers={
                "x-forwarded-proto": "https",
                "x-forwarded-host": "browser.andrewgarrett.dev",
                "x-forwarded-prefix": "/browser",
            },
        )
        assert forwarded_prefixed_remote.status_code == 200, forwarded_prefixed_remote.text
        assert forwarded_prefixed_remote.json()["novnc_url"].startswith(
            f"https://browser.andrewgarrett.dev/browser/v1/sessions/{session_id}/novnc/vnc.html?"
        )
        assert (
            f"path=%2Fbrowser%2Fv1%2Fsessions%2F{session_id}%2Fnovnc%2Fwebsockify"
            in forwarded_prefixed_remote.json()["novnc_url"]
        )

        completed = await client.post(
            f"/v1/sessions/{session_id}/complete",
            json={"token": control_token, "outcome": "paid"},
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["state"] == "completed"


@pytest.mark.asyncio
async def test_human_started_session_hands_over_to_agent_through_http_api():
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers={
                **headers,
                "x-forwarded-proto": "https",
                "x-forwarded-host": "browser.andrewgarrett.dev",
            },
            json={"conversation_id": "conv_human_first", "initial_owner": "human"},
        )
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["state"] == "human_active"
        assert body["lease_owner"] == "human"
        session_id = body["session_id"]
        control_token = body["control_token"]
        assert body["session_url"] == (f"https://browser.andrewgarrett.dev/sessions/{session_id}?token={control_token}")

        # The agent has no lease while the human drives the freshly started session.
        denied = await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=headers,
            json={"type": "current_page"},
        )
        assert denied.status_code == 403

        page = await client.get(f"/sessions/{session_id}", params={"token": control_token})
        assert page.status_code == 200
        assert "Hand over to agent" in page.text

        # The user hands over: this parks the session and mints a token for the agent.
        handover = await client.post(
            f"/v1/sessions/{session_id}/handover",
            json={"token": control_token, "handoff_note": "Search for flights"},
        )
        assert handover.status_code == 200, handover.text
        handover_body = handover.json()
        assert handover_body["state"] == "handover_requested"
        handover_token = handover_body["handover_token"]
        assert handover_body["agent_claim_url"].endswith(f"/v1/sessions/{session_id}/agent-claim")

        # The session page still loads (state + cancel) if the user reloads while pending.
        pending_page = await client.get(f"/sessions/{session_id}", params={"token": control_token})
        assert pending_page.status_code == 200
        assert "Handover pending" in pending_page.text

        # The agent has no lease until it claims with the handover token.
        not_yet = await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=headers,
            json={"type": "current_page"},
        )
        assert not_yet.status_code == 403

        # Claiming requires service auth in addition to the handover token.
        unauth_claim = await client.post(
            f"/v1/sessions/{session_id}/agent-claim",
            json={"token": handover_token},
        )
        assert unauth_claim.status_code == 401

        claimed = await client.post(
            f"/v1/sessions/{session_id}/agent-claim",
            headers=headers,
            json={"token": handover_token},
        )
        assert claimed.status_code == 200, claimed.text
        assert claimed.json()["state"] == "agent_active"
        assert claimed.json()["lease_owner"] == "agent"

        # The agent can now drive the browser the human set up.
        nav = await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=headers,
            json={"type": "navigate", "args": {"url": "https://example.test/flights"}},
        )
        assert nav.status_code == 200, nav.text

        # The handover token is one-time.
        reused = await client.post(
            f"/v1/sessions/{session_id}/agent-claim",
            headers=headers,
            json={"token": handover_token},
        )
        assert reused.status_code == 409


@pytest.mark.asyncio
async def test_visual_control_commands_accepted_by_http_model():
    """Regression: visual-control commands must not 422 at the Pydantic model layer.

    This test exercises the HTTP request path (ASGITransport → FastAPI → Pydantic) so
    that any future omission from AgentCommandRequest.type is caught at test time rather
    than discovered via live 422 errors.
    """
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post("/v1/sessions", headers=headers, json={"conversation_id": "conv_visual_http"})
        assert created.status_code == 200, created.text
        session_id = created.json()["session_id"]

        await client.post(
            f"/v1/sessions/{session_id}/agent-command",
            headers=headers,
            json={"type": "navigate", "args": {"url": "https://example.test/"}},
        )

        commands = [
            {"type": "mouse_click", "args": {"x": 100, "y": 200}},
            {"type": "mouse_move", "args": {"x": 50, "y": 50}},
            {"type": "mouse_down"},
            {"type": "mouse_up"},
            {"type": "mouse_wheel", "args": {"delta_x": 0, "delta_y": 100}},
            {"type": "keyboard_type", "args": {"text": "hello"}},
            {"type": "keyboard_press", "args": {"key": "Enter"}},
            {"type": "navigate_back"},
            {"type": "navigate_forward"},
        ]
        for cmd in commands:
            resp = await client.post(
                f"/v1/sessions/{session_id}/agent-command",
                headers=headers,
                json=cmd,
            )
            assert resp.status_code == 200, f"command {cmd['type']!r} got {resp.status_code}: {resp.text}"


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
        "https://handoff.example/base/v1/sessions/bs_example/novnc/vnc.html?"
        "autoconnect=1&resize=remote&path=%2Fbase%2Fv1%2Fsessions%2Fbs_example%2Fnovnc%2Fwebsockify"
    )


def test_remote_url_uses_authenticated_service_proxy_without_prefix():
    url = novnc_proxy_url(
        "bs_example",
        "https://handoff.example/",
        "http://127.0.0.1:34147/vnc.html?autoconnect=1&resize=remote",
    )

    assert url == (
        "https://handoff.example/v1/sessions/bs_example/novnc/vnc.html?"
        "autoconnect=1&resize=remote&path=%2Fv1%2Fsessions%2Fbs_example%2Fnovnc%2Fwebsockify"
    )


@pytest.mark.asyncio
async def test_public_url_override_replaces_internal_request_host(monkeypatch):
    """A configured external URL must win over the (possibly internal) request host so we
    never hand a cluster-internal address to a user or agent."""
    monkeypatch.setenv(main.PUBLIC_URL_ENV, "https://browser.example.com/app/")
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://browser.default.svc.cluster.local") as client:
        created = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_public_url", "initial_owner": "human"},
        )
        assert created.status_code == 200, created.text
        body = created.json()
        session_id = body["session_id"]
        control_token = body["control_token"]
        assert body["session_url"] == (f"https://browser.example.com/app/sessions/{session_id}?token={control_token}")

        handover = await client.post(
            f"/v1/sessions/{session_id}/handover",
            json={"token": control_token, "handoff_note": "take over"},
        )
        assert handover.status_code == 200, handover.text
        assert handover.json()["agent_claim_url"] == (
            f"https://browser.example.com/app/v1/sessions/{session_id}/agent-claim"
        )

        # The session page must carry the path prefix so its own API calls stay under /app.
        page = await client.get(f"/sessions/{session_id}", params={"token": control_token})
        assert page.status_code == 200
        assert 'data-base-path="/app"' in page.text


@pytest.mark.asyncio
async def test_public_url_override_rejects_relative_value(monkeypatch):
    monkeypatch.setenv(main.PUBLIC_URL_ENV, "browser.example.com")
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_bad_public_url", "initial_owner": "human"},
        )
        assert created.status_code == 500, created.text
        assert main.PUBLIC_URL_ENV in created.json()["detail"]
