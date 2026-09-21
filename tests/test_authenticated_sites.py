"""Authenticated-site sessions: what creating one fixes, and what it takes away.

The session type is the enforcement point, so these tests drive the HTTP API rather than the
registry: every protection has to hold for a caller who asks for the opposite.
"""

from __future__ import annotations

import asyncio
import base64
import os
from typing import cast

import pytest
from browser_handoff_service import main
from browser_handoff_service.jars import JarStore, load_jar_keys
from browser_handoff_service.main import app, registry
from browser_handoff_service.runtime import FakeBrowserWorker
from httpx import ASGITransport, AsyncClient
from starlette.websockets import WebSocket

TEST_SERVICE_TOKEN = "test-service-token"

SITE = "https://shop.example.com"
AUX = "https://auth.example.com"

LOGIN_STATE = {
    "cookies": [{"name": "sid", "value": "SESSION", "domain": "shop.example.com", "path": "/", "expires": -1}],
    "origins": [],
}


@pytest.fixture(autouse=True)
def fake_runtime(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)


@pytest.fixture(autouse=True)
def clear_registry():
    original_store = registry.jar_store
    for attr in ("sessions", "locks", "events", "tokens", "workers", "jar_locks"):
        getattr(registry, attr).clear()
    main._jwks_client = None
    yield
    for attr in ("sessions", "locks", "events", "tokens", "workers", "jar_locks"):
        getattr(registry, attr).clear()
    registry.jar_store = original_store
    main._jwks_client = None


def client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


def agent_headers() -> dict[str, str]:
    return {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


def enable_jars(tmp_path) -> JarStore:
    os.environ["BROWSER_JAR_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
    keys = load_jar_keys()
    os.environ.pop("BROWSER_JAR_KEY", None)
    store = JarStore(tmp_path / "jars", keys=keys)
    registry.jar_store = store
    return store


def oidc_headers(monkeypatch, subject: str = "user123") -> dict[str, str]:
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_ISSUER", "test-issuer")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience, issuer, options, leeway):
        if token.startswith("oidc-"):
            return {"sub": token[len("oidc-") :]}
        raise main.jwt.InvalidTokenError("invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)
    return {"authorization": f"Bearer oidc-{subject}"}


async def _save_jar(ac, monkeypatch, nav_allowlist: list[str] | None = None) -> dict:
    headers = oidc_headers(monkeypatch)
    resp = await ac.post("/v1/sessions", json={"conversation_id": "c0", "initial_owner": "human"}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    worker = cast(FakeBrowserWorker, registry.workers[body["worker_id"]])
    worker.url = f"{SITE}/account"
    worker.storage_state = LOGIN_STATE
    save = await ac.post(
        f"/v1/sessions/{body['session_id']}/save-jar",
        json={
            "label": "Shop",
            "token": body["control_token"],
            "origins": [SITE],
            "nav_allowlist": nav_allowlist or [],
            "probe": {"logged_in_selector": "[data-testid=logout]"},
        },
    )
    assert save.status_code == 200, save.text
    return save.json()


async def _authenticated_session(ac, **overrides) -> dict:
    payload = {
        "conversation_id": "c1",
        "authenticated_site": True,
        "confine_origins": [SITE],
        "credential_alias": "shop-login",
    }
    payload.update(overrides)
    resp = await ac.post("/v1/sessions", json=payload, headers=agent_headers())
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- session creation -----------------------------------------------------


@pytest.mark.asyncio
async def test_jarless_authenticated_session_reports_and_enforces_its_confinement():
    async with client() as ac:
        session = await _authenticated_session(ac, confine_origins=[f"{SITE}/login?next=1", AUX])
        # The record states the set actually enforced, normalized, so the creator can verify it.
        assert session["confine_origins"] == [SITE, AUX]
        assert session["authenticated_site"] is True
        assert session["confine_navigation"] is True
        assert session["allow_exec"] is False
        assert session["credential_alias"] == "shop-login"
        assert session["jar_id"] is None

        worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
        assert worker.confine_origins == [SITE, AUX]
        blocked = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": "navigate", "args": {"url": "https://evil.example.com/"}},
            headers=agent_headers(),
        )
        assert blocked.json()["result"]["blocked"] is True


@pytest.mark.asyncio
async def test_jarless_confinement_matches_a_jar_loaded_session(tmp_path, monkeypatch):
    """The jarless path is the same route guard, not a second implementation."""
    enable_jars(tmp_path)
    async with client() as ac:
        meta = await _save_jar(ac, monkeypatch, nav_allowlist=[AUX])
        jar_session = await _authenticated_session(ac, jar_id=meta["jar_id"], confine_origins=[SITE, AUX])
        jarless = await _authenticated_session(ac, confine_origins=[SITE, AUX])
        assert jar_session["confine_origins"] == jarless["confine_origins"] == [SITE, AUX]
        for session in (jar_session, jarless):
            worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
            assert worker.confine_origins == [SITE, AUX]
            for url, expect_blocked in ((f"{AUX}/sso", False), ("https://evil.example.com/", True)):
                resp = await ac.post(
                    f"/v1/sessions/{session['session_id']}/agent-command",
                    json={"type": "navigate", "args": {"url": url}},
                    headers=agent_headers(),
                )
                assert resp.json()["result"].get("blocked", False) is expect_blocked


@pytest.mark.asyncio
async def test_jar_and_explicit_confinement_must_agree(tmp_path, monkeypatch):
    enable_jars(tmp_path)
    async with client() as ac:
        meta = await _save_jar(ac, monkeypatch, nav_allowlist=[AUX])
        mismatch = await ac.post(
            "/v1/sessions",
            json={
                "conversation_id": "c1",
                "authenticated_site": True,
                "jar_id": meta["jar_id"],
                # Missing the jar's nav allowlist entry: the caller verified a narrower set than
                # the session would actually enforce.
                "confine_origins": [SITE],
            },
            headers=agent_headers(),
        )
        assert mismatch.status_code == 400
        assert "confinement mismatch" in mismatch.json()["detail"]


@pytest.mark.parametrize(
    ("payload", "detail"),
    [
        ({"authenticated_site": True, "allow_exec": True, "confine_origins": [SITE]}, "allow_exec"),
        (
            {"authenticated_site": True, "confine_navigation": False, "confine_origins": [SITE]},
            "confine_navigation",
        ),
        ({"authenticated_site": True}, "confine_origins"),
        ({"authenticated_site": True, "confine_origins": []}, "confine_origins"),
        ({"confine_origins": [SITE]}, "confine_origins requires authenticated_site"),
        ({"credential_alias": "x"}, "credential_alias requires authenticated_site"),
        ({"authenticated_site": True, "confine_origins": ["not-an-origin"]}, "not an exact origin"),
    ],
)
@pytest.mark.asyncio
async def test_incoherent_authenticated_site_requests_are_rejected(payload, detail):
    async with client() as ac:
        resp = await ac.post("/v1/sessions", json={"conversation_id": "c1", **payload}, headers=agent_headers())
        assert resp.status_code == 400, resp.text
        assert detail in resp.json()["detail"]


@pytest.mark.asyncio
async def test_oidc_callers_cannot_create_authenticated_site_sessions(monkeypatch):
    async with client() as ac:
        headers = oidc_headers(monkeypatch)
        for payload in (
            {"authenticated_site": True, "confine_origins": [SITE]},
            {"credential_alias": "shop-login"},
            {"confine_origins": [SITE]},
        ):
            resp = await ac.post("/v1/sessions", json={"conversation_id": "c1", **payload}, headers=headers)
            assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_a_human_handoff_keeps_the_session_confined():
    """A parked authenticated-site session is still origin-confined; nothing widens it."""
    async with client() as ac:
        session = await _authenticated_session(ac)
        worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
        resp = await ac.post(
            f"/v1/sessions/{session['session_id']}/handoff",
            json={"reason": "captcha", "allowed_resume": "never"},
            headers=agent_headers(),
        )
        assert resp.status_code == 200, resp.text
        assert worker._confinement_active is True


# --- read-back protection -------------------------------------------------


@pytest.mark.asyncio
async def test_exec_and_extract_are_denied_before_any_fill():
    async with client() as ac:
        session = await _authenticated_session(ac)
        for command in ({"type": "exec", "args": {"code": "document.cookie"}}, {"type": "extract", "args": {}}):
            resp = await ac.post(
                f"/v1/sessions/{session['session_id']}/agent-command", json=command, headers=agent_headers()
            )
            assert resp.status_code == 403, resp.text
            assert "authenticated-site session" in resp.json()["detail"]


@pytest.mark.parametrize(
    ("keys", "denied"),
    [
        ("Control+c", True),
        ("Control+KeyC", True),
        ("Control+KeyX", True),
        ("Control+KeyV", True),
        ("Meta+KeyC", True),
        ("ControlOrMeta+KeyV", True),
        ("Meta+V", True),
        ("Control+x", True),
        ("Control+Insert", True),
        ("Shift+Insert", True),
        ("Shift+Delete", True),
        # Playwright resolves this per platform; it is the same chord under a third spelling.
        ("ControlOrMeta+c", True),
        ("controlormeta+V", True),
        ("Enter", False),
        ("Control+a", False),
        ("Tab", False),
    ],
)
@pytest.mark.asyncio
async def test_transfer_chords_are_denied(keys, denied):
    async with client() as ac:
        session = await _authenticated_session(ac)
        for command_type, arg in (("press_key", "key"), ("keyboard_press", "keys")):
            resp = await ac.post(
                f"/v1/sessions/{session['session_id']}/agent-command",
                json={"type": command_type, "args": {arg: keys}},
                headers=agent_headers(),
            )
            assert (resp.status_code == 403) is denied, resp.text


@pytest.mark.parametrize(
    ("command_type", "args"),
    [
        # press_key presses args["key"] and ignores args["keys"], so a decoy in the argument the
        # runtime does not read must not make the chord look innocent.
        ("press_key", {"key": "Control+c", "keys": "Tab"}),
        ("keyboard_press", {"keys": "Control+c", "key": "Tab"}),
        # keyboard_press falls back to args["key"] when "keys" is absent.
        ("keyboard_press", {"key": "Control+v"}),
    ],
)
@pytest.mark.asyncio
async def test_the_chord_guard_reads_the_key_the_runtime_presses(command_type, args):
    async with client() as ac:
        session = await _authenticated_session(ac)
        resp = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": command_type, "args": args},
            headers=agent_headers(),
        )
        assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_a_decoy_in_an_unread_argument_does_not_deny_an_innocent_press():
    """The mirror runs both ways: press_key ignores "keys", so a chord there is not the key the
    browser receives and must not block an ordinary Tab."""
    async with client() as ac:
        session = await _authenticated_session(ac)
        resp = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": "press_key", "args": {"key": "Tab", "keys": "Control+c"}},
            headers=agent_headers(),
        )
        assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_typing_into_a_protected_control_is_still_allowed():
    """Writing is not leaking: the fence is on moving a value out, not putting one in."""
    async with client() as ac:
        session = await _authenticated_session(ac)
        worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
        worker.url = f"{SITE}/login"
        await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": "snapshot", "args": {}},
            headers=agent_headers(),
        )
        resp = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": "type_text", "args": {"ref": worker._ref, "text": "someone@example.com"}},
            headers=agent_headers(),
        )
        assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_screenshots_mask_protected_controls():
    async with client() as ac:
        session = await _authenticated_session(ac)
        worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
        assert worker.mask_protected is True
        ordinary = await ac.post("/v1/sessions", json={"conversation_id": "c2"}, headers=agent_headers())
        assert cast(FakeBrowserWorker, registry.workers[ordinary.json()["worker_id"]]).mask_protected is False


@pytest.mark.asyncio
async def test_a_password_field_is_masked_in_every_snapshot():
    async with client() as ac:
        session = await _authenticated_session(ac)
        worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
        worker.url = f"{SITE}/login"
        worker.autofill_fields = [
            {"ref": "e40", "input_type": "email", "name": "Email"},
            {"ref": "e41", "input_type": "password", "name": "Password"},
        ]
        worker.filled = [
            {"ref": "e40", "kind": "username", "value": "someone@example.com"},
            {"ref": "e41", "kind": "password", "value": "hunter2"},
        ]
        resp = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": "snapshot", "args": {}},
            headers=agent_headers(),
        )
        assert resp.status_code == 200, resp.text
        assert "hunter2" not in resp.text
        nodes = {node["ref"]: node for node in resp.json()["result"]["roots"] if node["ref"].startswith("e4")}
        assert nodes["e41"]["value_masked"] is True
        assert nodes["e41"]["has_value"] is True
        assert "value" not in nodes["e41"]
        # An ordinary field is untouched: blanket masking buys nothing and costs the task.
        assert nodes["e40"]["value"] == "someone@example.com"


# --- handoff and handback -------------------------------------------------


async def _park_with_human(ac, session: dict) -> str:
    """Hand the session to a human and claim it, as an MFA/captcha detour does."""
    handoff = await ac.post(
        f"/v1/sessions/{session['session_id']}/handoff",
        json={"reason": "otp", "allowed_resume": "never"},
        headers=agent_headers(),
    )
    assert handoff.status_code == 200, handoff.text
    token = handoff.json()["handoff_url"].split("token=")[1]
    claim = await ac.post(f"/v1/sessions/{session['session_id']}/claim", json={"token": token})
    assert claim.status_code == 200, claim.text
    return claim.json()["control_token"]


@pytest.mark.asyncio
async def test_a_parked_authenticated_site_session_can_be_handed_back():
    """The detour has to be a round trip: a run that parks for an MFA code and can never come
    back has not parked, it has ended."""
    async with client() as ac:
        session = await _authenticated_session(ac)
        worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
        control_token = await _park_with_human(ac, session)
        worker.url = f"{SITE}/verify-its-you"

        handover = await ac.post(
            f"/v1/sessions/{session['session_id']}/handover",
            json={"token": control_token, "handoff_note": "code entered"},
            headers=agent_headers(),
        )
        assert handover.status_code == 200, handover.text

        state = await ac.get(f"/v1/sessions/{session['session_id']}", headers=agent_headers())
        # state and lease_owner are what trusted orchestration polls on; both are on the record,
        # and "the human has handed back" reads as state == handover_requested.
        assert state.json()["state"] == "handover_requested"
        assert state.json()["lease_owner"] == "service"
        assert state.json()["allowed_resume"] == "after_sanitize"

        # The human's page is gone and a fresh one is open inside the confinement set.
        assert worker.url == SITE

        claimed = await ac.post(f"/v1/sessions/{session['session_id']}/agent-claim", headers=agent_headers())
        assert claimed.status_code == 200, claimed.text
        assert claimed.json()["state"] == "agent_active"
        assert claimed.json()["lease_owner"] == "agent"
        # Confinement is never lifted for these sessions, and the claim re-asserts it.
        assert worker._confinement_active is True
        resumed = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": "navigate", "args": {"url": "https://evil.example.com/"}},
            headers=agent_headers(),
        )
        assert resumed.json()["result"]["blocked"] is True


@pytest.mark.asyncio
async def test_the_human_page_is_sanitized_before_the_agent_sees_it():
    async with client() as ac:
        session = await _authenticated_session(ac)
        worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
        control_token = await _park_with_human(ac, session)
        worker.url = f"{SITE}/mid-form?step=2"
        worker.nav_error_urls = {SITE}

        handover = await ac.post(
            f"/v1/sessions/{session['session_id']}/handover",
            json={"token": control_token},
            headers=agent_headers(),
        )
        assert handover.status_code == 200, handover.text
        # The reopen failed (site down); the page stays blank rather than keeping the human's.
        assert worker.url is None
        state = await ac.get(f"/v1/sessions/{session['session_id']}", headers=agent_headers())
        # Nothing about the human's page survives onto the record the agent can read.
        assert state.json()["current_url_redacted"] is None
        assert state.json()["current_origin"] is None


@pytest.mark.asyncio
async def test_authenticated_handback_mints_no_token_and_revokes_human_control():
    async with client() as ac:
        session = await _authenticated_session(ac)
        control_token = await _park_with_human(ac, session)
        handover = await ac.post(
            f"/v1/sessions/{session['session_id']}/handover",
            json={"token": control_token},
            headers=agent_headers(),
        )
        assert handover.json()["handover_token"] is None
        assert (
            await ac.post(f"/v1/sessions/{session['session_id']}/agent-claim", headers=agent_headers())
        ).status_code == 200

        # A repeated claim and reuse of the human control token are refused.
        replay = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-claim",
            headers=agent_headers(),
        )
        assert replay.status_code == 409
        cancel = await ac.post(f"/v1/sessions/{session['session_id']}/cancel", json={"token": control_token})
        assert cancel.status_code == 403


@pytest.mark.asyncio
async def test_a_tokenless_claim_is_refused_outside_an_authenticated_site_session():
    async with client() as ac:
        create = await ac.post(
            "/v1/sessions", json={"conversation_id": "c1", "initial_owner": "human"}, headers=agent_headers()
        )
        session = create.json()
        handover = await ac.post(
            f"/v1/sessions/{session['session_id']}/handover",
            json={"token": session["control_token"]},
            headers=agent_headers(),
        )
        assert handover.status_code == 200, handover.text
        # An ordinary session still requires the one-time handover token.
        assert (
            await ac.post(f"/v1/sessions/{session['session_id']}/agent-claim", headers=agent_headers())
        ).status_code == 403
        assert (
            await ac.post(
                f"/v1/sessions/{session['session_id']}/agent-claim",
                json={"token": handover.json()["handover_token"]},
                headers=agent_headers(),
            )
        ).status_code == 200


@pytest.mark.asyncio
async def test_a_tokenless_claim_only_works_while_a_handover_is_pending():
    async with client() as ac:
        session = await _authenticated_session(ac)
        # Agent-owned, no handover outstanding: nothing to claim.
        assert (
            await ac.post(f"/v1/sessions/{session['session_id']}/agent-claim", headers=agent_headers())
        ).status_code == 409
        await _park_with_human(ac, session)
        # Human-owned but the human has not handed back: still nothing to claim.
        assert (
            await ac.post(f"/v1/sessions/{session['session_id']}/agent-claim", headers=agent_headers())
        ).status_code == 409


@pytest.mark.asyncio
async def test_an_ordinary_jar_loaded_session_still_cannot_be_handed_to_an_agent(tmp_path, monkeypatch):
    """The widening premise still holds where confinement can be lifted, so the refusal stands."""
    enable_jars(tmp_path)
    async with client() as ac:
        meta = await _save_jar(ac, monkeypatch)
        create = await ac.post(
            "/v1/sessions",
            json={"conversation_id": "c1", "jar_id": meta["jar_id"], "initial_owner": "human"},
            headers=agent_headers(),
        )
        session = create.json()
        handover = await ac.post(
            f"/v1/sessions/{session['session_id']}/handover",
            json={"token": session["control_token"]},
            headers=agent_headers(),
        )
        assert handover.status_code == 409
        assert "jar-loaded session cannot be handed to an agent" in handover.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("command_type", ["close_page", "navigate"])
async def test_failed_sanitization_never_publishes_claimable_state(monkeypatch, command_type):
    async with client() as ac:
        session = await _authenticated_session(ac)
        control_token = await _park_with_human(ac, session)
        worker = registry.workers[session["worker_id"]]
        original = worker.command

        async def failing_command(req):
            if req.type == command_type:
                raise RuntimeError("browser disconnected")
            return await original(req)

        monkeypatch.setattr(worker, "command", failing_command)
        with pytest.raises(RuntimeError, match="browser disconnected"):
            await registry.handover(session["session_id"], control_token, "")
        response = await ac.post(f"/v1/sessions/{session['session_id']}/agent-claim", headers=agent_headers())
        assert response.status_code == 409
        assert registry.get(session["session_id"]).state.value == "human_active"


@pytest.mark.asyncio
async def test_authenticated_handoff_page_uses_resume_instructions():
    async with client() as ac:
        session = await _authenticated_session(ac)
        html = main.SESSION_DETAIL_TEMPLATE.render(
            session=registry.get(session["session_id"]),
            token="control",
            base_path="",
            viewport_width=1280,
            viewport_height=720,
            save_jar_available=False,
        )
    assert "Tell your assistant to continue the website task" in html
    assert 'id="handover-token"' not in html
    assert "Copy the message below" not in html


@pytest.mark.asyncio
async def test_oidc_human_can_serialize_inactive_authenticated_site_defaults(monkeypatch):
    async with client() as ac:
        response = await ac.post(
            "/v1/sessions",
            json={
                "conversation_id": "ordinary-human",
                "authenticated_site": False,
                "confine_origins": None,
                "credential_alias": None,
            },
            headers=oidc_headers(monkeypatch),
        )
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "human_active"
        assert response.json()["authenticated_site"] is False


@pytest.mark.asyncio
async def test_live_novnc_bridge_stops_forwarding_after_handback():
    async with client() as ac:
        session = await _authenticated_session(ac)
        token = await _park_with_human(ac, session)
        session_id = session["session_id"]
        sent = []
        closed = asyncio.Event()

        class Upstream:
            async def send(self, data):
                sent.append(data)

            async def close(self, code=1000):
                assert code == 1008
                closed.set()

            def __aiter__(self):
                return self.messages()

            async def messages(self):
                await closed.wait()
                yield b"late-screen-frame"

        class Client:
            count = 0

            async def receive(self):
                self.count += 1
                if self.count == 2:
                    await registry.handover(session_id, token, "done")
                    await registry.agent_claim(session_id, None)
                return {"type": "websocket.receive", "bytes": b"human-input"}

        await main._bridge_websockets(cast(WebSocket, Client()), Upstream(), session_id=session_id, token=token)
        assert sent == [b"human-input"]
        assert closed.is_set()
        assert registry.get(session_id).state.value == "agent_active"
        assert not registry.workers[session["worker_id"]].closed
