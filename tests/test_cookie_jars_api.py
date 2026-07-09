"""Endpoint-level cookie-jar tests: auth gating, subject-scoped management, and the
never-return-cookie-values guarantee across the full save -> list -> get -> probe -> delete flow."""

from __future__ import annotations

import base64
import os
from typing import cast

import pytest
from browser_handoff_service import main
from browser_handoff_service.jars import JarStore, load_jar_keys
from browser_handoff_service.main import app, registry
from browser_handoff_service.runtime import FakeBrowserWorker
from httpx import ASGITransport, AsyncClient

TEST_SERVICE_TOKEN = "test-service-token"

SECRET_COOKIE_VALUE = "SUPERSECRETSESSION"
SECRET_LOCAL_VALUE = "SUPERSECRETLOCAL"
LOGIN_STATE = {
    "cookies": [
        {
            "name": "sid",
            "value": SECRET_COOKIE_VALUE,
            "domain": "shop.example.com",
            "path": "/",
            "expires": -1,
            "secure": True,
        },
    ],
    "origins": [
        {"origin": "https://shop.example.com", "localStorage": [{"name": "tok", "value": SECRET_LOCAL_VALUE}]},
    ],
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


def enable_jars(tmp_path, **kwargs) -> JarStore:
    os.environ["BROWSER_JAR_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
    keys = load_jar_keys()
    os.environ.pop("BROWSER_JAR_KEY", None)
    store = JarStore(tmp_path / "jars", keys=keys, **kwargs)
    registry.jar_store = store
    return store


def agent_headers() -> dict[str, str]:
    return {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


def oidc_headers(monkeypatch, subject: str = "user123") -> dict[str, str]:
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_ISSUER", "test-issuer")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience, issuer, options):
        if token.startswith("oidc-"):
            return {"sub": token[len("oidc-") :]}
        raise main.jwt.InvalidTokenError("invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)
    return {"authorization": f"Bearer oidc-{subject}"}


def client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


async def _save_human_jar(ac, monkeypatch, subject="user123", label="Shop", selector="[data-testid=logout]"):
    """Create a human OIDC session, seed a login, and save a jar via the control token."""
    headers = oidc_headers(monkeypatch, subject)
    resp = await ac.post("/v1/sessions", json={"conversation_id": "c1", "initial_owner": "human"}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    control_token = body["control_token"]
    worker = cast(FakeBrowserWorker, registry.workers[body["worker_id"]])
    worker.url = "https://shop.example.com/account"
    worker.storage_state = LOGIN_STATE
    save = await ac.post(
        f"/v1/sessions/{body['session_id']}/save-jar",
        json={"label": label, "token": control_token, "probe": {"logged_in_selector": selector}},
    )
    assert save.status_code == 200, save.text
    return save.json()


# --- keyless mode ---------------------------------------------------------


@pytest.mark.asyncio
async def test_keyless_mode_endpoints_503(tmp_path):
    registry.jar_store = JarStore(tmp_path / "jars", keys=[])
    async with client() as ac:
        assert (await ac.get("/v1/jars", headers=agent_headers())).status_code == 503
        # A create with jar_id fails closed (the load path raises JarDisabledError -> 503).
        resp = await ac.post(
            "/v1/sessions", json={"conversation_id": "c1", "jar_id": "jar_" + "a" * 32}, headers=agent_headers()
        )
        assert resp.status_code == 503


# --- load gating ----------------------------------------------------------


@pytest.mark.asyncio
async def test_direct_oidc_create_with_jar_id_rejected(tmp_path, monkeypatch):
    enable_jars(tmp_path)
    async with client() as ac:
        meta = await _save_human_jar(ac, monkeypatch)
        # A direct OIDC human create must not be able to load a jar (FA is the load chokepoint).
        headers = oidc_headers(monkeypatch)
        resp = await ac.post("/v1/sessions", json={"conversation_id": "c2", "jar_id": meta["jar_id"]}, headers=headers)
        assert resp.status_code == 403
        # The service (FA) path succeeds and reports the authenticated scope.
        ok = await ac.post(
            "/v1/sessions", json={"conversation_id": "c2", "jar_id": meta["jar_id"]}, headers=agent_headers()
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["jar_origins"] == ["https://shop.example.com"]
        assert ok.json()["confine_navigation"] is True


# --- never return cookie values ------------------------------------------


@pytest.mark.asyncio
async def test_cookie_values_never_returned_across_full_flow(tmp_path, monkeypatch):
    enable_jars(tmp_path)
    async with client() as ac:
        meta = await _save_human_jar(ac, monkeypatch)
        jar_id = meta["jar_id"]
        responses = [
            await ac.get("/v1/jars", headers=agent_headers()),
            await ac.get(f"/v1/jars/{jar_id}", headers=agent_headers()),
            await ac.post(f"/v1/jars/{jar_id}/probe", headers=agent_headers()),
            await ac.post("/v1/sessions", json={"conversation_id": "c9", "jar_id": jar_id}, headers=agent_headers()),
            await ac.delete(f"/v1/jars/{jar_id}", headers=agent_headers()),
        ]
        for resp in responses:
            assert resp.status_code == 200, resp.text
            assert SECRET_COOKIE_VALUE not in resp.text
            assert SECRET_LOCAL_VALUE not in resp.text
            # Probe internals never leak into listable metadata either.
            assert "logged_in_selector" not in resp.text and "data-testid" not in resp.text


# --- subject-scoped management -------------------------------------------


@pytest.mark.asyncio
async def test_oidc_management_is_subject_scoped(tmp_path, monkeypatch):
    enable_jars(tmp_path)
    async with client() as ac:
        mine = await _save_human_jar(ac, monkeypatch, subject="alice", label="Alice shop")
        theirs = await _save_human_jar(ac, monkeypatch, subject="bob", label="Bob shop")

        # Alice lists only her own jar.
        alice = oidc_headers(monkeypatch, "alice")
        listing = await ac.get("/v1/jars", headers=alice)
        ids = {j["jar_id"] for j in listing.json()}
        assert ids == {mine["jar_id"]}

        # Alice cannot get/delete/invalidate/probe Bob's jar.
        for verb, path in [
            ("get", f"/v1/jars/{theirs['jar_id']}"),
            ("delete", f"/v1/jars/{theirs['jar_id']}"),
            ("post", f"/v1/jars/{theirs['jar_id']}/invalidate"),
            ("post", f"/v1/jars/{theirs['jar_id']}/probe"),
        ]:
            resp = await getattr(ac, verb)(path, headers=oidc_headers(monkeypatch, "alice"))
            assert resp.status_code == 403, (verb, path, resp.status_code)

        # The service token sees and manages all jars.
        all_jars = await ac.get("/v1/jars", headers=agent_headers())
        assert {j["jar_id"] for j in all_jars.json()} == {mine["jar_id"], theirs["jar_id"]}
        assert (await ac.get(f"/v1/jars/{theirs['jar_id']}", headers=agent_headers())).status_code == 200


@pytest.mark.asyncio
async def test_agent_save_requires_service_token(tmp_path, monkeypatch):
    enable_jars(tmp_path)
    async with client() as ac:
        # Agent-owned session.
        created = await ac.post("/v1/sessions", json={"conversation_id": "c1"}, headers=agent_headers())
        sid = created.json()["session_id"]
        cast(FakeBrowserWorker, registry.workers[created.json()["worker_id"]]).storage_state = LOGIN_STATE
        await ac.post(
            f"/v1/sessions/{sid}/agent-command",
            json={"type": "navigate", "args": {"url": "https://shop.example.com/home"}},
            headers=agent_headers(),
        )
        # No service token and no control token -> rejected.
        resp = await ac.post(
            f"/v1/sessions/{sid}/save-jar",
            json={"label": "Shop", "origins": ["https://shop.example.com"], "probe": {"logged_in_selector": "[x]"}},
        )
        assert resp.status_code == 401
        # With the service token it succeeds.
        ok = await ac.post(
            f"/v1/sessions/{sid}/save-jar",
            json={"label": "Shop", "origins": ["https://shop.example.com"], "probe": {"logged_in_selector": "[x]"}},
            headers=agent_headers(),
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["saved_by"] == "agent"


# --- UI -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jars_ui_page_lists_own_jars(tmp_path, monkeypatch):
    enable_jars(tmp_path)
    async with client() as ac:
        await _save_human_jar(ac, monkeypatch, subject="alice", label="Alice Woolies")
        await _save_human_jar(ac, monkeypatch, subject="bob", label="Bob Coles")
        page = await ac.get("/jars", headers=oidc_headers(monkeypatch, "alice"))
        assert page.status_code == 200
        assert "Alice Woolies" in page.text
        assert "Bob Coles" not in page.text
        # Cookie values never appear in the rendered page.
        assert SECRET_COOKIE_VALUE not in page.text


@pytest.mark.asyncio
async def test_detail_endpoint_marks_rolled_back_jar_invalidated(tmp_path, monkeypatch):
    # GET /v1/jars/{id} must agree with list_meta: a jar rolled back behind a tombstone reads as
    # needing re-login even though its cleartext file still says invalidated_at is null.
    enable_jars(tmp_path)
    async with client() as ac:
        meta = await _save_human_jar(ac, monkeypatch)
        jar_id = meta["jar_id"]
        path = tmp_path / "jars" / f"{jar_id}.json"
        snapshot = path.read_bytes()  # pre-invalidation file (invalidated_at None)
        registry.jar_store.invalidate(jar_id)  # tombstone the generation
        path.write_bytes(snapshot)  # restore the older file: cleartext now lies "usable"

        resp = await ac.get(f"/v1/jars/{jar_id}", headers=agent_headers())
        assert resp.status_code == 200, resp.text
        assert resp.json()["invalidated_at"] is not None


@pytest.mark.asyncio
async def test_save_button_hidden_when_save_auth_gate_enabled(tmp_path, monkeypatch):
    # With the gate off the built-in "Save this login" button is offered; with the gate on it is
    # hidden, because this generic UI cannot supply the FA-issued save authorization.
    enable_jars(tmp_path)
    async with client() as ac:
        headers = oidc_headers(monkeypatch, "user123")
        body = (
            await ac.post("/v1/sessions", json={"conversation_id": "c1", "initial_owner": "human"}, headers=headers)
        ).json()
        page = await ac.get(f"/sessions/{body['session_id']}?token={body['control_token']}")
        assert page.status_code == 200
        assert 'id="save-jar"' in page.text

    registry.jar_store.require_save_authorization = True
    async with client() as ac:
        headers = oidc_headers(monkeypatch, "user123")
        body = (
            await ac.post("/v1/sessions", json={"conversation_id": "c2", "initial_owner": "human"}, headers=headers)
        ).json()
        page = await ac.get(f"/sessions/{body['session_id']}?token={body['control_token']}")
        assert page.status_code == 200
        assert 'id="save-jar"' not in page.text


@pytest.mark.asyncio
async def test_malformed_jar_id_rejected_on_service_read(tmp_path):
    # A malformed jar_id must be a 400 on the service-token detail read too, not a synthetic 200
    # stub that only the mutating paths would later reject.
    enable_jars(tmp_path)
    async with client() as ac:
        resp = await ac.get("/v1/jars/not-a-jar", headers=agent_headers())
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_service_token_can_delete_jar_after_key_rotation(tmp_path, monkeypatch):
    # A jar under a rotated/removed key can no longer be decrypted, but the service-token
    # "forget" kill-switch must still work (management must not decrypt to authorize the service).
    from browser_handoff_service.jars import JarStore, load_jar_keys

    enable_jars(tmp_path)
    async with client() as ac:
        meta = await _save_human_jar(ac, monkeypatch)
        jar_id = meta["jar_id"]
        # Rotate to a brand-new key (old key removed), pointing at the same jar dir.
        os.environ["BROWSER_JAR_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
        rotated_keys = load_jar_keys()
        os.environ.pop("BROWSER_JAR_KEY", None)
        registry.jar_store = JarStore(tmp_path / "jars", keys=rotated_keys)

        # Load fails closed (rotation), but the service token can still delete.
        create = await ac.post(
            "/v1/sessions", json={"conversation_id": "c9", "jar_id": jar_id}, headers=agent_headers()
        )
        assert create.status_code == 409
        deleted = await ac.delete(f"/v1/jars/{jar_id}", headers=agent_headers())
        assert deleted.status_code == 200, deleted.text
        assert not (tmp_path / "jars" / f"{jar_id}.json").exists()
