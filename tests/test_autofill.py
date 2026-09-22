"""Autofill: one release, one fill, and the plaintext goes nowhere else.

Keychute is faked at the transport, so the whole protocol runs — create, wait, grant lookup,
single-use read — without a second implementation of the flow to drift from the real one.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
import pytest
from browser_handoff_service import main
from browser_handoff_service.jars import JarStore, load_jar_keys
from browser_handoff_service.keychute import KeychuteClient
from browser_handoff_service.main import app, registry
from browser_handoff_service.models import AUTOFILL_FILL_CAP, LeaseOwner, SessionState
from browser_handoff_service.runtime import FakeBrowserWorker
from httpx import ASGITransport, AsyncClient

TEST_SERVICE_TOKEN = "test-service-token"

SITE = "https://shop.example.com"
PASSWORD = "hunter2-correct-horse"
USERNAME = "someone@example.com"

LOGIN_FIELDS: list[dict[str, Any]] = [
    {"ref": "e10", "input_type": "email", "autocomplete": "username", "name": "Email"},
    {"ref": "e11", "input_type": "password", "name": "Password"},
]


@pytest.fixture(autouse=True)
def fake_runtime(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)


@pytest.fixture(autouse=True)
def clear_registry():
    original = registry.keychute
    for attr in ("sessions", "locks", "events", "tokens", "workers", "jar_locks"):
        getattr(registry, attr).clear()
    main._jwks_client = None
    yield
    for attr in ("sessions", "locks", "events", "tokens", "workers", "jar_locks"):
        getattr(registry, attr).clear()
    registry.keychute = original
    main._jwks_client = None


class FakeKeychute:
    """A Keychute that behaves like the real one for the parts autofill uses."""

    def __init__(self, secret: str | dict[str, str] | None = None) -> None:
        self.secret = secret if secret is not None else {"username": USERNAME, "password": PASSWORD}
        self.state = "approved"
        # None => the request's own origin is granted (the ordinary standing-row case).
        self.granted_host: str | None = None
        self.granted_port: int | None = None
        self.revoked = False
        self.grant_info_unavailable = False
        self.lose_request_response = False
        self.mechanism = "autofill"
        self.expired = False
        self.reads = 0
        self.requests: list[dict[str, Any]] = []
        self.wait_calls = 0
        self.on_wait = None
        self.grant_id = str(uuid.uuid4())
        self.request_ids: dict[str, str] = {}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/access-requests" and request.method == "POST":
            body = json.loads(request.content)
            self.requests.append(body)
            # Idempotent by key, exactly as the real server is.
            request_id = self.request_ids.setdefault(body["idempotency_key"], str(uuid.uuid4()))
            if self.lose_request_response:
                raise httpx.ReadError("response lost", request=request)
            return httpx.Response(201, json=self._status(request_id))
        if path.endswith("/wait"):
            self.wait_calls += 1
            if self.on_wait is not None:
                self.on_wait()
            request_id = path.split("/")[3]
            return httpx.Response(200, json=self._status(request_id))
        if path.startswith("/v1/grants/") and path.endswith("/read"):
            self.reads += 1
            if self.reads > 1:
                return httpx.Response(410, json={"error": {"code": "grant-exhausted", "message": "already read"}})
            secret = self.secret if isinstance(self.secret, str) else json.dumps(self.secret)
            return httpx.Response(
                200, json={"secret": secret, "encoding": "utf8", "secret_version_id": str(uuid.uuid4())}
            )
        if path.startswith("/v1/grants/"):
            if self.grant_info_unavailable:
                return httpx.Response(503, json={"error": {"code": "unavailable", "message": "retry later"}})
            now = datetime.now(UTC)
            origin: dict[str, Any] = {"host": self.granted_host or "shop.example.com"}
            if self.granted_port is not None:
                origin["port"] = self.granted_port
            return httpx.Response(
                200,
                json={
                    "grant_id": self.grant_id,
                    "mechanism": self.mechanism,
                    "constraints": {
                        "origins": [origin],
                        "methods": [],
                        "path_prefixes": [],
                        "ttl_seconds": 600,
                        "max_uses": 1,
                    },
                    "not_after": (now - timedelta(seconds=1) if self.expired else now + timedelta(minutes=10))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "max_uses": 1,
                    "use_count": self.reads,
                    "revoked": self.revoked,
                    "server_time": now.isoformat().replace("+00:00", "Z"),
                },
            )
        return httpx.Response(404, json={"error": {"code": "not-found", "message": "not found"}})

    def _status(self, request_id: str) -> dict[str, Any]:
        status: dict[str, Any] = {
            "request_id": request_id,
            "state": self.state,
            "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        }
        if self.state == "approved":
            status["grant_id"] = self.grant_id
        if self.state == "denied":
            status["deny_reason"] = "the operator said no"
        return status


@pytest.fixture
def keychute(monkeypatch) -> FakeKeychute:
    fake = FakeKeychute()
    monkeypatch.setenv("BROWSER_KEYCHUTE_URL", "https://keychute.internal")
    monkeypatch.setenv("BROWSER_KEYCHUTE_TOKEN", "test-keychute-token")
    registry.keychute = KeychuteClient(transport=fake.transport())
    return fake


def client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


def agent_headers() -> dict[str, str]:
    return {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


async def _session(ac, **overrides) -> tuple[dict, FakeBrowserWorker]:
    payload: dict[str, Any] = {
        "conversation_id": "c1",
        "authenticated_site": True,
        "confine_origins": [SITE],
        "credential_alias": "shop-login",
    }
    payload.update(overrides)
    resp = await ac.post("/v1/sessions", json=payload, headers=agent_headers())
    assert resp.status_code == 200, resp.text
    session = resp.json()
    worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
    worker.url = f"{SITE}/login"
    worker.autofill_fields = [dict(field) for field in LOGIN_FIELDS]
    return session, worker


async def _autofill(ac, session_id: str, **body) -> httpx.Response:
    payload: dict[str, Any] = {"step_key": "password"}
    payload.update(body)
    return await ac.post(f"/v1/sessions/{session_id}/autofill", json=payload, headers=agent_headers())


# --- the fill itself ------------------------------------------------------


@pytest.mark.asyncio
async def test_a_fill_places_the_secret_and_reports_only_metadata(keychute, caplog):
    caplog.set_level(logging.DEBUG)
    async with client() as ac:
        session, worker = await _session(ac)
        resp = await _autofill(ac, session["session_id"])
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "filled"
        assert body["origin"] == SITE
        assert sorted(entry["kind"] for entry in body["filled"]) == ["password", "username"]
        assert {entry["ref"] for entry in body["filled"]} == {"e10", "e11"}

        # The values reached the page...
        assert {entry["ref"]: entry["value"] for entry in worker.filled} == {"e10": USERNAME, "e11": PASSWORD}
        # ...and nowhere the model can see. Every channel the service owns is checked, not just
        # the response that happened to carry the outcome.
        state = await ac.get(f"/v1/sessions/{session['session_id']}", headers=agent_headers())
        snapshot = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": "snapshot", "args": {}},
            headers=agent_headers(),
        )
        for response in (resp, state, snapshot):
            assert PASSWORD not in response.text
        # The event log is read directly: /events is an endless SSE stream, and what matters is
        # what it would ever emit.
        events = [event.model_dump_json() for event in registry.events[session["session_id"]]]
        assert events and not any(PASSWORD in event for event in events)
        assert PASSWORD not in caplog.text
        # The filled control is protected from here on, whatever its type becomes.
        assert "e11" in worker.protected_refs
        assert snapshot.json()["result"]["roots"][2]["value_masked"] is True

        # One request, one read: the grant is spent by the fill it was granted for.
        assert keychute.reads == 1
        assert len(keychute.requests) == 1
        request = keychute.requests[0]
        assert request["idempotency_key"] == f"{session['session_id']}:password"
        assert request["secret_name"] == "shop-login"
        assert request["mechanism"] == "autofill"
        assert request["constraints"]["origins"] == [{"host": "shop.example.com", "port": 443}]
        # An empty list subsets only an empty list, which is what lets a standing row match.
        assert request["constraints"]["methods"] == []
        assert request["constraints"]["path_prefixes"] == []
        assert request["constraints"]["max_uses"] == 1
        assert request["context"]["structured"]["origin"] == SITE


@pytest.mark.asyncio
async def test_a_bare_string_secret_fills_the_password(keychute):
    keychute.secret = PASSWORD
    async with client() as ac:
        session, worker = await _session(ac)
        resp = await _autofill(ac, session["session_id"], fields=[{"ref": "e11", "kind": "password"}])
        assert resp.json()["status"] == "filled", resp.text
        assert worker.filled == [{"ref": "e11", "kind": "password", "value": PASSWORD}]


@pytest.mark.asyncio
async def test_a_password_keeps_its_exact_bytes(keychute):
    """A stored password may begin or end with whitespace. Trimming it would look like a wrong
    password at the site rather than like the bug it is."""
    keychute.secret = "  spaced out\t"
    async with client() as ac:
        session, worker = await _session(ac)
        resp = await _autofill(ac, session["session_id"], fields=[{"ref": "e11", "kind": "password"}])
        assert resp.json()["status"] == "filled", resp.text
        assert worker.filled == [{"ref": "e11", "kind": "password", "value": "  spaced out\t"}]


@pytest.mark.asyncio
async def test_an_all_whitespace_password_is_still_a_password(keychute):
    keychute.secret = "   "
    async with client() as ac:
        session, worker = await _session(ac)
        resp = await _autofill(ac, session["session_id"], fields=[{"ref": "e11", "kind": "password"}])
        assert resp.json()["status"] == "filled", resp.text
        assert worker.filled == [{"ref": "e11", "kind": "password", "value": "   "}]


@pytest.mark.asyncio
async def test_a_json_looking_string_that_is_not_an_object_is_the_password(keychute):
    keychute.secret = "[1, 2, 3]"
    async with client() as ac:
        session, worker = await _session(ac)
        resp = await _autofill(ac, session["session_id"], fields=[{"ref": "e11", "kind": "password"}])
        assert resp.json()["status"] == "filled", resp.text
        assert worker.filled == [{"ref": "e11", "kind": "password", "value": "[1, 2, 3]"}]


@pytest.mark.asyncio
async def test_a_username_fill_does_not_make_the_control_look_like_a_password_field(keychute):
    """Masking and field identity are separate questions. A filled username is masked, but it is
    still not a password field — otherwise the next auto-detect sees two of them."""
    async with client() as ac:
        session, worker = await _session(ac)
        first = await _autofill(
            ac, session["session_id"], step_key="username", fields=[{"ref": "e10", "kind": "username"}]
        )
        assert first.json()["status"] == "filled", first.text
        assert "e10" in worker.protected_refs

        keychute.reads = 0
        keychute.grant_id = str(uuid.uuid4())
        second = await _autofill(ac, session["session_id"], step_key="password")
        assert second.json()["status"] == "filled", second.text
        # Auto-detect still names exactly one password, and it is the password input.
        assert [entry["kind"] for entry in second.json()["filled"] if entry["ref"] == "e11"] == ["password"]
        assert not any(entry["ref"] == "e10" and entry["kind"] == "password" for entry in second.json()["filled"])


@pytest.mark.asyncio
async def test_a_username_only_form_is_not_mistaken_for_a_password_form(keychute):
    async with client() as ac:
        session, worker = await _session(ac)
        worker.autofill_fields = [{"ref": "e10", "input_type": "email", "autocomplete": "username"}]
        first = await _autofill(
            ac, session["session_id"], step_key="username", fields=[{"ref": "e10", "kind": "username"}]
        )
        assert first.json()["status"] == "filled", first.text

        keychute.reads = 0
        keychute.grant_id = str(uuid.uuid4())
        second = await _autofill(ac, session["session_id"], step_key="password")
        # The one control on the page is a filled username; it is not also the password field.
        assert [entry["kind"] for entry in second.json()["filled"]] == ["username"], second.text


@pytest.mark.asyncio
async def test_a_secret_without_the_requested_kind_is_refused(keychute):
    keychute.secret = PASSWORD
    async with client() as ac:
        session, _ = await _session(ac)
        resp = await _autofill(ac, session["session_id"], fields=[{"ref": "e10", "kind": "username"}])
        assert resp.json()["reason"] == "grant_invalid", resp.text


# --- destination and element checks ---------------------------------------


@pytest.mark.asyncio
async def test_a_grant_for_another_origin_does_not_fill_this_one(keychute):
    """An origin the session may navigate is not thereby an origin the fill may target."""
    keychute.granted_host = "auth.example.com"
    async with client() as ac:
        session, worker = await _session(ac)
        resp = await _autofill(ac, session["session_id"])
        assert resp.json()["reason"] == "wrong_origin", resp.text
        assert worker.filled == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda kc: setattr(kc, "revoked", True), "grant_invalid"),
        (lambda kc: setattr(kc, "expired", True), "grant_invalid"),
        (lambda kc: setattr(kc, "mechanism", "brokered"), "grant_invalid"),
        (lambda kc: setattr(kc, "state", "denied"), "policy_denied"),
        (lambda kc: setattr(kc, "state", "expired"), "request_expired"),
    ],
)
async def test_an_unusable_release_never_reaches_the_page(keychute, mutate, reason):
    mutate(keychute)
    async with client() as ac:
        session, worker = await _session(ac)
        resp = await _autofill(ac, session["session_id"])
        assert resp.json()["reason"] == reason, resp.text
        assert worker.filled == []
        assert keychute.reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fields", "spec", "reason"),
    [
        (
            [{"ref": "e11", "input_type": "password", "iframe": True}],
            [{"ref": "e11", "kind": "password"}],
            "in_iframe",
        ),
        (
            [{"ref": "e11", "input_type": "password", "autocomplete": "new-password"}],
            [{"ref": "e11", "kind": "password"}],
            "new_password_field",
        ),
        (
            [{"ref": "e10", "input_type": "email"}],
            [{"ref": "e10", "kind": "password"}],
            "no_eligible_field",
        ),
        (
            [{"ref": "e11", "input_type": "password"}, {"ref": "e12", "input_type": "password"}],
            None,
            "ambiguous_fields",
        ),
        ([{"ref": "e11", "input_type": "password"}], [{"ref": "e99", "kind": "password"}], "stale_ref"),
        ([], None, "no_eligible_field"),
    ],
)
async def test_a_field_that_cannot_take_the_fill_is_refused_not_guessed(keychute, fields, spec, reason):
    async with client() as ac:
        session, worker = await _session(ac)
        worker.autofill_fields = fields
        resp = await _autofill(ac, session["session_id"], **({"fields": spec} if spec else {}))
        assert resp.json()["reason"] == reason, resp.text
        # Refused before anything was released: an element check costs no grant.
        assert keychute.reads == 0 and not keychute.requests


@pytest.mark.asyncio
async def test_an_iframe_only_password_is_named_as_such(keychute):
    async with client() as ac:
        session, worker = await _session(ac)
        worker.autofill_fields = [{"ref": "e11", "input_type": "password", "iframe": True}]
        resp = await _autofill(ac, session["session_id"])
        assert resp.json()["reason"] == "in_iframe", resp.text


@pytest.mark.asyncio
async def test_a_document_outside_the_confinement_set_is_never_filled(keychute):
    async with client() as ac:
        session, worker = await _session(ac)
        worker.url = None
        resp = await _autofill(ac, session["session_id"])
        assert resp.json()["reason"] == "wrong_origin", resp.text
        assert not keychute.requests


# --- serialization --------------------------------------------------------


@pytest.mark.asyncio
async def test_a_navigation_during_the_approval_wait_invalidates_the_target(keychute):
    """The site can navigate itself while an approval is pending; the fill must not land on
    whatever is there now."""
    keychute.state = "approved"

    async with client() as ac:
        session, worker = await _session(ac)
        keychute.state = "pending"

        def navigate_away() -> None:
            # Answer the wait with an approval, but replace the document first.
            keychute.state = "approved"
            worker.url = f"{SITE}/somewhere-else"
            worker._autofill_nonce = None

        keychute.on_wait = navigate_away
        resp = await _autofill(ac, session["session_id"], wait_seconds=1)
        assert resp.json()["reason"] == "target_invalidated", resp.text
        assert worker.filled == []
        # The grant's single read is unspent, so the retry after a re-snapshot can still use it.
        assert keychute.reads == 0


@pytest.mark.asyncio
async def test_a_pending_decision_parks_and_a_retry_reuses_the_same_request(keychute):
    keychute.state = "pending"
    async with client() as ac:
        session, _ = await _session(ac)
        first = await _autofill(ac, session["session_id"], wait_seconds=1)
        assert first.json()["status"] == "approval_pending"
        request_id = first.json()["request_id"]
        assert registry.sessions[session["session_id"]].autofill_pending["password"].request_id == request_id

        second = await _autofill(ac, session["session_id"], wait_seconds=1)
        assert second.json()["request_id"] == request_id
        # Same step, same idempotency key: a retry resumes the decision rather than opening a
        # second one for the operator to answer.
        assert {req["idempotency_key"] for req in keychute.requests} == {f"{session['session_id']}:password"}
        assert {req["context"]["reason"] for req in keychute.requests} == {
            f"Autofill shop-login login on {SITE} for the configured user (step password)"
        }


# --- session-level gates --------------------------------------------------


@pytest.mark.asyncio
async def test_an_ordinary_session_has_no_autofill(keychute):
    async with client() as ac:
        resp = await ac.post("/v1/sessions", json={"conversation_id": "c1"}, headers=agent_headers())
        session = resp.json()
        out = await _autofill(ac, session["session_id"])
        assert out.json()["reason"] == "not_authenticated_site", out.text
        assert not keychute.requests


@pytest.mark.asyncio
async def test_a_session_with_no_alias_has_no_autofill(keychute):
    async with client() as ac:
        session, _ = await _session(ac, credential_alias=None)
        resp = await _autofill(ac, session["session_id"])
        assert resp.json()["reason"] == "no_alias", resp.text
        assert not keychute.requests


@pytest.mark.asyncio
async def test_a_reported_bad_password_ends_autofill_for_the_session(keychute):
    async with client() as ac:
        session, worker = await _session(ac)
        assert (await _autofill(ac, session["session_id"])).json()["status"] == "filled"
        outcome = await ac.post(
            f"/v1/sessions/{session['session_id']}/autofill/outcome",
            json={"outcome": "bad_password"},
            headers=agent_headers(),
        )
        assert outcome.status_code == 200, outcome.text
        assert outcome.json()["autofill_bad_password"] is True
        worker.filled = []
        again = await _autofill(ac, session["session_id"], step_key="password-2")
        assert again.json()["reason"] == "bad_password_recorded", again.text
        assert worker.filled == []


@pytest.mark.asyncio
async def test_the_fill_cap_is_a_deterministic_backstop(keychute):
    async with client() as ac:
        session, _ = await _session(ac)
        for step in range(AUTOFILL_FILL_CAP):
            keychute.reads = 0
            keychute.grant_id = str(uuid.uuid4())
            resp = await _autofill(ac, session["session_id"], step_key=f"password-{step}")
            assert resp.json()["status"] == "filled", resp.text
        capped = await _autofill(ac, session["session_id"], step_key="one-too-many")
        assert capped.json()["reason"] == "fill_cap_reached", capped.text


@pytest.mark.asyncio
async def test_autofill_without_a_configured_broker_refuses(monkeypatch):
    monkeypatch.delenv("BROWSER_KEYCHUTE_URL", raising=False)
    monkeypatch.delenv("BROWSER_KEYCHUTE_TOKEN", raising=False)
    monkeypatch.delenv("BROWSER_KEYCHUTE_TOKEN_FILE", raising=False)
    registry.keychute = KeychuteClient()
    async with client() as ac:
        session, _ = await _session(ac)
        resp = await _autofill(ac, session["session_id"])
        assert resp.json()["reason"] == "keychute_unavailable", resp.text


@pytest.mark.asyncio
async def test_a_broker_outage_is_an_outcome_not_a_500(monkeypatch, keychute):
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    registry.keychute = KeychuteClient(transport=httpx.MockTransport(refuse))
    async with client() as ac:
        session, _ = await _session(ac)
        resp = await _autofill(ac, session["session_id"])
        assert resp.status_code == 200
        assert resp.json()["reason"] == "keychute_unavailable", resp.text


@pytest.mark.asyncio
async def test_autofill_requires_the_service_token(keychute):
    async with client() as ac:
        session, _ = await _session(ac)
        resp = await ac.post(f"/v1/sessions/{session['session_id']}/autofill", json={"step_key": "password"})
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_an_oversized_context_is_rejected(keychute):
    async with client() as ac:
        session, _ = await _session(ac)
        resp = await _autofill(ac, session["session_id"], context={"objective": "x" * 3000})
        assert resp.status_code == 400, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("origin", ["http://shop.example.com", "http://shop.example.com:443"])
async def test_http_autofill_is_refused_even_with_a_matching_host_and_port(keychute, origin):
    async with client() as ac:
        session, worker = await _session(ac, confine_origins=[origin])
        worker.url = origin + "/login"
        response = await _autofill(ac, session["session_id"])
        assert response.json()["reason"] == "wrong_origin"
        assert not keychute.requests
        assert keychute.reads == 0


@pytest.mark.asyncio
async def test_a_consumed_grant_is_rejected_before_another_read(keychute):
    async with client() as ac:
        session, worker = await _session(ac)
        assert (await _autofill(ac, session["session_id"])).json()["status"] == "filled"
        worker.filled.clear()
        response = await _autofill(ac, session["session_id"])
        assert response.json()["reason"] == "grant_invalid"
        assert keychute.reads == 1
        assert worker.filled == []


@pytest.mark.asyncio
async def test_spent_grants_count_toward_the_cap_even_when_the_payload_cannot_fill(keychute):
    keychute.secret = PASSWORD
    async with client() as ac:
        session, worker = await _session(ac)
        for index in range(AUTOFILL_FILL_CAP):
            keychute.reads = 0
            keychute.grant_id = str(uuid.uuid4())
            response = await _autofill(
                ac,
                session["session_id"],
                step_key=f"attempt-{index}",
                fields=[{"ref": "e10", "kind": "username"}],
            )
            assert response.json()["reason"] == "grant_invalid"
            assert keychute.reads == 1
        response = await _autofill(ac, session["session_id"], step_key="another")
        assert response.json()["reason"] == "fill_cap_reached"
        assert len(keychute.requests) == AUTOFILL_FILL_CAP
        assert worker.filled == []


@pytest.mark.asyncio
async def test_jar_revoked_during_approval_wait_is_not_filled(keychute, monkeypatch, tmp_path):
    monkeypatch.setenv("BROWSER_JAR_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    store = JarStore(tmp_path / "jars", keys=load_jar_keys())
    monkeypatch.setattr(registry, "jar_store", store)
    meta = store.save(
        jar_id=None,
        label="Shop",
        origins=[SITE],
        nav_allowlist=[],
        storage_mode="all",
        raw_storage_state={
            "cookies": [{"name": "sid", "value": "session", "domain": "shop.example.com", "path": "/", "expires": -1}],
            "origins": [],
        },
        probe_spec_url=None,
        probe_selector=None,
        probe_logged_out_prefix=None,
        saved_by="human",
        owner_subject="user123",
        form_factor="desktop",
        created_session_id="provisioning",
        conversation_id="c1",
        agent_supplied_probe=False,
    )
    keychute.state = "pending"

    def approve_after_revocation():
        store.invalidate(meta.jar_id, actor="human")
        keychute.state = "approved"

    keychute.on_wait = approve_after_revocation
    async with client() as ac:
        session, worker = await _session(ac, jar_id=meta.jar_id)
        response = await _autofill(ac, session["session_id"], wait_seconds=1)
        assert response.status_code == 410
        assert keychute.reads == 0
        assert worker.closed
        assert registry.get(session["session_id"]).state.value == "cancelled"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["username", "password"])
async def test_kind_only_request_uses_auto_detection(keychute, kind):
    async with client() as ac:
        session, worker = await _session(ac)
        response = await _autofill(ac, session["session_id"], fields=[{"kind": kind}])
        assert response.json()["status"] == "filled", response.text
        assert [field["kind"] for field in response.json()["filled"]] == [kind]
        assert len(worker.filled) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", [False, True])
async def test_pending_retry_keeps_the_original_document_binding(keychute, changed):
    keychute.state = "pending"
    async with client() as ac:
        session, worker = await _session(ac)
        first = await _autofill(ac, session["session_id"])
        assert first.json()["status"] == "approval_pending"
        if changed:
            await worker.autofill_prepare(None, "replacement-document")
        keychute.state = "approved"
        second = await _autofill(ac, session["session_id"])
        if changed:
            assert second.json()["reason"] == "target_invalidated"
            assert keychute.reads == 0
        else:
            assert second.json()["status"] == "filled"
            assert keychute.reads == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("deadline", ["expires_at", "idle_expires_at"])
async def test_expiry_during_approval_prevents_the_grant_read(keychute, deadline):
    keychute.state = "pending"
    async with client() as ac:
        session, worker = await _session(ac)

        def approve_after_expiry():
            setattr(registry.get(session["session_id"]), deadline, datetime.now(UTC) - timedelta(seconds=1))
            keychute.state = "approved"

        keychute.on_wait = approve_after_expiry
        response = await _autofill(ac, session["session_id"], wait_seconds=1)
        assert response.status_code == 410
        assert keychute.reads == 0
        assert not worker.filled


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state,owner",
    [
        (SessionState.HUMAN_ACTIVE, LeaseOwner.HUMAN),
        (SessionState.HANDOVER_REQUESTED, LeaseOwner.HUMAN),
        (SessionState.AGENT_ACTIVE, LeaseOwner.NONE),
    ],
)
async def test_bad_password_report_requires_agent_lease(keychute, state, owner):
    async with client() as ac:
        session, _ = await _session(ac)
        live = registry.sessions[session["session_id"]]
        live.state, live.lease_owner = state, owner
        response = await ac.post(
            f"/v1/sessions/{live.session_id}/autofill/outcome",
            json={"outcome": "bad_password"},
            headers=agent_headers(),
        )
        assert response.status_code == 403
        assert not live.autofill_bad_password


@pytest.mark.asyncio
async def test_approved_retry_retains_target_after_broker_failure(keychute):
    async with client() as ac:
        session, worker = await _session(ac)
        keychute.grant_info_unavailable = True
        first = await _autofill(ac, session["session_id"])
        assert first.json()["reason"] == "keychute_unavailable"
        await worker.autofill_prepare(None, "replacement-document")
        keychute.grant_info_unavailable = False
        second = await _autofill(ac, session["session_id"])
        assert second.json()["reason"] == "target_invalidated"
        assert keychute.reads == 0


@pytest.mark.asyncio
async def test_lost_creation_response_retains_original_target(keychute):
    async with client() as ac:
        session, worker = await _session(ac)
        keychute.lose_request_response = True
        first = await _autofill(ac, session["session_id"])
        assert first.json()["reason"] == "keychute_unavailable"
        await worker.autofill_prepare(None, "replacement-document")
        keychute.lose_request_response = False
        second = await _autofill(ac, session["session_id"])
        assert second.json()["reason"] == "target_invalidated"
        assert keychute.reads == 0
