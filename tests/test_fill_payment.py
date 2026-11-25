"""Blind payment fill: unit and ASGI API tests.

Exercises origin verification, fail-closed payment-iframe allowlist, field resolution,
read-back protection latching (without enabling Keychute autofill), validation error
scrubbing, and zero credential leakage across responses, events, snapshots, and logs.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Any, cast

import httpx
import pytest
from browser_handoff_service import main
from browser_handoff_service.jars import JarStore, load_jar_keys
from browser_handoff_service.main import app, registry
from browser_handoff_service.models import LeaseOwner, SessionState
from browser_handoff_service.runtime import (
    FakeBrowserWorker,
    _format_payment_input_value,
    _match_select_option,
    is_trusted_payment_frame_origin,
)
from httpx import ASGITransport, AsyncClient

TEST_SERVICE_TOKEN = "test-service-token"

MERCHANT = "https://shop.example.com"
STRIPE_ORIGIN = "https://js.stripe.com"
EVIL_ORIGIN = "https://evil-pay.example.net"

PAN = "4242424242429876"
PAN_SPACED = "4242 4242 4242 9876"
CVC = "9473"
EXP_MONTH = 4
EXP_YEAR = 2031
CARDHOLDER = "Jane Doe"


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


def card_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "expected_origin": MERCHANT,
        "card": {
            "number": PAN_SPACED,
            "exp_month": EXP_MONTH,
            "exp_year": EXP_YEAR,
            "cvc": CVC,
            "cardholder_name": CARDHOLDER,
        },
    }
    payload.update(overrides)
    return payload


async def _create_session(ac: AsyncClient, **overrides: Any) -> tuple[dict[str, Any], FakeBrowserWorker]:
    payload: dict[str, Any] = {"conversation_id": "conv-pay"}
    payload.update(overrides)
    resp = await ac.post("/v1/sessions", json=payload, headers=agent_headers())
    assert resp.status_code == 200, resp.text
    session = resp.json()
    worker = cast(FakeBrowserWorker, registry.workers[session["worker_id"]])
    worker.url = f"{MERCHANT}/checkout"
    return session, worker


async def _fill_payment(ac: AsyncClient, session_id: str, body: dict[str, Any] | None = None) -> httpx.Response:
    return await ac.post(
        f"/v1/sessions/{session_id}/fill-payment",
        json=body if body is not None else card_payload(),
        headers=agent_headers(),
    )


# --- payment-iframe allowlist & helper unit tests -------------------------


@pytest.mark.parametrize(
    ("frame_origin", "top_origin", "allowed"),
    [
        ("https://shop.example.com", "https://shop.example.com", True),
        ("https://shop.example.com:8443", "https://shop.example.com:8443", True),
        ("https://shop.example.com:8443", "https://shop.example.com", False),
        ("https://js.stripe.com", "https://shop.example.com", True),
        ("https://stripe.com", "https://shop.example.com", True),
        ("https://elements.stripe.network", "https://shop.example.com", True),
        ("https://checkoutshopper-live.adyen.com", "https://shop.example.com", True),
        ("https://checkoutshopper-live.adyenpayments.com", "https://shop.example.com", True),
        ("https://assets.braintreegateway.com", "https://shop.example.com", True),
        ("https://payments.braintree-api.com", "https://shop.example.com", True),
        ("https://www.paypal.com", "https://shop.example.com", True),
        ("https://checkout.shopifycs.com", "https://shop.example.com", True),
        ("https://pay.shop.app", "https://shop.example.com", True),
        ("https://pci-connect.squareup.com", "https://shop.example.com", True),
        ("https://web.squarecdn.com", "https://shop.example.com", True),
        ("https://js.checkout.com", "https://shop.example.com", True),
        ("https://api.recurly.com", "https://shop.example.com", True),
        ("https://flex.cybersource.com", "https://shop.example.com", True),
        ("https://accept.authorize.net", "https://shop.example.com", True),
        ("https://payments.worldpay.com", "https://shop.example.com", True),
        ("https://core.spreedly.com", "https://shop.example.com", True),
        ("https://js.basistheory.com", "https://shop.example.com", True),
        ("https://x.klarna.com", "https://shop.example.com", True),
        # Fail-closed rejections:
        ("http://js.stripe.com", "https://shop.example.com", False),
        ("https://js.stripe.com:8443", "https://shop.example.com", False),
        ("https://evilstripe.com", "https://shop.example.com", False),
        ("https://evil-stripe.com", "https://shop.example.com", False),
        ("https://stripe.com.evil.example", "https://shop.example.com", False),
        ("https://js.stripe.com.", "https://shop.example.com", False),
        ("https://shop.example.com", "http://shop.example.com", False),
        ("http://shop.example.com", "http://shop.example.com", False),
        ("about:blank", "https://shop.example.com", False),
        (None, "https://shop.example.com", False),
    ],
)
def test_trusted_payment_frame_origin_allowlist(frame_origin: str | None, top_origin: str, allowed: bool):
    assert is_trusted_payment_frame_origin(frame_origin, top_origin) is allowed


def test_select_option_matching_and_input_formatting():
    month_opts_num = [{"value": "", "label": "Month"}, {"value": "4", "label": "04 - April"}]
    assert _match_select_option("card_exp_month", month_opts_num, "04", 4, 2031) == "4"
    month_opts_name = [{"value": "apr", "label": "April"}]
    assert _match_select_option("card_exp_month", month_opts_name, "04", 4, 2031) == "apr"

    year_opts_4 = [{"value": "2030", "label": "2030"}, {"value": "2031", "label": "2031"}]
    assert _match_select_option("card_exp_year", year_opts_4, "2031", 4, 2031) == "2031"
    year_opts_2 = [{"value": "31", "label": "31"}]
    assert _match_select_option("card_exp_year", year_opts_2, "2031", 4, 2031) == "31"

    country_opts = [{"value": "AU", "label": "Australia"}, {"value": "US", "label": "United States"}]
    assert _match_select_option("billing_country", country_opts, "au", 4, 2031) == "AU"
    assert _match_select_option("billing_country", country_opts, "United States", 4, 2031) == "US"

    assert _format_payment_input_value("card_exp", "04/31", "MM / YY", None, 4, 2031) == "04/31"
    assert _format_payment_input_value("card_exp", "04/31", "MM / YYYY", 7, 4, 2031) == "04/2031"
    assert _format_payment_input_value("card_exp_year", "2031", "YY", 2, 4, 2031) == "31"
    assert _format_payment_input_value("card_exp_year", "2031", "YYYY", 4, 4, 2031) == "2031"


# --- happy paths: top-frame & cross-origin payment iframes ----------------


@pytest.mark.asyncio
async def test_top_frame_and_stripe_iframe_fill_places_card_and_leaks_nothing(caplog):
    caplog.set_level(logging.DEBUG)
    async with client() as ac:
        session, worker = await _create_session(ac)
        assert session["readback_protected"] is False
        assert session["autofill_enabled"] is False

        # Before payment fill on an ordinary session, exec/extract/transfer chords work.
        pre_exec = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": "exec", "args": {"code": "document.title"}},
            headers=agent_headers(),
        )
        assert pre_exec.status_code == 200

        worker.payment_fields = [
            {"ref": None, "kind": "card_number", "frame_origin": STRIPE_ORIGIN, "autocomplete": "cc-number"},
            {"ref": None, "kind": "card_exp", "frame_origin": STRIPE_ORIGIN, "autocomplete": "cc-exp"},
            {"ref": None, "kind": "card_cvc", "frame_origin": STRIPE_ORIGIN, "autocomplete": "cc-csc"},
            {"ref": "e20", "kind": "card_name", "frame_origin": MERCHANT, "autocomplete": "cc-name"},
            {
                "ref": "e21",
                "kind": "billing_postal_code",
                "frame_origin": MERCHANT,
                "autocomplete": "postal-code",
            },
            {
                "ref": "e22",
                "kind": "billing_country",
                "frame_origin": MERCHANT,
                "tag": "select",
                "options": [{"value": "AU", "label": "Australia"}, {"value": "US", "label": "United States"}],
            },
        ]
        body = card_payload(
            billing_address={"postal_code": "2000", "country": "Australia"},
        )
        resp = await _fill_payment(ac, session["session_id"], body)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "filled"
        assert data["origin"] == MERCHANT
        assert data["reason"] is None
        assert {entry["kind"]: entry["frame_origin"] for entry in data["filled"]} == {
            "card_number": STRIPE_ORIGIN,
            "card_exp": STRIPE_ORIGIN,
            "card_cvc": STRIPE_ORIGIN,
            "card_name": MERCHANT,
            "billing_postal_code": MERCHANT,
            "billing_country": MERCHANT,
        }
        assert {entry["kind"]: entry["value"] for entry in worker.payment_filled} == {
            "card_number": PAN,
            "card_exp": "04/31",
            "card_cvc": CVC,
            "card_name": CARDHOLDER,
            "billing_postal_code": "2000",
            "billing_country": "AU",
        }

        # Monotonic read-back protection latched on session and worker.
        state = await ac.get(f"/v1/sessions/{session['session_id']}", headers=agent_headers())
        assert state.status_code == 200
        state_json = state.json()
        assert state_json["readback_protected"] is True
        assert state_json["allow_exec"] is False
        assert state_json["autofill_enabled"] is False
        assert worker.mask_protected is True

        # Snapshot masks every filled main-frame control and never returns PAN/CVC.
        snap = await ac.post(
            f"/v1/sessions/{session['session_id']}/agent-command",
            json={"type": "snapshot", "args": {}},
            headers=agent_headers(),
        )
        assert snap.status_code == 200
        for channel in (resp.text, state.text, snap.text, caplog.text):
            assert PAN not in channel
            assert PAN_SPACED not in channel
        for channel in (resp.text, snap.text, caplog.text):
            assert CVC not in channel
        state_without_ids_or_times = {
            k: v
            for k, v in state_json.items()
            if k not in {"session_id", "worker_id", "created_at", "updated_at", "idle_expires_at", "expires_at"}
        }
        assert CVC not in str(state_without_ids_or_times)
        events = registry.events[session["session_id"]]
        assert any(ev.event_type == "fill_payment" for ev in events)
        assert not any(PAN in str(ev.metadata) or CVC in str(ev.metadata) for ev in events)

        # Post-fill read-back commands are denied.
        for cmd in (
            {"type": "exec", "args": {"code": "document.cookie"}},
            {"type": "extract", "args": {}},
            {"type": "press_key", "args": {"key": "Control+c"}},
            {"type": "keyboard_press", "args": {"keys": "Meta+v"}},
            {"type": "press_key", "args": {"key": "ControlOrMeta+c"}},
            {"type": "press_key", "args": {"key": "Shift+Insert"}},
        ):
            denied = await ac.post(
                f"/v1/sessions/{session['session_id']}/agent-command",
                json=cmd,
                headers=agent_headers(),
            )
            assert denied.status_code == 403, f"expected 403 for {cmd}, got {denied.status_code}"

        # Keychute password autofill remains strictly gated on autofill_enabled from creation!
        autofill_resp = await ac.post(
            f"/v1/sessions/{session['session_id']}/autofill",
            json={"step_key": "s1", "secret_name": "shop-login"},
            headers=agent_headers(),
        )
        assert autofill_resp.status_code == 200
        assert autofill_resp.json()["status"] == "refused"
        assert autofill_resp.json()["reason"] == "autofill_disabled"


# --- origin, frame, ambiguity, and navigation refusals --------------------


@pytest.mark.asyncio
async def test_refuses_plaintext_http_current_page_and_expected_origin():
    async with client() as ac:
        session, worker = await _create_session(ac)
        worker.url = "http://shop.example.com/checkout"
        worker.payment_fields = [{"ref": "e10", "kind": "card_number", "frame_origin": "http://shop.example.com"}]

        resp = await _fill_payment(ac, session["session_id"], card_payload(expected_origin=MERCHANT))
        assert resp.status_code == 200
        assert resp.json()["status"] == "refused"
        assert resp.json()["reason"] == "insecure_origin"
        assert worker.payment_filled == []
        # Refused before touching credentials -> did not needlessly latch readback_protected.
        assert registry.sessions[session["session_id"]].readback_protected is False

        # Plaintext HTTP expected_origin also refused even if page is HTTPS.
        worker.url = f"{MERCHANT}/checkout"
        resp2 = await _fill_payment(ac, session["session_id"], card_payload(expected_origin="http://shop.example.com"))
        assert resp2.status_code == 200
        assert resp2.json()["reason"] == "insecure_origin"


@pytest.mark.asyncio
async def test_refuses_wrong_origin_and_confined_session_mismatch():
    async with client() as ac:
        session, worker = await _create_session(ac)
        worker.url = "https://other.example.com/checkout"
        worker.payment_fields = [{"ref": "e10", "kind": "card_number"}]

        resp = await _fill_payment(ac, session["session_id"], card_payload(expected_origin=MERCHANT))
        assert resp.status_code == 200
        assert resp.json()["status"] == "refused"
        assert resp.json()["reason"] == "wrong_origin"
        assert resp.json()["origin"] == "https://other.example.com"
        assert worker.payment_filled == []


@pytest.mark.asyncio
async def test_refuses_untrusted_payment_frame_auto_and_explicit():
    async with client() as ac:
        session, worker = await _create_session(ac)
        # Main frame has cardholder name, but card fields are in an unrecognized 3rd-party frame.
        worker.payment_fields = [
            {"ref": "e10", "kind": "card_name", "frame_origin": MERCHANT},
            {"ref": "e50", "kind": "card_number", "frame_origin": EVIL_ORIGIN},
            {"ref": "e51", "kind": "card_exp", "frame_origin": EVIL_ORIGIN},
            {"ref": "e52", "kind": "card_cvc", "frame_origin": EVIL_ORIGIN},
        ]

        auto = await _fill_payment(ac, session["session_id"])
        assert auto.status_code == 200
        assert auto.json()["status"] == "refused"
        assert auto.json()["reason"] == "untrusted_payment_frame"
        assert worker.payment_filled == []

        # Explicit target pointing at a ref inside an untrusted frame also refuses untrusted_payment_frame.
        explicit = await _fill_payment(
            ac,
            session["session_id"],
            card_payload(fields=[{"ref": "e50", "kind": "card_number"}]),
        )
        assert explicit.status_code == 200
        assert explicit.json()["reason"] == "untrusted_payment_frame"
        assert worker.payment_filled == []


@pytest.mark.asyncio
async def test_refuses_ambiguous_fields_and_allows_explicit_override():
    async with client() as ac:
        session, worker = await _create_session(ac)
        worker.payment_fields = [
            {"ref": "e10", "kind": "card_number", "frame_origin": MERCHANT},
            {"ref": "e11", "kind": "card_number", "frame_origin": MERCHANT},
            {"ref": "e12", "kind": "card_exp", "frame_origin": MERCHANT},
            {"ref": "e13", "kind": "card_cvc", "frame_origin": MERCHANT},
        ]

        auto = await _fill_payment(ac, session["session_id"])
        assert auto.status_code == 200
        assert auto.json()["reason"] == "ambiguous_fields"
        assert worker.payment_filled == []

        # Explicit fields override resolves the ambiguity cleanly.
        explicit = await _fill_payment(
            ac,
            session["session_id"],
            card_payload(
                fields=[
                    {"ref": "e10", "kind": "card_number"},
                    {"ref": "e12", "kind": "card_exp"},
                    {"ref": "e13", "kind": "card_cvc"},
                ]
            ),
        )
        assert explicit.status_code == 200
        assert explicit.json()["status"] == "filled"
        assert [f["ref"] for f in explicit.json()["filled"]] == ["e10", "e12", "e13"]


@pytest.mark.asyncio
async def test_refuses_combined_and_split_expiry_ambiguity():
    async with client() as ac:
        session, worker = await _create_session(ac)
        worker.payment_fields = [
            {"ref": "e10", "kind": "card_number"},
            {"ref": "e11", "kind": "card_exp"},
            {"ref": "e12", "kind": "card_exp_month"},
            {"ref": "e13", "kind": "card_cvc"},
        ]
        resp = await _fill_payment(ac, session["session_id"])
        assert resp.status_code == 200
        assert resp.json()["reason"] == "ambiguous_fields"


@pytest.mark.asyncio
async def test_refuses_non_payment_form_without_card_number():
    async with client() as ac:
        session, worker = await _create_session(ac)
        # Only billing/name fields present — auto-detect must require card_number.
        worker.payment_fields = [
            {"ref": "e10", "kind": "card_name"},
            {"ref": "e11", "kind": "billing_postal_code"},
        ]
        resp = await _fill_payment(ac, session["session_id"], card_payload(billing_address={"postal_code": "2000"}))
        assert resp.status_code == 200
        assert resp.json()["reason"] == "no_eligible_field"
        assert worker.payment_filled == []


@pytest.mark.asyncio
async def test_refuses_invalid_refs_and_duplicate_explicit_targets():
    async with client() as ac:
        session, worker = await _create_session(ac)
        worker.payment_fields = [{"ref": "e10", "kind": "card_number"}]

        bad_syntax = await _fill_payment(
            ac, session["session_id"], card_payload(fields=[{"ref": "not-a-ref", "kind": "card_number"}])
        )
        assert bad_syntax.status_code == 200
        assert bad_syntax.json()["reason"] == "invalid_ref"

        missing = await _fill_payment(
            ac, session["session_id"], card_payload(fields=[{"ref": "e999", "kind": "card_number"}])
        )
        assert missing.status_code == 200
        assert missing.json()["reason"] == "invalid_ref"

        dup = await _fill_payment(
            ac,
            session["session_id"],
            card_payload(
                fields=[
                    {"ref": "e10", "kind": "card_number"},
                    {"ref": "e10", "kind": "card_cvc"},
                ]
            ),
        )
        assert dup.status_code == 200
        assert dup.json()["reason"] == "ambiguous_fields"


@pytest.mark.asyncio
async def test_mid_fill_navigation_aborts_with_target_invalidated_and_keeps_protection_latched():
    async with client() as ac:
        session, worker = await _create_session(ac)
        worker.payment_fields = [
            {"ref": "e10", "kind": "card_number"},
            {"ref": "e11", "kind": "card_exp"},
            {"ref": "e12", "kind": "card_cvc"},
        ]

        def navigate_on_second_target(target: dict[str, Any]) -> None:
            if target["kind"] == "card_exp":
                worker.url = "https://other.example.com/phish"
                worker._payment_nonce = None

        worker.on_payment_fill = navigate_on_second_target
        resp = await _fill_payment(ac, session["session_id"])
        assert resp.status_code == 200
        assert resp.json()["status"] == "refused"
        assert resp.json()["reason"] == "target_invalidated"
        # Stopped before card_exp/card_cvc were touched.
        assert [f["kind"] for f in worker.payment_filled] == ["card_number"]
        # Read-back protection latched monotonically BEFORE first fill, so it stays True!
        assert registry.sessions[session["session_id"]].readback_protected is True
        assert worker.mask_protected is True


# --- validation error scrubbing & auth/lifecycle --------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_body",
    [
        # Invalid exp_month (13)
        {
            "expected_origin": MERCHANT,
            "card": {"number": PAN, "exp_month": 13, "exp_year": 2031, "cvc": CVC},
        },
        # 2-digit exp_year rejected (must be 2000..2199)
        {
            "expected_origin": MERCHANT,
            "card": {"number": PAN, "exp_month": 4, "exp_year": 31, "cvc": CVC},
        },
        # Missing expected_origin (Pydantic would otherwise embed full body as `input`)
        {
            "card": {"number": PAN, "exp_month": 4, "exp_year": 2031, "cvc": CVC},
        },
        # Wrong type for card.number (int instead of str)
        {
            "expected_origin": MERCHANT,
            "card": {"number": 4242424242429876, "exp_month": 4, "exp_year": 2031, "cvc": CVC},
        },
        # Blank CVC
        {
            "expected_origin": MERCHANT,
            "card": {"number": PAN, "exp_month": 4, "exp_year": 2031, "cvc": "   "},
        },
        # Empty fields list
        {
            "expected_origin": MERCHANT,
            "card": {"number": PAN, "exp_month": 4, "exp_year": 2031, "cvc": CVC},
            "fields": [],
        },
    ],
)
async def test_validation_errors_never_echo_card_number_or_cvc(bad_body: dict[str, Any]):
    async with client() as ac:
        session, _ = await _create_session(ac)
        resp = await _fill_payment(ac, session["session_id"], bad_body)
        assert resp.status_code == 422, resp.text
        assert PAN not in resp.text
        assert CVC not in resp.text
        for err in resp.json()["detail"]:
            assert "input" not in err
            assert "ctx" not in err


@pytest.mark.asyncio
async def test_malformed_json_validation_error_never_echoes_raw_card():
    async with client() as ac:
        session, _ = await _create_session(ac)
        raw = f'{{"expected_origin":"{MERCHANT}","card":{{"number":"{PAN}","cvc":"{CVC}"'
        resp = await ac.post(
            f"/v1/sessions/{session['session_id']}/fill-payment",
            content=raw,
            headers={**agent_headers(), "content-type": "application/json"},
        )
        assert resp.status_code == 422
        assert PAN not in resp.text
        assert CVC not in resp.text


@pytest.mark.asyncio
async def test_auth_lease_and_revoked_jar_enforcement(tmp_path):
    async with client() as ac:
        session, _ = await _create_session(ac)
        sid = session["session_id"]

        # Unauthenticated -> 401
        unauth = await ac.post(f"/v1/sessions/{sid}/fill-payment", json=card_payload())
        assert unauth.status_code == 401

        # Unknown session -> 404
        missing = await _fill_payment(ac, "bs_does_not_exist")
        assert missing.status_code == 404

        # Human owns lease -> 403
        registry.sessions[sid].state = SessionState.HUMAN_ACTIVE
        registry.sessions[sid].lease_owner = LeaseOwner.HUMAN
        no_lease = await _fill_payment(ac, sid)
        assert no_lease.status_code == 403

        # Closed/terminal session -> 410
        registry.sessions[sid].state = SessionState.CANCELLED
        registry.sessions[sid].lease_owner = LeaseOwner.NONE
        closed = await _fill_payment(ac, sid)
        assert closed.status_code == 410

        # Revoked cookie jar -> 410 Gone (live session kill-switch cancels the session)
        os.environ["BROWSER_JAR_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
        keys = load_jar_keys()
        os.environ.pop("BROWSER_JAR_KEY", None)
        store = JarStore(tmp_path / "jars", keys=keys)
        registry.jar_store = store
        src_session, src_worker = await _create_session(ac)
        src_worker.storage_state = {
            "cookies": [{"name": "sid", "value": "S1", "domain": "shop.example.com", "path": "/", "expires": -1}],
            "origins": [],
        }
        saved = await ac.post(
            f"/v1/sessions/{src_session['session_id']}/save-jar",
            json={
                "label": "Shop",
                "origins": [MERCHANT],
                "probe": {"logged_in_selector": "#ok"},
            },
            headers=agent_headers(),
        )
        assert saved.status_code == 200, saved.text
        jar_id = saved.json()["jar_id"]
        jar_session, jar_worker = await _create_session(ac, jar_id=jar_id)
        jar_worker.payment_fields = [{"ref": "e10", "kind": "card_number"}]
        store.invalidate(jar_id, actor="service")
        revoked = await _fill_payment(ac, jar_session["session_id"])
        assert revoked.status_code == 410
        assert jar_worker.payment_filled == []
        assert registry.sessions[jar_session["session_id"]].state == SessionState.CANCELLED
