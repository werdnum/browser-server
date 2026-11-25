"""Real-browser tests for blind payment fill (PlaywrightBrowserWorker + Chromium).

Uses Playwright route interception to serve genuine multi-origin HTTPS documents
(merchant top-level frame, Stripe-like cross-origin payment iframes, same-origin
iframes, untrusted third-party iframes, and plaintext HTTP pages) without requiring
external network access or self-signed TLS certificates.

Skips cleanly when real Chromium is unavailable on the host, matching
``test_walker_masking_optional.py``. Set ``BROWSER_CHROMIUM_PATH`` to point at a
system Chrome (e.g. ``/usr/bin/google-chrome``).
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from browser_handoff_service import main
from browser_handoff_service.main import app, registry
from browser_handoff_service.models import AgentCommandRequest
from browser_handoff_service.runtime import PlaywrightBrowserWorker, RuntimeUnavailable
from httpx import ASGITransport, AsyncClient

TEST_SERVICE_TOKEN = "test-service-token"
MERCHANT = "https://shop.example.com"
STRIPE = "https://js.stripe.com"
EVIL = "https://evil-pay.example.net"
OTHER = "https://other.example.com"

PAN = "4242424242429876"
CVC = "9473"
EXP_MONTH = 4
EXP_YEAR = 2031
CARDHOLDER = "Jane Doe"


def _agent_headers() -> dict[str, str]:
    return {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}


def _card_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "expected_origin": MERCHANT,
        "card": {
            "number": PAN,
            "exp_month": EXP_MONTH,
            "exp_year": EXP_YEAR,
            "cvc": CVC,
            "cardholder_name": CARDHOLDER,
        },
    }
    body.update(overrides)
    return body


@pytest.fixture
def clear_registry():
    for attr in ("sessions", "locks", "events", "tokens", "workers", "jar_locks"):
        getattr(registry, attr).clear()
    main._jwks_client = None
    yield
    for attr in ("sessions", "locks", "events", "tokens", "workers", "jar_locks"):
        getattr(registry, attr).clear()
    main._jwks_client = None


@pytest.fixture
async def worker() -> Any:
    w = PlaywrightBrowserWorker("worker_fill_payment")
    try:
        await w.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real Chromium unavailable on this host: {exc}")
    try:
        yield w
    finally:
        await w.close()


async def _mount_pages(worker: PlaywrightBrowserWorker, pages: dict[str, str]) -> None:
    assert worker._context is not None

    async def handler(route: Any) -> None:
        html = pages.get(route.request.url)
        if html is not None:
            await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)
            return
        await route.abort()

    await worker._context.route("**/*", handler)


async def _wait_frames(worker: PlaywrightBrowserWorker, expected_count: int) -> None:
    assert worker._page is not None
    for frame in worker._page.frames:
        await frame.wait_for_load_state("domcontentloaded")
    assert len(worker._page.frames) >= expected_count


@pytest.mark.asyncio
async def test_real_cross_origin_stripe_iframes_and_main_frame_fill_with_full_readback_protection(
    monkeypatch, clear_registry
):
    """Full ASGI + real Chromium end-to-end test:
    - Cross-origin Stripe Elements iframes for card number / expiry / CVC
    - Main-frame inputs & <select> controls for cardholder name, postal code, and country
    - Stamps data-fa-protected="true" in BOTH main frame and cross-origin child iframes
    - Masks snapshots, screenshots, and dragstart across frames
    - Denies exec/extract/transfer chords after fill while keeping Keychute autofill disabled
    """
    monkeypatch.setenv("BROWSER_RUNTIME", "playwright")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)

    pages = {
        f"{MERCHANT}/checkout": f"""<!doctype html><title>Checkout</title>
        <form id="checkout">
          <label for="cname">Name on card</label>
          <input id="cname" name="cardholderName" autocomplete="cc-name" type="text">
          <iframe id="f-num" src="{STRIPE}/elements/number" width="300" height="40"></iframe>
          <iframe id="f-exp" src="{STRIPE}/elements/exp" width="150" height="40"></iframe>
          <iframe id="f-cvc" src="{STRIPE}/elements/cvc" width="150" height="40"></iframe>
          <label for="zip">Billing postal code</label>
          <input id="zip" name="billing_zip" autocomplete="billing postal-code" type="text">
          <label for="country">Billing country</label>
          <select id="country" name="billing_country" autocomplete="billing country">
            <option value="">Select</option>
            <option value="AU">Australia</option>
            <option value="US">United States</option>
          </select>
          <button type="submit">Pay</button>
        </form>""",
        f"{STRIPE}/elements/number": (
            '<!doctype html><input id="cc-num" name="cardnumber" autocomplete="cc-number" '
            'data-elements-stable-field-name="cardNumber" type="text">'
        ),
        f"{STRIPE}/elements/exp": (
            '<!doctype html><input id="cc-exp" name="exp-date" autocomplete="cc-exp" placeholder="MM / YY" type="text">'
        ),
        f"{STRIPE}/elements/cvc": ('<!doctype html><input id="cc-cvc" name="cvc" autocomplete="cc-csc" type="text">'),
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as ac:
        create = await ac.post("/v1/sessions", json={"conversation_id": "c-real-pay"}, headers=_agent_headers())
        if create.status_code == 503:
            try:
                raise RuntimeUnavailable(create.text)
            except RuntimeUnavailable as exc:
                pytest.skip(f"real Chromium unavailable on this host: {exc}")
        assert create.status_code == 200, create.text
        session = create.json()
        sid = session["session_id"]
        real_worker = cast(PlaywrightBrowserWorker, registry.workers[session["worker_id"]])
        try:
            await _mount_pages(real_worker, pages)
            nav = await ac.post(
                f"/v1/sessions/{sid}/agent-command",
                json={"type": "navigate", "args": {"url": f"{MERCHANT}/checkout"}},
                headers=_agent_headers(),
            )
            assert nav.status_code == 200
            await _wait_frames(real_worker, 4)

            # Before fill: exec works on an ordinary session.
            pre_exec = await ac.post(
                f"/v1/sessions/{sid}/agent-command",
                json={"type": "exec", "args": {"code": "document.title"}},
                headers=_agent_headers(),
            )
            assert pre_exec.status_code == 200
            assert pre_exec.json()["result"]["result"] == "Checkout"

            fill = await ac.post(
                f"/v1/sessions/{sid}/fill-payment",
                json=_card_body(billing_address={"postal_code": "2000", "country": "Australia"}),
                headers=_agent_headers(),
            )
            assert fill.status_code == 200, fill.text
            body = fill.json()
            assert body["status"] == "filled", body
            assert body["origin"] == MERCHANT
            assert PAN not in fill.text
            assert CVC not in fill.text

            by_kind = {item["kind"]: item for item in body["filled"]}
            assert by_kind["card_number"]["frame_origin"] == STRIPE
            assert by_kind["card_number"]["ref"] is None
            assert by_kind["card_exp"]["frame_origin"] == STRIPE
            assert by_kind["card_cvc"]["frame_origin"] == STRIPE
            assert by_kind["card_name"]["frame_origin"] == MERCHANT
            assert by_kind["card_name"]["ref"] is not None
            assert by_kind["billing_postal_code"]["frame_origin"] == MERCHANT
            assert by_kind["billing_country"]["frame_origin"] == MERCHANT

            # Verify DOM values AND data-fa-protected="true" across main frame and every Stripe iframe.
            assert real_worker._page is not None
            page = real_worker._page
            assert await page.locator("#cname").input_value() == CARDHOLDER
            assert await page.locator("#cname").get_attribute("data-fa-protected") == "true"
            assert await page.locator("#zip").input_value() == "2000"
            assert await page.locator("#zip").get_attribute("data-fa-protected") == "true"
            assert await page.locator("#country").input_value() == "AU"
            assert await page.locator("#country").get_attribute("data-fa-protected") == "true"

            num_frame = page.frame(url=f"{STRIPE}/elements/number")
            exp_frame = page.frame(url=f"{STRIPE}/elements/exp")
            cvc_frame = page.frame(url=f"{STRIPE}/elements/cvc")
            assert num_frame is not None and exp_frame is not None and cvc_frame is not None
            assert await num_frame.locator("#cc-num").input_value() == PAN
            assert await num_frame.locator("#cc-num").get_attribute("data-fa-protected") == "true"
            assert await exp_frame.locator("#cc-exp").input_value() == "04/31"
            assert await exp_frame.locator("#cc-exp").get_attribute("data-fa-protected") == "true"
            assert await cvc_frame.locator("#cc-cvc").input_value() == CVC
            assert await cvc_frame.locator("#cc-cvc").get_attribute("data-fa-protected") == "true"

            # Drag guard cancels dragstart on protected controls in BOTH main frame and Stripe iframe.
            for frame, sel in ((page.main_frame, "#cname"), (num_frame, "#cc-num")):
                allowed = await frame.locator(sel).evaluate(
                    "el => el.dispatchEvent(new DragEvent('dragstart', {bubbles: true, cancelable: true, composed: true}))"
                )
                assert allowed is False

            # Snapshot masks protected controls and never leaks card/billing secrets.
            snap = await ac.post(
                f"/v1/sessions/{sid}/agent-command",
                json={"type": "snapshot", "args": {}},
                headers=_agent_headers(),
            )
            assert snap.status_code == 200
            assert PAN not in snap.text
            assert CVC not in snap.text
            assert CARDHOLDER not in snap.text

            # Screenshot passes mask locators for every frame (main + 3 Stripe iframes) with >= 1 match each.
            original_screenshot = page.screenshot
            mask_counts: list[int] = []

            async def wrapped_screenshot(**kwargs: Any) -> bytes:
                mask_counts.extend([await loc.count() for loc in kwargs.get("mask", [])])
                return await original_screenshot(**kwargs)

            monkeypatch.setattr(page, "screenshot", wrapped_screenshot)
            shot = await ac.post(
                f"/v1/sessions/{sid}/agent-command",
                json={"type": "screenshot", "args": {}},
                headers=_agent_headers(),
            )
            assert shot.status_code == 200
            assert len(mask_counts) == 4
            assert all(count >= 1 for count in mask_counts)

            # Post-fill read-back protections deny exec, extract, and clipboard transfer chords.
            for cmd in (
                {"type": "exec", "args": {"code": "1+1"}},
                {"type": "extract", "args": {}},
                {"type": "press_key", "args": {"key": "Control+c"}},
            ):
                denied = await ac.post(
                    f"/v1/sessions/{sid}/agent-command",
                    json=cmd,
                    headers=_agent_headers(),
                )
                assert denied.status_code == 403

            # Keychute autofill is STILL refused on this non-autofill_enabled session.
            af = await ac.post(
                f"/v1/sessions/{sid}/autofill",
                json={"step_key": "k1", "secret_name": "shop-login"},
                headers=_agent_headers(),
            )
            assert af.status_code == 200
            assert af.json()["reason"] == "autofill_disabled"
        finally:
            await ac.post(f"/v1/sessions/{sid}/close", headers=_agent_headers())


@pytest.mark.asyncio
async def test_real_same_origin_iframe_and_split_select_expiry(worker: PlaywrightBrowserWorker):
    pages = {
        f"{MERCHANT}/checkout": f"""<!doctype html><title>Checkout</title>
        <iframe src="{MERCHANT}/card-frame" width="400" height="250"></iframe>""",
        f"{MERCHANT}/card-frame": """<!doctype html>
        <form>
          <label for="num">Card number</label>
          <input id="num" name="cardNumber" type="tel">
          <label for="mm">Expiry month</label>
          <select id="mm" name="expMonth">
            <option value="">Month</option>
            <option value="04">04 - April</option>
          </select>
          <label for="yy">Expiry year</label>
          <select id="yy" name="expYear">
            <option value="">Year</option>
            <option value="2031">2031</option>
          </select>
          <label for="cvv">Security code</label>
          <input id="cvv" name="securityCode" type="password">
        </form>""",
    }
    await _mount_pages(worker, pages)
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{MERCHANT}/checkout"}))
    await _wait_frames(worker, 2)

    available = ["card_number", "card_exp", "card_exp_month", "card_exp_year", "card_cvc"]
    prep = await worker.payment_prepare(MERCHANT, None, available, "nonce-same-origin")
    assert prep.get("ok"), prep
    result = await worker.payment_fill(
        "nonce-same-origin",
        MERCHANT,
        prep["targets"],
        {"card_number": PAN, "card_exp": "04/31", "card_exp_month": "04", "card_exp_year": "2031", "card_cvc": CVC},
        exp_month=EXP_MONTH,
        exp_year=EXP_YEAR,
    )
    assert result.get("ok"), result
    assert worker._page is not None
    child = worker._page.frame(url=f"{MERCHANT}/card-frame")
    assert child is not None
    assert await child.locator("#num").input_value() == PAN
    assert await child.locator("#mm").input_value() == "04"
    assert await child.locator("#yy").input_value() == "2031"
    assert await child.locator("#cvv").input_value() == CVC
    for sel in ("#num", "#mm", "#yy", "#cvv"):
        assert await child.locator(sel).get_attribute("data-fa-protected") == "true"


@pytest.mark.asyncio
async def test_real_untrusted_iframe_and_nested_under_untrusted_iframe_refused(worker: PlaywrightBrowserWorker):
    pages = {
        f"{MERCHANT}/untrusted": f"""<!doctype html>
        <input id="name" autocomplete="cc-name" type="text">
        <iframe src="{EVIL}/card" width="300" height="120"></iframe>""",
        f"{EVIL}/card": (
            '<!doctype html><input id="pan" autocomplete="cc-number" type="text">'
            '<input id="exp" autocomplete="cc-exp" type="text">'
            '<input id="cvc" autocomplete="cc-csc" type="text">'
        ),
        f"{MERCHANT}/nested": f"""<!doctype html>
        <iframe src="{EVIL}/wrapper" width="300" height="120"></iframe>""",
        f"{EVIL}/wrapper": f'<!doctype html><iframe src="{STRIPE}/elements/number" width="280" height="80"></iframe>',
        f"{STRIPE}/elements/number": '<!doctype html><input id="pan" autocomplete="cc-number" type="text">',
    }
    await _mount_pages(worker, pages)
    available = ["card_number", "card_exp", "card_cvc", "card_name"]

    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{MERCHANT}/untrusted"}))
    await _wait_frames(worker, 2)
    res1 = await worker.payment_prepare(MERCHANT, None, available, "nonce-u1")
    assert res1.get("error") is True and res1.get("reason") == "untrusted_payment_frame", res1

    # Even a Stripe iframe nested INSIDE an untrusted third-party iframe must be refused.
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{MERCHANT}/nested"}))
    await _wait_frames(worker, 3)
    res2 = await worker.payment_prepare(MERCHANT, None, available, "nonce-u2")
    assert res2.get("error") is True and res2.get("reason") == "untrusted_payment_frame", res2


@pytest.mark.asyncio
async def test_real_plaintext_http_and_wrong_origin_refused(worker: PlaywrightBrowserWorker):
    pages = {
        "http://shop.example.com/checkout": '<!doctype html><input autocomplete="cc-number" type="text">',
        f"{OTHER}/checkout": '<!doctype html><input autocomplete="cc-number" type="text">',
    }
    await _mount_pages(worker, pages)
    available = ["card_number", "card_exp", "card_cvc"]

    await worker.command(AgentCommandRequest(type="navigate", args={"url": "http://shop.example.com/checkout"}))
    res_http = await worker.payment_prepare(MERCHANT, None, available, "nonce-http")
    assert res_http.get("error") is True and res_http.get("reason") == "insecure_origin", res_http

    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{OTHER}/checkout"}))
    res_wrong = await worker.payment_prepare(MERCHANT, None, available, "nonce-wrong")
    assert res_wrong.get("error") is True and res_wrong.get("reason") == "wrong_origin", res_wrong


@pytest.mark.asyncio
async def test_real_mid_fill_navigation_aborts_with_target_invalidated(worker: PlaywrightBrowserWorker):
    pages = {
        f"{MERCHANT}/checkout": f"""<!doctype html>
        <input id="pan" autocomplete="cc-number" type="text">
        <input id="cvc" autocomplete="cc-csc" type="text">
        <script>
          document.getElementById('pan').addEventListener('input', () => {{
            window.location.href = '{OTHER}/redirected';
          }});
        </script>""",
        f"{OTHER}/redirected": '<!doctype html><input id="cvc" autocomplete="cc-csc" type="text">',
    }
    await _mount_pages(worker, pages)
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{MERCHANT}/checkout"}))

    prep = await worker.payment_prepare(MERCHANT, None, ["card_number", "card_cvc"], "nonce-nav")
    assert prep.get("ok"), prep
    result = await worker.payment_fill(
        "nonce-nav",
        MERCHANT,
        prep["targets"],
        {"card_number": PAN, "card_cvc": CVC},
        exp_month=EXP_MONTH,
        exp_year=EXP_YEAR,
    )
    assert result.get("error") is True and result.get("reason") == "target_invalidated", result
    assert worker._page is not None
    await worker._page.wait_for_url(f"{OTHER}/redirected")
    # CVC must never have been written to the redirected document.
    assert await worker._page.locator("#cvc").input_value() == ""


@pytest.mark.asyncio
async def test_real_ambiguous_fields_and_explicit_ref_override(worker: PlaywrightBrowserWorker):
    pages = {
        f"{MERCHANT}/checkout": """<!doctype html>
        <form>
          <label for="pan1">Primary card number</label><input id="pan1" autocomplete="cc-number" type="text">
          <label for="pan2">Backup card number</label><input id="pan2" autocomplete="cc-number" type="text">
          <label for="exp">Expiry</label><input id="exp" autocomplete="cc-exp" placeholder="MM/YY" type="text">
          <label for="cvc">CVC</label><input id="cvc" autocomplete="cc-csc" type="text">
        </form>""",
    }
    await _mount_pages(worker, pages)
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{MERCHANT}/checkout"}))

    ambig = await worker.payment_prepare(MERCHANT, None, ["card_number", "card_exp", "card_cvc"], "nonce-ambig")
    assert ambig.get("error") is True and ambig.get("reason") == "ambiguous_fields", ambig

    snap = await worker.command(AgentCommandRequest(type="snapshot", args={"next_ref": 1}))

    def find_ref(nodes: list[dict[str, Any]], label: str) -> str:
        for node in nodes:
            if node.get("name") == label and node.get("tag") == "input":
                return str(node["ref"])
            if node.get("children"):
                found = find_ref(node["children"], label)
                if found:
                    return found
        return ""

    pan1_ref = find_ref(snap["roots"], "Primary card number")
    exp_ref = find_ref(snap["roots"], "Expiry")
    cvc_ref = find_ref(snap["roots"], "CVC")
    assert pan1_ref and exp_ref and cvc_ref

    explicit = await worker.payment_prepare(
        MERCHANT,
        [
            {"ref": pan1_ref, "kind": "card_number"},
            {"ref": exp_ref, "kind": "card_exp"},
            {"ref": cvc_ref, "kind": "card_cvc"},
        ],
        ["card_number", "card_exp", "card_cvc"],
        "nonce-explicit",
    )
    assert explicit.get("ok"), explicit
    filled = await worker.payment_fill(
        "nonce-explicit",
        MERCHANT,
        explicit["targets"],
        {"card_number": PAN, "card_exp": "04/31", "card_cvc": CVC},
        exp_month=EXP_MONTH,
        exp_year=EXP_YEAR,
    )
    assert filled.get("ok"), filled
    assert worker._page is not None
    assert await worker._page.locator("#pan1").input_value() == PAN
    assert await worker._page.locator("#pan2").input_value() == ""
    assert await worker._page.locator("#exp").input_value() == "04/31"
    assert await worker._page.locator("#cvc").input_value() == CVC
