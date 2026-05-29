import pytest
from browser_handoff_service.main import _viewport_box, app, registry
from browser_handoff_service.models import (
    DEFAULT_FORM_FACTOR,
    ClientViewport,
    CreateSessionRequest,
    form_factor_profile,
    new_session,
)
from browser_handoff_service.runtime import (
    DEFAULT_DISPLAY_HEIGHT,
    DEFAULT_DISPLAY_WIDTH,
    LocalNovncDisplay,
    PlaywrightBrowserWorker,
    make_worker,
)
from httpx import ASGITransport, AsyncClient

TEST_SERVICE_TOKEN = "test-service-token"


@pytest.fixture(autouse=True)
def clear_registry():
    registry.sessions.clear()
    registry.locks.clear()
    registry.events.clear()
    registry.tokens.clear()
    registry.workers.clear()


def test_sessions_default_to_mobile_form_factor():
    assert DEFAULT_FORM_FACTOR == "mobile"
    req = CreateSessionRequest(conversation_id="conv_default")
    # The request defaults to auto-detection, which falls back to mobile with no client info.
    assert req.form_factor == "auto"
    assert req.resolved_form_factor() == "mobile"
    session = new_session(req)
    assert session.form_factor == "mobile"


def test_auto_detects_desktop_from_landscape_client():
    req = CreateSessionRequest(
        conversation_id="conv_landscape",
        client_viewport=ClientViewport(width=1920, height=1080),
    )
    assert req.form_factor == "auto"
    assert req.resolved_form_factor() == "desktop"
    assert new_session(req).form_factor == "desktop"


def test_auto_detects_mobile_from_portrait_client():
    req = CreateSessionRequest(
        conversation_id="conv_portrait",
        client_viewport=ClientViewport(width=390, height=844),
    )
    assert req.resolved_form_factor() == "mobile"
    assert new_session(req).form_factor == "mobile"


def test_explicit_form_factor_overrides_client_aspect_ratio():
    req = CreateSessionRequest(
        conversation_id="conv_override",
        form_factor="mobile",
        client_viewport=ClientViewport(width=1920, height=1080),
    )
    assert req.resolved_form_factor() == "mobile"


def test_mobile_profile_is_portrait_with_mobile_user_agent():
    profile = form_factor_profile("mobile")
    assert profile.height > profile.width  # portrait
    assert profile.user_agent and "Mobile" in profile.user_agent


def test_desktop_profile_is_landscape():
    profile = form_factor_profile("desktop")
    assert profile.width > profile.height  # landscape
    assert profile.user_agent is None


def test_unknown_form_factor_falls_back_to_default():
    assert form_factor_profile("nonsense") == form_factor_profile(DEFAULT_FORM_FACTOR)


def test_viewport_box_preserves_aspect_ratio_and_orientation():
    mobile = form_factor_profile("mobile")
    mw, mh = _viewport_box(mobile.width, mobile.height)
    assert mh > mw  # stays portrait on the page
    # aspect ratio preserved within rounding tolerance
    assert abs((mw / mh) - (mobile.width / mobile.height)) < 0.02

    desktop = form_factor_profile("desktop")
    dw, dh = _viewport_box(desktop.width, desktop.height)
    assert dw > dh  # stays landscape on the page
    assert dw <= 760 and dh <= 620


def test_make_worker_forwards_form_factor_dimensions(monkeypatch):
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    profile = form_factor_profile("mobile")
    worker = make_worker(
        "worker_ff",
        width=profile.width,
        height=profile.height,
        user_agent=profile.user_agent,
    )
    assert isinstance(worker, PlaywrightBrowserWorker)
    assert worker.width == profile.width
    assert worker.height == profile.height
    assert worker.user_agent == profile.user_agent


def test_local_novnc_display_defaults_match_desktop():
    display = LocalNovncDisplay("worker_display")
    assert display.width == DEFAULT_DISPLAY_WIDTH
    assert display.height == DEFAULT_DISPLAY_HEIGHT


def test_local_novnc_display_accepts_custom_dimensions():
    profile = form_factor_profile("mobile")
    display = LocalNovncDisplay("worker_display", width=profile.width, height=profile.height)
    assert display.width == profile.width
    assert display.height == profile.height


@pytest.mark.asyncio
async def test_create_session_records_requested_form_factor():
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_mobile_default"},
        )
        assert created.status_code == 200, created.text
        assert created.json()["form_factor"] == "mobile"

        desktop = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_desktop", "form_factor": "desktop"},
        )
        assert desktop.status_code == 200, desktop.text
        assert desktop.json()["form_factor"] == "desktop"


@pytest.mark.asyncio
async def test_create_session_auto_detects_form_factor_from_client_viewport():
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        landscape = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_landscape", "client_viewport": {"width": 1440, "height": 900}},
        )
        assert landscape.status_code == 200, landscape.text
        assert landscape.json()["form_factor"] == "desktop"

        portrait = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_portrait", "client_viewport": {"width": 414, "height": 896}},
        )
        assert portrait.status_code == 200, portrait.text
        assert portrait.json()["form_factor"] == "mobile"


@pytest.mark.asyncio
async def test_session_detail_viewport_matches_form_factor():
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_ui", "initial_owner": "human"},
        )
        assert created.status_code == 200, created.text
        session_url = created.json()["session_url"]

        page = await client.get(session_url)
        assert page.status_code == 200

    mobile = form_factor_profile("mobile")
    box_w, box_h = _viewport_box(mobile.width, mobile.height)
    assert f"width: {box_w}px" in page.text
    assert f"height: {box_h}px" in page.text
