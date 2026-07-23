"""Timezone plumbing: a requested IANA timezone reaches the browser context so
in-page ``new Date()`` / ``Intl`` report the caller's local time, with an
operator-level ``BROWSER_TIMEZONE`` default as the fallback."""

import pytest
from browser_handoff_service.main import app, registry
from browser_handoff_service.models import CreateSessionRequest, new_session
from browser_handoff_service.runtime import (
    FakeBrowserWorker,
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


def test_new_session_carries_requested_timezone():
    req = CreateSessionRequest(conversation_id="conv_tz", timezone_id="Australia/Sydney")
    assert new_session(req).timezone_id == "Australia/Sydney"


def test_new_session_timezone_defaults_to_none():
    assert new_session(CreateSessionRequest(conversation_id="conv_no_tz")).timezone_id is None


def test_make_worker_forwards_explicit_timezone(monkeypatch):
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    monkeypatch.delenv("BROWSER_TIMEZONE", raising=False)
    worker = make_worker("worker_tz", timezone_id="Europe/London")
    assert isinstance(worker, PlaywrightBrowserWorker)
    assert worker.timezone_id == "Europe/London"


def test_make_worker_falls_back_to_env_default(monkeypatch):
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    monkeypatch.setenv("BROWSER_TIMEZONE", "Australia/Sydney")
    worker = make_worker("worker_env_tz")
    assert isinstance(worker, PlaywrightBrowserWorker)
    assert worker.timezone_id == "Australia/Sydney"


def test_explicit_timezone_overrides_env_default(monkeypatch):
    monkeypatch.delenv("BROWSER_RUNTIME", raising=False)
    monkeypatch.setenv("BROWSER_TIMEZONE", "Australia/Sydney")
    worker = make_worker("worker_override_tz", timezone_id="America/New_York")
    assert isinstance(worker, PlaywrightBrowserWorker)
    assert worker.timezone_id == "America/New_York"


@pytest.mark.asyncio
async def test_create_session_applies_requested_timezone_to_worker():
    headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        created = await client.post(
            "/v1/sessions",
            headers=headers,
            json={"conversation_id": "conv_tz_api", "timezone_id": "Australia/Sydney"},
        )
    assert created.status_code == 200, created.text
    session = registry.sessions[created.json()["session_id"]]
    assert session.timezone_id == "Australia/Sydney"
    assert session.worker_id is not None
    worker = registry.workers[session.worker_id]
    assert isinstance(worker, FakeBrowserWorker)
    assert worker.timezone_id == "Australia/Sydney"
