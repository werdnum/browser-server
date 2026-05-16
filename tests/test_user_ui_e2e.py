from __future__ import annotations

import socket
import threading
from time import monotonic

import httpx
import pytest
import uvicorn
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import expect, sync_playwright

TEST_SERVICE_TOKEN = "test-service-token"


def _chromium_available() -> bool:
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            browser.close()
            return True
    except PlaywrightError:
        return False


def test_human_ui_e2e_with_real_playwright_browser(monkeypatch):
    if not _chromium_available():
        pytest.skip("real Playwright Chromium is unavailable on this host")

    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    port = _free_port()
    config = uvicorn.Config("browser_handoff_service.main:app", host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        _wait_for_service(f"http://127.0.0.1:{port}/health")

        headers = {"authorization": f"Bearer {TEST_SERVICE_TOKEN}"}
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=5) as client:
            created = client.post(
                "/v1/sessions",
                headers=headers,
                json={"conversation_id": "conv_user_e2e"},
            )
            created.raise_for_status()
            session_id = created.json()["session_id"]
            handoff = client.post(
                f"/v1/sessions/{session_id}/handoff",
                headers=headers,
                json={"reason": "payment", "handoff_note": "Review and pay"},
            )
            handoff.raise_for_status()
            handoff_url = handoff.json()["handoff_url"]

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
                page = browser.new_page()
                page.goto(handoff_url)
                expect(page.locator("#state")).to_have_text("handoff_requested")
                page.get_by_role("button", name="Claim").click()
                expect(page.locator("#state")).to_have_text("human_active")
                page.get_by_role("button", name="Extend").click()
                expect(page.locator("#state")).to_have_text("human_active")
                page.get_by_role("button", name="Mark sensitive").click()
                expect(page.locator("#state")).to_have_text("human_sensitive")
                page.get_by_role("button", name="Complete").click()
                expect(page.locator("#state")).to_have_text("completed")
                browser.close()

            denied = client.post(f"/v1/sessions/{session_id}/agent-command", headers=headers, json={"type": "snapshot"})
            assert denied.status_code == 403
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_service(url: str, *, timeout_seconds: float = 5) -> None:
    deadline = monotonic() + timeout_seconds
    pause = threading.Event()
    while monotonic() < deadline:
        try:
            if httpx.get(url, timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pause.wait(0.1)
    raise AssertionError("service did not start")
