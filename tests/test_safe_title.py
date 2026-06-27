"""``PlaywrightBrowserWorker._safe_title`` must survive the navigation race.

``page.title()`` runs inside the page's JS execution context. A client-side
redirect that fires right after ``page.goto`` resolves at ``domcontentloaded``
tears that context down, so the call raises "Execution context was destroyed,
most likely because of a navigation". Before the fix this bubbled up through
``registry.agent_command`` and ``main.map_errors`` as an opaque HTTP 500 whose
only detail was ``str(exc)`` (e.g. ``Page.title: Execution context was
destroyed...``). ``_safe_title`` waits for the replacement document and retries.
"""

import sys
import types

import pytest
from browser_handoff_service.runtime import PlaywrightBrowserWorker

_CONTEXT_DESTROYED = "Page.title: Execution context was destroyed, most likely because of a navigation."


@pytest.fixture
def playwright_error(monkeypatch):
    """Provide ``rebrowser_playwright.async_api.Error`` without the real driver.

    ``_safe_title`` imports the error type lazily; the package is not installed
    in the unit-test environment, so stub a module exposing a compatible
    ``Error`` class and have the fake page raise that same type.
    """

    class _Error(Exception):
        pass

    async_api = types.ModuleType("rebrowser_playwright.async_api")
    async_api.Error = _Error
    pkg = types.ModuleType("rebrowser_playwright")
    pkg.async_api = async_api
    monkeypatch.setitem(sys.modules, "rebrowser_playwright", pkg)
    monkeypatch.setitem(sys.modules, "rebrowser_playwright.async_api", async_api)
    return _Error


class _FakePage:
    def __init__(self, error_type, fail_times: int, final_title: str = "Landing"):
        self._error_type = error_type
        self._fail_times = fail_times
        self._final_title = final_title
        self.title_calls = 0
        self.load_state_waits = 0

    async def title(self) -> str:
        self.title_calls += 1
        if self.title_calls <= self._fail_times:
            raise self._error_type(_CONTEXT_DESTROYED)
        return self._final_title

    async def wait_for_load_state(self, state: str, **_kwargs) -> None:
        self.load_state_waits += 1


@pytest.mark.asyncio
async def test_safe_title_retries_after_navigation_destroys_context(playwright_error):
    worker = PlaywrightBrowserWorker("worker_safe_title")
    page = _FakePage(playwright_error, fail_times=1)

    title = await worker._safe_title(page)

    assert title == "Landing"
    assert page.title_calls == 2
    assert page.load_state_waits == 1


@pytest.mark.asyncio
async def test_safe_title_falls_back_to_empty_when_context_keeps_dying(playwright_error):
    worker = PlaywrightBrowserWorker("worker_safe_title")
    page = _FakePage(playwright_error, fail_times=99)

    title = await worker._safe_title(page)

    # Three attempts, then a graceful empty title rather than a 500.
    assert title == ""
    assert page.title_calls == 3


@pytest.mark.asyncio
async def test_safe_title_reraises_unrelated_playwright_errors(playwright_error):
    worker = PlaywrightBrowserWorker("worker_safe_title")

    class _BrokenPage:
        def __init__(self):
            self.title_calls = 0

        async def title(self) -> str:
            self.title_calls += 1
            raise playwright_error("Page.title: Target page, context or browser has been closed")

        async def wait_for_load_state(self, state, **_kwargs):  # pragma: no cover - not reached
            raise AssertionError("should not retry a non-navigation error")

    page = _BrokenPage()
    with pytest.raises(playwright_error):
        await worker._safe_title(page)
    assert page.title_calls == 1
