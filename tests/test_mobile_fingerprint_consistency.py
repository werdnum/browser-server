"""Cross-layer consistency of the mobile (Chrome-on-Android) emulated profile.

A pinned mobile UA has no mobile layout without a UA override, but a hard-pinned
Chrome version drifts from the Client Hints / ``navigator.userAgentData`` Chromium
derives from its real build, and an unpinned ``navigator.platform`` / DPR exposes the
host (desktop) surface under an Android UA. These tests pin the fixes on BOTH launch
paths — the deployment runs the headed *persistent* path, which previously skipped all
of them: the UA's Chrome version tracks the running build, the viewport reports a phone
DPR, and the mobile-profile init script (not the desktop plugin synthesis) is injected.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from browser_handoff_service import runtime as runtime_module
from browser_handoff_service.models import MOBILE_DEVICE_SCALE_FACTOR, MOBILE_USER_AGENT
from browser_handoff_service.runtime import PlaywrightBrowserWorker

_BROWSER_VERSION = "155.0.6723.58"
_DESKTOP_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
_MOBILE_UA_ALIGNED = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36"
)


class _StubPage:
    def __init__(self) -> None:
        self.url = "about:blank"

    async def evaluate(self, _expression: str) -> str:
        return _DESKTOP_UA


class _StubContext:
    def __init__(self, pages: list[_StubPage] | None = None) -> None:
        self.pages = pages if pages is not None else []
        self.init_scripts: list[str] = []
        self.routes: list[str] = []
        self.events: dict[str, Any] = {}
        self.closed = False

    async def new_page(self) -> _StubPage:
        page = _StubPage()
        self.pages.append(page)
        return page

    async def add_init_script(self, script: str) -> None:
        self.init_scripts.append(script)

    async def route(self, pattern: str, _handler: Any) -> None:
        self.routes.append(pattern)

    def on(self, event: str, handler: Any) -> None:
        self.events[event] = handler

    async def close(self) -> None:
        self.closed = True


class _StubBrowser:
    def __init__(self) -> None:
        self.contexts: list[_StubContext] = []
        self.context_calls: list[dict[str, Any]] = []
        self.version = _BROWSER_VERSION

    async def new_context(self, **kwargs: Any) -> _StubContext:
        self.context_calls.append(kwargs)
        context = _StubContext()
        self.contexts.append(context)
        return context

    async def close(self) -> None:
        return None


class _StubChromium:
    def __init__(self) -> None:
        self.launched: list[_StubBrowser] = []
        self.persistent_calls: list[dict[str, Any]] = []

    async def launch(self, **_kwargs: Any) -> _StubBrowser:
        browser = _StubBrowser()
        self.launched.append(browser)
        return browser

    async def launch_persistent_context(self, user_data_dir: str, **kwargs: Any) -> _StubContext:
        self.persistent_calls.append({"user_data_dir": user_data_dir, **kwargs})
        return _StubContext([_StubPage()])


class _StubPlaywright:
    def __init__(self) -> None:
        self.chromium = _StubChromium()

    async def start(self) -> _StubPlaywright:
        return self

    async def stop(self) -> None:
        return None


def _patch_playwright(monkeypatch: pytest.MonkeyPatch) -> _StubPlaywright:
    stub = _StubPlaywright()

    class _Factory:
        async def start(self) -> _StubPlaywright:
            return stub

    monkeypatch.setattr("patchright.async_api.async_playwright", lambda: _Factory())
    return stub


def _no_remote_display(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the noVNC stack absent so the persistent local-display fallback is deterministic."""

    class _UnavailableDisplay:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def start(self) -> str:
            from browser_handoff_service.runtime import RuntimeUnavailable

            raise RuntimeUnavailable("missing remote display binaries")

        def close(self) -> None:
            return None

    monkeypatch.setattr(runtime_module, "LocalNovncDisplay", _UnavailableDisplay)


# ---------------------------------------------------------------------------
# Incognito path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mobile_user_agent_version_tracks_browser_build(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    stub = _patch_playwright(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_mobile_ua", user_agent=MOBILE_USER_AGENT)
    await worker.start()
    try:
        call = stub.chromium.launched[0].context_calls[0]
        assert call["user_agent"] == _MOBILE_UA_ALIGNED
        assert call["is_mobile"] is True
        assert call["has_touch"] is True
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_mobile_context_reports_phone_scale_factor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    stub = _patch_playwright(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_mobile_dpr", user_agent=MOBILE_USER_AGENT)
    await worker.start()
    try:
        call = stub.chromium.launched[0].context_calls[0]
        assert call["device_scale_factor"] == MOBILE_DEVICE_SCALE_FACTOR
        assert MOBILE_DEVICE_SCALE_FACTOR > 1
        assert call["screen"] == {"width": worker.width, "height": worker.height}
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_mobile_init_script_patches_android_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    _patch_playwright(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_mobile_script", user_agent=MOBILE_USER_AGENT)
    await worker.start()
    try:
        script = cast(Any, worker._context).init_scripts[0]
        assert "Linux armv81" in script  # navigator.platform agrees with the Android UA
        # Desktop-only plugin synthesis must not appear under a mobile UA.
        assert "PDF Viewer" not in script
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_desktop_init_script_keeps_plugin_synthesis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    _patch_playwright(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_desktop_script")
    await worker.start()
    try:
        script = cast(Any, worker._context).init_scripts[0]
        assert "PDF Viewer" in script
        assert "Linux armv81" not in script
    finally:
        await worker.close()


# ---------------------------------------------------------------------------
# Persistent path (the deployment: BROWSER_CONTEXT_PERSISTENT=1, headed Chrome)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_persistent_mobile_applies_consistent_emulation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", "1")
    monkeypatch.setenv("BROWSER_CHROMIUM_CHANNEL", "chrome")
    stub = _patch_playwright(monkeypatch)
    _no_remote_display(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_persistent_mobile", user_agent=MOBILE_USER_AGENT)
    await worker.start()
    try:
        call = stub.chromium.persistent_calls[0]
        # The mobile identity (UA, viewport, touch) and the consistency layers all apply.
        assert call["user_agent"] == _MOBILE_UA_ALIGNED
        assert call["viewport"] == {"width": worker.width, "height": worker.height}
        assert call["is_mobile"] is True
        assert call["has_touch"] is True
        assert call["device_scale_factor"] == MOBILE_DEVICE_SCALE_FACTOR
        # The Android platform/memory patch is injected on the real-profile path too.
        script = cast(Any, worker._context).init_scripts[0]
        assert "Linux armv81" in script
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_persistent_desktop_stays_unemulated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", "1")
    monkeypatch.setenv("BROWSER_CHROMIUM_CHANNEL", "chrome")
    stub = _patch_playwright(monkeypatch)
    _no_remote_display(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_persistent_desktop")
    await worker.start()
    try:
        call = stub.chromium.persistent_calls[0]
        # The genuine desktop real profile stays untouched: no UA, no viewport emulation,
        # no init script, and no throwaway version probe.
        assert "user_agent" not in call
        assert call["no_viewport"] is True
        assert "device_scale_factor" not in call
        assert cast(Any, worker._context).init_scripts == []
        assert stub.chromium.launched == []
    finally:
        await worker.close()


def test_mobile_user_agent_unchanged_without_version() -> None:
    worker = PlaywrightBrowserWorker("worker_no_version", user_agent=MOBILE_USER_AGENT)
    # A failed/absent version probe must never drop the device identity; the pinned UA
    # passes through unchanged rather than failing the session.
    assert worker._mobile_user_agent(None) == MOBILE_USER_AGENT


def test_chrome_version_rewrite_only_touches_the_product_token() -> None:
    rewritten = runtime_module._CHROME_UA_VERSION_RE.sub(
        "Chrome/155.0.0.0", "Mozilla/5.0 ... Chrome/120.0.0.0 Mobile Safari/537.36", count=1
    )
    assert rewritten.endswith(" Chrome/155.0.0.0 Mobile Safari/537.36")
    assert "120.0.0.0" not in rewritten
