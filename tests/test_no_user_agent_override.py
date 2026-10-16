"""Sessions keep the browser's own user agent; no form factor overrides it.

A pinned device UA has to be corroborated by every other observable layer (platform,
Client Hints, DPR, plugins, GPU), and each compensating patch is itself a tell, so
sessions run browser-as-is. The mobile form factor is only a portrait window/viewport.
The sole UA rewrite left is the headless build's "HeadlessChrome" product token, which
is a louder automation tell than any UA we could pin.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from browser_handoff_service import runtime as runtime_module
from browser_handoff_service.models import FormFactor, form_factor_profile
from browser_handoff_service.runtime import (
    PLUGIN_SYNTHESIS_SCRIPT,
    STEALTH_INIT_SCRIPT,
    PlaywrightBrowserWorker,
)

_HEADLESS_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/155.0.0.0 Safari/537.36"
)
_DEMASKED_UA = _HEADLESS_UA.replace("HeadlessChrome", "Chrome")


class _StubPage:
    def __init__(self) -> None:
        self.url = "about:blank"

    async def evaluate(self, _expression: str) -> str:
        return _HEADLESS_UA


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


def _real_context_call(browser: _StubBrowser) -> dict[str, Any]:
    """The context kwargs for the session context.

    The headless-UA demasking probe creates a throwaway context first, so the session
    context is the last one recorded.
    """
    return browser.context_calls[-1]


def test_form_factor_has_no_user_agent_field() -> None:
    # There is no UA to override: the profile chooses only the window/viewport shape.
    assert set(FormFactor.__dataclass_fields__) == {"width", "height"}


@pytest.mark.asyncio
async def test_mobile_incognito_only_demasks_the_headless_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    stub = _patch_playwright(monkeypatch)
    profile = form_factor_profile("mobile")
    worker = PlaywrightBrowserWorker("worker_mobile", width=profile.width, height=profile.height)
    await worker.start()
    try:
        call = _real_context_call(stub.chromium.launched[0])
        # The only UA rewrite is the headless product token; nothing else is emulated.
        assert call["user_agent"] == _DEMASKED_UA
        assert "is_mobile" not in call
        assert "has_touch" not in call
        assert call["viewport"] == {"width": profile.width, "height": profile.height}
        assert call["screen"] == {"width": profile.width, "height": profile.height}
        assert call["device_scale_factor"] == 1
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_mobile_incognito_gets_the_desktop_plugin_synthesis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    _patch_playwright(monkeypatch)
    profile = form_factor_profile("mobile")
    worker = PlaywrightBrowserWorker("worker_mobile_script", width=profile.width, height=profile.height)
    await worker.start()
    try:
        scripts: list[str] = cast(Any, worker._context).init_scripts
        assert scripts == [STEALTH_INIT_SCRIPT + "\n" + PLUGIN_SYNTHESIS_SCRIPT]
        assert "PDF Viewer" in scripts[0]
        # No Android platform patch: the UA is the host's own, so the host platform is correct.
        assert "Linux armv81" not in scripts[0]
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_mobile_and_desktop_incognito_get_identical_ua_treatment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    stub = _patch_playwright(monkeypatch)
    mobile = form_factor_profile("mobile")
    desktop = form_factor_profile("desktop")
    mobile_worker = PlaywrightBrowserWorker("worker_m", width=mobile.width, height=mobile.height)
    desktop_worker = PlaywrightBrowserWorker("worker_d", width=desktop.width, height=desktop.height)
    await mobile_worker.start()
    await desktop_worker.start()
    try:
        mobile_call = _real_context_call(stub.chromium.launched[0])
        desktop_call = _real_context_call(stub.chromium.launched[1])
        # The form factor changes only the viewport/screen dimensions, never the UA surface.
        differing = {k for k in mobile_call if mobile_call[k] != desktop_call.get(k)}
        assert differing <= {"viewport", "screen"}
    finally:
        await mobile_worker.close()
        await desktop_worker.close()


@pytest.mark.asyncio
async def test_persistent_overrides_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", "1")
    stub = _patch_playwright(monkeypatch)
    _no_remote_display(monkeypatch)
    profile = form_factor_profile("mobile")
    worker = PlaywrightBrowserWorker("worker_persistent", width=profile.width, height=profile.height)
    await worker.start()
    try:
        call = stub.chromium.persistent_calls[0]
        # A real profile is browser-as-is: portrait window is the viewport, nothing emulated,
        # no init script, and no throwaway version-probe launch.
        assert call["no_viewport"] is True
        assert "viewport" not in call
        assert "user_agent" not in call
        assert "is_mobile" not in call
        assert "has_touch" not in call
        assert "device_scale_factor" not in call
        assert cast(Any, worker._context).init_scripts == []
        assert stub.chromium.launched == []
    finally:
        await worker.close()
