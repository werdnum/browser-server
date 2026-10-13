"""The persistent-context launch mode (``BROWSER_CONTEXT_PERSISTENT``).

Off by default. When enabled, ``start()`` must launch a *headed persistent
context* (a real profile) instead of an incognito ``launch()`` + ``new_context()``:
patchright's documented best-practice posture against Cloudflare-class
interstitials. Fences must hold on that path too: a jar's storage_state fails
closed, confinement still installs its route guard, the per-session profile dir
is removed on close, and the default (incognito) launch is unchanged.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from browser_handoff_service import runtime as runtime_module
from browser_handoff_service.runtime import (
    PlaywrightBrowserWorker,
    RuntimeUnavailable,
    persistent_context_enabled,
)

_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"


class _StubPage:
    def __init__(self) -> None:
        self.url = "about:blank"

    async def evaluate(self, _expression: str) -> str:
        return _UA


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

    async def new_context(self, **_kwargs: Any) -> _StubContext:
        context = _StubContext()
        self.contexts.append(context)
        return context

    async def close(self) -> None:
        return None


class _StubChromium:
    def __init__(self) -> None:
        self.launch_calls: list[dict[str, Any]] = []
        self.persistent_calls: list[dict[str, Any]] = []

    async def launch(self, **kwargs: Any) -> _StubBrowser:
        self.launch_calls.append(kwargs)
        return _StubBrowser()

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


class _StubPlaywrightFactory:
    """Shape of ``patchright.async_api.async_playwright``: sync call, async start."""

    def __init__(self, playwright: _StubPlaywright) -> None:
        self._playwright = playwright

    async def start(self) -> _StubPlaywright:
        return self._playwright


def _patch_playwright(monkeypatch: pytest.MonkeyPatch) -> _StubPlaywright:
    stub = _StubPlaywright()
    monkeypatch.setattr(
        "patchright.async_api.async_playwright",
        lambda: _StubPlaywrightFactory(stub),
    )
    return stub


def _no_remote_display(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the noVNC stack absent so the local-display fallback is deterministic."""

    class _UnavailableDisplay:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def start(self) -> str:
            raise RuntimeUnavailable("missing remote display binaries")

        def close(self) -> None:
            return None

    monkeypatch.setattr(runtime_module, "LocalNovncDisplay", _UnavailableDisplay)


def test_persistent_flag_parses_and_defaults_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    assert persistent_context_enabled() is False
    for value in ("1", "true", "yes", "on", " TRUE "):
        monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", value)
        assert persistent_context_enabled() is True, value
    for value in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", value)
        assert persistent_context_enabled() is False, value


@pytest.mark.asyncio
async def test_persistent_start_launches_headed_real_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", "1")
    monkeypatch.setenv("BROWSER_CHROMIUM_CHANNEL", "chrome")
    stub = _patch_playwright(monkeypatch)
    _no_remote_display(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_persistent")
    await worker.start()
    try:
        assert worker.headed is True
        # The real-profile launch: headed persistent context, branded channel,
        # desktop profile without viewport emulation — and no incognito launch.
        assert len(stub.chromium.persistent_calls) == 1
        call = stub.chromium.persistent_calls[0]
        assert call["channel"] == "chrome"
        assert call["headless"] is False
        assert call["no_viewport"] is True
        assert "viewport" not in call
        assert stub.chromium.launch_calls == []
        # The page comes from the persistent context's own (initial) page.
        assert worker._context is not None
        assert worker._page is worker._context.pages[0]
        # A host without the noVNC stack still starts: the window opens on the
        # local display and there is no remote mirror.
        assert worker.remote_url is None
        assert worker._display is None
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_persistent_profile_dir_removed_on_close(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", "1")
    _patch_playwright(monkeypatch)
    _no_remote_display(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_profile_cleanup")
    await worker.start()
    assert worker._profile_tmpdir is not None
    profile_dir = worker._profile_tmpdir.name
    assert os.path.exists(profile_dir)  # noqa: ASYNC240 - trivial temp-dir existence probe
    await worker.close()
    assert worker._profile_tmpdir is None
    assert not os.path.exists(profile_dir)  # noqa: ASYNC240 - trivial temp-dir existence probe


@pytest.mark.asyncio
async def test_persistent_jar_storage_state_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", "1")
    stub = _patch_playwright(monkeypatch)
    worker = PlaywrightBrowserWorker(
        "worker_persistent_jar",
        storage_state={"cookies": [], "origins": []},
    )
    with pytest.raises(RuntimeUnavailable, match="storage_state"):
        await worker.start()
    assert stub.chromium.persistent_calls == []
    assert stub.chromium.launch_calls == []


@pytest.mark.asyncio
async def test_persistent_keeps_confinement_and_skips_init_scripts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", "1")
    _patch_playwright(monkeypatch)
    _no_remote_display(monkeypatch)
    worker = PlaywrightBrowserWorker(
        "worker_persistent_confined",
        confine_origins=["https://shop.example.com"],
    )
    await worker.start()
    try:
        context: Any = worker._context
        # Confinement installs its route guard and popup watcher on the
        # persistent context exactly as on an incognito one.
        assert context.routes == ["**/*"]
        assert "page" in context.events
        # No fingerprint-injection init script on the real-profile path: the real
        # Chrome surfaces are already genuine, and patching them is a tell.
        assert context.init_scripts == []
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_persistent_mobile_keeps_explicit_viewport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_CONTEXT_PERSISTENT", "1")
    stub = _patch_playwright(monkeypatch)
    _no_remote_display(monkeypatch)
    worker = PlaywrightBrowserWorker(
        "worker_persistent_mobile",
        user_agent="Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36",
    )
    await worker.start()
    try:
        call = stub.chromium.persistent_calls[0]
        # The mobile profile (UA + touch + explicit viewport) is a deliberate
        # product feature and stays as it is on the incognito path.
        assert call["viewport"] == {"width": worker.width, "height": worker.height}
        assert call["is_mobile"] is True
        assert call["has_touch"] is True
        assert call["user_agent"] == worker.user_agent
        assert "no_viewport" not in call
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_default_incognito_launch_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    monkeypatch.delenv("BROWSER_CHROMIUM_CHANNEL", raising=False)
    stub = _patch_playwright(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_default")
    await worker.start()
    try:
        assert worker.persistent is False
        assert stub.chromium.persistent_calls == []
        assert len(stub.chromium.launch_calls) == 1
        call = stub.chromium.launch_calls[0]
        assert call["headless"] is True
        assert call["channel"] is None
        assert worker._profile_tmpdir is None
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_channel_env_passes_to_incognito_launch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROWSER_CONTEXT_PERSISTENT", raising=False)
    monkeypatch.setenv("BROWSER_CHROMIUM_CHANNEL", "chromium")
    stub = _patch_playwright(monkeypatch)
    worker = PlaywrightBrowserWorker("worker_channel")
    await worker.start()
    try:
        assert stub.chromium.launch_calls[0]["channel"] == "chromium"
    finally:
        await worker.close()
