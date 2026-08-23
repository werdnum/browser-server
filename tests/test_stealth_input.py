"""Stealth-mode input humanization: type_text gating and click holds.

The humanized path must never change command semantics: type_text REPLACES the
field value, specialized controls keep fill()'s serialized-value behavior, and
BROWSER_STEALTH=0 restores vanilla Playwright calls exactly.
"""

from typing import Any

import pytest
from browser_handoff_service.models import AgentCommandRequest
from browser_handoff_service.runtime import PlaywrightBrowserWorker


class _RecordingLocator:
    def __init__(self, text_like: bool):
        self.text_like = text_like
        self.calls: list[tuple[str, tuple, dict]] = []

    async def evaluate(self, _expression: str):
        return self.text_like

    async def click(self, *args, **kwargs):
        self.calls.append(("click", args, kwargs))

    async def fill(self, *args, **kwargs):
        self.calls.append(("fill", args, kwargs))

    async def press_sequentially(self, *args, **kwargs):
        self.calls.append(("press_sequentially", args, kwargs))


class _StubPage:
    def __init__(self, locator: _RecordingLocator):
        self._locator = locator
        self.url = "https://shop.example.com/form"

    def locator(self, _selector: str) -> _RecordingLocator:
        return self._locator

    async def wait_for_load_state(self, *_args, **_kwargs) -> None:
        return None

    async def title(self) -> str:
        return "Form"


async def _run_type_text(worker: PlaywrightBrowserWorker, locator: Any, text: str) -> None:
    worker._page = _StubPage(locator)  # ty: ignore[invalid-assignment]
    await worker.command(AgentCommandRequest(type="type_text", args={"selector": "#f", "text": text}))


@pytest.mark.asyncio
async def test_short_text_like_input_uses_humanized_typing_and_replaces_value():
    worker = PlaywrightBrowserWorker("worker_type_textlike")
    locator = _RecordingLocator(text_like=True)
    await _run_type_text(worker, locator, "hello")
    kinds = [call[0] for call in locator.calls]
    assert kinds == ["click", "fill", "press_sequentially"], kinds
    # fill("") clears before keystrokes so typing REPLACES rather than splices.
    assert locator.calls[1][1] == ("",)
    assert locator.calls[2][1] == ("hello",)


@pytest.mark.asyncio
async def test_specialized_input_falls_back_to_fill():
    worker = PlaywrightBrowserWorker("worker_type_specialized")
    locator = _RecordingLocator(text_like=False)
    await _run_type_text(worker, locator, "2024-01-15")
    kinds = [call[0] for call in locator.calls]
    assert kinds == ["fill"], kinds
    assert locator.calls[0][1] == ("2024-01-15",)


@pytest.mark.asyncio
async def test_long_text_bypasses_humanized_typing():
    worker = PlaywrightBrowserWorker("worker_type_long")
    locator = _RecordingLocator(text_like=True)
    await _run_type_text(worker, locator, "x" * 201)
    assert [call[0] for call in locator.calls] == ["fill"]


@pytest.mark.asyncio
async def test_unresolvable_target_falls_back_to_fill(monkeypatch):
    worker = PlaywrightBrowserWorker("worker_type_gone")
    monkeypatch.setenv("BROWSER_STEALTH", "1")
    worker.stealth = True

    class _GoneLocator:
        async def evaluate(self, _expression: str):
            raise RuntimeError("element detached")

        async def fill(self, *args, **kwargs):
            self.fill_args = args

    locator = _GoneLocator()
    await _run_type_text(worker, locator, "hi")
    assert locator.fill_args == ("hi",)


class _ClickRecordingLocator:
    def __init__(self):
        self.click_kwargs: dict | None = None

    async def click(self, *args, **kwargs):
        self.click_kwargs = kwargs


class _ClickStubMouse:
    def __init__(self):
        self.click_kwargs: dict | None = None

    async def click(self, x, y, **kwargs):  # noqa: ARG002 - signature mirror
        self.click_kwargs = kwargs


class _ClickStubPage:
    url = "https://shop.example.com/page"

    def __init__(self) -> None:
        self.recording = _ClickRecordingLocator()
        self.mouse = _ClickStubMouse()

    def locator(self, _selector: str) -> _ClickRecordingLocator:
        return self.recording

    async def wait_for_load_state(self, *_args, **_kwargs) -> None:
        return None

    async def title(self) -> str:
        return "Page"


@pytest.mark.asyncio
async def test_click_hold_present_when_stealth_on_absent_when_off(monkeypatch):
    page = _ClickStubPage()

    stealth_worker = PlaywrightBrowserWorker("worker_stealth_click")
    stealth_worker.stealth = True
    stealth_worker._page = page  # ty: ignore[invalid-assignment]
    await stealth_worker.command(AgentCommandRequest(type="click", args={"selector": "#b"}))
    assert page.recording.click_kwargs is not None and "delay" in page.recording.click_kwargs

    plain_worker = PlaywrightBrowserWorker("worker_plain_click")
    plain_worker.stealth = False
    plain_page = _ClickStubPage()
    plain_worker._page = plain_page  # ty: ignore[invalid-assignment]
    await plain_worker.command(AgentCommandRequest(type="click", args={"selector": "#b"}))
    assert plain_page.recording.click_kwargs == {}

    stealth_mouse_worker = PlaywrightBrowserWorker("worker_stealth_mouse")
    stealth_mouse_worker.stealth = True
    mouse_page = _ClickStubPage()
    stealth_mouse_worker._page = mouse_page  # ty: ignore[invalid-assignment]
    await stealth_mouse_worker.command(AgentCommandRequest(type="mouse_click", args={"x": 10, "y": 20}))
    assert mouse_page.mouse.click_kwargs is not None and "delay" in mouse_page.mouse.click_kwargs

    plain_mouse_worker = PlaywrightBrowserWorker("worker_plain_mouse")
    plain_mouse_worker.stealth = False
    plain_mouse_page = _ClickStubPage()
    plain_mouse_worker._page = plain_mouse_page  # ty: ignore[invalid-assignment]
    await plain_mouse_worker.command(AgentCommandRequest(type="mouse_click", args={"x": 10, "y": 20}))
    assert plain_mouse_page.mouse.click_kwargs == {}
