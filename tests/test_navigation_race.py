"""The navigate command must survive a page that redirects out from under it.

These run the *real* ``PlaywrightBrowserWorker`` (patchright + Chromium) against a
*real* locally served page, so the navigate -> ``page.title()`` path actually
meets a navigating page instead of a stub. The production failure was an opaque
HTTP 500 whose detail read ``Page.title: Execution context was destroyed, most
likely because of a navigation``: ``page.title()`` evaluates in the page's JS
context, and a client-side redirect that fires right after ``goto`` resolves at
``domcontentloaded`` tears that context down. ``_safe_title`` waits for the
replacement document and retries.

Skips (rather than fails) when a real browser cannot be launched on the host, so
the suite stays green on machines without the matching Chromium build. Set
``BROWSER_CHROMIUM_PATH`` to point the worker at a system Chrome when only a
different revision is installed.
"""

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from browser_handoff_service.models import AgentCommandRequest
from browser_handoff_service.runtime import PlaywrightBrowserWorker, RuntimeUnavailable

# Page A parses, fires DOMContentLoaded (so ``goto`` resolves here), then a
# queued microtask navigates to page B — the real-world client-side redirect.
_PAGE_A = (
    b"<!doctype html><title>First</title><h1>first</h1>"
    b"<script>setTimeout(function(){location.replace('/next');}, 0)</script>"
)
_PAGE_B = b"<!doctype html><title>Second</title><h1>second</h1>"


class _RedirectingHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # silence per-request stderr logging
        pass

    def do_GET(self):
        body = _PAGE_B if self.path.startswith("/next") else _PAGE_A
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def redirect_server() -> Iterator[str]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = ThreadingHTTPServer(("127.0.0.1", port), _RedirectingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


async def _started_worker() -> PlaywrightBrowserWorker:
    worker = PlaywrightBrowserWorker("worker_navigation_race")
    try:
        await worker.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real Chromium unavailable on this host: {exc}")
    return worker


@pytest.mark.asyncio
async def test_navigate_survives_client_side_redirect(redirect_server):
    """A real redirecting page resolves to a clean result, not an HTTP 500."""
    worker = await _started_worker()
    try:
        result = await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{redirect_server}/"}))
    finally:
        await worker.close()

    # Before the fix this raised "Execution context was destroyed" out of
    # page.title(). The command must now return a real title (either the
    # original or the redirected document), never an error.
    assert result["title"] in {"First", "Second"}
    assert "127.0.0.1" in result["url"]


@pytest.mark.asyncio
async def test_safe_title_recovers_when_a_navigation_destroys_the_context():
    """Deterministically drive ``_safe_title``'s retry over a real page.

    Fault injection on a *real* page object (not a Playwright stub): the first
    ``title()`` raises the genuine context-destroyed error, exactly as a
    mid-navigation read does, then the real ``page.title()`` is retried.
    """
    from patchright.async_api import Error as PlaywrightError

    worker = await _started_worker()
    try:
        await worker.command(
            AgentCommandRequest(
                type="navigate",
                args={"url": "data:text/html,<title>Landing</title><h1>x</h1>"},
            )
        )
        assert worker._page is not None
        real_page = worker._page

        class _ContextDestroyedOnce:
            """Real page, but the first title() read fails like a navigation race."""

            def __init__(self) -> None:
                self.title_calls = 0
                self.load_state_waits = 0

            async def title(self) -> str:
                self.title_calls += 1
                if self.title_calls == 1:
                    raise PlaywrightError(
                        "Page.title: Execution context was destroyed, most likely because of a navigation."
                    )
                return await real_page.title()

            async def wait_for_load_state(self, *args, **kwargs):
                self.load_state_waits += 1
                return await real_page.wait_for_load_state(*args, **kwargs)

        flaky = _ContextDestroyedOnce()
        title = await worker._safe_title(flaky)
    finally:
        await worker.close()

    assert title == "Landing"
    assert flaky.title_calls == 2  # failed once, retried once
    assert flaky.load_state_waits == 1  # waited for the new document before retrying


@pytest.mark.asyncio
async def test_snapshot_recovers_when_a_navigation_destroys_the_context():
    """The snapshot command must survive the same navigation race as _safe_title.

    Production failure: browser_open/snapshot 500'd with ``Page.evaluate:
    Execution context was destroyed, most likely because of a navigation.``
    because the snapshot handler called ``page.evaluate(_SNAPSHOT_JS)`` with no
    recovery, unlike the title-read path. Fault injection on a real page: the
    first ``evaluate`` fails like a mid-navigation read, then the real walker
    runs.
    """
    from patchright.async_api import Error as PlaywrightError

    worker = await _started_worker()
    try:
        await worker.command(
            AgentCommandRequest(
                type="navigate",
                args={"url": "data:text/html,<title>Landing</title><h1>x</h1>"},
            )
        )
        assert worker._page is not None
        real_page = worker._page

        class _ContextDestroyedOnce:
            """Real page, but the first evaluate() fails like a navigation race."""

            def __init__(self) -> None:
                self.evaluate_calls = 0
                self.load_state_waits = 0

            @property
            def url(self) -> str:  # delegated to real page
                return real_page.url

            async def evaluate(self, *args, **kwargs):
                self.evaluate_calls += 1
                if self.evaluate_calls == 1:
                    raise PlaywrightError(
                        "Page.evaluate: Execution context was destroyed, most likely because of a navigation."
                    )
                return await real_page.evaluate(*args, **kwargs)

            async def title(self) -> str:  # pragma: no cover - delegated
                return await real_page.title()

            async def wait_for_load_state(self, *args, **kwargs):
                self.load_state_waits += 1
                return await real_page.wait_for_load_state(*args, **kwargs)

        flaky = _ContextDestroyedOnce()
        result = await worker._dispatch_command(AgentCommandRequest(type="snapshot", args={}), flaky)
    finally:
        await worker.close()

    assert flaky.evaluate_calls == 2  # failed once, retried once
    assert flaky.load_state_waits == 1  # waited for the new document before retrying
    assert result["elements"] >= 1  # the retried walker saw the real DOM
    assert "partial" not in result


@pytest.mark.asyncio
async def test_snapshot_returns_degraded_result_when_context_keeps_getting_destroyed():
    """If the context is destroyed on every attempt, snapshot must not 500.

    The agent-command endpoint converts an uncaught exception into an opaque
    HTTP 500 while the registry holds the session lock; a well-formed empty
    snapshot (marked ``partial``) lets clients refresh refs and retry instead.
    """
    from patchright.async_api import Error as PlaywrightError

    worker = await _started_worker()
    try:
        await worker.command(
            AgentCommandRequest(
                type="navigate",
                args={"url": "data:text/html,<title>Landing</title><h1>x</h1>"},
            )
        )
        assert worker._page is not None
        real_page = worker._page

        class _AlwaysDestroyed:
            """Real page whose evaluate() always fails like a navigation race."""

            def __init__(self) -> None:
                self.evaluate_calls = 0
                self.load_state_waits = 0

            @property
            def url(self) -> str:  # delegated to real page
                return real_page.url

            async def evaluate(self, *args, **kwargs):
                self.evaluate_calls += 1
                raise PlaywrightError(
                    "Page.evaluate: Execution context was destroyed, most likely because of a navigation."
                )

            async def title(self) -> str:  # pragma: no cover - delegated
                return await real_page.title()

            async def wait_for_load_state(self, *args, **kwargs):
                self.load_state_waits += 1
                return await real_page.wait_for_load_state(*args, **kwargs)

        always = _AlwaysDestroyed()
        result = await worker._dispatch_command(AgentCommandRequest(type="snapshot", args={}), always)
    finally:
        await worker.close()

    assert always.evaluate_calls == 3  # initial attempt + bounded retries
    assert result["partial"] is True
    assert result["elements"] == 0
    assert result["roots"] == []
    assert "data:" in result["url"]  # still a usable url, not an error payload
