"""A password's value does not leave the page through a snapshot.

These run the *real* ``PlaywrightBrowserWorker`` against a real locally served page, because the
whole property lives in the DOM: the walker reads ``el.value`` itself, the protection is an
attribute it stamps, and a "show password" toggle is a live type change no fake reproduces.

Skips (rather than fails) when a real browser cannot be launched on the host, like
``test_ref_identity.py``. Set ``BROWSER_CHROMIUM_PATH`` to point the worker at a system Chrome
when only a different revision is installed.
"""

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from browser_handoff_service.models import AgentCommandRequest
from browser_handoff_service.runtime import PlaywrightBrowserWorker, RuntimeUnavailable

SECRET = "correct-horse-battery-staple"

_LOGIN_PAGE = f"""<!doctype html><title>Sign in</title>
<h1>Sign in</h1>
<form>
  <label for="user">Email</label><input id="user" type="email" autocomplete="username" value="a@example.com">
  <label for="pw">Password</label><input id="pw" type="password" value="{SECRET}">
  <label for="empty">Confirm</label><input id="empty" type="password">
  <button id="reveal" type="button">Show</button>
  <button id="go" type="submit">Sign in</button>
</form>
<script>
document.getElementById('reveal').addEventListener('click', () => {{
  document.getElementById('pw').setAttribute('type', 'text');
}});
</script>
""".encode()


class _StaticHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # silence per-request stderr logging
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(_LOGIN_PAGE)))
        self.end_headers()
        self.wfile.write(_LOGIN_PAGE)


@pytest.fixture
def page_server() -> Iterator[str]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = ThreadingHTTPServer(("127.0.0.1", port), _StaticHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
async def worker() -> Any:
    worker = PlaywrightBrowserWorker("worker_walker_masking")
    try:
        await worker.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real Chromium unavailable on this host: {exc}")
    try:
        yield worker
    finally:
        await worker.close()


def _flatten(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for node in nodes:
        out.append(node)
        out.extend(_flatten(node.get("children", [])))
    return out


def _by_name(nodes: list[dict[str, Any]], name: str) -> dict[str, Any]:
    matches = [node for node in _flatten(nodes) if node.get("name") == name and node.get("tag") == "input"]
    assert len(matches) == 1, f"expected one {name!r} input, got {len(matches)}"
    return matches[0]


async def _snapshot(worker: Any) -> dict[str, Any]:
    return await worker.command(AgentCommandRequest(type="snapshot", args={"next_ref": 1}))


@pytest.mark.asyncio
async def test_a_password_value_never_reaches_a_snapshot(worker, page_server):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{page_server}/login"}))
    snapshot = await _snapshot(worker)

    assert SECRET not in repr(snapshot)
    password = _by_name(snapshot["roots"], "Password")
    assert password["value_masked"] is True
    assert password["has_value"] is True
    assert "value" not in password

    # Filled from empty is reported as such, so the agent can tell a filled field from a blank one.
    empty = _by_name(snapshot["roots"], "Confirm")
    assert empty["value_masked"] is True
    assert empty["has_value"] is False

    # An ordinary field keeps its value: blanket masking would cost the task and buy nothing.
    assert _by_name(snapshot["roots"], "Email")["value"] == "a@example.com"


@pytest.mark.asyncio
async def test_a_show_password_toggle_does_not_unprotect_the_control(worker, page_server):
    """The stamp is on the element, so a type change cannot turn a protected control back into
    a readable one."""
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{page_server}/login"}))
    await _snapshot(worker)
    await worker.command(AgentCommandRequest(type="click", args={"selector": "#reveal"}))

    revealed = await _snapshot(worker)
    assert SECRET not in repr(revealed)
    password = _by_name(revealed["roots"], "Password")
    assert password["input_type"] == "text"
    assert password["value_masked"] is True
    assert "value" not in password


@pytest.mark.asyncio
async def test_an_autofilled_control_is_stamped_and_masked_from_then_on(worker, page_server):
    """A fill protects whatever it touched, not only fields that were passwords to begin with."""
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{page_server}/login"}))
    snapshot = await _snapshot(worker)
    email_ref = _by_name(snapshot["roots"], "Email")["ref"]

    prepared = await worker.autofill_prepare([{"ref": email_ref, "kind": "username"}], "nonce-1")
    assert prepared.get("ok"), prepared
    result = await worker.autofill_fill("nonce-1", prepared["origin"], prepared["targets"], {"username": SECRET})
    assert result.get("ok"), result

    after = await _snapshot(worker)
    assert SECRET not in repr(after)
    email = _by_name(after["roots"], "Email")
    assert email["value_masked"] is True
    assert email["has_value"] is True


@pytest.mark.asyncio
async def test_a_fill_refuses_a_new_password_field_and_a_moved_document(worker, page_server):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{page_server}/login"}))
    snapshot = await _snapshot(worker)
    confirm_ref = _by_name(snapshot["roots"], "Confirm")["ref"]

    # Two visible password fields: which one is the login field is not a guess worth making.
    auto = await worker.autofill_prepare(None, "nonce-2")
    assert auto.get("reason") == "ambiguous_fields", auto

    prepared = await worker.autofill_prepare([{"ref": confirm_ref, "kind": "password"}], "nonce-3")
    assert prepared.get("ok"), prepared

    # A navigation between the resolve and the fill replaces the document, and the nonce with it.
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{page_server}/login"}))
    result = await worker.autofill_fill("nonce-3", prepared["origin"], prepared["targets"], {"password": SECRET})
    assert result.get("reason") == "target_invalidated", result
