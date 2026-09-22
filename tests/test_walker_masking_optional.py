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


async def _fill_username(worker: Any, ref: str, nonce: str) -> None:
    prepared = await worker.autofill_prepare([{"ref": ref, "kind": "username"}], nonce)
    assert prepared.get("ok"), prepared
    result = await worker.autofill_fill(nonce, prepared["origin"], prepared["targets"], {"username": SECRET})
    assert result.get("ok"), result


@pytest.mark.asyncio
async def test_a_filled_username_is_masked_but_is_still_not_a_password_field(worker, page_server):
    """Read-back protection and field identity are separate marks on the control.

    Deriving "this is a password field" from the masking stamp makes an autofilled username look
    like a second password on the next auto-detect."""
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{page_server}/login"}))
    await worker._page.set_content('<input type="email" autocomplete="username"><input type="password">')
    await _snapshot(worker)
    await _fill_username(worker, "e1", "nonce-u1")

    prepared = await worker.autofill_prepare(None, "nonce-u2")
    assert prepared.get("ok"), prepared
    chosen = {target["ref"]: target["kind"] for target in prepared["targets"]}
    assert chosen == {"e1": "username", "e2": "password"}

    # The username is still masked — only its identity as a password field was wrong.
    snapshot = await _snapshot(worker)
    assert SECRET not in repr(snapshot)


@pytest.mark.asyncio
async def test_a_username_only_form_does_not_become_its_own_password_field(worker, page_server):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{page_server}/login"}))
    await worker._page.set_content('<input type="email" autocomplete="username">')
    await _snapshot(worker)
    await _fill_username(worker, "e1", "nonce-s1")

    prepared = await worker.autofill_prepare(None, "nonce-s2")
    assert prepared.get("ok"), prepared
    assert [(target["ref"], target["kind"]) for target in prepared["targets"]] == [("e1", "username")]


@pytest.mark.asyncio
async def test_a_password_fill_survives_a_show_password_toggle_as_a_password_field(worker, page_server):
    """The converse mark: a filled password stays a password field when the page flips its type,
    and does not become an identifier candidate."""
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{page_server}/login"}))
    await worker._page.set_content('<input type="password">')
    await _snapshot(worker)
    prepared = await worker.autofill_prepare([{"ref": "e1", "kind": "password"}], "nonce-p1")
    assert prepared.get("ok"), prepared
    assert (await worker.autofill_fill("nonce-p1", prepared["origin"], prepared["targets"], {"password": SECRET})).get(
        "ok"
    )
    await worker._page.evaluate("() => document.querySelector('[data-fa-ref=e1]').setAttribute('type', 'text')")

    again = await worker.autofill_prepare(None, "nonce-p2")
    assert again.get("ok"), again
    assert [(target["ref"], target["kind"]) for target in again["targets"]] == [("e1", "password")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "() => document.querySelector('label[for=pw]').textContent = 'New password'",
        "() => document.querySelector('#pw').setAttribute('role', 'searchbox')",
    ],
)
@pytest.mark.parametrize("when", ["before_prepare", "before_verify"])
async def test_autofill_rejects_a_repurposed_snapshot_ref(worker, page_server, mutation, when):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{page_server}/login"}))
    snapshot = await _snapshot(worker)
    password_ref = _by_name(snapshot["roots"], "Password")["ref"]
    fields = [{"ref": password_ref, "kind": "password"}]
    if when == "before_prepare":
        await worker._page.evaluate(mutation)
        result = await worker.autofill_prepare(fields, "changed-field")
        assert result.get("reason") == "stale_ref", result
    else:
        prepared = await worker.autofill_prepare(fields, "changed-field")
        assert prepared.get("ok"), prepared
        await worker._page.evaluate(mutation)
        result = await worker.autofill_fill(
            "changed-field", prepared["origin"], prepared["targets"], {"password": "replacement-secret"}
        )
        assert result.get("reason") == "target_invalidated", result
        assert await worker._page.locator("#pw").input_value() == SECRET


@pytest.mark.asyncio
async def test_close_page_discards_human_history(worker, page_server):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/human"}))
    human_page = worker._page
    await human_page.locator("#user").fill("human-only-otp")
    await worker.command(AgentCommandRequest(type="close_page"))
    assert human_page.is_closed()
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/resumed"}))
    for _ in range(2):
        await worker.command(AgentCommandRequest(type="navigate_back"))
    snapshot = await worker.command(AgentCommandRequest(type="snapshot"))
    assert "human-only-otp" not in str(snapshot)
    assert worker._page.url == "about:blank"


@pytest.mark.asyncio
@pytest.mark.parametrize("capture_first", [False, True])
async def test_reveal_before_first_snapshot_stays_protected(worker, page_server, capture_first):
    worker.mask_protected = True
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/login"}))
    if capture_first:
        await worker.command(AgentCommandRequest(type="screenshot"))
    await worker.command(AgentCommandRequest(type="click", args={"selector": "#reveal"}))
    snapshot = await _snapshot(worker)
    assert SECRET not in repr(snapshot)
    password = _by_name(snapshot["roots"], "Password")
    assert password["input_type"] == "text"
    assert password["value_masked"] is True


@pytest.mark.asyncio
async def test_username_handler_cannot_repurpose_password_target(worker, page_server):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/login"}))
    await worker._page.set_content(
        '<input type="email" autocomplete="username" id="user">'
        '<input type="password" id="pw">'
        '<script>document.querySelector("#user").addEventListener("input", () => '
        'document.querySelector("#pw").setAttribute("autocomplete", "new-password"))</script>'
    )
    prepared = await worker.autofill_prepare(None, "multi-field")
    assert prepared.get("ok"), prepared
    result = await worker.autofill_fill(
        "multi-field", prepared["origin"], prepared["targets"], {"username": "user", "password": SECRET}
    )
    assert result.get("reason") == "target_invalidated", result
    assert await worker._page.locator("#pw").input_value() == ""
    assert await worker._page.locator("#user").input_value() == "user"


@pytest.mark.asyncio
async def test_auto_detected_target_keeps_identity_without_prior_snapshot(worker, page_server):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/login"}))
    await worker._page.set_content('<label for="pw">Current password</label><input type="password" id="pw">')
    prepared = await worker.autofill_prepare(None, "auto-identity")
    assert prepared.get("ok"), prepared
    assert prepared["targets"][0]["ref"] is not None
    await worker._page.locator("label").evaluate("el => el.textContent = 'Replacement password'")
    result = await worker.autofill_fill("auto-identity", prepared["origin"], prepared["targets"], {"password": SECRET})
    assert result.get("reason") == "target_invalidated", result
    assert await worker._page.locator("#pw").input_value() == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["username", "password"])
async def test_kind_only_fill_auto_detects_only_the_requested_field(worker, page_server, kind):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/login"}))
    await worker._page.set_content(
        '<input type="email" autocomplete="username" id="user"><input type="password" id="pw">'
    )
    prepared = await worker.autofill_prepare([{"kind": kind}], "kind-only")
    assert prepared.get("ok"), prepared
    assert [target["kind"] for target in prepared["targets"]] == [kind]
    result = await worker.autofill_fill("kind-only", prepared["origin"], prepared["targets"], {kind: SECRET})
    assert result.get("ok"), result
    assert await worker._page.locator("#user").input_value() == (SECRET if kind == "username" else "")
    assert await worker._page.locator("#pw").input_value() == (SECRET if kind == "password" else "")


@pytest.mark.asyncio
@pytest.mark.parametrize("fields", [None, [{"kind": "password"}]])
async def test_auto_detection_preserves_refs_across_navigation(worker, page_server, fields):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/first"}))
    first = await worker.command(AgentCommandRequest(type="snapshot", args={"next_ref": 100}))
    old_refs = {node["ref"] for node in _flatten(first["roots"]) if node.get("ref")}
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/second"}))
    await worker._page.locator("#empty").evaluate("el => el.remove()")
    prepared = await worker.autofill_prepare(fields, "new-document")
    assert prepared.get("ok"), prepared
    assert all(int(target["ref"][1:]) >= first["next_ref"] for target in prepared["targets"])
    second = await worker.command(AgentCommandRequest(type="snapshot", args={"next_ref": 1}))
    new_refs = {node["ref"] for node in _flatten(second["roots"]) if node.get("ref")}
    assert old_refs.isdisjoint(new_refs)
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/third"}))
    third = await worker.command(AgentCommandRequest(type="snapshot", args={"next_ref": 1}))
    assert all(int(node["ref"][1:]) >= second["next_ref"] for node in _flatten(third["roots"]) if node.get("ref"))


@pytest.mark.asyncio
async def test_fill_handler_cannot_remove_post_fill_masking_target(worker, page_server):
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/login"}))
    await worker._page.set_content(
        '<input type="password" id="pw">'
        '<script>document.querySelector("#pw").addEventListener("input", event => {'
        'event.target.type = "text"; event.target.removeAttribute("data-fa-autofill-target");'
        "})</script>"
    )
    prepared = await worker.autofill_prepare(None, "mask-before-input")
    result = await worker.autofill_fill(
        "mask-before-input", prepared["origin"], prepared["targets"], {"password": SECRET}
    )
    assert result.get("ok"), result
    snapshot = await worker.command(AgentCommandRequest(type="snapshot", args={}))
    assert SECRET not in str(snapshot)
    assert await worker._page.locator("#pw").get_attribute("data-fa-protected") is not None


@pytest.mark.asyncio
async def test_child_frame_password_is_stamped_and_masked(worker, page_server, monkeypatch):
    worker.mask_protected = True
    await worker.command(AgentCommandRequest(type="navigate", args={"url": page_server + "/login"}))
    await worker._page.set_content('<iframe src="/child"></iframe>')
    frame = worker._page.frames[1]
    await frame.wait_for_selector("#pw")
    await worker.command(AgentCommandRequest(type="press_key", args={"key": "Tab"}))
    assert await frame.locator("#pw").get_attribute("data-fa-protected") is not None
    await frame.locator("#pw").evaluate("el => el.type = 'text'")
    original = worker._page.screenshot
    masked = []

    async def capture(**kwargs):
        masked.extend([await locator.count() for locator in kwargs["mask"]])
        return await original(**kwargs)

    monkeypatch.setattr(worker._page, "screenshot", capture)
    await worker.command(AgentCommandRequest(type="screenshot", args={}))
    assert len(masked) == 2
    assert masked[1] >= 1
