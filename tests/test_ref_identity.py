"""A ref names one node, and the page decides when it stops resolving.

These run the *real* ``PlaywrightBrowserWorker`` (patchright + Chromium) against a real locally
served page, because the whole contract lives in the DOM: refs survive a re-snapshot, a fresh
number never repeats one already stamped or already issued, and an action on a ref whose node a
snapshot would no longer list fails immediately instead of waiting out Playwright's actionability
timeout. A fake page cannot exercise any of that.

Skips (rather than fails) when a real browser cannot be launched on the host, like
``test_navigation_race.py``. Set ``BROWSER_CHROMIUM_PATH`` to point the worker at a system Chrome
when only a different revision is installed.
"""

import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from browser_handoff_service.models import AgentCommandRequest, CreateSessionRequest
from browser_handoff_service.registry import SessionRegistry
from browser_handoff_service.runtime import PlaywrightBrowserWorker, RuntimeUnavailable, coerce_next_ref

_PAGE_A = b"""<!doctype html><title>Alpha</title>
<h1>Alpha</h1>
<button id="one">One</button>
<button id="two">Two</button>
<label for="name">Name</label><input id="name" type="text">
<select id="pick" aria-label="Pick"><option value="a">A</option><option value="b">B</option></select>
<div id="box"><button id="boxed">Boxed</button></div>
<input id="go" type="submit" value="Review">
"""

_PAGE_B = b"""<!doctype html><title>Beta</title>
<h1>Beta</h1>
<button id="only">Only</button>
"""

# The exact sentence a caller (and the model behind it) is shown for a ref that no longer resolves.
_STALE_REASON = "ref {ref} is no longer on the page as snapshotted; the page has changed since the last snapshot"


class _StaticHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # silence per-request stderr logging
        pass

    def do_GET(self):
        body = _PAGE_B if self.path.startswith("/b") else _PAGE_A
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
    worker = PlaywrightBrowserWorker("worker_ref_identity")
    try:
        await worker.start()
    except RuntimeUnavailable as exc:
        pytest.skip(f"real Chromium unavailable on this host: {exc}")
    try:
        yield worker
    finally:
        await worker.close()


async def _navigate(worker: Any, url: str) -> dict[str, Any]:
    return await worker.command(AgentCommandRequest(type="navigate", args={"url": url}))


async def _snapshot(worker: Any, next_ref: int | None = None) -> dict[str, Any]:
    args = {} if next_ref is None else {"next_ref": next_ref}
    return await worker.command(AgentCommandRequest(type="snapshot", args=args))


async def _exec(worker: Any, code: str) -> dict[str, Any]:
    return await worker.command(AgentCommandRequest(type="exec", args={"code": code}))


def _flatten(roots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for node in roots:
        out.append(node)
        out.extend(_flatten(node.get("children", [])))
    return out


def _by_name(snapshot: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [node for node in _flatten(snapshot["roots"]) if node["name"] == name]
    assert matches, f"no node named {name!r} in {snapshot['roots']}"
    return matches[0]


def _refs(snapshot: dict[str, Any]) -> list[str]:
    return [node["ref"] for node in _flatten(snapshot["roots"])]


async def test_re_snapshotting_an_unchanged_page_reuses_every_ref(worker, page_server):
    await _navigate(worker, f"{page_server}/a")
    first = await _snapshot(worker, 1)
    second = await _snapshot(worker, first["next_ref"])

    assert _refs(first) == _refs(second)
    assert second["next_ref"] == first["next_ref"]
    assert second["elements"] == len(_refs(second))


async def test_a_node_inserted_before_another_does_not_renumber_it(worker, page_server):
    await _navigate(worker, f"{page_server}/a")
    first = await _snapshot(worker, 1)
    existing = {node["name"]: node["ref"] for node in _flatten(first["roots"])}

    await _exec(worker, "document.body.insertAdjacentHTML('afterbegin', '<button>Zero</button>'); return 1")
    second = await _snapshot(worker, first["next_ref"])

    for name, ref in existing.items():
        assert _by_name(second, name)["ref"] == ref
    assert _by_name(second, "Zero")["ref"] == f"e{first['next_ref']}"
    assert second["next_ref"] == first["next_ref"] + 1


async def test_a_relabelled_node_is_stale_until_it_is_renumbered(worker, page_server):
    await _navigate(worker, f"{page_server}/a")
    first = await _snapshot(worker, 1)
    ref = _by_name(first, "Two")["ref"]

    await _exec(worker, "document.getElementById('two').textContent = 'Renamed'; return 1")

    acted = await worker.command(AgentCommandRequest(type="click", args={"ref": ref}))
    assert acted["code"] == "stale_ref"
    assert acted["cause"] == "changed"

    second = await _snapshot(worker, first["next_ref"])
    assert _by_name(second, "Renamed")["ref"] == f"e{first['next_ref']}"
    assert ref not in _refs(second)
    assert _by_name(second, "One")["ref"] == _by_name(first, "One")["ref"]


async def test_a_button_input_is_named_by_its_value_and_stale_when_it_changes(worker, page_server):
    await _navigate(worker, f"{page_server}/a")
    first = await _snapshot(worker, 1)
    ref = _by_name(first, "Review")["ref"]

    await _exec(worker, "document.getElementById('go').value = 'Pay'; return 1")

    acted = await worker.command(AgentCommandRequest(type="click", args={"ref": ref}))
    assert acted["code"] == "stale_ref"
    assert acted["cause"] == "changed"
    second = await _snapshot(worker, first["next_ref"])
    assert _by_name(second, "Pay")["ref"] != ref


async def test_a_cloned_node_with_a_hidden_original_gets_a_fresh_usable_ref(worker, page_server):
    await _navigate(worker, f"{page_server}/a")
    first = await _snapshot(worker, 1)
    ref = _by_name(first, "Two")["ref"]

    await _exec(
        worker,
        "const two = document.getElementById('two'); const clone = two.cloneNode(true); "
        "clone.id = 'two-clone'; two.after(clone); two.style.display = 'none'; return 1",
    )

    stale = await worker.command(AgentCommandRequest(type="click", args={"ref": ref}))
    assert stale["code"] == "stale_ref"

    second = await _snapshot(worker, first["next_ref"])
    clone_ref = _by_name(second, "Two")["ref"]
    assert clone_ref != ref
    acted = await worker.command(AgentCommandRequest(type="click", args={"ref": clone_ref}))
    assert acted["accepted"] is True


async def test_numbering_continues_across_navigation_and_reload(worker, page_server):
    seen: list[str] = []
    counter = 1
    for url in (f"{page_server}/a", f"{page_server}/b", f"{page_server}/a", f"{page_server}/a"):
        await _navigate(worker, url)
        snapshot = await _snapshot(worker, counter)
        assert all(int(ref[1:]) >= counter for ref in _refs(snapshot))
        seen.extend(_refs(snapshot))
        counter = snapshot["next_ref"]

    assert len(seen) == len(set(seen))


async def test_a_counter_below_the_documents_stamps_allocates_above_them(worker, page_server):
    await _navigate(worker, f"{page_server}/a")
    stamped = await _snapshot(worker, 500)
    highest = max(int(ref[1:]) for ref in _refs(stamped))

    await _exec(worker, "document.body.insertAdjacentHTML('beforeend', '<button>Late</button>'); return 1")
    rewound = await _snapshot(worker, 1)

    assert _by_name(rewound, "Late")["ref"] == f"e{highest + 1}"
    assert rewound["next_ref"] == highest + 2
    for name, ref in {node["name"]: node["ref"] for node in _flatten(stamped["roots"])}.items():
        assert _by_name(rewound, name)["ref"] == ref


@pytest.mark.parametrize(
    ("command", "extra_args"),
    [("click", {}), ("type_text", {"text": "hello"}), ("select", {"value": "b"})],
)
@pytest.mark.parametrize("scenario", ["removed", "hidden", "relabelled", "previous_document"])
async def test_an_action_on_an_unresolvable_ref_fails_fast(worker, page_server, command, extra_args, scenario):
    await _navigate(worker, f"{page_server}/a")
    snapshot = await _snapshot(worker, 1)

    if scenario == "removed":
        ref = _by_name(snapshot, "Two")["ref"]
        await _exec(worker, "document.getElementById('two').remove(); return 1")
        expected_cause = "missing"
    elif scenario == "hidden":
        ref = _by_name(snapshot, "Boxed")["ref"]
        await _exec(worker, "document.getElementById('box').style.display = 'none'; return 1")
        expected_cause = "hidden"
    elif scenario == "relabelled":
        ref = _by_name(snapshot, "Two")["ref"]
        await _exec(worker, "document.getElementById('two').textContent = 'Renamed'; return 1")
        expected_cause = "changed"
    else:
        ref = _by_name(snapshot, "Two")["ref"]
        await _navigate(worker, f"{page_server}/b")
        expected_cause = "missing"

    started = time.monotonic()
    result = await worker.command(AgentCommandRequest(type=command, args={"ref": ref, **extra_args}))
    elapsed = time.monotonic() - started

    # Playwright's default actionability timeout is 30s; the point of the in-page check is that a
    # miss never reaches it.
    assert elapsed < 5, f"{command} on a {scenario} ref took {elapsed:.1f}s"
    assert result == {
        "error": True,
        "code": "stale_ref",
        "ref": ref,
        "cause": expected_cause,
        "reason": _STALE_REASON.format(ref=ref),
        "url": result["url"],
        "title": result["title"],
    }
    assert "127.0.0.1" in result["url"]


@pytest.mark.parametrize("ref", ["", "e", "12", "e1x", "e1'] , [data-fa-ref='e2"])
async def test_a_malformed_ref_is_rejected_without_touching_the_page(worker, page_server, ref):
    await _navigate(worker, f"{page_server}/a")
    result = await worker.command(AgentCommandRequest(type="click", args={"ref": ref}))

    assert result["error"] is True
    assert result["code"] == "invalid_ref"
    assert result["ref"] == ref
    assert result["reason"]


async def test_actions_on_a_live_ref_are_accepted(worker, page_server):
    await _navigate(worker, f"{page_server}/a")
    snapshot = await _snapshot(worker, 1)

    typed = await worker.command(
        AgentCommandRequest(type="type_text", args={"ref": _by_name(snapshot, "Name")["ref"], "text": "Ada"})
    )
    assert typed["accepted"] is True

    selected = await worker.command(
        AgentCommandRequest(type="select", args={"ref": _by_name(snapshot, "Pick")["ref"], "value": "b"})
    )
    assert selected["accepted"] is True

    clicked = await worker.command(AgentCommandRequest(type="click", args={"ref": _by_name(snapshot, "One")["ref"]}))
    assert clicked["accepted"] is True

    after = await _snapshot(worker, snapshot["next_ref"])
    assert _by_name(after, "Name")["value"] == "Ada"


async def test_a_raw_selector_action_is_unaffected_by_ref_handling(worker, page_server):
    await _navigate(worker, f"{page_server}/a")
    result = await worker.command(AgentCommandRequest(type="click", args={"selector": "#one"}))
    assert result["accepted"] is True


async def test_fake_runtime_snapshot_reports_and_advances_the_counter():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_refs"))
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://example.test/page"}),
    )

    first = await registry.agent_command(session.session_id, AgentCommandRequest(type="snapshot", args={"next_ref": 7}))
    assert first.result["roots"][0]["ref"] == "e7"
    assert first.result["next_ref"] == 8

    again = await registry.agent_command(
        session.session_id, AgentCommandRequest(type="snapshot", args={"next_ref": first.result["next_ref"]})
    )
    assert again.result["roots"][0]["ref"] == "e7"
    assert again.result["next_ref"] == 8

    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://example.test/other"}),
    )
    moved = await registry.agent_command(
        session.session_id, AgentCommandRequest(type="snapshot", args={"next_ref": again.result["next_ref"]})
    )
    assert moved.result["roots"][0]["ref"] == "e8"


async def test_fake_runtime_returns_a_stale_ref_error_rather_than_failing_the_command():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_stale"))
    await registry.agent_command(
        session.session_id,
        AgentCommandRequest(type="navigate", args={"url": "https://example.test/page"}),
    )
    snapshot = await registry.agent_command(
        session.session_id, AgentCommandRequest(type="snapshot", args={"next_ref": 3})
    )
    live_ref = snapshot.result["roots"][0]["ref"]

    accepted = await registry.agent_command(
        session.session_id, AgentCommandRequest(type="click", args={"ref": live_ref})
    )
    assert accepted.ok
    assert accepted.result["accepted"] is True

    stale = await registry.agent_command(session.session_id, AgentCommandRequest(type="click", args={"ref": "e1"}))
    assert stale.ok
    assert stale.result["code"] == "stale_ref"
    assert stale.result["reason"] == _STALE_REASON.format(ref="e1")

    malformed = await registry.agent_command(
        session.session_id, AgentCommandRequest(type="click", args={"ref": "nope"})
    )
    assert malformed.ok
    assert malformed.result["code"] == "invalid_ref"

    trailing_newline = await registry.agent_command(
        session.session_id, AgentCommandRequest(type="click", args={"ref": "e1\n"})
    )
    assert trailing_newline.result["code"] == "invalid_ref"


async def test_fake_runtime_same_url_reload_replaces_the_document():
    registry = SessionRegistry()
    session, _ = await registry.create_session(CreateSessionRequest(conversation_id="conv_reload"))
    url = "https://example.test/page"
    await registry.agent_command(session.session_id, AgentCommandRequest(type="navigate", args={"url": url}))
    before = await registry.agent_command(
        session.session_id, AgentCommandRequest(type="snapshot", args={"next_ref": 3})
    )
    old_ref = before.result["roots"][0]["ref"]

    await registry.agent_command(session.session_id, AgentCommandRequest(type="navigate", args={"url": url}))
    stale = await registry.agent_command(session.session_id, AgentCommandRequest(type="click", args={"ref": old_ref}))
    assert stale.result["code"] == "stale_ref"
    after = await registry.agent_command(
        session.session_id, AgentCommandRequest(type="snapshot", args={"next_ref": before.result["next_ref"]})
    )
    assert after.result["roots"][0]["ref"] != old_ref


def test_coerce_next_ref_clamps_to_the_javascript_safe_integer_range():
    assert coerce_next_ref(2**60) == 2**53 - 2**32
    assert coerce_next_ref("12") == 12
    assert coerce_next_ref(None) == 1
    assert coerce_next_ref(-5) == 1
    assert coerce_next_ref(float("inf")) == 1
