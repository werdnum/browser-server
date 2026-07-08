"""Cookie-jar mechanism tests: JarStore encryption/scope/revocation and registry integration.

These run entirely in the fake runtime (no browser). Security-regression coverage from the
design's testing plan lives here and in ``test_cookie_jars_api.py``."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import cast

import pytest
from browser_handoff_service.jars import (
    JarDecryptError,
    JarDisabledError,
    JarRevokedError,
    JarStore,
    JarValidationError,
    filter_storage_state,
    load_jar_keys,
    normalize_label,
    redact_probe_url,
    registrable_domain,
)
from browser_handoff_service.models import (
    AgentCommandRequest,
    CookieJarMeta,
    CreateSessionRequest,
    ProbeSpec,
    SaveJarRequest,
    SessionState,
    StorageMode,
)
from browser_handoff_service.registry import AuthorizationError, ConflictError, SessionRegistry
from browser_handoff_service.runtime import FakeBrowserWorker


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def make_store(tmp_path: Path, *, keys: str | None = None, max_bytes: int = 5 * 1024 * 1024) -> JarStore:
    monkey_key = keys if keys is not None else _key()
    os.environ["BROWSER_JAR_KEY"] = monkey_key
    parsed = load_jar_keys()
    os.environ.pop("BROWSER_JAR_KEY", None)
    return JarStore(tmp_path / "jars", keys=parsed, max_bytes=max_bytes)


def fake_worker(reg: SessionRegistry, worker_id: str | None) -> FakeBrowserWorker:
    return cast(FakeBrowserWorker, reg.workers[worker_id or ""])


LOGIN_STATE = {
    "cookies": [
        {
            "name": "sid",
            "value": "SECRETVALUE",
            "domain": "shop.example.com",
            "path": "/",
            "expires": -1,
            "secure": True,
        },
        {"name": "pref", "value": "p", "domain": "shop.example.com", "path": "/account", "expires": 4102444800},
        {"name": "wide", "value": "w", "domain": ".example.com", "path": "/", "expires": 4102444800},
        {"name": "idp", "value": "IDPVALUE", "domain": "accounts.google.com", "path": "/", "expires": 4102444800},
        {"name": "sib", "value": "s", "domain": "accounts.example.com", "path": "/", "expires": 4102444800},
    ],
    "origins": [
        {"origin": "https://shop.example.com", "localStorage": [{"name": "tok", "value": "LOCALSECRET"}]},
        {"origin": "https://accounts.example.com", "localStorage": [{"name": "x", "value": "y"}]},
    ],
}


def save_login(
    store: JarStore,
    *,
    jar_id: str | None = None,
    label: str = "Shop",
    origins: list[str] | None = None,
    nav_allowlist: list[str] | None = None,
    storage_mode: StorageMode | None = "all",
    raw_storage_state: dict | None = None,
    probe_spec_url: str | None = "https://shop.example.com/account",
    probe_selector: str | None = "[data-testid=logout]",
    probe_logged_out_prefix: str | None = None,
    saved_by: str = "human",
    owner_subject: str | None = "user123",
    form_factor: str = "desktop",
) -> CookieJarMeta:
    return store.save(
        jar_id=jar_id,
        label=label,
        origins=origins if origins is not None else ["https://shop.example.com"],
        nav_allowlist=nav_allowlist if nav_allowlist is not None else [],
        storage_mode=storage_mode,
        raw_storage_state=raw_storage_state if raw_storage_state is not None else LOGIN_STATE,
        probe_spec_url=probe_spec_url,
        probe_selector=probe_selector,
        probe_logged_out_prefix=probe_logged_out_prefix,
        saved_by=saved_by,
        owner_subject=owner_subject,
        form_factor=form_factor,
        created_session_id="bs_1",
        conversation_id="conv_1",
        agent_supplied_probe=False,
    )


# --- scope filtering ------------------------------------------------------


def test_scope_filter_excludes_idp_and_sibling_keeps_domain_and_path(tmp_path):
    filtered, stats = filter_storage_state(LOGIN_STATE, ["https://shop.example.com"], "all")
    names = {c["name"] for c in filtered["cookies"]}
    # sid (host-only match), pref (Path=/account retained), wide (Domain=.example.com sent to shop)
    assert names == {"sid", "pref", "wide"}
    # IdP cookie (accounts.google.com) and host-only sibling (accounts.example.com) excluded.
    assert "idp" not in names and "sib" not in names
    origins = {o["origin"] for o in filtered["origins"]}
    assert origins == {"https://shop.example.com"}  # sibling-origin localStorage dropped
    assert stats.cookie_count == 3
    assert stats.origin_storage_count == 1
    assert stats.contains_session_cookies is True  # sid is a session cookie
    assert stats.session_cookies_only is False


def test_scope_filter_cookies_only_drops_origin_storage():
    filtered, stats = filter_storage_state(LOGIN_STATE, ["https://shop.example.com"], "cookies_only")
    assert filtered["origins"] == []
    assert stats.origin_storage_count == 0
    assert {c["name"] for c in filtered["cookies"]} == {"sid", "pref", "wide"}


def test_registrable_domain_handles_co_uk():
    assert registrable_domain("https://shop.example.co.uk") == "example.co.uk"
    assert registrable_domain("https://shop.example.com") == "example.com"


# --- encryption / persistence --------------------------------------------


def test_encrypt_decrypt_round_trip(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    loaded = store.load(meta.jar_id)
    assert loaded.meta.jar_id == meta.jar_id
    assert {c["name"] for c in loaded.storage_state["cookies"]} == {"sid", "pref", "wide"}
    assert loaded.probe.logged_in_selector == "[data-testid=logout]"


def test_metadata_never_contains_cookie_values(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    blob = meta.model_dump_json()
    assert "SECRETVALUE" not in blob and "LOCALSECRET" not in blob
    # No probe internals in listable metadata.
    assert "logged_in_selector" not in blob and "data-testid" not in blob


def test_fresh_nonce_per_write(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    nonce1 = json.loads((tmp_path / "jars" / f"{meta.jar_id}.json").read_text())["nonce"]
    save_login(store, jar_id=meta.jar_id)
    nonce2 = json.loads((tmp_path / "jars" / f"{meta.jar_id}.json").read_text())["nonce"]
    assert nonce1 != nonce2


def test_metadata_tamper_fails_closed(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["owner_subject"] = "attacker"
    path.write_text(json.dumps(record))
    with pytest.raises(JarDecryptError):
        store.load(meta.jar_id)


def test_origins_tamper_fails_closed(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["origins"] = ["https://evil.example.com"]
    path.write_text(json.dumps(record))
    with pytest.raises(JarDecryptError):
        store.load(meta.jar_id)


# --- keyless / rotation ---------------------------------------------------


def test_keyless_mode_is_fail_closed(tmp_path):
    store = JarStore(tmp_path / "jars", keys=[])
    assert store.enabled is False
    with pytest.raises(JarDisabledError):
        save_login(store)


def test_wrong_key_reports_rotation_but_delete_still_works(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    other = make_store(tmp_path)  # different key, same dir
    with pytest.raises(JarDecryptError) as exc:
        other.load(meta.jar_id)
    assert exc.value.kind == "rotation"
    # A wrong-key jar is still deletable.
    other.delete(meta.jar_id)
    assert not (tmp_path / "jars" / f"{meta.jar_id}.json").exists()


def test_key_rotation_list_still_reads_old_jar(tmp_path):
    old = _key()
    store = make_store(tmp_path, keys=old)
    meta = save_login(store)
    new = _key()
    rotated = make_store(tmp_path, keys=f"{new},{old}")  # new key first for writes, old for reads
    assert rotated.load(meta.jar_id).meta.jar_id == meta.jar_id


# --- path traversal / validation ------------------------------------------


@pytest.mark.parametrize("bad", ["../../etc/passwd", "jar_notlongenough", "jar_" + "z" * 32, "bs_1234"])
def test_jar_id_path_traversal_rejected(tmp_path, bad):
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        store.load(bad)


def test_label_normalization():
    assert normalize_label("  hi\nthere\t ") == "hithere"
    assert len(normalize_label("x" * 200)) == 80


def test_probe_url_redaction_strips_query_fragment_userinfo():
    assert redact_probe_url("https://u:p@example.com/account?token=x#y") == "https://example.com/account"


def test_probe_url_must_be_in_scope(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://evil.example.com/account")


def test_probe_url_rejects_sensitive_path(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://shop.example.com/reset/deadbeefdeadbeef00")


# --- revocation / rollback ------------------------------------------------


def test_invalidate_makes_unloadable_refresh_reenables(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    store.invalidate(meta.jar_id)
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)
    meta2 = save_login(store, jar_id=meta.jar_id)
    assert meta2.generation > meta.generation
    assert meta2.invalidated_at is None
    assert store.load(meta.jar_id).meta.generation == meta2.generation


def test_delete_is_terminal(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    store.delete(meta.jar_id)
    with pytest.raises(JarRevokedError):
        save_login(store, jar_id=meta.jar_id)


def test_revocation_rollback_of_file_is_rejected(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    pre_invalidation = path.read_bytes()  # gen 1, not invalidated
    store.invalidate(meta.jar_id)
    path.write_bytes(pre_invalidation)  # restore the older, still-valid-looking file
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


def test_invalidation_tamper_clear_still_blocked(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    store.invalidate(meta.jar_id)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["invalidated_at"] = None  # try to clear the kill-switch in cleartext
    path.write_text(json.dumps(record))
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


# --- refresh cannot widen -------------------------------------------------


def test_refresh_cannot_widen_origins(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    with pytest.raises(JarValidationError):
        save_login(store, jar_id=meta.jar_id, origins=["https://shop.example.com", "https://other.example.com"])


def test_refresh_cannot_widen_nav_allowlist(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store, nav_allowlist=["https://api.example.com"])
    with pytest.raises(JarValidationError):
        save_login(store, jar_id=meta.jar_id, nav_allowlist=["https://api.example.com", "https://new.example.com"])


def test_refresh_cannot_widen_storage_mode(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store, storage_mode="cookies_only")
    with pytest.raises(JarValidationError):
        save_login(store, jar_id=meta.jar_id, storage_mode="all")
    # Preserving (omit) and narrowing are fine.
    meta2 = save_login(store, jar_id=meta.jar_id, storage_mode=None)
    assert meta2.storage_mode == "cookies_only"


def test_bounded_export_size_cap(tmp_path):
    store = make_store(tmp_path, max_bytes=200)
    big = {
        "cookies": [
            {"name": f"c{i}", "value": "x" * 50, "domain": "shop.example.com", "path": "/", "expires": -1}
            for i in range(50)
        ],
        "origins": [],
    }
    with pytest.raises(JarValidationError):
        save_login(store, raw_storage_state=big)


# --- registry integration (fake runtime) ----------------------------------


@pytest.fixture(autouse=True)
def fake_runtime(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "svc")


def registry_with_store(tmp_path) -> SessionRegistry:
    return SessionRegistry(jar_store=make_store(tmp_path))


async def _human_login_session(reg: SessionRegistry, subject="user123"):
    session, ctl = await reg.create_session(
        CreateSessionRequest(conversation_id="c1", initial_owner="human"), owner_subject=subject
    )
    worker = fake_worker(reg, session.worker_id)
    worker.url = "https://shop.example.com/account"
    worker.storage_state = LOGIN_STATE
    return session, ctl


@pytest.mark.asyncio
async def test_human_save_requires_owner_subject(tmp_path):
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg, subject=None)
    with pytest.raises(AuthorizationError):
        await reg.save_jar(
            session.session_id,
            SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec()),
            actor="human",
        )


@pytest.mark.asyncio
async def test_exec_denied_in_jar_loaded_session(tmp_path):
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[data-testid=logout]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    with pytest.raises(AuthorizationError):
        await reg.agent_command(loaded.session_id, AgentCommandRequest(type="exec", args={"code": "document.cookie"}))
    # allow_exec opt-in permits it.
    loaded2, _ = await reg.create_session(
        CreateSessionRequest(conversation_id="c3", jar_id=meta.jar_id, allow_exec=True)
    )
    res = await reg.agent_command(loaded2.session_id, AgentCommandRequest(type="exec", args={"code": "1"}))
    assert res.ok is True


@pytest.mark.asyncio
async def test_confinement_blocks_off_scope_and_sibling_and_port(tmp_path):
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    for off in (
        "https://evil.example.com/",  # off-scope
        "https://accounts.example.com/",  # sibling subdomain sharing registrable domain
        "https://shop.example.com:8443/",  # different port
    ):
        res = await reg.agent_command(loaded.session_id, AgentCommandRequest(type="navigate", args={"url": off}))
        assert res.result.get("blocked") is True, off
    # In-scope navigation proceeds.
    ok = await reg.agent_command(
        loaded.session_id, AgentCommandRequest(type="navigate", args={"url": "https://shop.example.com/cart"})
    )
    assert ok.result.get("blocked") is None


@pytest.mark.asyncio
async def test_jarless_session_exec_and_navigation_unaffected(tmp_path):
    reg = registry_with_store(tmp_path)
    session, _ = await reg.create_session(CreateSessionRequest(conversation_id="c1"))
    res = await reg.agent_command(session.session_id, AgentCommandRequest(type="exec", args={"code": "1"}))
    assert res.ok is True
    nav = await reg.agent_command(
        session.session_id, AgentCommandRequest(type="navigate", args={"url": "https://anywhere.test/"})
    )
    assert nav.result.get("blocked") is None


@pytest.mark.asyncio
async def test_no_cloning_new_jar_from_jar_loaded_session(tmp_path):
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    # A jar-loaded session cannot save a *new* jar (that would clone credentials past the kill-switch).
    with pytest.raises(ConflictError):
        await reg.save_jar(loaded.session_id, SaveJarRequest(label="Clone", probe=ProbeSpec()), actor="agent")


@pytest.mark.asyncio
async def test_invalidated_jar_cannot_be_loaded_into_session(tmp_path):
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    await reg.invalidate_jar(meta.jar_id)
    with pytest.raises(JarRevokedError):
        await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))


@pytest.mark.asyncio
async def test_revocation_closes_loaded_and_producer_sessions(tmp_path):
    reg = registry_with_store(tmp_path)
    producer, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        producer.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    await reg.delete_jar(meta.jar_id)
    assert reg.sessions[loaded.session_id].state == SessionState.CANCELLED
    assert reg.sessions[producer.session_id].state == SessionState.CANCELLED


@pytest.mark.asyncio
async def test_jar_loaded_session_cannot_request_resumable_handoff(tmp_path):
    from browser_handoff_service.models import HandoffRequest

    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    with pytest.raises(ConflictError):
        await reg.handoff(
            loaded.session_id, HandoffRequest(reason="captcha", allowed_resume="after_sanitize"), "http://testserver"
        )


@pytest.mark.asyncio
async def test_probe_signal_less_is_uncertain_and_selector_present_is_fresh(tmp_path, monkeypatch):
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    # Signal-less probe (empty spec) -> uncertain.
    meta = await reg.save_jar(
        session.session_id, SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec()), actor="human"
    )
    result = await reg.probe_jar(meta.jar_id)
    assert result.result == "uncertain"

    # A jar whose selector the probe worker "finds" reads fresh. Patch make_worker so the
    # throwaway probe worker reports the selector present.
    import browser_handoff_service.registry as reg_mod

    session2, ctl2 = await _human_login_session(reg)
    meta2 = await reg.save_jar(
        session2.session_id,
        SaveJarRequest(label="Shop2", token=ctl2, probe=ProbeSpec(logged_in_selector="[data-testid=logout]")),
        actor="human",
    )
    original = reg_mod.make_worker

    def make_worker_with_selector(*args, **kwargs) -> FakeBrowserWorker:
        worker = cast(FakeBrowserWorker, original(*args, **kwargs))
        worker.present_selectors = {"[data-testid=logout]"}
        return worker

    monkeypatch.setattr(reg_mod, "make_worker", make_worker_with_selector)
    result2 = await reg.probe_jar(meta2.jar_id)
    assert result2.result == "fresh"


@pytest.mark.asyncio
async def test_probe_rate_limited(tmp_path):
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        session.session_id, SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec()), actor="human"
    )
    await reg.probe_jar(meta.jar_id)
    with pytest.raises(ConflictError):
        await reg.probe_jar(meta.jar_id)


@pytest.mark.asyncio
async def test_jar_load_defaults_to_producing_form_factor(tmp_path):
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    session.form_factor = "desktop"
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    assert meta.form_factor == "desktop"
    # An agent-created load with no viewport would default to mobile; the jar's desktop wins.
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    assert loaded.form_factor == "desktop"


@pytest.mark.asyncio
async def test_agent_save_denied_when_human_owns_lease(tmp_path):
    reg = registry_with_store(tmp_path)
    session, _ = await _human_login_session(reg)
    with pytest.raises(AuthorizationError):
        await reg.save_jar(session.session_id, SaveJarRequest(label="Shop", probe=ProbeSpec()), actor="agent")


@pytest.mark.asyncio
async def test_agent_probe_url_is_derived_not_arbitrary(tmp_path):
    reg = registry_with_store(tmp_path)
    # Agent-owned session that has navigated to shop.
    session, _ = await reg.create_session(CreateSessionRequest(conversation_id="c1"))
    fake_worker(reg, session.worker_id).storage_state = LOGIN_STATE
    await reg.agent_command(
        session.session_id, AgentCommandRequest(type="navigate", args={"url": "https://shop.example.com/home"})
    )
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(
            label="Shop",
            origins=["https://shop.example.com"],
            probe=ProbeSpec(url="https://shop.example.com/logout", logged_in_selector="[x]"),
        ),
        actor="agent",
    )
    # The agent-supplied /logout url is ignored; the stored probe targets the derived landing page.
    loaded = reg.jar_store.load(meta.jar_id)
    assert loaded.probe.url == "https://shop.example.com/"
