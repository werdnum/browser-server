"""Cookie-jar mechanism tests: JarStore encryption/scope/revocation and registry integration.

These run entirely in the fake runtime (no browser). Security-regression coverage from the
design's testing plan lives here and in ``test_cookie_jars_api.py``."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from browser_handoff_service.jars import (
    JarDecryptError,
    JarDisabledError,
    JarError,
    JarNotFoundError,
    JarRevokedError,
    JarStore,
    JarValidationError,
    filter_storage_state,
    load_jar_keys,
    normalize_label,
    normalize_origin,
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
from browser_handoff_service.registry import (
    AuthorizationError,
    ConflictError,
    SessionInactiveError,
    SessionRegistry,
)
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
    revoke_precondition: int | None = None,
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
        revoke_precondition=revoke_precondition,
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


# --- regression tests for review findings ---------------------------------


def test_probe_path_rejects_five_digit_account_id(tmp_path):
    # Design example /users/12345/account: a 5-digit account id in the path is sensitive.
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://shop.example.com/users/12345/account")


@pytest.mark.asyncio
async def test_registry_refresh_omitted_origins_preserves_multi_origin_scope(tmp_path):
    # A refresh through the registry that omits `origins` must keep the stored multi-origin
    # scope, not collapse it to the live page's single origin.
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(
            label="Shop",
            token=ctl,
            origins=["https://shop.example.com", "https://api.example.com"],
            probe=ProbeSpec(logged_in_selector="[x]"),
        ),
        actor="human",
    )
    assert set(meta.origins) == {"https://shop.example.com", "https://api.example.com"}
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    fake_worker(reg, loaded.worker_id).storage_state = LOGIN_STATE
    refreshed = await reg.save_jar(
        loaded.session_id,
        SaveJarRequest(label="Shop", jar_id=meta.jar_id, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="agent",
    )
    assert set(refreshed.origins) == {"https://shop.example.com", "https://api.example.com"}


def test_invalidate_and_delete_work_after_key_rotation(tmp_path):
    # A jar under a rotated/removed key can no longer be decrypted, but must stay revocable.
    old = _key()
    store = make_store(tmp_path, keys=old)
    meta = save_login(store)
    rotated = make_store(tmp_path, keys=_key())  # brand-new key, old key removed
    with pytest.raises(JarDecryptError):
        rotated.load(meta.jar_id)
    # invalidate lands the tombstone even though it cannot re-seal the blob.
    rotated.invalidate(meta.jar_id)
    with pytest.raises(JarRevokedError):
        # load now fails closed on the tombstone (revoked) rather than only on decrypt.
        rotated.load(meta.jar_id)
    # delete still destroys the blob.
    rotated.delete(meta.jar_id)
    assert not (tmp_path / "jars" / f"{meta.jar_id}.json").exists()


@pytest.mark.asyncio
async def test_confinement_disabled_when_jar_loaded_session_handed_to_human(tmp_path):
    from browser_handoff_service.models import HandoffRequest

    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    worker = fake_worker(reg, loaded.worker_id)
    assert worker._confinement_active is True
    await reg.handoff(loaded.session_id, HandoffRequest(reason="captcha"), "http://testserver")
    # Confinement must be off once the human is about to drive (no off-scope SSO trap).
    assert worker._confinement_active is False


@pytest.mark.asyncio
async def test_handover_rejected_for_jar_loaded_session(tmp_path):
    from browser_handoff_service.models import HandoffRequest

    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    _, url = await reg.handoff(loaded.session_id, HandoffRequest(reason="captcha"), "http://testserver")
    handoff_token = url.split("token=", 1)[1]
    _, control_token = await reg.claim(loaded.session_id, handoff_token)
    # A jar-loaded session that passed to human control cannot be handed back to the agent as the
    # same context; the agent must start a fresh, re-filtered jar-loaded session.
    with pytest.raises(ConflictError):
        await reg.handover(loaded.session_id, control_token, "take over")


@pytest.mark.asyncio
async def test_agent_selector_dropped_when_present_on_logged_out_baseline(tmp_path, monkeypatch):
    reg = registry_with_store(tmp_path)
    session, _ = await reg.create_session(CreateSessionRequest(conversation_id="c1"))
    fake_worker(reg, session.worker_id).storage_state = LOGIN_STATE
    await reg.agent_command(
        session.session_id, AgentCommandRequest(type="navigate", args={"url": "https://shop.example.com/home"})
    )

    import browser_handoff_service.registry as reg_mod

    original = reg_mod.make_worker

    def make_worker_selector_present(*args, **kwargs) -> FakeBrowserWorker:
        worker = cast(FakeBrowserWorker, original(*args, **kwargs))
        # The selector is present even when logged out => it does not discriminate.
        worker.present_selectors = {"[data-testid=logout]"}
        return worker

    monkeypatch.setattr(reg_mod, "make_worker", make_worker_selector_present)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(
            label="Shop",
            origins=["https://shop.example.com"],
            probe=ProbeSpec(logged_in_selector="[data-testid=logout]"),
        ),
        actor="agent",
    )
    # A non-discriminating agent selector is dropped, so the jar reads uncertain, never fake-fresh.
    loaded = reg.jar_store.load(meta.jar_id)
    assert loaded.probe.logged_in_selector is None


# --- regression tests for Codex review comments ---------------------------


def test_normalize_origin_canonicalizes_default_ports():
    assert normalize_origin("https://shop.example.com:443/x") == "https://shop.example.com"
    assert normalize_origin("http://shop.example.com:80/x") == "http://shop.example.com"
    # A non-default port is preserved.
    assert normalize_origin("https://shop.example.com:8443/x") == "https://shop.example.com:8443"


def test_invalidate_persists_cleartext_flag_under_current_key(tmp_path):
    # Regression: setting invalidated_at before decrypt made the current-key re-seal fail, so the
    # cleartext flag was never written and listings showed the jar as not needing re-login.
    store = make_store(tmp_path)
    meta = save_login(store)
    store.invalidate(meta.jar_id)
    # The re-sealed jar still decrypts (current key) and its metadata shows the invalidation.
    assert store.get_meta_verified(meta.jar_id).invalidated_at is not None
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


def test_owner_subject_preserved_on_agent_refresh(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store, owner_subject="user123")
    # An agent/service refresh carries no subject; the human owner must survive.
    refreshed = save_login(store, jar_id=meta.jar_id, owner_subject=None)
    assert refreshed.owner_subject == "user123"


def test_tombstone_visible_across_instances_sharing_the_dir(tmp_path):
    key = _key()
    a = make_store(tmp_path, keys=key)
    meta = save_login(a)
    b = make_store(tmp_path, keys=key)  # separate long-lived instance, same jar dir
    assert b.load(meta.jar_id).meta.jar_id == meta.jar_id
    a.invalidate(meta.jar_id)  # revoked via instance A
    with pytest.raises(JarRevokedError):
        b.load(meta.jar_id)  # instance B re-derives from the shared log and observes it


def test_forged_tombstone_log_entry_is_ignored(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    store.delete(meta.jar_id)  # terminal tombstone (authenticated)
    log = tmp_path / "jars" / "jar-tombstones.jsonl"
    forged = {"jar_id": meta.jar_id, "generation": 9999, "reason": "invalidated", "hmac": "00" * 32}
    with log.open("a") as handle:
        handle.write(json.dumps(forged) + "\n")
    # The forged entry fails the HMAC chain, so the verified prefix (deleted) still stands: a
    # re-save of the deleted id is refused despite the forged "invalidated" line.
    with pytest.raises(JarRevokedError):
        save_login(store, jar_id=meta.jar_id)


def test_external_anchor_cannot_lower_revoked_generation(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    store.invalidate(meta.jar_id)
    # An attacker who can edit the plaintext anchor file (but not the key) tries to clear it.
    (tmp_path / "jars" / "jar-anchor.json").write_text(
        json.dumps({meta.jar_id: {"generation": 0, "reason": "invalidated"}})
    )
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)  # high-water comes from the authenticated log, not the anchor


def test_refresh_explicit_empty_nav_allowlist_narrows(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store, nav_allowlist=["https://api.example.com"])
    assert meta.nav_allowlist == ["https://api.example.com"]
    # Explicit [] clears the allowlist; None preserves it.
    narrowed = store.save(
        jar_id=meta.jar_id,
        label="Shop",
        origins=[],
        nav_allowlist=[],
        storage_mode=None,
        raw_storage_state=LOGIN_STATE,
        probe_spec_url=None,
        probe_selector="[x]",
        probe_logged_out_prefix=None,
        saved_by="human",
        owner_subject="user123",
        form_factor="desktop",
        created_session_id="bs_1",
        conversation_id="conv_1",
        agent_supplied_probe=False,
    )
    assert narrowed.nav_allowlist == []


@pytest.mark.asyncio
async def test_human_owned_jar_load_disables_confinement(tmp_path):
    # A service-token create with initial_owner="human" + jar_id loads a jar into a human-driven
    # session; confinement (agent-only) must be off so the human is not trapped.
    reg = registry_with_store(tmp_path)
    producer, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        producer.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    human_loaded, _ = await reg.create_session(
        CreateSessionRequest(conversation_id="c2", initial_owner="human", jar_id=meta.jar_id),
        owner_subject="user123",
    )
    assert human_loaded.jar_id == meta.jar_id
    assert fake_worker(reg, human_loaded.worker_id)._confinement_active is False


# --- regression tests for Codex review round 2 ----------------------------


def test_normalize_origin_preserves_ipv6_brackets():
    assert normalize_origin("http://[::1]:8000/x") == "http://[::1]:8000"
    assert normalize_origin("http://[::1]:80/x") == "http://[::1]"
    assert normalize_origin("https://[2001:db8::1]/x") == "https://[2001:db8::1]"


def test_tombstone_survives_key_rotation_blocks_rollback(tmp_path):
    # After BROWSER_JAR_KEY=new,old rotation, tombstone entries signed under the old key must
    # still verify — otherwise the high-water mark is dropped and a restored pre-invalidation
    # file loads under the still-configured old data key.
    old = _key()
    a = make_store(tmp_path, keys=old)
    meta = save_login(a)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    pre_invalidation = path.read_bytes()  # gen 1, invalidated_at is None
    a.invalidate(meta.jar_id)
    path.write_bytes(pre_invalidation)  # rollback to before invalidation
    rotated = make_store(tmp_path, keys=f"{_key()},{old}")  # new write key, old retained for reads
    with pytest.raises(JarRevokedError):
        rotated.load(meta.jar_id)


def test_refresh_tombstones_superseded_generation(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store, origins=["https://shop.example.com", "https://api.example.com"])
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    wider = path.read_bytes()  # gen 1, two origins
    save_login(store, jar_id=meta.jar_id, origins=["https://shop.example.com"])  # gen 2, narrowed
    path.write_bytes(wider)  # restore the older, wider file
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)  # the superseded generation was tombstoned by the refresh


def test_forged_line_does_not_hide_a_later_revocation(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    log = tmp_path / "jars" / "jar-tombstones.jsonl"
    with log.open("a") as handle:  # inject a forged line BEFORE the real revocation
        handle.write(
            json.dumps({"jar_id": "jar_" + "0" * 32, "generation": 1, "reason": "invalidated", "hmac": "bad"}) + "\n"
        )
    store.invalidate(meta.jar_id)  # legitimate revocation appended after the forged line
    # The forged line is skipped (not a stop) and the real revocation chains from the verified
    # tail, so it is still observed.
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


def test_list_meta_skips_restored_deleted_jar(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    blob = path.read_bytes()
    store.delete(meta.jar_id)
    path.write_bytes(blob)  # a backup/rollback restores the deleted blob
    assert meta.jar_id not in [m.jar_id for m in store.list_meta()]


def test_jar_audit_records_the_real_actor(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    store.delete(meta.jar_id, actor="subject:alice")
    audit = (tmp_path / "jars" / "jar-audit.jsonl").read_text().splitlines()
    last = json.loads(audit[-1])
    assert last["op"] == "jar_deleted" and last["actor"] == "subject:alice"


@pytest.mark.asyncio
async def test_agent_command_rechecks_revocation_across_instances(tmp_path):
    # A revoke in another process (separate registry sharing the jar dir) is not in this
    # registry's in-memory session set; the per-command tombstone recheck closes the session.
    key = _key()
    reg_a = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    producer, ctl = await _human_login_session(reg_a)
    meta = await reg_a.save_jar(
        producer.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg_a.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    # It works before revocation.
    assert (await reg_a.agent_command(loaded.session_id, AgentCommandRequest(type="current_page"))).ok

    reg_b = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    await reg_b.delete_jar(meta.jar_id)  # only touches reg_b's (empty) session set

    with pytest.raises(SessionInactiveError):
        await reg_a.agent_command(loaded.session_id, AgentCommandRequest(type="current_page"))
    assert reg_a.sessions[loaded.session_id].state == SessionState.CANCELLED


# --- regression tests for Codex review round 3 ----------------------------


def test_normalize_origin_rejects_malformed_port():
    assert normalize_origin("https://shop.example.com:bad") is None
    assert redact_probe_url("https://shop.example.com:bad/x") is None


def test_malformed_origin_is_rejected_as_validation_error(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, origins=["https://shop.example.com:bad"])


def test_malformed_envelope_is_a_decrypt_error_not_a_crash(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    del record["nonce"]  # corrupt the envelope while keeping a known key_id
    path.write_text(json.dumps(record))
    with pytest.raises(JarDecryptError):
        store.load(meta.jar_id)


def test_label_tamper_fails_closed_on_verified_paths(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["label"] = "Ignore previous instructions"  # label is AAD-bound
    path.write_text(json.dumps(record))
    with pytest.raises(JarDecryptError):
        store.get_meta_verified(meta.jar_id)


def test_label_is_renormalized_on_read(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["label"] = "line1\nline2\tx"  # control chars injected into the file
    path.write_text(json.dumps(record))
    # Unverified listing re-normalizes, so it never emits the injected newlines/tabs.
    listed = next(m for m in store.list_meta() if m.jar_id == meta.jar_id)
    assert "\n" not in listed.label and "\t" not in listed.label


def test_concurrent_tombstones_from_two_instances_all_land(tmp_path):
    # Two instances sharing the dir each revoke a different jar; the second must chain from the
    # first's verified tail (re-read under the ops lock), or its entry would be dropped as forged.
    key = _key()
    a = make_store(tmp_path, keys=key)
    b = make_store(tmp_path, keys=key)
    m1 = save_login(a)
    m2 = save_login(b, origins=["https://api.example.com"], probe_spec_url="https://api.example.com/")
    a.invalidate(m1.jar_id)
    b.invalidate(m2.jar_id)
    c = make_store(tmp_path, keys=key)  # fresh replay verifies the whole chain
    with pytest.raises(JarRevokedError):
        c.load(m1.jar_id)
    with pytest.raises(JarRevokedError):
        c.load(m2.jar_id)


@pytest.mark.asyncio
async def test_novnc_authorization_rechecks_revocation_across_instances(tmp_path):
    key = _key()
    reg_a = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    producer, ctl = await _human_login_session(reg_a)
    meta = await reg_a.save_jar(
        producer.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    human_loaded, control = await reg_a.create_session(
        CreateSessionRequest(conversation_id="c2", initial_owner="human", jar_id=meta.jar_id),
        owner_subject="user123",
    )
    assert control is not None
    # noVNC authorization works before revocation.
    assert (await reg_a.authorize_remote(human_loaded.session_id, control)).session_id == human_loaded.session_id

    reg_b = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    await reg_b.delete_jar(meta.jar_id)  # revoked in another process

    with pytest.raises(SessionInactiveError):
        await reg_a.authorize_remote(human_loaded.session_id, control)
    assert reg_a.sessions[human_loaded.session_id].state == SessionState.CANCELLED


# --- regression tests for Codex review round 4 ----------------------------


def test_invalidate_generation_tamper_blocks_all_versions(tmp_path):
    # Lower the cleartext generation, then invalidate. The tampered file cannot decrypt (gen is
    # AAD-bound), so invalidate must block EVERY version fail-closed rather than tombstone the
    # lowered generation and let the restored original load.
    store = make_store(tmp_path)
    meta = save_login(store)  # generation 1
    save_login(store, jar_id=meta.jar_id)  # generation 2 (authentic)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    authentic_gen2 = path.read_bytes()
    record = json.loads(path.read_text())
    record["meta"]["generation"] = 1  # attacker lowers it below the intended tombstone
    path.write_text(json.dumps(record))
    store.invalidate(meta.jar_id)
    path.write_bytes(authentic_gen2)  # restore the real gen-2 file
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


def test_refresh_from_rolled_back_file_lands_above_tombstone(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)  # gen 1
    gen1 = (tmp_path / "jars" / f"{meta.jar_id}.json").read_bytes()
    save_login(store, jar_id=meta.jar_id)  # gen 2
    store.invalidate(meta.jar_id)  # tombstone gen 2
    (tmp_path / "jars" / f"{meta.jar_id}.json").write_bytes(gen1)  # roll back to gen 1
    refreshed = save_login(store, jar_id=meta.jar_id)  # re-login
    assert refreshed.generation > 2  # above the tombstone high-water, so it actually loads
    assert store.load(meta.jar_id).meta.generation == refreshed.generation


def test_recheck_loadable_fails_closed_on_cleartext_tamper(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    store.invalidate(meta.jar_id)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["invalidated_at"] = None  # try to clear the kill-switch in cleartext
    record["meta"]["generation"] = 999  # and jump above the tombstone
    path.write_text(json.dumps(record))
    # The live-session recheck verifies the envelope, so the tamper fails closed (revoked).
    assert store.recheck_loadable(meta.jar_id) is False


def test_refresh_with_all_invalid_origins_rejected(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    with pytest.raises(JarValidationError):
        save_login(store, jar_id=meta.jar_id, origins=["https://shop.example.com:bad"])


def test_malformed_explicit_probe_url_rejected(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://shop.example.com:bad/account")


def test_listing_marks_rolled_back_invalidated_generation(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    gen1 = (tmp_path / "jars" / f"{meta.jar_id}.json").read_bytes()
    save_login(store, jar_id=meta.jar_id)  # gen 2
    store.invalidate(meta.jar_id)  # tombstone gen 2
    (tmp_path / "jars" / f"{meta.jar_id}.json").write_bytes(gen1)  # restore gen-1 file (invalidated_at None)
    listed = next(m for m in store.list_meta() if m.jar_id == meta.jar_id)
    assert listed.invalidated_at is not None  # surfaced as needing re-login, not usable


@pytest.mark.asyncio
async def test_save_jar_rejected_after_cross_process_invalidation(tmp_path):
    key = _key()
    reg_a = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    producer, ctl = await _human_login_session(reg_a)
    meta = await reg_a.save_jar(
        producer.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg_a.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    fake_worker(reg_a, loaded.worker_id).storage_state = LOGIN_STATE

    reg_b = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    await reg_b.invalidate_jar(meta.jar_id)  # kill-switch in another process

    # The jar-loaded session can no longer refresh its own jar_id (which would undo the kill-switch).
    with pytest.raises(SessionInactiveError):
        await reg_a.save_jar(
            loaded.session_id,
            SaveJarRequest(label="Shop", jar_id=meta.jar_id, probe=ProbeSpec(logged_in_selector="[x]")),
            actor="agent",
        )


# --- regression tests for Codex review round 5 ----------------------------


def test_jar_file_copied_under_different_id_is_rejected(tmp_path):
    store = make_store(tmp_path)
    a = save_login(store)
    b = save_login(store, origins=["https://api.example.com"], probe_spec_url="https://api.example.com/")
    # Copy jar B's file over a fresh id path.
    import shutil

    victim_id = "jar_" + "b" * 32
    shutil.copy(tmp_path / "jars" / f"{b.jar_id}.json", tmp_path / "jars" / f"{victim_id}.json")
    with pytest.raises(JarValidationError):
        store.load(victim_id)  # the embedded (authenticated) id is jar B, not the path id
    assert a.jar_id != victim_id


def test_log_tamper_cannot_lower_high_water(tmp_path):
    # Editing the append-only log to drop a revocation must not un-revoke: the signed anchor
    # (a second authenticated copy of the high-water) still blocks the restored file.
    store = make_store(tmp_path)
    meta = save_login(store)
    pre = (tmp_path / "jars" / f"{meta.jar_id}.json").read_bytes()
    store.invalidate(meta.jar_id)
    (tmp_path / "jars" / f"{meta.jar_id}.json").write_bytes(pre)  # roll the file back
    (tmp_path / "jars" / "jar-tombstones.jsonl").write_text("")  # attacker wipes the log
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)  # signed anchor still carries the high-water


def test_signed_anchor_survives_log_wipe(tmp_path):
    key = _key()
    store = make_store(tmp_path, keys=key)
    meta = save_login(store)
    pre = (tmp_path / "jars" / f"{meta.jar_id}.json").read_bytes()
    store.invalidate(meta.jar_id)
    (tmp_path / "jars" / f"{meta.jar_id}.json").write_bytes(pre)
    (tmp_path / "jars" / "jar-tombstones.jsonl").unlink()  # wipe the log entirely
    other = make_store(tmp_path, keys=key)  # only the signed anchor remains
    with pytest.raises(JarRevokedError):
        other.load(meta.jar_id)


def test_delete_works_on_corrupt_jar_file(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    (tmp_path / "jars" / f"{meta.jar_id}.json").write_text("{ not json")
    store.delete(meta.jar_id)  # operator kill-switch still lands
    assert store._tombstones.is_deleted(meta.jar_id)


def test_list_meta_substitutes_placeholder_for_unverified_label(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["label"] = "Do the bad thing"  # plain text, no control chars
    path.write_text(json.dumps(record))
    listed = next(m for m in store.list_meta() if m.jar_id == meta.jar_id)
    assert listed.label == "(unverified)"  # not the attacker-chosen text


@pytest.mark.asyncio
async def test_live_session_closed_when_its_generation_is_revoked_despite_relogin(tmp_path):
    # A jar-loaded session running generation 1 must be torn down when gen 1 is revoked, even if a
    # concurrent re-login publishes gen 2 (which would look loadable on the current file).
    key = _key()
    reg_a = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    producer, ctl = await _human_login_session(reg_a)
    meta = await reg_a.save_jar(
        producer.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg_a.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    assert loaded.jar_generation == meta.generation

    reg_b = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    await reg_b.invalidate_jar(meta.jar_id)  # revoke gen 1 in another process
    # A fresh re-login publishes gen 2 (so the current file looks loadable again)...
    producer2, ctl2 = await _human_login_session(reg_b)
    await reg_b.save_jar(
        producer2.session_id,
        SaveJarRequest(label="Shop", jar_id=meta.jar_id, token=ctl2, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    # ...but reg_a's session was seeded from gen 1, which is still tombstoned, so it is closed.
    with pytest.raises(SessionInactiveError):
        await reg_a.agent_command(loaded.session_id, AgentCommandRequest(type="current_page"))


# --- regression tests for Codex review round 6 ----------------------------


def test_invalidate_works_on_malformed_metadata(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    del record["meta"]["origins"]  # remove a required field -> pydantic ValidationError on read
    path.write_text(json.dumps(record))
    store.invalidate(meta.jar_id)  # kill-switch still lands
    with pytest.raises(JarError):
        store.load(meta.jar_id)


def test_get_meta_unverified_substitutes_unverified_label(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["label"] = "malicious instructions"  # plain text, no control chars
    path.write_text(json.dumps(record))
    assert store.get_meta_unverified(meta.jar_id).label == "(unverified)"


def test_invalidate_blocks_all_versions_on_key_id_tamper(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)  # gen 1
    save_login(store, jar_id=meta.jar_id)  # gen 2 (authentic)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    authentic_gen2 = path.read_bytes()
    record = json.loads(path.read_text())
    record["key_id"] = "deadbeefcafe"  # unconfigured => decrypt hits the "rotation" branch
    record["meta"]["generation"] = 1  # ...and the generation is lowered
    path.write_text(json.dumps(record))
    store.invalidate(meta.jar_id)  # must block every version, not just gen 1
    path.write_bytes(authentic_gen2)  # restore the real gen-2 file
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


@pytest.mark.asyncio
async def test_session_jar_revoked_helper_across_instances(tmp_path):
    key = _key()
    reg_a = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    producer, ctl = await _human_login_session(reg_a)
    meta = await reg_a.save_jar(
        producer.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg_a.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    assert reg_a.session_jar_revoked(loaded.session_id) is False
    reg_b = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    await reg_b.delete_jar(meta.jar_id)
    assert reg_a.session_jar_revoked(loaded.session_id) is True


# --- regression tests for Codex review round 7 ----------------------------


def test_non_string_envelope_field_is_a_decrypt_error_not_a_crash(tmp_path):
    # A file where nonce/blob is not a string (e.g. a JSON number) must decode to a controlled
    # corruption error rather than an uncaught AttributeError bubbling up as a 500.
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["nonce"] = 12345  # not a base64 string
    path.write_text(json.dumps(record))
    with pytest.raises(JarDecryptError):
        store.load(meta.jar_id)


def test_non_dict_meta_is_a_validation_error_not_a_crash(tmp_path):
    # ``meta`` that is not an object (a bare string/list) must not crash the path-id check with an
    # AttributeError; it is a controlled validation error so the file is treated as not-its-path.
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"] = "not a dict"
    path.write_text(json.dumps(record))
    with pytest.raises(JarValidationError):
        store.load(meta.jar_id)


def test_percent_encoded_sensitive_probe_path_rejected(tmp_path):
    # ``/%31%32%33%34%35%36`` decodes to ``/123456`` (an account-id-shaped segment). A raw scan
    # would miss it because the encoded form has no all-digit run; percent-decoding first catches it.
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://shop.example.com/%31%32%33%34%35%36")


def test_unverified_metadata_returns_stub_not_tampered_scope(tmp_path):
    # When the envelope does not verify, no cleartext field can be trusted. Both the detail and the
    # list surfaces must return a safe needs-relogin stub (empty origins, invalidated) rather than
    # echoing an attacker-tampered origin/status alongside the placeholder label.
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["label"] = "malicious instructions"  # breaks AAD -> envelope no longer verifies
    record["meta"]["origins"] = ["https://attacker.example.com"]  # forged scope
    record["meta"]["invalidated_at"] = None  # forged "still usable" status
    path.write_text(json.dumps(record))

    detail = store.get_meta_unverified(meta.jar_id)
    assert detail.label == "(unverified)"
    assert detail.origins == []  # forged scope not surfaced
    assert detail.invalidated_at is not None  # surfaced as needing re-login

    listed = next(m for m in store.list_meta() if m.jar_id == meta.jar_id)
    assert listed.label == "(unverified)"
    assert listed.origins == []
    assert listed.invalidated_at is not None


# --- regression tests for Codex review round 8 ----------------------------


def test_encoded_slash_hides_no_sensitive_probe_segment(tmp_path):
    # /reset%2Fdeadbeefdeadbeef00 -> decode-before-split yields ["reset", "deadbeefdeadbeef00"];
    # the 18-hex token must be caught, not buried inside one raw segment containing an encoded slash.
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://shop.example.com/reset%2Fdeadbeefdeadbeef00")


def test_action_like_probe_path_rejected(tmp_path):
    # A replayed freshness GET to /logout would sign the saved login out.
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://shop.example.com/logout")
    # Encoded, and as a non-final segment, are both caught (decode-before-split + any-segment scan).
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://shop.example.com/%6cogout")
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://shop.example.com/signout/confirm")


def test_non_action_probe_path_allowed(tmp_path):
    # A page that merely contains an action word as a substring is not an action endpoint.
    store = make_store(tmp_path)
    meta = save_login(store, probe_spec_url="https://shop.example.com/account/logout-history")
    assert meta.jar_id


def test_verify_owner_survives_rolled_back_display_mutation(tmp_path):
    # list_meta marks a rolled-back generation invalidated for display by mutating the AAD-bound
    # invalidated_at on the returned object. verify_owner must re-derive meta from disk so that
    # mutation cannot make the decrypt fail and hide the jar from its rightful owner.
    store = make_store(tmp_path)
    meta = save_login(store, owner_subject="user123")  # gen 1
    gen1 = (tmp_path / "jars" / f"{meta.jar_id}.json").read_bytes()
    save_login(store, jar_id=meta.jar_id, owner_subject="user123")  # gen 2
    store.invalidate(meta.jar_id)  # tombstone gen 2
    (tmp_path / "jars" / f"{meta.jar_id}.json").write_bytes(gen1)  # restore gen-1 file (invalidated_at None)

    listed = next(m for m in store.list_meta() if m.jar_id == meta.jar_id)
    assert listed.invalidated_at is not None  # display-mutated to needs-relogin
    assert store.verify_owner(listed, meta.jar_id) is True  # ownership still verifies


def test_refresh_write_failure_leaves_prior_jar_loadable(tmp_path, monkeypatch):
    # If the refresh write fails after the old generation would have been tombstoned, the prior jar
    # must not be bricked. Write-before-tombstone means nothing is revoked when the write throws.
    store = make_store(tmp_path)
    meta = save_login(store)  # gen 1, loadable
    original = store._write_record

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(store, "_write_record", boom)
    with pytest.raises(OSError):
        save_login(store, jar_id=meta.jar_id)  # refresh write fails
    monkeypatch.setattr(store, "_write_record", original)

    loaded = store.load(meta.jar_id)  # old generation never tombstoned -> still loads
    assert loaded.meta.generation == meta.generation


def test_refresh_rejects_all_malformed_nav_allowlist(tmp_path):
    # A non-empty nav_allowlist that all fails normalization (typo'd port) must be a validation
    # error, not a silent clear of the stored allowlist.
    store = make_store(tmp_path)
    meta = save_login(store, nav_allowlist=["https://idp.example.com"])
    with pytest.raises(JarValidationError):
        save_login(store, jar_id=meta.jar_id, nav_allowlist=["https://idp.example.com:bad"])
    # An explicit empty list is still a legitimate clear.
    refreshed = save_login(store, jar_id=meta.jar_id, nav_allowlist=[])
    assert refreshed.nav_allowlist == []


def test_probe_freshness_is_authenticated(tmp_path):
    # last_probe_* are AAD-bound: a filesystem writer without the key cannot forge a "fresh".
    store = make_store(tmp_path)
    meta = save_login(store)
    store.record_probe(meta.jar_id, "fresh")
    loaded = store.load(meta.jar_id)  # re-seal preserves the payload and round-trips
    assert loaded.meta.last_probe_result == "fresh"
    assert {c["name"] for c in loaded.storage_state["cookies"]} == {"sid", "pref", "wide"}

    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["last_probe_result"] = "stale"  # tamper the cleartext freshness field
    path.write_text(json.dumps(record))
    with pytest.raises(JarError):
        store.load(meta.jar_id)  # AAD mismatch now fails closed


@pytest.mark.asyncio
async def test_agent_save_from_human_session_keeps_human_owner(tmp_path):
    # A NEW jar saved by the agent from a human-created session (handed over to the agent) is
    # attributed to that human so they can see and forget it in their subject-scoped /jars view.
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg, subject="user123")
    _, handover_token = await reg.handover(session.session_id, ctl, "take over")
    await reg.agent_claim(session.session_id, handover_token)  # agent now owns the lease; owner retained
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", origins=["https://shop.example.com"], probe=ProbeSpec()),
        actor="agent",
    )
    assert meta.owner_subject == "user123"


@pytest.mark.asyncio
async def test_agent_cannot_refresh_a_jar_not_loaded_into_its_session(tmp_path):
    # An agent may refresh ONLY the jar loaded into its own session. A jarless (handed-over) agent
    # session refreshing another user's jar_id is a prompt-injection vector — it must be rejected,
    # not filter the live state into the victim's scope and tombstone their generation.
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg, subject="user123")
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    other, ctl2 = await _human_login_session(reg, subject="user456")
    _, ho = await reg.handover(other.session_id, ctl2, "take over")
    await reg.agent_claim(other.session_id, ho)  # jarless agent session
    with pytest.raises(AuthorizationError):
        await reg.save_jar(
            other.session_id,
            SaveJarRequest(label="Shop", jar_id=meta.jar_id, origins=["https://shop.example.com"], probe=ProbeSpec()),
            actor="agent",
        )
    # The victim's jar is untouched (still owned by user123, generation unchanged).
    after = reg.jar_store.get_meta_verified(meta.jar_id)
    assert after.owner_subject == "user123" and after.generation == meta.generation


@pytest.mark.asyncio
async def test_save_authorization_uses_dedicated_secret_not_service_token(tmp_path, monkeypatch):
    # When the save-authorization gate is on, the full-API service bearer must NOT satisfy it — a
    # dedicated secret does — so relaying the save token to the browser cannot grant API access.
    store = make_store(tmp_path)
    store.require_save_authorization = True
    reg = SessionRegistry(jar_store=store)
    human, ctl = await _human_login_session(reg, subject="user123")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "svc-token")
    monkeypatch.setenv("BROWSER_JAR_SAVE_AUTHORIZATION_TOKEN", "save-token")

    with pytest.raises(AuthorizationError):
        await reg.save_jar(
            human.session_id,
            SaveJarRequest(
                label="Shop", token=ctl, save_authorization="svc-token", probe=ProbeSpec(logged_in_selector="[x]")
            ),
            actor="human",
        )
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(
            label="Shop", token=ctl, save_authorization="save-token", probe=ProbeSpec(logged_in_selector="[x]")
        ),
        actor="human",
    )
    assert meta.owner_subject == "user123"


# --- regression tests for Codex review round 10 ---------------------------


def test_session_cookie_jar_expires_after_ttl(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)  # LOGIN_STATE's "sid" is a session cookie (expires -1)
    assert meta.contains_session_cookies is True
    store.session_ttl = timedelta(seconds=-1)  # any elapsed time now exceeds the window
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)
    # And it surfaces as needing re-login in listings, not as usable.
    listed = next(m for m in store.list_meta() if m.jar_id == meta.jar_id)
    assert listed.invalidated_at is not None


def test_persistent_cookie_jar_not_expired_by_ttl(tmp_path):
    store = make_store(tmp_path)
    persistent = {
        "cookies": [
            {
                "name": "sid",
                "value": "x",
                "domain": "shop.example.com",
                "path": "/",
                "expires": 4102444800,
                "secure": True,
            }
        ],
        "origins": [],
    }
    meta = save_login(store, raw_storage_state=persistent)
    assert meta.contains_session_cookies is False
    store.session_ttl = timedelta(seconds=-1)  # even so, persistent-cookie jars carry no TTL
    assert store.load(meta.jar_id).meta.jar_id == meta.jar_id


def test_session_retention_fields_are_authenticated(tmp_path):
    # contains_session_cookies and updated_at gate the TTL, so a filesystem writer must not be able
    # to clear the flag or push the timestamp forward to dodge retention: both are AAD-bound, so a
    # cleartext edit of either fails the load closed.
    store = make_store(tmp_path)

    a = save_login(store)
    pa = tmp_path / "jars" / f"{a.jar_id}.json"
    ra = json.loads(pa.read_text())
    ra["meta"]["contains_session_cookies"] = False  # try to dodge the TTL by clearing the flag
    pa.write_text(json.dumps(ra))
    with pytest.raises(JarError):
        store.load(a.jar_id)

    b = save_login(store, origins=["https://api.example.com"], probe_spec_url="https://api.example.com/")
    pb = tmp_path / "jars" / f"{b.jar_id}.json"
    rb = json.loads(pb.read_text())
    rb["meta"]["updated_at"] = (datetime.now(UTC) + timedelta(days=3650)).isoformat()  # push past the window
    pb.write_text(json.dumps(rb))
    with pytest.raises(JarError):
        store.load(b.jar_id)


def test_probe_spec_field_length_bounded():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ProbeSpec(logged_in_selector="a" * 3000)


def test_oversized_probe_rejected_by_payload_cap(tmp_path):
    # A selector under the per-field cap can still push the sealed payload past a small byte cap.
    store = make_store(tmp_path, max_bytes=500)
    with pytest.raises(JarValidationError):
        save_login(
            store,
            probe_selector="a" * 400,
            probe_spec_url="https://shop.example.com/",
            raw_storage_state={"cookies": [], "origins": []},
        )


def test_refresh_tombstone_failure_leaves_prior_jar_loadable(tmp_path, monkeypatch):
    # Staged refresh: if tombstoning the old generation fails, the staged replacement is discarded
    # and the prior jar stays loadable — no brick, and no un-revoked rollback window either.
    store = make_store(tmp_path)
    meta = save_login(store)  # gen 1

    def boom(*args, **kwargs):
        raise OSError("tombstone log volume full")

    monkeypatch.setattr(store._tombstones, "record", boom)
    with pytest.raises(OSError):
        save_login(store, jar_id=meta.jar_id)  # refresh: staged write ok, tombstone fails
    monkeypatch.undo()

    loaded = store.load(meta.jar_id)  # old generation intact and never tombstoned
    assert loaded.meta.generation == meta.generation


@pytest.mark.asyncio
async def test_agent_save_drops_nav_allowlist(tmp_path):
    # Agent-supplied nav_allowlist is untrusted (it widens the confinement boundary), so it is
    # dropped on an agent save.
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg, subject="user123")
    _, ho = await reg.handover(session.session_id, ctl, "take over")
    await reg.agent_claim(session.session_id, ho)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", nav_allowlist=["https://evil.example.com"], probe=ProbeSpec()),
        actor="agent",
    )
    assert meta.nav_allowlist == []


@pytest.mark.asyncio
async def test_agent_save_origins_derived_from_live_page(tmp_path):
    # Agent-supplied origins are untrusted (a prompt-injected page could name an off-site origin
    # whose cookies are in the live context); the capture origin is derived server-side.
    reg = registry_with_store(tmp_path)
    session, ctl = await _human_login_session(reg, subject="user123")  # worker.url = shop.example.com/account
    _, ho = await reg.handover(session.session_id, ctl, "take over")
    await reg.agent_claim(session.session_id, ho)
    meta = await reg.save_jar(
        session.session_id,
        SaveJarRequest(label="Shop", origins=["https://evil.example.com"], probe=ProbeSpec()),
        actor="agent",
    )
    assert meta.origins == ["https://shop.example.com"]


# --- regression tests for Codex review round 9 ----------------------------


def test_malformed_logged_out_prefix_rejected(tmp_path):
    # A non-empty logged_out_url_prefix that cannot normalize must fail the save, not silently
    # disable the stale-login redirect signal.
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, probe_logged_out_prefix="https://shop.example.com:bad/login")


def test_detail_read_marks_rolled_back_generation(tmp_path):
    # annotate_revocation (shared by list_meta and the single-jar detail read) surfaces a jar that
    # was rolled back behind a tombstone as needing re-login, even though its cleartext file says
    # invalidated_at is null.
    store = make_store(tmp_path)
    meta = save_login(store)  # gen 1
    gen1 = (tmp_path / "jars" / f"{meta.jar_id}.json").read_bytes()
    save_login(store, jar_id=meta.jar_id)  # gen 2
    store.invalidate(meta.jar_id)  # tombstone gen 2
    (tmp_path / "jars" / f"{meta.jar_id}.json").write_bytes(gen1)  # restore gen-1 (invalidated_at None)

    raw = store.get_meta_unverified(meta.jar_id)
    assert raw.invalidated_at is None  # cleartext still says usable
    assert store.annotate_revocation(raw).invalidated_at is not None  # detail read surfaces it


@pytest.mark.asyncio
async def test_jar_loaded_session_survives_self_refresh(tmp_path):
    # A jar-loaded session that refreshes ITS OWN jar publishes a new generation and tombstones the
    # one it was seeded from. Its loaded generation must advance so the next command does not see
    # the superseded generation as revoked and cancel the session.
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg, subject="user123")
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    assert loaded.jar_generation == meta.generation
    fake_worker(reg, loaded.worker_id).storage_state = LOGIN_STATE

    refreshed = await reg.save_jar(
        loaded.session_id,
        SaveJarRequest(label="Shop", jar_id=meta.jar_id, origins=["https://shop.example.com"], probe=ProbeSpec()),
        actor="agent",
    )
    assert refreshed.generation == meta.generation + 1
    # The next command must succeed (session not self-cancelled) and reflect the advanced generation.
    result = await reg.agent_command(loaded.session_id, AgentCommandRequest(type="current_page"))
    assert result.ok
    assert reg.sessions[loaded.session_id].jar_generation == refreshed.generation


@pytest.mark.asyncio
async def test_touch_loaded_failure_does_not_break_session_create(tmp_path, monkeypatch):
    # A failed last_loaded_at touch must not leave a live authenticated context registered while
    # returning an error — the touch is best-effort.
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg, subject="user123")
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )

    def boom(_jar_id):
        raise OSError("disk full")

    monkeypatch.setattr(reg.jar_store, "touch_loaded", boom)
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    assert loaded.jar_id == meta.jar_id
    assert loaded.state == SessionState.AGENT_ACTIVE
    result = await reg.agent_command(loaded.session_id, AgentCommandRequest(type="current_page"))
    assert result.ok


@pytest.mark.asyncio
async def test_cookies_only_save_ignores_large_client_storage(tmp_path):
    # A cookies_only save must not fail on a large IndexedDB/localStorage: the cap should apply to
    # the cookies-only export, not the full client storage that is filtered out anyway.
    reg = SessionRegistry(jar_store=make_store(tmp_path, max_bytes=4096))
    human, ctl = await _human_login_session(reg, subject="user123")
    big = {
        "cookies": [
            {"name": "sid", "value": "x", "domain": "shop.example.com", "path": "/", "expires": -1, "secure": True}
        ],
        "origins": [{"origin": "https://shop.example.com", "localStorage": [{"name": "big", "value": "A" * 10000}]}],
    }
    fake_worker(reg, human.worker_id).storage_state = big

    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", storage="cookies_only", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    assert meta.storage_mode == "cookies_only"
    assert meta.origin_storage_count == 0
    loaded = reg.jar_store.load(meta.jar_id)
    assert loaded.storage_state["origins"] == []
    assert {c["name"] for c in loaded.storage_state["cookies"]} == {"sid"}


# --- regression tests for Codex review round 11 ---------------------------


def test_record_probe_dropped_when_generation_advanced(tmp_path):
    # A probe that ran against an old generation must not stamp its result / rate-limit timestamp
    # onto a jar that was refreshed to a newer generation in the meantime.
    store = make_store(tmp_path)
    meta = save_login(store)  # gen 1
    save_login(store, jar_id=meta.jar_id)  # gen 2 (current)
    stale = store.record_probe(meta.jar_id, "fresh", expected_generation=meta.generation)  # gen 1
    assert stale.last_probe_result is None  # not stamped onto gen 2
    current = store.get_meta_verified(meta.jar_id)
    store.record_probe(meta.jar_id, "fresh", expected_generation=current.generation)  # gen 2 matches
    assert store.load(meta.jar_id).meta.last_probe_result == "fresh"


@pytest.mark.asyncio
async def test_live_session_closed_when_jar_file_removed(tmp_path):
    # A shared-volume writer that removes/corrupts the jar file WITHOUT a tombstone must not keep a
    # seeded authenticated context alive: the per-command recheck fails closed when it no longer
    # authenticates.
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    (tmp_path / "jars" / f"{meta.jar_id}.json").unlink()  # file vanishes from the shared volume
    with pytest.raises(SessionInactiveError):
        await reg.agent_command(loaded.session_id, AgentCommandRequest(type="current_page"))


@pytest.mark.asyncio
async def test_create_cancels_when_seeded_generation_revoked_during_startup(tmp_path, monkeypatch):
    # If another pod refreshes the jar while worker.start() is awaiting, the seeded generation is
    # tombstoned while the file advances to a newer loadable one. The post-start recheck must catch
    # the SEEDED generation being revoked, not just "is the current file loadable".
    key = _key()
    reg_a = SessionRegistry(jar_store=make_store(tmp_path, keys=key))
    producer, ctl = await _human_login_session(reg_a)
    meta = await reg_a.save_jar(
        producer.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )  # gen 1
    reg_b = SessionRegistry(jar_store=make_store(tmp_path, keys=key))

    orig_start = FakeBrowserWorker.start
    done: list[bool] = []

    async def start_then_refresh(self):
        await orig_start(self)
        if not done:  # once, and before any nested worker start re-enters here
            done.append(True)
            prod2, ctl2 = await _human_login_session(reg_b)
            await reg_b.save_jar(
                prod2.session_id,
                SaveJarRequest(label="Shop", jar_id=meta.jar_id, token=ctl2, probe=ProbeSpec(logged_in_selector="[x]")),
                actor="human",
            )  # publishes gen 2, tombstones gen 1

    monkeypatch.setattr(FakeBrowserWorker, "start", start_then_refresh)
    with pytest.raises(JarRevokedError):
        await reg_a.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))


# --- regression tests for Codex review round 12 ---------------------------


def test_tombstone_log_with_undecodable_byte_does_not_jam_killswitch(tmp_path):
    # A corrupt/undecodable byte in the tombstone log must not make every revocation check raise;
    # the malformed line is skipped and a fresh invalidate still lands.
    store = make_store(tmp_path)
    a = save_login(store)
    store.invalidate(a.jar_id)
    log = tmp_path / "jars" / "jar-tombstones.jsonl"  # anchor/log live inside the jar dir
    with open(log, "ab") as fh:
        fh.write(b"\xff\xfe not valid utf-8 or json\n")
    # blocked_reason/high_water still work: the earlier invalidation is still observed...
    with pytest.raises(JarRevokedError):
        store.load(a.jar_id)
    # ...and a new invalidate can still be appended despite the garbage line.
    b = save_login(store, origins=["https://api.example.com"], probe_spec_url="https://api.example.com/")
    store.invalidate(b.jar_id)
    with pytest.raises(JarRevokedError):
        store.load(b.jar_id)


@pytest.mark.asyncio
async def test_probe_in_scope_network_failure_is_error_not_stale(tmp_path, monkeypatch):
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(
            label="Shop",
            token=ctl,
            probe=ProbeSpec(url="https://shop.example.com/account", logged_in_selector="[data-testid=logout]"),
        ),
        actor="human",
    )
    # Make the (in-scope) probe target fail with a network error rather than redirect off-scope.
    from browser_handoff_service import registry as registry_module

    real_make_worker = registry_module.make_worker

    def make_worker_with_outage(worker_id, **kwargs):
        worker = cast(FakeBrowserWorker, real_make_worker(worker_id, **kwargs))
        worker.nav_error_urls.add("https://shop.example.com/account")
        return worker

    monkeypatch.setattr(registry_module, "make_worker", make_worker_with_outage)
    result = await reg.probe_jar(meta.jar_id)
    assert result.result == "error"  # a transient outage, not "stale"


@pytest.mark.asyncio
async def test_concurrent_probes_do_not_both_run(tmp_path):
    import asyncio

    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[data-testid=logout]")),
        actor="human",
    )
    results = await asyncio.gather(reg.probe_jar(meta.jar_id), reg.probe_jar(meta.jar_id), return_exceptions=True)
    conflicts = [r for r in results if isinstance(r, ConflictError)]
    oks = [r for r in results if not isinstance(r, Exception)]
    assert len(oks) == 1 and len(conflicts) == 1  # the second is rejected, not run in parallel


@pytest.mark.asyncio
async def test_create_releases_jar_lock_before_worker_start(tmp_path, monkeypatch):
    # The jar lock must not be held across worker.start(): a same-process invalidate for the jar
    # must be able to land while a create for it is still starting its worker.
    import asyncio

    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )

    from browser_handoff_service import registry as registry_module

    real_make_worker = registry_module.make_worker
    invalidated: list[bool] = []

    def make_worker_that_invalidates_on_start(worker_id, **kwargs):
        worker = cast(FakeBrowserWorker, real_make_worker(worker_id, **kwargs))
        orig_start = worker.start

        async def start():
            if not invalidated:
                invalidated.append(True)
                # If the jar lock were still held by create, this would time out; it returns,
                # proving the lock was released before worker.start().
                await asyncio.wait_for(reg.invalidate_jar(meta.jar_id), timeout=2)
            await orig_start()

        monkeypatch.setattr(worker, "start", start)
        return worker

    monkeypatch.setattr(registry_module, "make_worker", make_worker_that_invalidates_on_start)
    with pytest.raises(JarRevokedError):
        await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    assert invalidated == [True]


# --- regression tests for Codex review round 13 ---------------------------


def test_revocation_state_lives_inside_jar_dir(tmp_path):
    # The tombstone/anchor/audit/lock must live INSIDE jar_dir so mounting BROWSER_JAR_DIR captures
    # the kill-switch — not in the parent, which operators do not mount.
    store = make_store(tmp_path)
    meta = save_login(store)
    store.invalidate(meta.jar_id)
    jars_dir = tmp_path / "jars"
    assert (jars_dir / "jar-tombstones.jsonl").exists()
    assert (jars_dir / "jar-anchor.json").exists()
    assert not (tmp_path / "jar-tombstones.jsonl").exists()  # not stranded in the parent
    assert not (tmp_path / "jar-anchor.json").exists()


@pytest.mark.asyncio
async def test_agent_selector_dropped_when_baseline_nav_errors(tmp_path, monkeypatch):
    # If the logged-out baseline navigation fails in-scope (DNS/TLS/outage -> "error"), the agent's
    # selector must NOT be trusted as authenticated-only.
    reg = registry_with_store(tmp_path)
    sess, _ = await reg.create_session(CreateSessionRequest(conversation_id="c1"))
    worker = fake_worker(reg, sess.worker_id)
    worker.url = "https://shop.example.com/home"
    worker.storage_state = LOGIN_STATE

    from browser_handoff_service import registry as registry_module

    real_make_worker = registry_module.make_worker

    def make_worker_baseline_outage(worker_id, **kwargs):
        w = cast(FakeBrowserWorker, real_make_worker(worker_id, **kwargs))
        if worker_id.startswith("baseline_probe"):
            w.nav_error_urls.add("https://shop.example.com/")  # baseline nav fails in-scope
        return w

    monkeypatch.setattr(registry_module, "make_worker", make_worker_baseline_outage)
    meta = await reg.save_jar(
        sess.session_id,
        SaveJarRequest(label="Shop", probe=ProbeSpec(logged_in_selector="[data-testid=logout]")),
        actor="agent",
    )
    loaded = reg.jar_store.load(meta.jar_id)
    assert loaded.probe.logged_in_selector is None  # dropped: no real logged-out baseline


# --- regression tests for Codex review round 14 ---------------------------


def test_high_entropy_probe_token_rejected(tmp_path):
    # A base64url magic-link/invite token in the probe path must be rejected, not just all-hex ids.
    store = make_store(tmp_path)
    with pytest.raises(JarValidationError):
        save_login(store, probe_spec_url="https://shop.example.com/invite/AbCdEfGhIjKlMnOpQrStUv")


def test_readable_probe_slug_allowed(tmp_path):
    # A lowercase human-readable slug is not a token and stays allowed.
    store = make_store(tmp_path)
    assert save_login(store, probe_spec_url="https://shop.example.com/account-settings").jar_id


def test_save_request_bounds_origin_count_and_length():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        SaveJarRequest(label="x", probe=ProbeSpec(), origins=[f"https://s{i}.example.com" for i in range(100)])
    with pytest.raises(ValidationError):
        SaveJarRequest(label="x", probe=ProbeSpec(), nav_allowlist=["https://" + "a" * 3000 + ".example.com"])


def test_metadata_size_counts_toward_cap(tmp_path):
    # A jar with empty storage but a huge origin list must still be rejected by the byte cap.
    store = make_store(tmp_path, max_bytes=1500)
    many = ["https://shop.example.com"] + [f"https://s{i}.example.com" for i in range(200)]
    with pytest.raises(JarValidationError):
        save_login(
            store,
            origins=many,
            raw_storage_state={"cookies": [], "origins": []},
            probe_spec_url="https://shop.example.com/",
        )


def test_refresh_survives_anchor_write_failure(tmp_path, monkeypatch):
    # Once the tombstone log append (the durable commit) succeeds, a failure of the secondary signed
    # anchor write must NOT abort the refresh: the new generation still publishes (no brick) and the
    # old generation stays revoked via the authoritative log.
    import browser_handoff_service.jars as jars_mod

    store = make_store(tmp_path)
    meta = save_login(store)  # gen 1
    gen1 = (tmp_path / "jars" / f"{meta.jar_id}.json").read_bytes()

    real_atomic = jars_mod._atomic_write

    def flaky_atomic(path, data, mode=0o600, *, before_rename=None):
        if path.name == "jar-anchor.json":
            raise OSError("anchor volume full")
        return real_atomic(path, data, mode, before_rename=before_rename)

    monkeypatch.setattr(jars_mod, "_atomic_write", flaky_atomic)
    refreshed = save_login(store, jar_id=meta.jar_id)  # gen 2: log commits, anchor write fails
    monkeypatch.undo()

    assert refreshed.generation == meta.generation + 1
    assert store.load(meta.jar_id).meta.generation == refreshed.generation  # new gen published, not bricked
    (tmp_path / "jars" / f"{meta.jar_id}.json").write_bytes(gen1)  # restore the old file
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)  # old generation still revoked via the log


# --- regression tests for Codex review round 15 ---------------------------


def test_invalid_nonce_length_is_decrypt_error_not_crash(tmp_path):
    # A base64-valid but wrong-length nonce makes AESGCM raise ValueError (not InvalidTag); it must
    # fail closed as a JarError, not a 500 that would block the service-token kill-switch.
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["nonce"] = base64.b64encode(b"short").decode()  # 5 bytes, not 12
    path.write_text(json.dumps(record))
    with pytest.raises(JarError):
        store.load(meta.jar_id)
    assert store.get_meta_unverified(meta.jar_id).label == "(unverified)"  # management path stays usable


def test_encoded_record_cap_accounts_for_base64_inflation(tmp_path):
    # A plaintext payload under the cap can still exceed it once base64-encoded + metadata; the cap
    # is enforced on the actual serialized file.
    store = make_store(tmp_path, max_bytes=1200)
    state = {
        "cookies": [
            {
                "name": "sid",
                "value": "x" * 800,
                "domain": "shop.example.com",
                "path": "/",
                "expires": -1,
                "secure": True,
            }
        ],
        "origins": [],
    }
    with pytest.raises(JarValidationError):
        save_login(store, raw_storage_state=state, probe_spec_url="https://shop.example.com/")


@pytest.mark.asyncio
async def test_producing_session_closed_when_jar_file_removed(tmp_path):
    # A source session that PRODUCED a jar holds the unfiltered login; a shared-volume tamper that
    # removes the jar file (no tombstone) must fail it closed too, like a jar-loaded session.
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    assert meta.jar_id in reg.sessions[human.session_id].produced_jar_ids
    assert reg.session_jar_revoked(human.session_id) is False
    (tmp_path / "jars" / f"{meta.jar_id}.json").unlink()  # removed without a tombstone
    assert reg.session_jar_revoked(human.session_id) is True


@pytest.mark.asyncio
async def test_agent_save_drops_logged_out_prefix(tmp_path):
    # Agent-supplied logged_out_url_prefix is untrusted: a prompt-injected page could set it to the
    # landing origin so every probe reads stale. It is dropped on an agent save.
    reg = registry_with_store(tmp_path)
    sess, ctl = await _human_login_session(reg, subject="user123")
    _, ho = await reg.handover(sess.session_id, ctl, "take over")
    await reg.agent_claim(sess.session_id, ho)
    meta = await reg.save_jar(
        sess.session_id,
        SaveJarRequest(label="Shop", probe=ProbeSpec(logged_out_url_prefix="https://shop.example.com/")),
        actor="agent",
    )
    assert reg.jar_store.load(meta.jar_id).probe.logged_out_url_prefix is None


# --- regression tests for Codex review round 16 ---------------------------


def test_reserve_probe_is_durable_across_instances(tmp_path):
    # The probe reservation is written to the shared file, so another pod sharing BROWSER_JAR_DIR
    # sees the rate-limit and will not run a duplicate authenticated probe.
    key = _key()
    a = make_store(tmp_path, keys=key)
    meta = save_login(a)
    assert a.reserve_probe(meta.jar_id, meta.generation) is True
    b = make_store(tmp_path, keys=key)  # a second pod on the same volume
    assert b.reserve_probe(meta.jar_id, meta.generation) is False
    # A stale generation cannot reserve either.
    assert a.reserve_probe(meta.jar_id, meta.generation + 5) is False


def test_delete_of_missing_file_records_terminal_tombstone(tmp_path):
    # Forgetting a jar whose file already vanished must still record the terminal tombstone, so a
    # restored backup cannot revive the login.
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    backup = path.read_bytes()
    path.unlink()  # file vanishes without a tombstone
    store.delete(meta.jar_id)  # trusted forget of a now-missing jar
    path.write_bytes(backup)  # attacker restores an old backup
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


def test_invalidate_of_missing_file_records_tombstone(tmp_path):
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    backup = path.read_bytes()
    path.unlink()
    store.invalidate(meta.jar_id)
    path.write_bytes(backup)
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


@pytest.mark.asyncio
async def test_save_jar_malformed_id_allocates_no_lock(tmp_path):
    # A malformed jar_id must be rejected before a per-jar lock is cached, so callers cannot leave
    # permanent entries in self.jar_locks by POSTing random/oversized ids.
    reg = registry_with_store(tmp_path)
    sess, ctl = await _human_login_session(reg)
    with pytest.raises(JarValidationError):
        await reg.save_jar(
            sess.session_id,
            SaveJarRequest(label="x", jar_id="not-a-jar", token=ctl, probe=ProbeSpec()),
            actor="human",
        )
    assert "not-a-jar" not in reg.jar_locks


# --- regression tests for Codex review round 17 ---------------------------


def test_reserve_probe_fails_when_revoked_by_another_instance(tmp_path):
    # A revocation that lands (from another pod) after load but before the reservation must still be
    # a kill-switch: reserve_probe rechecks invalidation/tombstone under the ops lock.
    key = _key()
    a = make_store(tmp_path, keys=key)
    meta = save_login(a)
    b = make_store(tmp_path, keys=key)
    b.invalidate(meta.jar_id)  # another pod revokes
    assert a.reserve_probe(meta.jar_id, meta.generation) is False


@pytest.mark.asyncio
async def test_cookies_only_widening_refresh_does_not_materialize_localstorage(tmp_path):
    # Refreshing a cookies_only jar with storage="all" is an invalid widening. It must be rejected
    # as a validation error WITHOUT first materializing the live page's large localStorage.
    reg = SessionRegistry(jar_store=make_store(tmp_path, max_bytes=4096))
    human, ctl = await _human_login_session(reg, subject="user123")
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", storage="cookies_only", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    fake_worker(reg, human.worker_id).storage_state = {
        "cookies": [
            {"name": "sid", "value": "x", "domain": "shop.example.com", "path": "/", "expires": -1, "secure": True}
        ],
        "origins": [{"origin": "https://shop.example.com", "localStorage": [{"name": "big", "value": "A" * 10000}]}],
    }
    with pytest.raises(JarValidationError):
        await reg.save_jar(
            human.session_id,
            SaveJarRequest(
                label="Shop", jar_id=meta.jar_id, storage="all", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")
            ),
            actor="human",
        )


@pytest.mark.asyncio
async def test_self_refresh_narrowing_tightens_worker_confinement(tmp_path):
    # A jar-loaded session that refreshes its own jar to a narrower scope must tighten the LIVE
    # worker's route guard, not just the session metadata.
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg, subject="user123")
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(
            label="Shop",
            origins=["https://shop.example.com", "https://api.example.com"],
            token=ctl,
            probe=ProbeSpec(logged_in_selector="[x]"),
        ),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    worker = fake_worker(reg, loaded.worker_id)
    assert "https://api.example.com" in worker.confine_origins
    worker.storage_state = LOGIN_STATE

    await reg.save_jar(
        loaded.session_id,
        SaveJarRequest(label="Shop", jar_id=meta.jar_id, origins=["https://shop.example.com"], probe=ProbeSpec()),
        actor="agent",
    )
    assert "https://api.example.com" not in worker.confine_origins  # live worker tightened
    assert "https://shop.example.com" in worker.confine_origins


# --- regression tests for Codex review round 18 ---------------------------


def test_invalidate_succeeds_when_reseal_fails_after_tombstone(tmp_path, monkeypatch):
    # If the post-tombstone re-seal fails (disk full), invalidate must still succeed: the tombstone
    # is the durable commit, so the caller can close live sessions and the jar stays revoked.
    import browser_handoff_service.jars as jars_mod

    store = make_store(tmp_path)
    meta = save_login(store)
    real_atomic = jars_mod._atomic_write

    def flaky(path, data, mode=0o600, *, before_rename=None):
        if path.name == f"{meta.jar_id}.json":  # the jar re-seal, not the tombstone/anchor
            raise OSError("jar volume full")
        return real_atomic(path, data, mode, before_rename=before_rename)

    monkeypatch.setattr(jars_mod, "_atomic_write", flaky)
    result = store.invalidate(meta.jar_id)  # must not raise
    assert result.invalidated_at is not None
    monkeypatch.undo()
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)  # still revoked via the committed tombstone


def test_jar_file_deleted_mid_read_is_not_found_not_crash(tmp_path, monkeypatch):
    # A shared-volume race where the file vanishes between exists() and read must surface as a
    # controlled JarNotFoundError, not an opaque 500.
    import browser_handoff_service.jars as jars_mod

    store = make_store(tmp_path)
    meta = save_login(store)
    real_read_text = jars_mod.Path.read_text

    def vanishing_read_text(self, *args, **kwargs):
        if self.name == f"{meta.jar_id}.json":
            raise FileNotFoundError(self)
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(jars_mod.Path, "read_text", vanishing_read_text)
    with pytest.raises(JarNotFoundError):
        store.load(meta.jar_id)


# --- regression tests for Codex review round 19 ---------------------------


@pytest.mark.asyncio
async def test_agent_selector_dropped_when_baseline_selector_errors(tmp_path, monkeypatch):
    # A selector that fails to EVALUATE on the logged-out baseline (malformed/transient) must not be
    # read as "absent" and accepted as discriminating.
    reg = registry_with_store(tmp_path)
    sess, _ = await reg.create_session(CreateSessionRequest(conversation_id="c1"))
    worker = fake_worker(reg, sess.worker_id)
    worker.url = "https://shop.example.com/home"
    worker.storage_state = LOGIN_STATE

    from browser_handoff_service import registry as registry_module

    real_make_worker = registry_module.make_worker

    def mk(worker_id, **kwargs):
        w = cast(FakeBrowserWorker, real_make_worker(worker_id, **kwargs))
        if worker_id.startswith("baseline_probe"):
            w.error_selectors.add("[data-testid=logout]")
        return w

    monkeypatch.setattr(registry_module, "make_worker", mk)
    meta = await reg.save_jar(
        sess.session_id,
        SaveJarRequest(label="Shop", probe=ProbeSpec(logged_in_selector="[data-testid=logout]")),
        actor="agent",
    )
    assert reg.jar_store.load(meta.jar_id).probe.logged_in_selector is None  # dropped, not trusted


@pytest.mark.asyncio
async def test_probe_selector_evaluation_error_is_error_not_stale(tmp_path, monkeypatch):
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(
            label="Shop",
            token=ctl,
            probe=ProbeSpec(url="https://shop.example.com/account", logged_in_selector="[data-testid=logout]"),
        ),
        actor="human",
    )
    from browser_handoff_service import registry as registry_module

    real_make_worker = registry_module.make_worker

    def mk(worker_id, **kwargs):
        w = cast(FakeBrowserWorker, real_make_worker(worker_id, **kwargs))
        w.error_selectors.add("[data-testid=logout]")
        return w

    monkeypatch.setattr(registry_module, "make_worker", mk)
    result = await reg.probe_jar(meta.jar_id)
    assert result.result == "error"  # a selector eval failure is not "stale"


@pytest.mark.asyncio
async def test_refresh_widening_rejected_before_export(tmp_path, monkeypatch):
    # An out-of-scope refresh must be rejected BEFORE any browser export (or baseline probe), so a
    # prompt-injected agent refresh cannot force the live context to export.
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg, subject="user123")
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(label="Shop", token=ctl, probe=ProbeSpec(logged_in_selector="[x]")),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    worker = fake_worker(reg, loaded.worker_id)

    async def boom_export(*args, **kwargs):
        raise AssertionError("export must not run for an invalid widening")

    monkeypatch.setattr(worker, "export_storage_state", boom_export)
    with pytest.raises(JarValidationError):
        await reg.save_jar(
            loaded.session_id,
            SaveJarRequest(label="Shop", jar_id=meta.jar_id, origins=["https://evil.example.com"], probe=ProbeSpec()),
            actor="agent",
        )


@pytest.mark.asyncio
async def test_bad_control_token_save_allocates_no_lock(tmp_path):
    # A human save with a bad control token must be rejected before a per-jar lock is cached.
    reg = registry_with_store(tmp_path)
    human, _ = await _human_login_session(reg, subject="user123")
    jar_id = "jar_" + "a" * 32
    with pytest.raises(AuthorizationError):
        await reg.save_jar(
            human.session_id,
            SaveJarRequest(label="x", jar_id=jar_id, token="garbage", probe=ProbeSpec()),
            actor="human",
        )
    assert jar_id not in reg.jar_locks


# --- regression tests for Codex review round 20 ---------------------------


def test_unreadable_jar_file_is_jar_error_not_crash(tmp_path, monkeypatch):
    # A read-time OSError (EACCES/chmod/ACL, dir-at-path) must be a controlled JarError, so the
    # service-token kill-switch and live-session checks don't 500.
    import browser_handoff_service.jars as jars_mod

    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    backup = path.read_bytes()
    real_read_text = jars_mod.Path.read_text

    def eacces_read_text(self, *args, **kwargs):
        if self.name == f"{meta.jar_id}.json":
            raise PermissionError("EACCES")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(jars_mod.Path, "read_text", eacces_read_text)
    with pytest.raises(JarError):
        store.load(meta.jar_id)
    # And delete still records a terminal tombstone despite the unreadable blob.
    store.delete(meta.jar_id)
    monkeypatch.undo()
    path.write_bytes(backup)  # a restored backup must stay blocked by the terminal tombstone
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


def test_refresh_rejected_after_terminal_invalidation(tmp_path):
    # A terminal (_MAX_GENERATION) invalidation must not be undone by a same-id refresh publishing
    # 2**63; require a fresh jar id.
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    backup = path.read_bytes()
    record = json.loads(path.read_text())
    record["blob"] = base64.b64encode(b"tampered").decode()  # break decrypt -> un-authenticatable
    path.write_text(json.dumps(record))
    store.invalidate(meta.jar_id)  # records the _MAX_GENERATION terminal tombstone
    path.write_bytes(backup)  # restore the authentic file
    with pytest.raises(JarRevokedError):
        save_login(store, jar_id=meta.jar_id)


def test_delete_succeeds_when_unlink_fails_after_tombstone(tmp_path, monkeypatch):
    import browser_handoff_service.jars as jars_mod

    store = make_store(tmp_path)
    meta = save_login(store)
    real_unlink = jars_mod.Path.unlink

    def boom_unlink(self, *args, **kwargs):
        if self.name == f"{meta.jar_id}.json":
            raise OSError("unlink failed")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(jars_mod.Path, "unlink", boom_unlink)
    result = store.delete(meta.jar_id)  # must not raise; tombstone is the commit
    assert result.jar_id == meta.jar_id
    monkeypatch.undo()
    with pytest.raises(JarRevokedError):
        store.load(meta.jar_id)


def test_save_rejects_refresh_when_precondition_generation_revoked(tmp_path):
    # The refresh-vs-revoke precondition: a refresh from a session whose captured generation was
    # revoked must be rejected under the ops lock, not resurrect the jar from stale state.
    store = make_store(tmp_path)
    meta = save_login(store)  # gen 1
    store.invalidate(meta.jar_id)  # revoke gen 1
    with pytest.raises(JarRevokedError):
        save_login(store, jar_id=meta.jar_id, revoke_precondition=meta.generation)
    # A jarless re-login (no precondition) may still re-enable it.
    reenabled = save_login(store, jar_id=meta.jar_id)
    assert reenabled.generation > meta.generation


@pytest.mark.asyncio
async def test_self_refresh_narrowing_evicts_off_scope_page(tmp_path):
    # A narrowing self-refresh must evict the CURRENT page if the refresh dropped its origin, not
    # just tighten the route guard for future navigations.
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg, subject="user123")
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(
            label="Shop",
            origins=["https://shop.example.com", "https://api.example.com"],
            token=ctl,
            probe=ProbeSpec(logged_in_selector="[x]"),
        ),
        actor="human",
    )
    loaded, _ = await reg.create_session(CreateSessionRequest(conversation_id="c2", jar_id=meta.jar_id))
    worker = fake_worker(reg, loaded.worker_id)
    worker.url = "https://api.example.com/page"  # current page on the origin about to be dropped
    worker.storage_state = LOGIN_STATE
    await reg.save_jar(
        loaded.session_id,
        SaveJarRequest(label="Shop", jar_id=meta.jar_id, origins=["https://shop.example.com"], probe=ProbeSpec()),
        actor="agent",
    )
    assert worker.url == "about:blank"  # off-scope current page evicted


# --- regression tests for Codex review round 21 ---------------------------


def test_extension_suffixed_logout_probe_rejected(tmp_path):
    # /logout.php (and .aspx/.do) must be rejected as action-like, not just the bare /logout.
    store = make_store(tmp_path)
    for path in ("/logout.php", "/account/signout.aspx", "/delete.do"):
        with pytest.raises(JarValidationError):
            save_login(store, probe_spec_url=f"https://shop.example.com{path}")
    # A real page that merely contains the word is still allowed.
    assert save_login(store, probe_spec_url="https://shop.example.com/logout-history").jar_id


def test_unreadable_tombstone_log_fails_closed(tmp_path, monkeypatch):
    # If the tombstone log EXISTS but cannot be read, revocation checks must fail closed (block the
    # load) and record must surface a controlled error — never read as "nothing revoked".
    import browser_handoff_service.jars as jars_mod

    store = make_store(tmp_path)
    meta = save_login(store)
    store.invalidate(meta.jar_id)  # create the log with a real tombstone
    log = tmp_path / "jars" / "jar-tombstones.jsonl"
    real_read_text = jars_mod.Path.read_text

    def eacces_read_text(self, *args, **kwargs):
        if self.name == log.name:
            raise PermissionError("EACCES")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(jars_mod.Path, "read_text", eacces_read_text)
    b = save_login(store)  # a *different*, un-tombstoned jar
    with pytest.raises(JarError):
        store.load(b.jar_id)  # fail closed: cannot verify revocation state
    with pytest.raises(JarError):
        store.invalidate(b.jar_id)  # record surfaces a controlled error, not a 500


@pytest.mark.asyncio
async def test_probe_in_scope_err_failed_is_error_not_stale(tmp_path, monkeypatch):
    # A generic in-scope navigation failure (no off-scope abort) must classify as "error", not
    # "stale" — the route guard's off-scope-abort flag, not the net:: code, decides "blocked".
    reg = registry_with_store(tmp_path)
    human, ctl = await _human_login_session(reg)
    meta = await reg.save_jar(
        human.session_id,
        SaveJarRequest(
            label="Shop",
            token=ctl,
            probe=ProbeSpec(url="https://shop.example.com/account", logged_in_selector="[data-testid=logout]"),
        ),
        actor="human",
    )
    from browser_handoff_service import registry as registry_module

    real_make_worker = registry_module.make_worker

    def mk(worker_id, **kwargs):
        w = cast(FakeBrowserWorker, real_make_worker(worker_id, **kwargs))
        w.nav_error_urls.add("https://shop.example.com/account")  # in-scope outage, not off-scope
        return w

    monkeypatch.setattr(registry_module, "make_worker", mk)
    result = await reg.probe_jar(meta.jar_id)
    assert result.result == "error"


# --- regression tests for Codex review round 22 ---------------------------


@pytest.mark.asyncio
async def test_create_malformed_jar_id_allocates_no_lock(tmp_path):
    reg = registry_with_store(tmp_path)
    with pytest.raises(JarValidationError):
        await reg.create_session(CreateSessionRequest(conversation_id="c1", jar_id="not-a-jar"))
    assert "not-a-jar" not in reg.jar_locks


def test_save_fails_when_audit_append_fails(tmp_path, monkeypatch):
    # A durable credential must not be acknowledged without its durable audit record.
    import browser_handoff_service.jars as jars_mod

    store = make_store(tmp_path)
    real_open = jars_mod.Path.open

    def boom_open(self, *args, **kwargs):
        if self.name == "jar-audit.jsonl":
            raise OSError("audit volume full")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(jars_mod.Path, "open", boom_open)
    with pytest.raises(JarError):
        save_login(store)


def test_agent_self_refresh_preserves_session_ttl_anchor(tmp_path):
    # An agent self-refresh must not reset the session-cookie retention anchor (that would let it
    # keep a browser-close credential replayable indefinitely); a human re-login does reset it.
    store = make_store(tmp_path)
    meta = save_login(store, saved_by="human")  # LOGIN_STATE has a session cookie
    assert meta.contains_session_cookies is True
    anchor = meta.session_ttl_anchor
    assert anchor is not None

    agent_refresh = save_login(store, jar_id=meta.jar_id, saved_by="agent")
    assert agent_refresh.session_ttl_anchor == anchor  # preserved, not extended

    human_refresh = save_login(store, jar_id=meta.jar_id, saved_by="human")
    assert human_refresh.session_ttl_anchor is not None
    assert human_refresh.session_ttl_anchor > anchor


def test_session_ttl_anchor_is_authenticated(tmp_path):
    # The retention anchor gates the TTL, so a filesystem writer must not push it forward to dodge
    # retention: it is AAD-bound.
    store = make_store(tmp_path)
    meta = save_login(store)
    path = tmp_path / "jars" / f"{meta.jar_id}.json"
    record = json.loads(path.read_text())
    record["meta"]["session_ttl_anchor"] = (datetime.now(UTC) + timedelta(days=3650)).isoformat()
    path.write_text(json.dumps(record))
    with pytest.raises(JarError):
        store.load(meta.jar_id)
