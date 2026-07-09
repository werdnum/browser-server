"""Cookie jars: browser-server's first durable, encrypted state.

A *cookie jar* is a named, scope-filtered, encrypted blob of Playwright ``storage_state``
(cookies + localStorage + IndexedDB) captured from a session after a human logs in, plus
cleartext metadata. The jar can later be seeded into a fresh session's browser context so
an agent browses the site as the logged-in user without anyone re-entering credentials.

This module is the *mechanism* half of the design (encryption, scope filtering, atomic
persistence, rollback-proof revocation, freshness metadata). Policy — confirmation gating,
profile placement, taint labelling — lives in the Family Assistant client and requires zero
changes here. See ``cookie-jar-design.md``.

Security invariants enforced here:

- Jar contents (cookie/storage names and values) are never returned or logged — only metadata.
- Jars are encrypted with AES-256-GCM under an operator key; keyless => feature disabled, 503.
- Security-critical cleartext metadata (origins, nav_allowlist, owner_subject, storage_mode,
  key_id, jar_id, generation, invalidated_at) is bound as AES-GCM AAD, so tampering with the
  file without the key fails decryption closed.
- Revocation is rollback-proof via a monotonic ``generation`` counter and an append-only,
  HMAC-chained tombstone whose high-water mark is anchored outside ``BROWSER_JAR_DIR``.
- Every ``jar_id`` is validated against ``jar_[0-9a-f]{32}`` before it touches the filesystem.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import tldextract
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import CookieJarMeta, JarProbeConfig, ProbeResultName, StorageMode, now_utc

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _canonical_netloc(scheme: str, host: str, port: int | None) -> str:
    """Host plus port, with the scheme's default port canonicalized away so ``https://h`` and
    ``https://h:443`` compare equal (else confinement/probe treat them as different origins)."""
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        return f"{host}:{port}"
    return host


JAR_KEY_ENV = "BROWSER_JAR_KEY"
JAR_DIR_ENV = "BROWSER_JAR_DIR"
JAR_MAX_BYTES_ENV = "BROWSER_JAR_MAX_BYTES"
JAR_SAVE_AUTH_REQUIRED_ENV = "BROWSER_JAR_REQUIRE_SAVE_AUTHORIZATION"

DEFAULT_DATA_DIR = "/var/lib/browser-handoff"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
PROBE_MIN_INTERVAL = timedelta(minutes=15)
LABEL_MAX_LEN = 80

# The strict generated form. A caller-supplied jar_id that does not match is rejected before
# it is ever used to build a filesystem path, closing path traversal.
JAR_ID_RE = re.compile(r"^jar_[0-9a-f]{32}$")

# Offline PSL matcher (no network at runtime). Registrable domains are informational display
# metadata only; they never widen capture and are not the confinement boundary.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


class JarError(Exception):
    """Base for jar failures."""


class JarDisabledError(JarError):
    """No encryption key configured; the feature is fail-closed (maps to HTTP 503)."""


class JarNotFoundError(JarError):
    """No jar with that id (maps to HTTP 404)."""


class JarValidationError(JarError):
    """Malformed request: bad id, out-of-scope probe, illegal widening (maps to HTTP 400/409)."""


class JarRevokedError(JarError):
    """Jar is invalidated, deleted, or a rolled-back file; unloadable (maps to HTTP 409)."""


class JarDecryptError(JarError):
    """Blob cannot be decrypted. ``kind`` distinguishes 'rotation' from 'corruption'."""

    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.kind = kind


def validate_jar_id(jar_id: str) -> str:
    if not isinstance(jar_id, str) or not JAR_ID_RE.match(jar_id):
        raise JarValidationError("invalid jar_id")
    return jar_id


def normalize_label(label: str) -> str:
    """Trim, strip control characters/newlines, cap length, plain text only.

    A caller-supplied label can resurface in the FA ``list_saved_sessions`` tool, so a
    page-driven save must not be able to plant instruction-like markup that becomes durable
    prompt injection. The FA side additionally renders it as untrusted data."""
    cleaned = "".join(ch for ch in label if ch.isprintable() and ch not in "\r\n\t")
    cleaned = cleaned.strip()
    if len(cleaned) > LABEL_MAX_LEN:
        cleaned = cleaned[:LABEL_MAX_LEN].rstrip()
    return cleaned


def normalize_origin(value: str) -> str | None:
    """Reduce a URL/origin to exact ``scheme://host[:port]`` (no path/query/fragment/userinfo)."""
    from urllib.parse import urlsplit

    parsed = urlsplit(value.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    netloc = _canonical_netloc(parsed.scheme, parsed.hostname.lower(), parsed.port)
    return f"{parsed.scheme}://{netloc}"


def redact_probe_url(value: str) -> str | None:
    """Reconstruct a probe URL from scheme + host + port + path only.

    Query, fragment, and userinfo (``user:pass@``) are all dropped so no probe url becomes a
    back door around the never-store-sensitive-full-URLs guarantee."""
    from urllib.parse import urlsplit, urlunsplit

    parsed = urlsplit(value.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    netloc = _canonical_netloc(parsed.scheme, parsed.hostname.lower(), parsed.port)
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def registrable_domain(origin: str) -> str | None:
    from urllib.parse import urlsplit

    host = urlsplit(origin).hostname
    if not host:
        return None
    ext = _EXTRACT(host)
    # ``top_domain_under_public_suffix`` on newer tldextract; ``registered_domain`` on older.
    return getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or None


# High-entropy / sensitive path segments a probe target must not carry (secrets, magic links,
# account ids in the path — stripping query/fragment is not enough).
_HEX_SEG_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
# 5+ all-digit segments read as account ids (the design's own example is /users/12345/account);
# 4-digit segments (years, etc.) are left alone.
_LONG_DIGIT_RE = re.compile(r"^\d{5,}$")


def _path_looks_sensitive(path: str) -> bool:
    for segment in path.split("/"):
        if not segment:
            continue
        if _HEX_SEG_RE.match(segment) or _LONG_DIGIT_RE.match(segment) or len(segment) > 64:
            return True
    return False


def _cookie_matches_origin(cookie: dict[str, Any], origin_host: str, origin_secure: bool) -> bool:
    """A cookie is in scope iff it would actually be sent to the declared origin under that
    origin's host and scheme — honoring the Domain attribute, host-only cookies, and Secure.

    Path is deliberately NOT used to exclude: declared origins carry no path and a
    ``Path=/account`` cookie is still needed for URLs under the same origin."""
    domain = str(cookie.get("domain", "")).lower().lstrip(".")
    if not domain:
        return False
    host_only = not str(cookie.get("domain", "")).startswith(".")
    if host_only:
        if domain != origin_host:
            return False
    else:
        # Domain=.example.com is sent to example.com and any subdomain.
        if not (origin_host == domain or origin_host.endswith("." + domain)):
            return False
    if cookie.get("secure") and not origin_secure:
        return False
    return True


@dataclass
class FilterStats:
    cookie_count: int
    origin_storage_count: int
    earliest_cookie_expiry: datetime | None
    session_cookies_only: bool
    contains_session_cookies: bool


def filter_storage_state(
    raw: dict[str, Any], origins: list[str], storage_mode: StorageMode
) -> tuple[dict[str, Any], FilterStats]:
    """Scope-filter a raw Playwright ``storage_state`` to the declared origins.

    - cookies: kept iff sent to at least one declared origin (Domain/host-only + Secure).
    - origin storage (localStorage/IndexedDB): kept iff its origin is *exactly* declared.
    - ``cookies_only`` drops all origin storage regardless.

    Pure and browser-free so it is unit-testable."""
    from urllib.parse import urlsplit

    parsed_origins = []
    exact_origins = set()
    for origin in origins:
        norm = normalize_origin(origin)
        if norm is None:
            continue
        exact_origins.add(norm)
        split = urlsplit(norm)
        parsed_origins.append((split.hostname or "", split.scheme == "https"))

    kept_cookies = []
    earliest: datetime | None = None
    contains_session = False
    persistent_count = 0
    for cookie in raw.get("cookies", []) or []:
        if not any(_cookie_matches_origin(cookie, host, secure) for host, secure in parsed_origins):
            continue
        kept_cookies.append(cookie)
        expires = cookie.get("expires")
        # Playwright encodes a session cookie as expires == -1 (or missing).
        if expires in (None, -1, -1.0) or (isinstance(expires, (int, float)) and expires < 0):
            contains_session = True
        else:
            persistent_count += 1
            try:
                when = datetime.fromtimestamp(float(expires), tz=UTC)
            except (OverflowError, OSError, ValueError):
                when = None
            if when is not None and (earliest is None or when < earliest):
                earliest = when

    kept_origin_storage = []
    if storage_mode == "all":
        for entry in raw.get("origins", []) or []:
            entry_origin = normalize_origin(str(entry.get("origin", "")))
            if entry_origin is not None and entry_origin in exact_origins:
                kept_origin_storage.append(entry)

    filtered = {"cookies": kept_cookies, "origins": kept_origin_storage}
    stats = FilterStats(
        cookie_count=len(kept_cookies),
        origin_storage_count=len(kept_origin_storage),
        earliest_cookie_expiry=earliest,
        session_cookies_only=(len(kept_cookies) > 0 and persistent_count == 0),
        contains_session_cookies=contains_session,
    )
    return filtered, stats


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _key_id(key: bytes) -> str:
    return hashlib.sha256(b"jar-key-id\x00" + key).hexdigest()[:12]


def load_jar_keys() -> list[tuple[str, bytes]]:
    """Parse ``BROWSER_JAR_KEY`` (comma-separated urlsafe-base64, 32 bytes each).

    The first key is used for new writes; the rest are still accepted for reads so a rotation
    can be non-disruptive. Returns ``[(key_id, key_bytes), ...]`` or ``[]`` when unset."""
    raw = os.environ.get(JAR_KEY_ENV, "").strip()
    if not raw:
        return []
    keys: list[tuple[str, bytes]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            key = base64.urlsafe_b64decode(part)
        except Exception as exc:
            raise JarError(f"{JAR_KEY_ENV} contains an undecodable key") from exc
        if len(key) != 32:
            raise JarError(f"{JAR_KEY_ENV} keys must be 32 bytes (urlsafe-base64 of AES-256)")
        keys.append((_key_id(key), key))
    return keys


class TombstoneStore:
    """Append-only, HMAC-chained revocation log plus an external high-water anchor.

    The log records ``(jar_id, generation, reason)`` for every revocation; the anchor keeps
    the max tombstoned generation per jar. ``load``/``probe`` consult the anchor and fail
    closed whenever a file's generation is <= the tombstoned generation — so a restored old
    jar file is rejected, closing the rollback.

    The high-water mark is derived by replaying the **HMAC-authenticated** log on each check
    (not from a trusted plaintext file), and re-derived whenever the log changes on disk — so
    another worker/pod's revocation is observed without a restart, and editing a single
    plaintext anchor file cannot lower a revoked generation. Forged log entries (appended
    without ``BROWSER_JAR_KEY``) fail the chain and are ignored.

    ``external_anchor_path`` is an *optional* operator-provided trusted high-water (a KMS/DB/WORM
    export) that can only *raise* the mark, closing the one residual — truncation of the on-disk
    log — that HMAC chaining alone cannot detect. Absent it, protection is against single-file
    tampering and forged appends, not a whole-filesystem restore that also truncates the log."""

    def __init__(self, log_path: Path, external_anchor_path: Path, hmac_key: bytes) -> None:
        self._log_path = log_path
        self._external_anchor_path = external_anchor_path
        self._hmac_key = hmac_key
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_mtime: float | None = None
        self._cache_valid = False

    def _chain_hmac(self, prev: str, payload: str) -> str:
        return hmac.new(self._hmac_key, (prev + "\n" + payload).encode("utf-8"), hashlib.sha256).hexdigest()

    def _payload(self, jar_id: str, generation: int, reason: str) -> str:
        return json.dumps({"jar_id": jar_id, "generation": generation, "reason": reason}, sort_keys=True)

    @staticmethod
    def _fold(anchor: dict[str, dict[str, Any]], jar_id: str, generation: int, reason: str) -> None:
        current = anchor.get(jar_id, {"generation": 0, "reason": reason})
        # A delete is terminal and always wins over an invalidation at the same generation.
        new_reason = "deleted" if reason == "deleted" or current.get("reason") == "deleted" else "invalidated"
        anchor[jar_id] = {"generation": max(generation, current.get("generation", 0)), "reason": new_reason}

    def _rebuild(self) -> dict[str, dict[str, Any]]:
        anchor: dict[str, dict[str, Any]] = {}
        if self._log_path.exists():
            prev = ""
            for line in self._log_path.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    expected = self._chain_hmac(
                        prev, self._payload(record["jar_id"], record["generation"], record["reason"])
                    )
                except Exception:
                    break
                if not hmac.compare_digest(expected, str(record.get("hmac", ""))):
                    # Tampered/forged entry: the verified prefix is authoritative; stop here.
                    break
                prev = record["hmac"]
                self._fold(anchor, record["jar_id"], record["generation"], record["reason"])
        # An optional trusted external anchor may only RAISE the mark (close the truncation gap).
        if self._external_anchor_path.exists():
            try:
                external = json.loads(self._external_anchor_path.read_text())
            except Exception:
                external = {}
            for jar_id, entry in external.items() if isinstance(external, dict) else []:
                self._fold(anchor, jar_id, int(entry.get("generation", 0)), str(entry.get("reason", "invalidated")))
        return anchor

    def _current(self) -> dict[str, dict[str, Any]]:
        try:
            mtime = self._log_path.stat().st_mtime if self._log_path.exists() else None
        except OSError:
            mtime = None
        if not self._cache_valid or mtime != self._cache_mtime:
            self._cache = self._rebuild()
            self._cache_mtime = mtime
            self._cache_valid = True
        return self._cache

    def record(self, jar_id: str, generation: int, reason: str) -> None:
        prev = ""
        if self._log_path.exists():
            for line in reversed(self._log_path.read_text().splitlines()):
                if line.strip():
                    try:
                        prev = json.loads(line)["hmac"]
                    except Exception:
                        prev = ""
                    break
        payload = self._payload(jar_id, generation, reason)
        record = {"jar_id": jar_id, "generation": generation, "reason": reason, "hmac": self._chain_hmac(prev, payload)}
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._log_path.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
        self._cache_valid = False  # force a re-derive from the authenticated log on next check

    def blocked_reason(self, jar_id: str, generation: int) -> str | None:
        """Return why a jar file at ``generation`` is blocked, or None if loadable."""
        entry = self._current().get(jar_id)
        if entry is None:
            return None
        if entry.get("reason") == "deleted":
            return "deleted"
        if generation <= entry.get("generation", 0):
            return "invalidated"
        return None

    def is_deleted(self, jar_id: str) -> bool:
        entry = self._current().get(jar_id)
        return bool(entry and entry.get("reason") == "deleted")


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically (temp file + fsync + rename), mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# Security-critical meta fields bound as AES-GCM AAD (a tamper of any of these without the key
# fails decryption closed).
_AAD_FIELDS = ("jar_id", "origins", "nav_allowlist", "owner_subject", "storage_mode", "generation", "invalidated_at")


def _aad_for(meta: CookieJarMeta, key_id: str) -> bytes:
    payload = {
        "jar_id": meta.jar_id,
        "origins": sorted(meta.origins),
        "nav_allowlist": sorted(meta.nav_allowlist),
        "owner_subject": meta.owner_subject,
        "storage_mode": meta.storage_mode,
        "generation": meta.generation,
        "invalidated_at": meta.invalidated_at.isoformat() if meta.invalidated_at else None,
        "key_id": key_id,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class LoadedJar:
    meta: CookieJarMeta
    storage_state: dict[str, Any]
    probe: JarProbeConfig


class JarStore:
    """Encrypt/decrypt, scope-filter, atomically persist, and revoke cookie jars.

    One file per jar under ``jar_dir`` (``jar_<id>.json``, mode 0600). The tombstone log and
    anchor live in ``jar_dir``'s parent so a rollback of the jar directory alone cannot revive
    a revoked login. Injected into the app like the registry; sessions stay in-memory while
    jars survive restarts."""

    def __init__(
        self,
        jar_dir: str | os.PathLike[str],
        *,
        keys: list[tuple[str, bytes]] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        require_save_authorization: bool = False,
    ) -> None:
        self.jar_dir = Path(jar_dir)
        self._keys = keys if keys is not None else load_jar_keys()
        self.max_bytes = max_bytes
        self.require_save_authorization = require_save_authorization
        anchor_dir = self.jar_dir.parent
        # The tombstone HMAC key is derived from the write key so it needs no separate secret;
        # without the key an attacker cannot forge a consistent chain.
        hmac_key = hashlib.sha256(b"jar-tombstone\x00" + (self._keys[0][1] if self._keys else b"")).digest()
        self._tombstones = TombstoneStore(anchor_dir / "jar-tombstones.jsonl", anchor_dir / "jar-anchor.json", hmac_key)
        self._audit_path = anchor_dir / "jar-audit.jsonl"

    # -- configuration ------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return bool(self._keys)

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise JarDisabledError("cookie jars are disabled: no BROWSER_JAR_KEY configured")

    @property
    def _write_key(self) -> tuple[str, bytes]:
        return self._keys[0]

    def _path(self, jar_id: str) -> Path:
        return self.jar_dir / f"{validate_jar_id(jar_id)}.json"

    # -- crypto -------------------------------------------------------------
    def _encrypt(self, meta: CookieJarMeta, payload: dict[str, Any]) -> dict[str, Any]:
        key_id, key = self._write_key
        nonce = os.urandom(12)  # fresh per write — GCM nonce reuse collapses confidentiality+integrity
        aad = _aad_for(meta, key_id)
        ct = AESGCM(key).encrypt(nonce, json.dumps(payload).encode("utf-8"), aad)
        return {"key_id": key_id, "nonce": _b64e(nonce), "blob": _b64e(ct)}

    def _decrypt(self, meta: CookieJarMeta, record: dict[str, Any]) -> dict[str, Any]:
        record_key_id = record.get("key_id")
        candidates = [(kid, key) for kid, key in self._keys if kid == record_key_id]
        if not candidates:
            raise JarDecryptError(
                "jar was encrypted under a key that is not configured; re-login after key rotation",
                kind="rotation",
            )
        nonce = _b64d(record["nonce"])
        ct = _b64d(record["blob"])
        for kid, key in candidates:
            aad = _aad_for(meta, kid)
            try:
                plaintext = AESGCM(key).decrypt(nonce, ct, aad)
            except InvalidTag:
                continue
            return json.loads(plaintext)
        raise JarDecryptError("jar blob failed authentication (tampered or corrupted)", kind="corruption")

    # -- persistence --------------------------------------------------------
    def _read_record(self, jar_id: str) -> dict[str, Any]:
        path = self._path(jar_id)
        if not path.exists():
            raise JarNotFoundError(jar_id)
        return json.loads(path.read_text())

    def _write_record(self, meta: CookieJarMeta, storage_state: dict[str, Any], probe: JarProbeConfig) -> None:
        payload = {"storage_state": storage_state, "probe": probe.model_dump()}
        sealed = self._encrypt(meta, payload)
        record = {"meta": meta.model_dump(mode="json"), **sealed}
        _atomic_write(self._path(meta.jar_id), json.dumps(record).encode("utf-8"))

    def _meta_from_record(self, record: dict[str, Any]) -> CookieJarMeta:
        return CookieJarMeta.model_validate(record["meta"])

    def get_meta_verified(self, jar_id: str) -> CookieJarMeta:
        """Read a jar's metadata and *verify the AEAD envelope* before trusting it.

        Management ownership decisions must not rest on cleartext ``owner_subject`` alone —
        someone who edits a jar file without the key could rewrite it. Verifying the envelope
        makes that tamper fail closed."""
        self._require_enabled()
        record = self._read_record(jar_id)
        meta = self._meta_from_record(record)
        self._decrypt(meta, record)  # raises on tamper/rotation/corruption
        return meta

    def get_meta_unverified(self, jar_id: str) -> CookieJarMeta:
        self._require_enabled()
        return self._meta_from_record(self._read_record(jar_id))

    def list_meta(self) -> list[CookieJarMeta]:
        """All jar metadata (cleartext). Ownership filtering is applied by the caller."""
        self._require_enabled()
        metas: list[CookieJarMeta] = []
        if not self.jar_dir.exists():
            return metas
        for path in sorted(self.jar_dir.glob("jar_*.json")):
            try:
                metas.append(self._meta_from_record(json.loads(path.read_text())))
            except Exception:
                continue
        return metas

    def verify_owner(self, meta: CookieJarMeta, jar_id: str) -> bool:
        """True iff the jar's AEAD envelope authenticates (so ``owner_subject`` is trustworthy)."""
        try:
            self._decrypt(meta, self._read_record(jar_id))
            return True
        except JarError:
            return False

    # -- probe validation ---------------------------------------------------
    def build_probe(
        self,
        spec_url: str | None,
        logged_in_selector: str | None,
        logged_out_url_prefix: str | None,
        *,
        origins: list[str],
        nav_allowlist: list[str],
        agent_supplied: bool,
    ) -> JarProbeConfig:
        """Validate and redact a probe config.

        - ``url`` is validated against the ``origins + nav_allowlist`` boundary and must be an
          approved stable path (no high-entropy/sensitive segments). An agent save may not
          point the replayed navigation at an arbitrary path — the caller derives a stable
          landing page for the agent path before calling this.
        - ``logged_out_url_prefix`` is a classification pattern and MAY be off-scope (expired
          sessions bounce to an IdP/login origin); query/fragment/userinfo are still stripped.
        - A signal-less probe (no selector, no prefix) is allowed and always reads uncertain."""
        reachable = set()
        for origin in [*origins, *nav_allowlist]:
            norm = normalize_origin(origin)
            if norm:
                reachable.add(norm)

        url = redact_probe_url(spec_url) if spec_url else None
        if url is not None:
            origin = normalize_origin(url)
            if origin not in reachable:
                raise JarValidationError("probe url must be within the jar origins + nav_allowlist")
            from urllib.parse import urlsplit

            if _path_looks_sensitive(urlsplit(url).path):
                raise JarValidationError("probe url path contains a high-entropy or sensitive segment")
            if agent_supplied:
                raise JarValidationError("agent saves may not supply an explicit probe url")

        prefix = redact_probe_url(logged_out_url_prefix) if logged_out_url_prefix else None
        selector = (logged_in_selector or "").strip() or None
        return JarProbeConfig(url=url or "", logged_in_selector=selector, logged_out_url_prefix=prefix)

    # -- save / refresh -----------------------------------------------------
    def save(
        self,
        *,
        jar_id: str | None,
        label: str,
        origins: list[str],
        nav_allowlist: list[str] | None,
        storage_mode: StorageMode | None,
        raw_storage_state: dict[str, Any],
        probe_spec_url: str | None,
        probe_selector: str | None,
        probe_logged_out_prefix: str | None,
        saved_by: str,
        owner_subject: str | None,
        form_factor: str,
        created_session_id: str,
        conversation_id: str,
        agent_supplied_probe: bool,
    ) -> CookieJarMeta:
        self._require_enabled()
        self._enforce_size(raw_storage_state)

        existing: CookieJarMeta | None = None
        if jar_id is not None:
            validate_jar_id(jar_id)
            if self._tombstones.is_deleted(jar_id):
                raise JarRevokedError("this jar_id was deleted and is terminal; create a new jar")
            existing = self.get_meta_verified(jar_id)  # verifies envelope; raises if missing/tampered

        if existing is not None:
            resolved_origins, resolved_allowlist, resolved_storage_mode = self._resolve_refresh_scope(
                existing, origins, nav_allowlist, storage_mode
            )
        else:
            resolved_origins = [o for o in (normalize_origin(x) for x in origins) if o]
            if not resolved_origins:
                raise JarValidationError("a jar must declare at least one origin")
            resolved_allowlist = [o for o in (normalize_origin(x) for x in (nav_allowlist or [])) if o]
            resolved_storage_mode = storage_mode or "all"

        probe = self.build_probe(
            probe_spec_url,
            probe_selector,
            probe_logged_out_prefix,
            origins=resolved_origins,
            nav_allowlist=resolved_allowlist,
            agent_supplied=agent_supplied_probe,
        )

        filtered, stats = filter_storage_state(raw_storage_state, resolved_origins, resolved_storage_mode)

        now = now_utc()
        new_id = jar_id or f"jar_{os.urandom(16).hex()}"
        reg_domains = sorted({d for o in resolved_origins if (d := registrable_domain(o))})
        meta = CookieJarMeta(
            jar_id=new_id,
            label=normalize_label(label),
            origins=resolved_origins,
            nav_allowlist=resolved_allowlist,
            registrable_domains=reg_domains,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            last_loaded_at=existing.last_loaded_at if existing else None,
            version=(existing.version + 1) if existing else 1,
            generation=(existing.generation + 1) if existing else 1,
            saved_by="human" if saved_by == "human" else "agent",
            # Preserve the stored owner on refresh when the caller has no subject (an agent/service
            # refresh of a human-owned jar), so it does not silently become ownerless and vanish
            # from the human's subject-scoped /jars view.
            owner_subject=owner_subject
            if owner_subject is not None
            else (existing.owner_subject if existing else None),
            form_factor=form_factor,
            storage_mode=resolved_storage_mode,
            created_session_id=existing.created_session_id if existing else created_session_id,
            conversation_id=existing.conversation_id if existing else conversation_id,
            cookie_count=stats.cookie_count,
            origin_storage_count=stats.origin_storage_count,
            earliest_cookie_expiry=stats.earliest_cookie_expiry,
            session_cookies_only=stats.session_cookies_only,
            contains_session_cookies=stats.contains_session_cookies,
            has_probe=True,
            # Refresh resets freshness/invalidation so a re-login jar no longer reads stale.
            last_probe_at=None,
            last_probe_result=None,
            invalidated_at=None,
        )
        self._write_record(meta, filtered, probe)
        self._audit("jar_refreshed" if existing else "jar_saved", meta, saved_by)
        return meta

    def _resolve_refresh_scope(
        self,
        existing: CookieJarMeta,
        origins: list[str],
        nav_allowlist: list[str] | None,
        storage_mode: StorageMode | None,
    ) -> tuple[list[str], list[str], StorageMode]:
        """A refresh may only preserve or narrow scope: it re-filters against the *stored* scope,
        may not add allowlist origins, and may not widen ``cookies_only`` back to ``all``."""
        stored_origins = set(existing.origins)
        if origins:
            requested = {o for o in (normalize_origin(x) for x in origins) if o}
            if not requested <= stored_origins:
                raise JarValidationError("refresh cannot widen jar origins; create a new jar")
            resolved_origins = sorted(requested)
        else:
            resolved_origins = list(existing.origins)

        stored_allowlist = set(existing.nav_allowlist)
        if nav_allowlist is None:
            # Omitted => preserve the stored allowlist.
            resolved_allowlist = list(existing.nav_allowlist)
        else:
            # Explicit (including []) => narrow to exactly this subset (an empty list clears it).
            requested_allow = {o for o in (normalize_origin(x) for x in nav_allowlist) if o}
            if not requested_allow <= stored_allowlist:
                raise JarValidationError("refresh cannot widen nav_allowlist; create a new jar")
            resolved_allowlist = sorted(requested_allow)

        if storage_mode is None:
            resolved_mode: StorageMode = existing.storage_mode
        elif existing.storage_mode == "cookies_only" and storage_mode == "all":
            raise JarValidationError("refresh cannot widen storage_mode from cookies_only to all; create a new jar")
        else:
            resolved_mode = storage_mode
        return resolved_origins, resolved_allowlist, resolved_mode

    def _enforce_size(self, raw_storage_state: dict[str, Any]) -> None:
        # Backstop cap; the worker also bounds the export at the source before materialization.
        size = len(json.dumps(raw_storage_state).encode("utf-8"))
        if size > self.max_bytes:
            raise JarValidationError(f"captured storage_state exceeds the {self.max_bytes}-byte limit")

    # -- load ---------------------------------------------------------------
    def load(self, jar_id: str) -> LoadedJar:
        """Decrypt a jar for seeding into a context. Fails closed on invalidation, deletion,
        rollback (generation <= tombstoned), or decrypt failure."""
        self._require_enabled()
        validate_jar_id(jar_id)
        record = self._read_record(jar_id)
        meta = self._meta_from_record(record)
        if meta.invalidated_at is not None:
            raise JarRevokedError("jar is invalidated and cannot be loaded until refreshed")
        blocked = self._tombstones.blocked_reason(jar_id, meta.generation)
        if blocked is not None:
            raise JarRevokedError(f"jar is revoked ({blocked})")
        payload = self._decrypt(meta, record)
        probe = JarProbeConfig.model_validate(payload.get("probe", {"url": ""}))
        return LoadedJar(meta=meta, storage_state=payload.get("storage_state", {}), probe=probe)

    def recheck_loadable(self, jar_id: str) -> bool:
        """Post-registration recheck used to close load/revocation races: re-read the jar and
        confirm it was not revoked in the window between the load and session registration."""
        try:
            meta = self.get_meta_unverified(jar_id)
        except JarError:
            return False
        if meta.invalidated_at is not None:
            return False
        return self._tombstones.blocked_reason(jar_id, meta.generation) is None

    def touch_loaded(self, jar_id: str) -> None:
        try:
            record = self._read_record(jar_id)
        except JarError:
            return
        meta = self._meta_from_record(record)
        meta.last_loaded_at = now_utc()
        payload = self._decrypt(meta, record)
        self._write_record(meta, payload.get("storage_state", {}), JarProbeConfig.model_validate(payload["probe"]))
        self._audit("jar_loaded", meta, "service")

    # -- revocation ---------------------------------------------------------
    def invalidate(self, jar_id: str) -> CookieJarMeta:
        self._require_enabled()
        validate_jar_id(jar_id)
        record = self._read_record(jar_id)
        meta = self._meta_from_record(record)
        # Tombstone FIRST (needs only the cleartext generation), so the kill-switch lands even
        # for a jar whose blob can no longer be decrypted after a key rotation. The tombstone —
        # not the cleartext invalidated_at — is the rollback-proof block on load/probe.
        self._tombstones.record(jar_id, meta.generation, "invalidated")
        # Decrypt with the ORIGINAL metadata first — invalidated_at is AAD-bound, so mutating it
        # before decrypt would change the AAD and make the current-key decrypt fail spuriously.
        try:
            payload = self._decrypt(meta, record)
        except JarDecryptError:
            # Rotated/corrupt key: cannot re-seal, but still persist the cleartext invalidated_at
            # (so listings/UI show "needs re-login") without re-encrypting the undecryptable blob.
            meta.invalidated_at = now_utc()
            meta.updated_at = meta.invalidated_at
            record["meta"] = meta.model_dump(mode="json")
            _atomic_write(self._path(jar_id), json.dumps(record).encode("utf-8"))
            self._audit("jar_invalidated", meta, "service")
            return meta
        # Now set invalidated_at and re-seal so it is bound as AAD (clearing it in cleartext then
        # fails closed).
        meta.invalidated_at = now_utc()
        meta.updated_at = meta.invalidated_at
        self._write_record(meta, payload.get("storage_state", {}), JarProbeConfig.model_validate(payload["probe"]))
        self._audit("jar_invalidated", meta, "service")
        return meta

    def delete(self, jar_id: str) -> CookieJarMeta:
        self._require_enabled()
        validate_jar_id(jar_id)
        record = self._read_record(jar_id)
        meta = self._meta_from_record(record)
        # A delete is terminal: tombstone by reason before destroying the blob so the id can
        # never be recreated, even by a caller that still holds it.
        self._tombstones.record(jar_id, meta.generation, "deleted")
        self._path(jar_id).unlink(missing_ok=True)
        self._audit("jar_deleted", meta, "service")
        return meta

    # -- probe --------------------------------------------------------------
    def probe_allowed_at(self, meta: CookieJarMeta) -> datetime | None:
        """Earliest time the jar may be probed again, or None if allowed now."""
        if meta.last_probe_at is None:
            return None
        next_allowed = meta.last_probe_at + PROBE_MIN_INTERVAL
        return next_allowed if next_allowed > now_utc() else None

    def record_probe(self, jar_id: str, result: ProbeResultName) -> CookieJarMeta:
        record = self._read_record(jar_id)
        meta = self._meta_from_record(record)
        meta.last_probe_at = now_utc()
        meta.last_probe_result = result
        payload = self._decrypt(meta, record)
        self._write_record(meta, payload.get("storage_state", {}), JarProbeConfig.model_validate(payload["probe"]))
        return meta

    # -- audit --------------------------------------------------------------
    def _audit(self, op: str, meta: CookieJarMeta, actor: str) -> None:
        """Durable, structured jar-audit record (non-secret metadata only). Jars outlive the
        in-memory session-event stream, so their audit trail must too."""
        entry = {
            "ts": now_utc().isoformat(),
            "op": op,
            "jar_id": meta.jar_id,
            "origins": meta.origins,
            "actor": actor,
            "generation": meta.generation,
            "version": meta.version,
        }
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError:
            pass


def jar_store_from_env() -> JarStore:
    jar_dir = os.environ.get(JAR_DIR_ENV) or os.path.join(DEFAULT_DATA_DIR, "jars")
    try:
        max_bytes = int(os.environ.get(JAR_MAX_BYTES_ENV, "") or DEFAULT_MAX_BYTES)
    except ValueError:
        max_bytes = DEFAULT_MAX_BYTES
    require_auth = os.environ.get(JAR_SAVE_AUTH_REQUIRED_ENV, "").lower() in ("1", "true", "yes")
    return JarStore(jar_dir, max_bytes=max_bytes, require_save_authorization=require_auth)


__all__ = [
    "JarStore",
    "JarError",
    "JarDisabledError",
    "JarNotFoundError",
    "JarValidationError",
    "JarRevokedError",
    "JarDecryptError",
    "LoadedJar",
    "filter_storage_state",
    "normalize_label",
    "normalize_origin",
    "redact_probe_url",
    "registrable_domain",
    "validate_jar_id",
    "load_jar_keys",
    "jar_store_from_env",
    "JAR_ID_RE",
]
