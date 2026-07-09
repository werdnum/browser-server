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
  key_id, jar_id, generation, invalidated_at, and the freshness fields last_probe_at/
  last_probe_result) is bound as AES-GCM AAD, so tampering with the file without the key fails
  decryption closed.
- Revocation is rollback-proof via a monotonic ``generation`` counter and an append-only,
  HMAC-authenticated tombstone log whose high-water mark is re-derived (verified) on each check.
- Every ``jar_id`` is validated against ``jar_[0-9a-f]{32}`` before it touches the filesystem.

Deployment note: this store is designed to be safe on a **shared filesystem directory** — a
single RWO volume today, or a replicated RWX volume (e.g. Longhorn) shared by multiple pods
tomorrow. Cross-process safety rests only on POSIX file semantics: atomic temp-file+rename
writes, an fsync'd append-only HMAC log re-read fresh per check (close-to-open consistency), and
POSIX advisory locks (``fcntl.lockf``) around tombstone-mutating operations. No database is
introduced, so persisting the (currently in-memory, process-lifetime) session registry onto the
same shared directory is a natural, self-contained follow-up.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import hmac
import json
import logging
import os
import re
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import tldextract
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import CookieJarMeta, JarProbeConfig, ProbeResultName, StorageMode, now_utc

logger = logging.getLogger(__name__)

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _canonical_netloc(scheme: str, host: str, port: int | None) -> str:
    """Host plus port, with the scheme's default port canonicalized away so ``https://h`` and
    ``https://h:443`` compare equal (else confinement/probe treat them as different origins).

    An IPv6 literal host (``::1``) is re-bracketed so the result stays a parseable origin."""
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        return f"{host}:{port}"
    return host


JAR_KEY_ENV = "BROWSER_JAR_KEY"
JAR_DIR_ENV = "BROWSER_JAR_DIR"
JAR_MAX_BYTES_ENV = "BROWSER_JAR_MAX_BYTES"
JAR_SAVE_AUTH_REQUIRED_ENV = "BROWSER_JAR_REQUIRE_SAVE_AUTHORIZATION"
JAR_SESSION_TTL_HOURS_ENV = "BROWSER_JAR_SESSION_TTL_HOURS"

DEFAULT_DATA_DIR = "/var/lib/browser-handoff"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
PROBE_MIN_INTERVAL = timedelta(minutes=15)
# Bounded retention for a jar that captured any browser-session-lifetime cookie (expires == -1):
# a session cookie is meant to die on browser close, so a jar holding one must not stay loadable as
# a replayable credential indefinitely. Keys on contains_session_cookies (not session_cookies_only),
# since the server cannot tell which cookie is auth-bearing. See cookie-jar-design.md ("Retention").
DEFAULT_SESSION_TTL = timedelta(hours=12)
# Probe strings live inside the sealed payload, which is not covered by the raw_storage_state cap,
# so bound them at the edge as well to keep a save from writing an oversized jar file.
PROBE_FIELD_MAX_LEN = 2048
LABEL_MAX_LEN = 80
# Tombstone generation used when a jar's real generation cannot be authenticated (tampered
# metadata): block *every* version of the id fail-closed. Comfortably above any real counter.
_MAX_GENERATION = 2**63 - 1

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
    """Reduce a URL/origin to exact ``scheme://host[:port]`` (no path/query/fragment/userinfo).

    Returns None for anything unparseable — including a malformed port (``host:bad``), whose
    ``.port`` access raises ``ValueError`` — so a bad scope value is rejected as an invalid
    origin rather than bubbling up as a 500."""
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        netloc = _canonical_netloc(parsed.scheme, parsed.hostname.lower(), parsed.port)
    except ValueError:
        return None
    return f"{parsed.scheme}://{netloc}"


def redact_probe_url(value: str) -> str | None:
    """Reconstruct a probe URL from scheme + host + port + path only.

    Query, fragment, and userinfo (``user:pass@``) are all dropped so no probe url becomes a
    back door around the never-store-sensitive-full-URLs guarantee."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        netloc = _canonical_netloc(parsed.scheme, parsed.hostname.lower(), parsed.port)
    except ValueError:
        return None
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

# State-changing endpoints a replayed freshness GET (with the saved login) must never hit — a
# routine probe of /logout would sign the user out; /delete, /revoke, etc. are worse. Matched as
# an exact decoded path segment (so /account/logout-history, a real page, is left alone).
_ACTION_SEGMENTS = frozenset(
    {
        "logout",
        "log-out",
        "signout",
        "sign-out",
        "logoff",
        "log-off",
        "delete",
        "remove",
        "revoke",
        "disconnect",
        "deactivate",
        "unsubscribe",
        "close-account",
        "delete-account",
    }
)


def _split_path_segments(path: str) -> list[str]:
    from urllib.parse import unquote

    # Decode BEFORE splitting so an encoded slash (%2F) cannot bury a sensitive/action subsegment
    # inside one raw segment (e.g. /reset%2Fdeadbeef… must split into "reset" and the token).
    return [seg for seg in unquote(path).split("/") if seg]


def _path_looks_sensitive(path: str) -> bool:
    for segment in _split_path_segments(path):
        if _HEX_SEG_RE.match(segment) or _LONG_DIGIT_RE.match(segment) or len(segment) > 64:
            return True
    return False


def _path_looks_action_like(path: str) -> bool:
    return any(seg.lower() in _ACTION_SEGMENTS for seg in _split_path_segments(path))


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
    """Rollback-proof revocation high-water, kept as TWO authenticated copies:

    1. An append-only, HMAC-chained log of ``(jar_id, generation, reason)`` — the audit trail.
       Replayed and verified on every check; a forged/tampered line fails the chain and is
       skipped, and new entries chain from the last *verified* entry (an injected line cannot
       poison later revocations).
    2. A self-maintained, HMAC-*signed* anchor file (a second authenticated copy of the per-jar
       max). ``load``/``probe`` fold BOTH and block whenever a jar file's generation is <= the
       resulting high-water.

    The two copies close single-file tampering: editing the log alone cannot lower the mark (the
    signed anchor still carries it); editing the anchor alone breaks its HMAC and it is ignored
    (the log covers it). Both are re-read fresh per check (no cache) for NFS close-to-open
    consistency, so another pod's revocation is seen without a restart. Documented residual: a
    whole-filesystem rollback that reverts BOTH the log and the anchor together — that needs the
    anchor on external monotonic/WORM storage, which an operator can mount at
    ``external_anchor_path``."""

    def __init__(self, log_path: Path, external_anchor_path: Path, hmac_keys: list[bytes]) -> None:
        self._log_path = log_path
        self._external_anchor_path = external_anchor_path
        # A list so verification survives BROWSER_JAR_KEY rotation: entries signed with an older
        # key still verify under that key's derived HMAC key. New entries sign with keys[0].
        self._hmac_keys = hmac_keys or [hashlib.sha256(b"jar-tombstone\x00").digest()]

    def _chain_hmac(self, prev: str, payload: str, key: bytes) -> str:
        return hmac.new(key, (prev + "\n" + payload).encode("utf-8"), hashlib.sha256).hexdigest()

    def _verify(self, prev: str, payload: str, mac: str) -> bool:
        return any(hmac.compare_digest(self._chain_hmac(prev, payload, k), mac) for k in self._hmac_keys)

    def _payload(self, jar_id: str, generation: int, reason: str) -> str:
        return json.dumps({"jar_id": jar_id, "generation": generation, "reason": reason}, sort_keys=True)

    @staticmethod
    def _fold(anchor: dict[str, dict[str, Any]], jar_id: str, generation: int, reason: str) -> None:
        current = anchor.get(jar_id, {"generation": 0, "reason": reason})
        # A delete is terminal and always wins over an invalidation at the same generation.
        new_reason = "deleted" if reason == "deleted" or current.get("reason") == "deleted" else "invalidated"
        anchor[jar_id] = {"generation": max(generation, current.get("generation", 0)), "reason": new_reason}

    def _replay_log(self) -> tuple[dict[str, dict[str, Any]], str]:
        """Replay only the append-only log, verifying each line's HMAC against any configured key.
        A forged or malformed line is SKIPPED (not a stop) and does not advance the chain, so a
        legitimate revocation appended after an injected line is still observed — and its ``prev``
        chains from the last *verified* entry. Returns (high-water anchor, last-verified hmac)."""
        anchor: dict[str, dict[str, Any]] = {}
        prev = ""
        if self._log_path.exists():
            for line in self._log_path.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    payload = self._payload(record["jar_id"], record["generation"], record["reason"])
                except Exception:
                    continue
                if not self._verify(prev, payload, str(record.get("hmac", ""))):
                    continue  # forged/tampered line: skip without advancing the verified chain
                prev = record["hmac"]
                self._fold(anchor, record["jar_id"], record["generation"], record["reason"])
        return anchor, prev

    def _anchor_mac(self, jars: dict[str, dict[str, Any]]) -> str:
        canonical = json.dumps(jars, sort_keys=True, separators=(",", ":"))
        return self._chain_hmac("", canonical, self._hmac_keys[0])

    def _read_signed_anchor(self) -> dict[str, dict[str, Any]]:
        """The self-maintained, HMAC-signed high-water anchor. It is a second *authenticated*
        copy of the mark, so tampering the log alone (dropping a revocation line) cannot lower the
        effective high-water — the signed anchor still carries it. A tampered anchor fails its
        HMAC and is ignored (the log then covers it). Defeating both at once requires forging this
        HMAC (needs the key) or deleting the anchor *and* tampering the log — the documented
        whole-filesystem-rollback residual that an external monotonic/WORM anchor closes."""
        if not self._external_anchor_path.exists():
            return {}
        try:
            doc = json.loads(self._external_anchor_path.read_text())
            jars = doc["jars"]
            mac = str(doc["hmac"])
        except Exception:
            return {}
        if not isinstance(jars, dict):
            return {}
        if not any(
            hmac.compare_digest(self._chain_hmac("", json.dumps(jars, sort_keys=True, separators=(",", ":")), k), mac)
            for k in self._hmac_keys
        ):
            return {}
        return jars

    def _replay(self) -> tuple[dict[str, dict[str, Any]], str]:
        anchor, prev = self._replay_log()
        for jar_id, entry in self._read_signed_anchor().items():
            self._fold(anchor, jar_id, int(entry.get("generation", 0)), str(entry.get("reason", "invalidated")))
        return anchor, prev

    def _current(self) -> dict[str, dict[str, Any]]:
        # Re-derive from the on-disk log + signed anchor on every revocation-critical check rather
        # than caching: on a shared (NFS-backed, e.g. Longhorn RWX) volume, opening them fresh
        # gives close-to-open consistency with another pod's just-committed revocation, whereas an
        # mtime/attr cache could keep serving a revoked login for the NFS attribute-cache window.
        # Both are small so a full verified replay is cheap; compaction is a future optimization.
        anchor, _ = self._replay()
        return anchor

    def record(self, jar_id: str, generation: int, reason: str) -> None:
        # Chain from the last *verified* entry, not the last physical line, so an injected line
        # cannot poison the chain for subsequent real revocations.
        _, prev = self._replay_log()
        payload = self._payload(jar_id, generation, reason)
        record = {
            "jar_id": jar_id,
            "generation": generation,
            "reason": reason,
            "hmac": self._chain_hmac(prev, payload, self._hmac_keys[0]),
        }
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        newly_created = not self._log_path.exists()
        with self._log_path.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())  # durable + visible to other pods before the ops lock drops
        if newly_created:
            # Persist the new directory entry too, so a crash right after acknowledging a
            # revocation cannot lose the whole log file from the page cache.
            _fsync_dir(self._log_path.parent)
        # Update the signed high-water anchor (a second authenticated copy of the mark) so a later
        # tamper of the log alone cannot lower the effective high-water below this point.
        combined, _ = self._replay()
        self._fold(combined, jar_id, generation, reason)
        doc = {"jars": combined, "hmac": self._anchor_mac(combined)}
        _atomic_write(self._external_anchor_path, json.dumps(doc).encode("utf-8"))

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

    def high_water(self, jar_id: str) -> int:
        """The highest tombstoned generation for a jar (0 if none). A newly published generation
        must exceed this to be loadable — used so a refresh from a rolled-back file still lands
        above the tombstone rather than re-writing an already-revoked generation."""
        entry = self._current().get(jar_id)
        return int(entry.get("generation", 0)) if entry else 0


def _fsync_dir(directory: Path) -> None:
    """Durably commit a directory entry (a create/rename) so it survives a crash."""
    with contextlib.suppress(OSError):
        dir_fd = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _atomic_write(
    path: Path, data: bytes, mode: int = 0o600, *, before_rename: Callable[[], None] | None = None
) -> None:
    """Write ``data`` to ``path`` atomically (temp file + fsync + rename + dir fsync), mode 0600.

    ``before_rename`` runs after the temp file is durably written but BEFORE it is published over
    ``path``. If it raises, the temp file is discarded and ``path`` is left untouched — used by a
    refresh to durably tombstone the superseded generation between staging and publishing the new
    one, so neither a staging failure nor a tombstone failure can leave the jar bricked or the old
    generation un-revoked."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        if before_rename is not None:
            before_rename()
        os.replace(tmp, path)
        # fsync the directory so the rename (the new/updated entry) is itself durable — else a
        # crash can lose an acknowledged save/refresh even though the temp file was fsync'd.
        _fsync_dir(path.parent)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# Security-critical meta fields bound as AES-GCM AAD (a tamper of any of these without the key
# fails decryption closed). ``label`` is included because it is durable prompt-injection surface
# that must not be rewritable in the file without detection.
_AAD_FIELDS = (
    "jar_id",
    "label",
    "origins",
    "nav_allowlist",
    "owner_subject",
    "storage_mode",
    "generation",
    "invalidated_at",
    # Freshness fields are AAD-bound too: on a shared volume a filesystem writer without the key
    # must not be able to forge a "fresh" result or push last_probe_at into the future to suppress
    # real probes. record_probe re-seals so these stay authenticated.
    "last_probe_at",
    "last_probe_result",
)


def _aad_for(meta: CookieJarMeta, key_id: str) -> bytes:
    payload = {
        "jar_id": meta.jar_id,
        "label": meta.label,
        "origins": sorted(meta.origins),
        "nav_allowlist": sorted(meta.nav_allowlist),
        "owner_subject": meta.owner_subject,
        "storage_mode": meta.storage_mode,
        "generation": meta.generation,
        "invalidated_at": meta.invalidated_at.isoformat() if meta.invalidated_at else None,
        "last_probe_at": meta.last_probe_at.isoformat() if meta.last_probe_at else None,
        "last_probe_result": meta.last_probe_result,
        "key_id": key_id,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class LoadedJar:
    meta: CookieJarMeta
    storage_state: dict[str, Any]
    probe: JarProbeConfig


def _stub_meta(jar_id: str, label: str = "(unreadable jar)") -> CookieJarMeta:
    """Minimal metadata for a jar whose file cannot be parsed — so a service-token kill-switch
    (delete/invalidate) can still return a response and audit the action."""
    now = now_utc()
    return CookieJarMeta(
        jar_id=jar_id,
        label=label,
        origins=[],
        saved_by="agent",
        created_session_id="",
        conversation_id="",
        created_at=now,
        updated_at=now,
        invalidated_at=now,
    )


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
        session_ttl: timedelta = DEFAULT_SESSION_TTL,
    ) -> None:
        self.jar_dir = Path(jar_dir)
        self._keys = keys if keys is not None else load_jar_keys()
        self.max_bytes = max_bytes
        self.require_save_authorization = require_save_authorization
        self.session_ttl = session_ttl
        anchor_dir = self.jar_dir.parent
        # A tombstone HMAC key per configured data key (needs no separate secret; an attacker
        # without any key cannot forge a consistent chain). Passing *all* keys means the log stays
        # verifiable across a BROWSER_JAR_KEY=new,old rotation — entries signed under the old key
        # still verify — while new entries are signed with the current write key (keys[0]).
        hmac_keys = [hashlib.sha256(b"jar-tombstone\x00" + key).digest() for _, key in self._keys]
        self._tombstones = TombstoneStore(
            anchor_dir / "jar-tombstones.jsonl", anchor_dir / "jar-anchor.json", hmac_keys
        )
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

    @contextlib.contextmanager
    def _ops_lock(self) -> Iterator[None]:
        """Serialize tombstone-mutating operations (save/invalidate/delete) *across processes*
        sharing the jar directory. Without it two workers can append tombstones chained from the
        same tail (one silently dropped as forged) or a refresh can publish a higher generation
        over another worker's just-written invalidation.

        Uses POSIX advisory byte-range locks (``fcntl.lockf``/F_SETLKW) rather than BSD ``flock``
        because they are the reliable choice on NFS-backed shared volumes (e.g. a Longhorn RWX
        volume), which is the intended durable-state deployment. *Intra*-process serialization is
        already provided by synchronous execution — every jar_store mutation is a sync call with
        no ``await`` inside, so the event loop cannot interleave two of them — and the lock is
        held only briefly (encrypt + atomic rename)."""
        lock_path = self.jar_dir.parent / "jar-ops.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "w") as handle:
            fcntl.lockf(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.lockf(handle.fileno(), fcntl.LOCK_UN)

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
        # Malformed envelope (missing/undecodable nonce or blob) is a corruption case, not an
        # uncaught 500 — surface it fail-closed like an authentication failure.
        try:
            nonce = _b64d(record["nonce"])
            ct = _b64d(record["blob"])
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            # KeyError (missing field), ValueError/binascii.Error (bad base64), TypeError/
            # AttributeError (non-string field) all mean a malformed envelope — a controlled
            # corruption error, not an uncaught 500.
            raise JarDecryptError("jar envelope is malformed (tampered or corrupted)", kind="corruption") from exc
        for kid, key in candidates:
            aad = _aad_for(meta, kid)
            try:
                plaintext = AESGCM(key).decrypt(nonce, ct, aad)
            except InvalidTag:
                continue
            try:
                return json.loads(plaintext)
            except ValueError as exc:
                raise JarDecryptError("jar plaintext is not valid JSON (corrupted)", kind="corruption") from exc
        raise JarDecryptError("jar blob failed authentication (tampered or corrupted)", kind="corruption")

    # -- persistence --------------------------------------------------------
    def _read_record(self, jar_id: str) -> dict[str, Any]:
        path = self._path(jar_id)
        if not path.exists():
            raise JarNotFoundError(jar_id)
        try:
            record = json.loads(path.read_text())
        except ValueError as exc:
            # Unparseable file (corrupted/tampered): a controlled corruption error, not a 500.
            raise JarDecryptError("jar file is not valid JSON (corrupted)", kind="corruption") from exc
        # The path id must equal the embedded (AEAD-authenticated) meta.jar_id: otherwise a valid
        # file for jar_B copied/restored as jar_A.json would authenticate as jar_B while the
        # tombstone lookup uses jar_A, seeding a revoked login under a fresh id. jar_id is
        # AAD-bound, so an attacker cannot rewrite it to match the path without breaking decrypt.
        meta_obj = record.get("meta") if isinstance(record, dict) else None
        if not isinstance(meta_obj, dict) or meta_obj.get("jar_id") != jar_id:
            raise JarValidationError("jar file id does not match its path")
        return record

    def _write_record(
        self,
        meta: CookieJarMeta,
        storage_state: dict[str, Any],
        probe: JarProbeConfig,
        *,
        before_rename: Callable[[], None] | None = None,
    ) -> None:
        payload = {"storage_state": storage_state, "probe": probe.model_dump()}
        sealed = self._encrypt(meta, payload)
        record = {"meta": meta.model_dump(mode="json"), **sealed}
        _atomic_write(self._path(meta.jar_id), json.dumps(record).encode("utf-8"), before_rename=before_rename)

    def _meta_from_record(self, record: dict[str, Any]) -> CookieJarMeta:
        try:
            meta = CookieJarMeta.model_validate(record["meta"])
        except (KeyError, TypeError, ValueError) as exc:
            # Missing/invalid metadata (pydantic ValidationError subclasses ValueError) is a
            # controlled corruption case, not a 500 — so delete/invalidate can still kill-switch it.
            raise JarDecryptError("jar metadata is malformed (corrupted)", kind="corruption") from exc
        # Re-normalize the label on every read: even a file edited without the key cannot make a
        # listing emit control characters/newlines/over-length markup (defense in depth on top of
        # the AAD binding, which fails the *verified* paths closed on any label tamper).
        meta.label = normalize_label(meta.label)
        return meta

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
        """Metadata for management that does not require the blob to decrypt (so rotated/corrupt
        jars stay manageable). If the envelope does NOT verify, none of the cleartext fields can
        be trusted — a filesystem writer could tamper an AAD-bound origin/status — so a safe
        needs-relogin stub is returned rather than mixing authenticated and unauthenticated
        fields. A verified jar's metadata is returned as-is (all AAD fields are authenticated)."""
        self._require_enabled()
        record = self._read_record(jar_id)
        meta = self._meta_from_record(record)
        try:
            self._decrypt(meta, record)
        except JarError:
            return _stub_meta(jar_id, label="(unverified)")
        return meta

    def list_meta(self) -> list[CookieJarMeta]:
        """All jar metadata (cleartext). Ownership filtering is applied by the caller."""
        self._require_enabled()
        metas: list[CookieJarMeta] = []
        if not self.jar_dir.exists():
            return metas
        for path in sorted(self.jar_dir.glob("jar_*.json")):
            try:
                record = json.loads(path.read_text())
                meta = self._meta_from_record(record)
            except Exception:
                continue
            # A file whose name does not match its authenticated id (a copy/restore under a new
            # name) is not a real jar for this id.
            if path.stem != meta.jar_id:
                continue
            # A restored/rolled-back jar file whose id was deleted (terminal tombstone) must not
            # reappear in listings, even though its blob is back on disk.
            if self._tombstones.is_deleted(meta.jar_id):
                continue
            # Authenticate the envelope: if it does not verify, none of the cleartext fields
            # (origins, invalidated_at, status, label) can be trusted, so return a safe
            # needs-relogin stub rather than surfacing attacker-chosen scope/status/text.
            try:
                self._decrypt(meta, record)
            except JarError:
                metas.append(_stub_meta(meta.jar_id, label="(unverified)"))
                continue
            # A file rolled back behind an invalidation tombstone would otherwise show as usable
            # (often with no cleartext invalidated_at); surface it as needing re-login so a
            # user/agent does not pick a jar that can never load.
            metas.append(self.annotate_revocation(meta))
        return metas

    def annotate_revocation(self, meta: CookieJarMeta) -> CookieJarMeta:
        """If a jar's generation is blocked by the tombstone high-water (e.g. an older file
        restored behind a refresh/invalidation tombstone) but its cleartext ``invalidated_at`` is
        still null, surface it as needing re-login. Shared by ``list_meta`` and the single-jar
        detail read so both agree with what ``load()``/``probe()`` will actually accept."""
        if meta.invalidated_at is None and (
            self._tombstones.blocked_reason(meta.jar_id, meta.generation) or self._session_ttl_expired(meta)
        ):
            meta.invalidated_at = meta.updated_at
        return meta

    def verify_owner(self, meta: CookieJarMeta, jar_id: str) -> bool:
        """True iff the jar's AEAD envelope authenticates and its *authenticated* owner_subject
        matches the passed meta's. Re-derives meta from disk before decrypting, so a display-only
        field that ``list_meta`` mutates on the returned object (e.g. ``invalidated_at`` on a
        rolled-back generation, which is AAD-bound) cannot make verification fail and hide the jar
        from its rightful owner."""
        try:
            record = self._read_record(jar_id)
            disk_meta = self._meta_from_record(record)
            self._decrypt(disk_meta, record)
        except JarError:
            return False
        return disk_meta.owner_subject == meta.owner_subject

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
        if spec_url and url is None:
            # A caller-supplied probe url that fails to normalize (bad port/scheme) must be
            # rejected, not silently downgraded to a target-less (always-"uncertain") probe.
            raise JarValidationError("probe url is malformed")
        if url is not None:
            origin = normalize_origin(url)
            if origin not in reachable:
                raise JarValidationError("probe url must be within the jar origins + nav_allowlist")
            from urllib.parse import urlsplit

            probe_path = urlsplit(url).path
            if _path_looks_sensitive(probe_path):
                raise JarValidationError("probe url path contains a high-entropy or sensitive segment")
            if _path_looks_action_like(probe_path):
                raise JarValidationError("probe url path looks like a state-changing action (e.g. logout)")
            if agent_supplied:
                raise JarValidationError("agent saves may not supply an explicit probe url")

        prefix = redact_probe_url(logged_out_url_prefix) if logged_out_url_prefix else None
        if logged_out_url_prefix and prefix is None:
            # A non-empty prefix that fails to normalize (bad port/scheme) must be rejected, not
            # silently dropped — that would disable the logged-out-redirect signal and let an
            # otherwise-stale jar read "uncertain"/selector-only instead of failing the save.
            raise JarValidationError("probe logged_out_url_prefix is malformed")
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
        # Hold the cross-process ops lock across the whole read-existing -> tombstone-old ->
        # write-new sequence so a refresh cannot interleave with another worker's invalidate.
        with self._ops_lock():
            return self._save_locked(
                jar_id=jar_id,
                label=label,
                origins=origins,
                nav_allowlist=nav_allowlist,
                storage_mode=storage_mode,
                raw_storage_state=raw_storage_state,
                probe_spec_url=probe_spec_url,
                probe_selector=probe_selector,
                probe_logged_out_prefix=probe_logged_out_prefix,
                saved_by=saved_by,
                owner_subject=owner_subject,
                form_factor=form_factor,
                created_session_id=created_session_id,
                conversation_id=conversation_id,
                agent_supplied_probe=agent_supplied_probe,
            )

    def _save_locked(
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

        # The size cap counts the STORED payload (filtered storage + probe), not just the raw export:
        # probe strings live inside the sealed blob and are bounded at the model edge too, but a
        # combined check keeps a large selector/prefix from writing a jar past the configured cap.
        payload_bytes = len(json.dumps({"storage_state": filtered, "probe": probe.model_dump()}).encode("utf-8"))
        if payload_bytes > self.max_bytes:
            raise JarValidationError(f"sealed jar payload exceeds the {self.max_bytes}-byte limit")

        now = now_utc()
        new_id = jar_id or f"jar_{os.urandom(16).hex()}"
        reg_domains = sorted({d for o in resolved_origins if (d := registrable_domain(o))})
        # A refresh must publish a generation ABOVE the tombstone high-water, not merely
        # existing.generation + 1: if the on-disk file rolled back behind the log (gen1 restored
        # after gen2 was invalidated), a naive +1 would re-write an already-tombstoned generation
        # and the "successful" refresh would still be unloadable.
        new_generation = (max(existing.generation, self._tombstones.high_water(new_id)) + 1) if existing else 1
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
            generation=new_generation,
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
        if existing is not None:
            # Stage the replacement, durably tombstone the superseded generation, THEN publish (the
            # tombstone runs in _atomic_write's before_rename hook, between the fsync'd temp write
            # and the rename). This handles both partial-failure directions: a staging failure
            # tombstones nothing (prior jar intact), and a tombstone failure discards the staged
            # file (prior jar intact, no rollback bypass). Only once the old generation is durably
            # revoked does the new generation become reachable.
            old_generation = existing.generation
            self._write_record(
                meta,
                filtered,
                probe,
                before_rename=lambda: self._tombstones.record(meta.jar_id, old_generation, "invalidated"),
            )
        else:
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
            if not requested:
                # A non-empty request that all fails normalization (e.g. a typo'd port) must not
                # silently wipe the jar's scope down to no origins.
                raise JarValidationError("refresh origins contained no valid origin")
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
            if nav_allowlist and not requested_allow:
                # A non-empty request that all fails normalization (e.g. a typo'd port) must not
                # be read as an intentional clear that silently drops the stored allowlist.
                raise JarValidationError("refresh nav_allowlist contained no valid origin")
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
        if self._session_ttl_expired(meta):
            raise JarRevokedError("jar with a session cookie exceeded its bounded retention; re-login required")
        payload = self._decrypt(meta, record)
        probe = JarProbeConfig.model_validate(payload.get("probe", {"url": ""}))
        return LoadedJar(meta=meta, storage_state=payload.get("storage_state", {}), probe=probe)

    def is_revoked_generation(self, jar_id: str, generation: int | None) -> bool:
        """Whether a SPECIFIC (authenticated) generation of a jar is revoked. Used for live-session
        kill-switch checks against the generation actually seeded into the running context, so a
        later higher-generation re-login cannot mask that the running context's generation was
        tombstoned. Consults only the authenticated tombstone (no cleartext file trust)."""
        if self._tombstones.is_deleted(jar_id):
            return True
        gen = generation if generation is not None else 0
        return self._tombstones.blocked_reason(jar_id, gen) is not None

    def recheck_loadable(self, jar_id: str) -> bool:
        """Whether a jar is currently loadable — used both for the post-registration load race
        and for live-session revocation rechecks. Verifies the AEAD envelope so a file edited
        without the key (cleartext ``invalidated_at`` cleared or ``generation`` raised above the
        tombstone) cannot keep a live authenticated session running past the kill-switch."""
        try:
            meta = self.get_meta_verified(jar_id)  # authenticates generation + invalidated_at
        except JarError:
            return False  # missing/tampered/rotated/corrupt => treat as revoked, fail closed
        if meta.invalidated_at is not None:
            return False
        if self._session_ttl_expired(meta):
            return False
        return self._tombstones.blocked_reason(jar_id, meta.generation) is None

    def _session_ttl_expired(self, meta: CookieJarMeta) -> bool:
        """A jar that captured a browser-session cookie is loadable only within a bounded window of
        its last save (updated_at); after that a browser-close login must not remain replayable.
        Persistent-cookie-only jars have no such cap (their staleness surfaces via probing)."""
        if not meta.contains_session_cookies:
            return False
        return now_utc() - meta.updated_at > self.session_ttl

    def touch_loaded(self, jar_id: str) -> None:
        with self._ops_lock():
            try:
                record = self._read_record(jar_id)
            except JarError:
                return
            meta = self._meta_from_record(record)
            meta.last_loaded_at = now_utc()
            # last_loaded_at is not AAD-bound, so patch the cleartext meta and keep the existing
            # sealed blob (no decrypt/re-encrypt). Re-reading under the ops lock means a concurrent
            # refresh's higher-generation blob is never clobbered by a stale-generation rewrite.
            record["meta"] = meta.model_dump(mode="json")
            _atomic_write(self._path(jar_id), json.dumps(record).encode("utf-8"))
            self._audit("jar_loaded", meta, "service")

    # -- revocation ---------------------------------------------------------
    def invalidate(self, jar_id: str, *, actor: str = "service") -> CookieJarMeta:
        self._require_enabled()
        validate_jar_id(jar_id)
        with self._ops_lock():
            return self._invalidate_locked(jar_id, actor)

    def _invalidate_locked(self, jar_id: str, actor: str) -> CookieJarMeta:
        try:
            record = self._read_record(jar_id)
            meta = self._meta_from_record(record)
        except JarNotFoundError:
            raise
        except JarError:
            # Corrupt/unparseable/id-mismatched/invalid-metadata file: honor the kill-switch
            # anyway. The generation is unknowable, so block every version fail-closed (the file
            # stays but is unloadable).
            self._tombstones.record(jar_id, _MAX_GENERATION, "invalidated")
            stub = _stub_meta(jar_id)
            self._audit("jar_invalidated", stub, actor)
            return stub
        # Authenticate the generation BEFORE recording the tombstone: `generation` is AAD-bound,
        # so a successful decrypt proves the cleartext generation is genuine. Tombstoning a
        # tampered (lowered) generation would let a restored original file with the real, higher
        # generation slip past blocked_reason and load a supposedly-revoked login.
        try:
            payload = self._decrypt(meta, record)
        except JarDecryptError:
            # The generation cannot be authenticated — whether the blob was tampered (corruption)
            # or the cleartext key_id was edited to an unconfigured value (rotation) — so block
            # EVERY version of this id fail-closed rather than trust a possibly-lowered cleartext
            # generation. A genuinely rotated jar is un-refreshable anyway (get_meta_verified fails
            # on refresh), so this loses nothing; delete still works, and re-login uses a new id.
            self._tombstones.record(jar_id, _MAX_GENERATION, "invalidated")
            meta.invalidated_at = now_utc()
            meta.updated_at = meta.invalidated_at
            record["meta"] = meta.model_dump(mode="json")
            _atomic_write(self._path(jar_id), json.dumps(record).encode("utf-8"))
            self._audit("jar_invalidated", meta, actor)
            return meta
        # Decryptable: the generation is authenticated. Tombstone it, then re-seal with
        # invalidated_at bound as AAD (so clearing it in cleartext later fails closed).
        self._tombstones.record(jar_id, meta.generation, "invalidated")
        meta.invalidated_at = now_utc()
        meta.updated_at = meta.invalidated_at
        self._write_record(meta, payload.get("storage_state", {}), JarProbeConfig.model_validate(payload["probe"]))
        self._audit("jar_invalidated", meta, actor)
        return meta

    def delete(self, jar_id: str, *, actor: str = "service") -> CookieJarMeta:
        self._require_enabled()
        validate_jar_id(jar_id)
        with self._ops_lock():
            try:
                meta = self._meta_from_record(self._read_record(jar_id))
            except JarNotFoundError:
                raise
            except JarError:
                # Corrupt/unparseable/id-mismatched file: still honor the kill-switch. A delete is
                # terminal regardless of generation, so tombstone at the max generation and unlink.
                self._tombstones.record(jar_id, _MAX_GENERATION, "deleted")
                self._unlink_durably(jar_id)
                stub = _stub_meta(jar_id)
                self._audit("jar_deleted", stub, actor)
                return stub
            # A delete is terminal: tombstone by reason before destroying the blob so the id can
            # never be recreated, even by a caller that still holds it.
            self._tombstones.record(jar_id, meta.generation, "deleted")
            self._unlink_durably(jar_id)
            self._audit("jar_deleted", meta, actor)
            return meta

    def _unlink_durably(self, jar_id: str) -> None:
        """Remove the jar blob and fsync the directory so the removal survives a crash — otherwise
        the encrypted credential file can reappear on disk after a DELETE the API already acked."""
        path = self._path(jar_id)
        path.unlink(missing_ok=True)
        _fsync_dir(path.parent)

    # -- probe --------------------------------------------------------------
    def probe_allowed_at(self, meta: CookieJarMeta) -> datetime | None:
        """Earliest time the jar may be probed again, or None if allowed now."""
        if meta.last_probe_at is None:
            return None
        next_allowed = meta.last_probe_at + PROBE_MIN_INTERVAL
        return next_allowed if next_allowed > now_utc() else None

    def record_probe(self, jar_id: str, result: ProbeResultName) -> CookieJarMeta:
        with self._ops_lock():
            record = self._read_record(jar_id)
            meta = self._meta_from_record(record)
            try:
                payload = self._decrypt(meta, record)
            except JarError:
                # The jar no longer authenticates (rotated key / tampered file): do not touch the
                # freshness fields — there is nothing safe to re-seal them against.
                return meta
            meta.last_probe_at = now_utc()
            meta.last_probe_result = result
            # last_probe_* are AAD-bound, so re-seal the whole record (fresh nonce) rather than
            # patch cleartext: a filesystem writer without the key then cannot forge a "fresh"
            # result or a future last_probe_at. Re-reading + re-decrypting under the ops lock means
            # a probe that finished after a concurrent refresh re-seals the refreshed payload, not
            # a stale one.
            self._write_record(
                meta,
                payload.get("storage_state", {}),
                JarProbeConfig.model_validate(payload.get("probe", {"url": ""})),
            )
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
            newly_created = not self._audit_path.exists()
            with self._audit_path.open("a") as handle:
                handle.write(json.dumps(entry) + "\n")
                handle.flush()
                os.fsync(handle.fileno())  # durable: the credential audit trail must survive a crash
            if newly_created:
                _fsync_dir(self._audit_path.parent)
        except OSError:
            # A failed audit write must not defeat a kill-switch (availability of revocation beats
            # the audit record), but it is a real operational problem — surface it, don't swallow.
            logger.warning("failed to append jar-audit record for %s (%s)", meta.jar_id, op, exc_info=True)


def jar_store_from_env() -> JarStore:
    jar_dir = os.environ.get(JAR_DIR_ENV) or os.path.join(DEFAULT_DATA_DIR, "jars")
    try:
        max_bytes = int(os.environ.get(JAR_MAX_BYTES_ENV, "") or DEFAULT_MAX_BYTES)
    except ValueError:
        max_bytes = DEFAULT_MAX_BYTES
    require_auth = os.environ.get(JAR_SAVE_AUTH_REQUIRED_ENV, "").lower() in ("1", "true", "yes")
    try:
        ttl_hours = float(os.environ.get(JAR_SESSION_TTL_HOURS_ENV, "") or "")
        session_ttl = timedelta(hours=ttl_hours) if ttl_hours > 0 else DEFAULT_SESSION_TTL
    except ValueError:
        session_ttl = DEFAULT_SESSION_TTL
    return JarStore(jar_dir, max_bytes=max_bytes, require_save_authorization=require_auth, session_ttl=session_ttl)


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
