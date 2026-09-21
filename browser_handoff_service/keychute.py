"""Keychute client: request a release, wait for the decision, read the plaintext once.

browser-server is registered with Keychute as a ``trusted-client`` for the ``autofill``
mechanism, so it receives credential bytes directly. Everything in this module is built around
that: the plaintext exists as a ``bytearray`` the caller zeroes, and nothing derived from a
response body ever reaches a log message or an exception string. Errors are built from Keychute's
own non-secret ``{"error": {"code", "message"}}`` envelope and from status codes.

Configuration is read lazily from the environment per call, like the other ``BROWSER_*`` settings,
so an operator can roll the token file without restarting the service:

``BROWSER_KEYCHUTE_URL``           the in-cluster origin (no path), e.g. ``https://keychute.svc``
``BROWSER_KEYCHUTE_TOKEN_FILE``    bearer token file, re-read per request
``BROWSER_KEYCHUTE_TOKEN``         bearer token inline (takes precedence)
``BROWSER_KEYCHUTE_CA_BUNDLE``     PEM path for the internal CA
``BROWSER_KEYCHUTE_EXTERNAL_URL``  externally reachable base for approval links (optional)

Unconfigured is not an error here: ``configured`` is false and the caller refuses the operation.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import ssl
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

KEYCHUTE_URL_ENV = "BROWSER_KEYCHUTE_URL"
KEYCHUTE_TOKEN_ENV = "BROWSER_KEYCHUTE_TOKEN"
KEYCHUTE_TOKEN_FILE_ENV = "BROWSER_KEYCHUTE_TOKEN_FILE"
KEYCHUTE_CA_BUNDLE_ENV = "BROWSER_KEYCHUTE_CA_BUNDLE"
KEYCHUTE_EXTERNAL_URL_ENV = "BROWSER_KEYCHUTE_EXTERNAL_URL"

# Keychute's own bounds: a status body is small and a secret is not a file store.
_STATUS_LIMIT = 64 * 1024
_SECRET_LIMIT = 64 * 1024
# Keychute caps /wait server-side at 300s; the autofill endpoint asks for far less.
_MAX_WAIT_SECONDS = 300
_HTTP_SLACK_SECONDS = 15
_CALL_TIMEOUT_SECONDS = 30.0

RequestStateName = Literal["pending", "approved", "denied", "expired"]
_REQUEST_STATES: frozenset[str] = frozenset({"pending", "approved", "denied", "expired"})


class KeychuteNotConfigured(RuntimeError):
    """No Keychute endpoint/credentials configured; autofill is unavailable."""


class KeychuteError(RuntimeError):
    """A Keychute call failed. The message never contains credential material."""


@dataclass(frozen=True)
class AccessRequestStatus:
    request_id: str
    state: RequestStateName
    grant_id: str | None = None
    deny_reason: str | None = None


@dataclass(frozen=True)
class GrantOrigin:
    host: str
    port: int | None = None

    def effective_port(self) -> int:
        return self.port if self.port is not None else 443

    def matches(self, host: str, port: int | None) -> bool:
        """Same target iff host and *effective* port agree — Keychute's own rule."""
        return self.host == host.lower() and self.effective_port() == (port if port is not None else 443)


@dataclass(frozen=True)
class GrantInfo:
    grant_id: str
    mechanism: str
    origins: tuple[GrantOrigin, ...]
    not_after: datetime
    revoked: bool
    use_count: int
    max_uses: int | None
    # Keychute's clock, which ``not_after`` is judged against. Expiry is decided here against
    # this and never against the local clock: a host running minutes fast would otherwise call a
    # freshly approved grant expired.
    server_time: datetime | None


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise KeychuteError(f"Keychute returned no {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise KeychuteError(f"Keychute returned a malformed {field}") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _api_error(response: httpx.Response, body: bytes, operation: str) -> KeychuteError:
    """Build a secret-free error from Keychute's standard envelope."""
    detail = ""
    try:
        decoded = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = None
    error = decoded.get("error") if isinstance(decoded, dict) else None
    if isinstance(error, dict):
        code, message = error.get("code"), error.get("message")
        if isinstance(code, str) and isinstance(message, str):
            detail = f": {message} ({code})"
    return KeychuteError(f"Keychute {operation} failed with HTTP {response.status_code}{detail}")


def _parse_status(body: bytes) -> AccessRequestStatus:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeychuteError("Keychute returned malformed request status JSON") from exc
    if not isinstance(value, dict):
        raise KeychuteError("Keychute returned malformed request status")
    request_id, state = value.get("request_id"), value.get("state")
    grant_id, deny_reason = value.get("grant_id"), value.get("deny_reason")
    if not isinstance(request_id, str) or state not in _REQUEST_STATES:
        raise KeychuteError("Keychute returned malformed request status")
    for candidate in (request_id, grant_id):
        if candidate is None:
            continue
        if not isinstance(candidate, str):
            raise KeychuteError("Keychute returned a malformed id")
        try:
            uuid.UUID(candidate)
        except ValueError as exc:
            raise KeychuteError("Keychute returned a malformed id") from exc
    if deny_reason is not None and not isinstance(deny_reason, str):
        raise KeychuteError("Keychute returned a malformed denial reason")
    return AccessRequestStatus(
        request_id=request_id,
        state=state,
        grant_id=grant_id,
        deny_reason=deny_reason,
    )


class KeychuteClient:
    """One client for the whole service; configuration is resolved per call.

    ``transport`` exists so tests can drive the full protocol against a fake server without a
    network or a parallel implementation of the flow.
    """

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    # -- configuration ----------------------------------------------------

    @property
    def configured(self) -> bool:
        try:
            self._base_url()
        except KeychuteNotConfigured:
            return False
        return bool(os.environ.get(KEYCHUTE_TOKEN_ENV) or os.environ.get(KEYCHUTE_TOKEN_FILE_ENV))

    def approval_url(self, request_id: str) -> str | None:
        """Where a human goes to decide, when the operator configured an external base."""
        raw = os.environ.get(KEYCHUTE_EXTERNAL_URL_ENV, "").strip().rstrip("/")
        return f"{raw}/requests/{request_id}" if raw else None

    def _base_url(self) -> str:
        raw = os.environ.get(KEYCHUTE_URL_ENV, "").strip()
        if not raw:
            raise KeychuteNotConfigured(f"{KEYCHUTE_URL_ENV} is not set")
        url = raw.rstrip("/")
        try:
            parsed = urlsplit(url)
            _ = parsed.port
        except ValueError as exc:
            raise KeychuteNotConfigured(f"{KEYCHUTE_URL_ENV} is not a valid URL") from exc
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise KeychuteNotConfigured(f"{KEYCHUTE_URL_ENV} must be an http(s) origin")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise KeychuteNotConfigured(f"{KEYCHUTE_URL_ENV} must be an origin without a path")
        return url

    async def _bearer(self) -> str:
        token = os.environ.get(KEYCHUTE_TOKEN_ENV, "").strip()
        if token:
            return token
        token_file = os.environ.get(KEYCHUTE_TOKEN_FILE_ENV, "").strip()
        if not token_file:
            raise KeychuteNotConfigured("no Keychute token or token file configured")
        try:
            # Re-read per request so a rolled token takes effect without a restart.
            raw = await asyncio.to_thread(Path(token_file).read_text, encoding="utf-8")
        except OSError as exc:
            raise KeychuteError("cannot read the configured Keychute token file") from exc
        token = raw.strip()
        if not token:
            raise KeychuteError("the configured Keychute token file is empty")
        return token

    def _ssl_context(self) -> ssl.SSLContext:
        ca_bundle = os.environ.get(KEYCHUTE_CA_BUNDLE_ENV, "").strip() or None
        try:
            return ssl.create_default_context(cafile=ca_bundle)
        except OSError as exc:
            raise KeychuteError("cannot load the configured Keychute CA bundle") from exc

    # -- transport --------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        if self._transport is not None:
            return httpx.AsyncClient(transport=self._transport, follow_redirects=False)
        return httpx.AsyncClient(verify=self._ssl_context(), follow_redirects=False)

    async def _call(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        timeout: float,  # noqa: ASYNC109 - httpx owns the deadline; it is not a cancellation scope
        limit: int = _STATUS_LIMIT,
    ) -> tuple[httpx.Response, bytes]:
        headers = {"Authorization": f"Bearer {await self._bearer()}"}
        base = self._base_url()
        try:
            async with self._client() as client:
                async with client.stream(
                    method, f"{base}{path}", headers=headers, json=json_body, timeout=timeout
                ) as response:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > limit:
                            raise KeychuteError(f"Keychute response exceeded the {limit}-byte limit")
                    return response, bytes(body)
        except httpx.HTTPError as exc:
            # Deliberately not str(exc): a transport error can carry the request URL, and the URL
            # is the one place a caller could later be tempted to put anything sensitive.
            raise KeychuteError(f"Keychute request to {path.split('?')[0]} failed") from exc

    # -- operations -------------------------------------------------------

    async def create_access_request(
        self,
        *,
        idempotency_key: str,
        secret_name: str,
        origin_host: str,
        origin_port: int | None,
        ttl_seconds: int,
        reason: str,
        structured: dict[str, Any] | None = None,
    ) -> AccessRequestStatus:
        """Create (or replay) the access request for one fill step.

        Idempotent by ``idempotency_key``: an ``approval_pending`` retry of the same step reaches
        the same request rather than opening a second one. Empty ``methods``/``path_prefixes`` are
        load-bearing — a standing policy row matches only when the request is a subset in every
        dimension, and an empty list subsets only an empty list.
        """
        origin: dict[str, Any] = {"host": origin_host}
        if origin_port is not None:
            origin["port"] = origin_port
        body: dict[str, Any] = {
            "idempotency_key": idempotency_key,
            "secret_name": secret_name,
            "mechanism": "autofill",
            "constraints": {
                "origins": [origin],
                "methods": [],
                "path_prefixes": [],
                "ttl_seconds": ttl_seconds,
                "max_uses": 1,
            },
            "context": {"reason": reason, "structured": structured or {}},
        }
        response, raw = await self._call("POST", "/v1/access-requests", json_body=body, timeout=_CALL_TIMEOUT_SECONDS)
        if not response.is_success:
            raise _api_error(response, raw, "access request")
        return _parse_status(raw)

    async def wait(self, request_id: str, timeout_seconds: int) -> AccessRequestStatus:
        """Long-poll one decision. Returns whatever state is current when the poll ends."""
        poll = max(1, min(timeout_seconds, _MAX_WAIT_SECONDS))
        response, raw = await self._call(
            "GET",
            f"/v1/access-requests/{request_id}/wait?timeout_seconds={poll}",
            timeout=poll + _HTTP_SLACK_SECONDS,
        )
        if not response.is_success:
            raise _api_error(response, raw, "approval wait")
        return _parse_status(raw)

    async def grant_info(self, grant_id: str) -> GrantInfo:
        """The grant as APPROVED — an operator may have narrowed what was asked for."""
        response, raw = await self._call("GET", f"/v1/grants/{grant_id}", timeout=_CALL_TIMEOUT_SECONDS)
        if not response.is_success:
            raise _api_error(response, raw, "grant lookup")
        try:
            value = json.loads(raw)
            constraints = value["constraints"]
            raw_origins = constraints["origins"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise KeychuteError("Keychute returned malformed grant metadata") from exc
        if not isinstance(value, dict) or not isinstance(raw_origins, list):
            raise KeychuteError("Keychute returned malformed grant metadata")
        origins: list[GrantOrigin] = []
        for entry in raw_origins:
            if not isinstance(entry, dict) or not isinstance(entry.get("host"), str):
                raise KeychuteError("Keychute returned a malformed grant origin")
            port = entry.get("port")
            if port is not None and not isinstance(port, int):
                raise KeychuteError("Keychute returned a malformed grant origin")
            origins.append(GrantOrigin(host=str(entry["host"]).lower(), port=port))
        mechanism = value.get("mechanism")
        if not isinstance(mechanism, str):
            raise KeychuteError("Keychute returned a malformed grant mechanism")
        server_time = value.get("server_time")
        return GrantInfo(
            grant_id=str(value.get("grant_id") or grant_id),
            mechanism=mechanism,
            origins=tuple(origins),
            not_after=_parse_time(value.get("not_after"), "grant expiry"),
            revoked=bool(value.get("revoked", True)),
            use_count=int(value.get("use_count") or 0),
            max_uses=value.get("max_uses") if isinstance(value.get("max_uses"), int) else None,
            server_time=_parse_time(server_time, "server time") if server_time is not None else None,
        )

    async def read_grant(self, grant_id: str, idempotency_key: str) -> bytearray:
        """Exercise a grant's single read.

        Returns a mutable buffer so the caller can zero it: the plaintext must not outlive the
        fill. A different idempotency key is a second logical read and Keychute refuses it, which
        is what keeps one grant to one fill.
        """
        response, raw = await self._call(
            "POST",
            f"/v1/grants/{grant_id}/read",
            json_body={"idempotency_key": idempotency_key},
            timeout=_CALL_TIMEOUT_SECONDS,
            limit=_SECRET_LIMIT,
        )
        if not response.is_success:
            raise _api_error(response, raw, "grant read")
        try:
            value = json.loads(raw)
            secret = value["secret"]
            encoding = value.get("encoding", "utf8")
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise KeychuteError("Keychute returned a malformed grant read") from exc
        if not isinstance(secret, str) or encoding not in ("utf8", "base64"):
            raise KeychuteError("Keychute returned a malformed grant read")
        if encoding == "base64":
            try:
                return bytearray(base64.b64decode(secret, validate=True))
            except (ValueError, TypeError) as exc:
                raise KeychuteError("Keychute returned an undecodable secret payload") from exc
        return bytearray(secret.encode("utf-8"))


def zero(buffer: bytearray) -> None:
    """Overwrite a secret buffer in place. Best effort — Python strings derived from it cannot
    be wiped, which is why the plaintext is only ever decoded at the point of the fill."""
    for index in range(len(buffer)):
        buffer[index] = 0
