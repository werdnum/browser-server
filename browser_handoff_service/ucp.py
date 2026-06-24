from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

# Universal Commerce Protocol (UCP) merchant discovery.
#
# A UCP merchant advertises its shopping capabilities and MCP endpoints from a
# well-known profile document. The browser worker probes this document for the
# origin it is currently on and, when a merchant advertises shopping support,
# attaches a hint to the accessibility ``snapshot`` so the driving agent can pick
# UCP shopping tools without merchant-specific endpoints being hardcoded.
#
# The probe is a read-only HTTPS GET to a fixed path; its response never reaches
# the page and we never POST to discovered endpoints from here, so there is no
# SSRF surface to defend (no plaintext targets, no state change, no readback).

UCP_WELL_KNOWN_PATH = "/.well-known/ucp"

# Canonical UCP shopping service identifier and its capability namespace.
SHOPPING_SERVICE = "dev.ucp.shopping"
_SHOPPING_CAPABILITY_PREFIX = f"{SHOPPING_SERVICE}."

# A capability suffix surfaced to the agent must be a short, safe token: the
# profile is merchant-controlled, so this prevents newlines or prose from being
# injected into the agent-facing hint.
_CAPABILITY_SUFFIX_RE = re.compile(r"^[a-z0-9_.-]{1,40}$")

# Compact caps on the merchant-controlled arrays that reach the agent (rendered
# hint, structured snapshot fields, and session event metadata), so a hostile or
# misconfigured profile cannot bloat an API response or in-memory event record.
_MAX_SHOPPING_CAPABILITIES = 12
_MAX_SHOPPING_ENDPOINTS = 8

# ``fetch(url) -> parsed JSON | None``: returns the decoded JSON body of a 2xx
# response, or ``None`` for any failure (network error, non-2xx, invalid JSON).
UCPFetch = Callable[[str], Awaitable[Any]]

_UNSET = object()


def merchant_origin(url: str | None) -> str | None:
    """Return the HTTPS origin (``scheme://netloc``) for ``url``, else ``None``.

    Only HTTPS origins are eligible for discovery: a UCP probe (and anything a
    caller might build on it) must never traverse plaintext.
    """
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname:
        return None
    return f"{parts.scheme}://{parts.netloc}"


@dataclass(frozen=True)
class ShoppingEndpoint:
    """A shopping service endpoint and the transport an agent reaches it over."""

    transport: str
    url: str


@dataclass(frozen=True)
class MerchantUCPProfile:
    """A merchant's discovered UCP profile for a single origin."""

    origin: str
    endpoints: tuple[ShoppingEndpoint, ...] = ()
    service_names: tuple[str, ...] = ()
    capability_names: tuple[str, ...] = ()
    version: str | None = None

    @property
    def supports_shopping(self) -> bool:
        return bool(self.endpoints)

    def shopping_capabilities(self) -> tuple[str, ...]:
        """Sanitized, deduplicated shopping capability suffixes (e.g. ``cart``).

        Only suffixes under the ``dev.ucp.shopping.`` namespace that match the
        safe-token shape are returned, so a merchant cannot smuggle prose into
        anything rendered for the agent.
        """
        suffixes: list[str] = []
        for capability in self.capability_names:
            if not capability.startswith(_SHOPPING_CAPABILITY_PREFIX):
                continue
            suffix = capability[len(_SHOPPING_CAPABILITY_PREFIX) :]
            if _CAPABILITY_SUFFIX_RE.match(suffix) and suffix not in suffixes:
                suffixes.append(suffix)
        return tuple(suffixes)


def _is_shopping_service(namespace: str) -> bool:
    return namespace == SHOPPING_SERVICE or namespace.startswith(_SHOPPING_CAPABILITY_PREFIX)


def _resolve_endpoint(origin: str, raw_endpoint: str) -> str | None:
    """Resolve a (possibly relative) endpoint against ``origin``, keeping only HTTPS.

    Relative paths like ``/api/ucp/mcp`` resolve against the origin; absolute
    URLs are accepted as-is. Non-HTTPS or host-less results are rejected, as is a
    merchant-controlled value malformed enough to make ``urlsplit`` raise (e.g.
    ``https://[::1``) — discovery must never bubble a parse error to the caller.
    """
    try:
        resolved = urljoin(f"{origin}/", raw_endpoint)
        parts = urlsplit(resolved)
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname:
        return None
    return resolved


def parse_merchant_profile(origin: str, payload: Any) -> MerchantUCPProfile | None:
    """Parse a ``/.well-known/ucp`` document into a :class:`MerchantUCPProfile`.

    Follows the UCP profile envelope (https://ucp.dev/documentation/core-concepts/):
    discovery data lives under a top-level ``ucp`` object, whose ``services`` and
    ``capabilities`` are objects keyed by namespace (each value a list of versioned
    declarations). An unwrapped document is tolerated as a fallback.

    Tolerates malformed payloads, returning a profile with whatever could be
    extracted (and ``supports_shopping`` ``False`` when no usable shopping
    endpoint is advertised). Returns ``None`` only when the payload is not an
    object at all. Any HTTPS shopping endpoint counts regardless of transport —
    the conforming UCP guides publish ``dev.ucp.shopping`` over REST as well as
    MCP — so the transport is surfaced alongside each endpoint.
    """
    if not isinstance(payload, dict):
        return None
    envelope = payload.get("ucp")
    if not isinstance(envelope, dict):
        envelope = payload

    service_names: list[str] = []
    endpoints: list[ShoppingEndpoint] = []
    raw_services = envelope.get("services")
    if isinstance(raw_services, dict):
        for namespace, declarations in raw_services.items():
            if not isinstance(namespace, str) or not namespace:
                continue
            service_names.append(namespace)
            if not _is_shopping_service(namespace) or not isinstance(declarations, list):
                continue
            for declaration in declarations:
                if not isinstance(declaration, dict):
                    continue
                transport = declaration.get("transport")
                if not isinstance(transport, str) or not transport:
                    continue
                raw_endpoint = declaration.get("endpoint")
                if not isinstance(raw_endpoint, str) or not raw_endpoint:
                    continue
                resolved = _resolve_endpoint(origin, raw_endpoint)
                if resolved is None:
                    continue
                endpoint = ShoppingEndpoint(transport=transport.lower(), url=resolved)
                if endpoint not in endpoints:
                    endpoints.append(endpoint)

    raw_capabilities = envelope.get("capabilities")
    capability_names = (
        [key for key in raw_capabilities if isinstance(key, str)] if isinstance(raw_capabilities, dict) else []
    )

    version = envelope.get("version")
    return MerchantUCPProfile(
        origin=origin,
        # Bound the stored arrays so a hostile profile cannot bloat the per-origin cache.
        endpoints=tuple(endpoints[:_MAX_SHOPPING_ENDPOINTS]),
        service_names=tuple(dict.fromkeys(service_names)),
        capability_names=tuple(dict.fromkeys(capability_names)),
        version=version if isinstance(version, str) else None,
    )


def format_ucp_hint(profile: MerchantUCPProfile) -> str | None:
    """Render a single-line, agent-facing hint for a shopping-capable profile."""
    if not profile.supports_shopping:
        return None
    suffixes = profile.shopping_capabilities()[:_MAX_SHOPPING_CAPABILITIES]
    capability_text = ", ".join(suffixes) if suffixes else "shopping"
    return f"\U0001f6d2 This site advertises UCP shopping support at {profile.origin}. Capabilities: {capability_text}."


async def discover_merchant_ucp_profile(origin: str, fetch: UCPFetch) -> MerchantUCPProfile | None:
    """Probe ``{origin}/.well-known/ucp`` via ``fetch`` and parse the result.

    Swallows every failure (network, non-2xx, invalid JSON), returning ``None``
    so callers can fall back without special exception handling.
    """
    try:
        payload = await fetch(f"{origin}{UCP_WELL_KNOWN_PATH}")
    except Exception:
        return None
    if payload is None:
        return None
    return parse_merchant_profile(origin, payload)


class UCPDetector:
    """Per-session UCP discovery: one probe per origin, hint only on origin change.

    A browser worker owns one detector. ``snapshot_hint`` is called for each
    snapshot with the page's current URL; it probes a newly reached HTTPS origin
    at most once (caching both positive and negative results) and emits a hint
    only when the origin changes, so repeated snapshots on the same page stay
    quiet.
    """

    def __init__(self, fetch: UCPFetch) -> None:
        self._fetch = fetch
        self._cache: dict[str, MerchantUCPProfile | None] = {}
        self._last_origin: object = _UNSET

    async def snapshot_hint(self, url: str | None) -> dict[str, Any] | None:
        origin = merchant_origin(url)
        changed = origin != self._last_origin
        self._last_origin = origin
        if origin is None or not changed:
            return None
        profile = await self._profile_for_origin(origin)
        if profile is None or not profile.supports_shopping:
            return None
        hint = format_ucp_hint(profile)
        if hint is None:
            return None
        return {
            "origin": profile.origin,
            "version": profile.version,
            "capabilities": list(profile.shopping_capabilities()[:_MAX_SHOPPING_CAPABILITIES]),
            "endpoints": [
                {"transport": endpoint.transport, "url": endpoint.url}
                for endpoint in profile.endpoints[:_MAX_SHOPPING_ENDPOINTS]
            ],
            "hint": hint,
        }

    async def _profile_for_origin(self, origin: str) -> MerchantUCPProfile | None:
        if origin in self._cache:
            return self._cache[origin]
        profile = await discover_merchant_ucp_profile(origin, self._fetch)
        self._cache[origin] = profile
        return profile
