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

# Cap the number of capabilities rendered into a hint to keep it compact.
_MAX_HINT_CAPABILITIES = 12

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
class MerchantUCPProfile:
    """A merchant's discovered UCP profile for a single origin."""

    origin: str
    mcp_endpoints: tuple[str, ...] = ()
    service_names: tuple[str, ...] = ()
    capability_names: tuple[str, ...] = ()
    version: str | None = None

    @property
    def supports_shopping(self) -> bool:
        return bool(self.mcp_endpoints)

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


def _is_shopping_service(name: str | None, capabilities: list[str]) -> bool:
    if isinstance(name, str) and (name == SHOPPING_SERVICE or name.startswith(_SHOPPING_CAPABILITY_PREFIX)):
        return True
    return any(
        capability == SHOPPING_SERVICE or capability.startswith(_SHOPPING_CAPABILITY_PREFIX)
        for capability in capabilities
    )


def _resolve_endpoint(origin: str, raw_endpoint: str) -> str | None:
    """Resolve a (possibly relative) endpoint against ``origin``, keeping only HTTPS.

    Relative paths like ``/api/ucp/mcp`` resolve against the origin; absolute
    URLs are accepted as-is. Non-HTTPS or host-less results are rejected.
    """
    resolved = urljoin(f"{origin}/", raw_endpoint)
    parts = urlsplit(resolved)
    if parts.scheme != "https" or not parts.hostname:
        return None
    return resolved


def parse_merchant_profile(origin: str, payload: Any) -> MerchantUCPProfile | None:
    """Parse a ``/.well-known/ucp`` document into a :class:`MerchantUCPProfile`.

    Tolerates malformed payloads, returning a profile with whatever could be
    extracted (and ``supports_shopping`` ``False`` when no usable shopping MCP
    endpoint is advertised). Returns ``None`` only when the payload is not an
    object at all.
    """
    if not isinstance(payload, dict):
        return None

    raw_services = payload.get("services")
    services = raw_services if isinstance(raw_services, list) else []

    service_names: list[str] = []
    capability_names: list[str] = []
    endpoints: list[str] = []

    for service in services:
        if not isinstance(service, dict):
            continue
        name = service.get("name") or service.get("id")
        if isinstance(name, str) and name:
            service_names.append(name)
        raw_capabilities = service.get("capabilities")
        service_capabilities = (
            [item for item in raw_capabilities if isinstance(item, str)] if isinstance(raw_capabilities, list) else []
        )
        capability_names.extend(service_capabilities)

        if not _is_shopping_service(name if isinstance(name, str) else None, service_capabilities):
            continue
        raw_bindings = service.get("bindings")
        if not isinstance(raw_bindings, list):
            continue
        for binding in raw_bindings:
            if not isinstance(binding, dict):
                continue
            transport = binding.get("transport") or binding.get("type")
            if not isinstance(transport, str) or transport.lower() != "mcp":
                continue
            raw_endpoint = binding.get("endpoint") or binding.get("url")
            if not isinstance(raw_endpoint, str) or not raw_endpoint:
                continue
            resolved = _resolve_endpoint(origin, raw_endpoint)
            if resolved is not None and resolved not in endpoints:
                endpoints.append(resolved)

    version = payload.get("version")
    return MerchantUCPProfile(
        origin=origin,
        mcp_endpoints=tuple(endpoints),
        service_names=tuple(dict.fromkeys(service_names)),
        capability_names=tuple(dict.fromkeys(capability_names)),
        version=version if isinstance(version, str) else None,
    )


def format_ucp_hint(profile: MerchantUCPProfile) -> str | None:
    """Render a single-line, agent-facing hint for a shopping-capable profile."""
    if not profile.supports_shopping:
        return None
    suffixes = profile.shopping_capabilities()[:_MAX_HINT_CAPABILITIES]
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
            "capabilities": list(profile.shopping_capabilities()),
            "endpoints": list(profile.mcp_endpoints),
            "hint": hint,
        }

    async def _profile_for_origin(self, origin: str) -> MerchantUCPProfile | None:
        if origin in self._cache:
            return self._cache[origin]
        profile = await discover_merchant_ucp_profile(origin, self._fetch)
        self._cache[origin] = profile
        return profile
