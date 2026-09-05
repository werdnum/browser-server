from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import re
import shutil
import socket
import subprocess
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Protocol, cast

import httpx

from .models import AgentCommandRequest
from .security import redact_url
from .ucp import UCPDetector

# Bound the merchant-controlled UCP probe so a huge or slow-trickle
# /.well-known/ucp response cannot tie up the snapshot — which the registry
# awaits while holding the session lock — past a small fixed budget.
_UCP_PROBE_TIMEOUT_S = 5.0
_UCP_PROBE_MAX_BYTES = 256 * 1024

# Product token Chromium's headless build puts in its native user agent, in place of "Chrome".
_HEADLESS_UA_TOKEN = "HeadlessChrome"


def stealth_enabled() -> bool:
    """Whether the JS-fingerprint patches and humanized input timing are active.

    On by default; ``BROWSER_STEALTH=0`` (or false/no/off) turns them off, e.g. to
    debug a site that misbehaves under the patched ``navigator``/``window.chrome``
    surfaces. The launch-flag hardening below is gated on this too so an operator
    can get a plain vanilla Playwright browser back with one variable.
    """
    return os.environ.get("BROWSER_STEALTH", "1").strip().lower() not in {"0", "false", "no", "off"}


# Runs in every frame (main + iframes) before page scripts on each navigation.
# Covers the cheap JS-level tells: ``navigator.webdriver``, the missing
# ``window.chrome`` object of a non-Chrome UA, the empty plugins/mimeTypes arrays
# of headless builds, the permissions-query inconsistency, and the SwiftShader /
# llvmpipe software-renderer strings headless WebGL reports. Deliberately NOT a
# full anti-fingerprinting layer: CDP-protocol and TLS-level detection are out of
# scope here (patchright handles part of the former).
STEALTH_INIT_SCRIPT = """
(() => {
  const win = window;
  // Init scripts run exactly once per document, so no re-entry guard is needed —
  // and a page-visible marker would itself be a trivial automation tell.

  try {
    Object.defineProperty(Navigator.prototype, 'webdriver', {
      get: () => false,
      set: () => {},
      configurable: true,
    });
  } catch (err) {}

  if (!win.chrome) {
    win.chrome = {};
  }
  if (!win.chrome.runtime) {
    win.chrome.runtime = {
      connect: () => ({ onMessage: { addListener: () => {} }, postMessage: () => {} }),
      sendMessage: () => {},
      id: undefined,
    };
  }
  if (!win.chrome.app) {
    win.chrome.app = {
      isInstalled: false,
      InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
      RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
      getDetails: () => null,
      installState: () => 'not_installed',
    };
  }
  if (!win.chrome.csi) {
    win.chrome.csi = () => ({ startE: Date.now(), onloadT: Date.now(), pageT: 0, tran: 0 });
  }
  if (!win.chrome.loadTimes) {
    win.chrome.loadTimes = () => ({
      commitLoadTime: Date.now() / 1000,
      connectionInfo: 'h2',
      finishDocumentLoadTime: Date.now() / 1000,
      finishLoadTime: Date.now() / 1000,
      firstPaintAfterLoadTime: 0,
      firstPaintTime: Date.now() / 1000,
      navigationType: 'Other',
      npnNegotiatedProtocol: 'h2',
      requestTime: Date.now() / 1000,
      startLoadTime: Date.now() / 1000,
      wasAlternateProtocolAvailable: false,
      wasFetchedViaSpdy: true,
      wasNpnNegotiated: true,
    });
  }

  try {
    Object.defineProperty(Navigator.prototype, 'languages', {
      get: () => [navigator.language || 'en-US'],
      configurable: true,
    });
  } catch (err) {}

  if (win.Notification && navigator.permissions && navigator.permissions.query) {
    const originalQuery = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = (parameters) => {
      if (parameters && parameters.name === 'notifications') {
        // Spoof only the state getter on the NATIVE PermissionStatus so sites
        // keep a real EventTarget (addEventListener/removeEventListener/onchange)
        // instead of the plain object a hand-rolled response would give them.
        return originalQuery(parameters).then((status) => {
          try {
            Object.defineProperty(status, 'state', {
              get: () => Notification.permission,
              configurable: true,
            });
          } catch (err) {}
          return status;
        });
      }
      return originalQuery(parameters);
    };
  }

  const maskWebGL = (proto) => {
    if (!proto || !proto.getParameter) return;
    const originalGetParameter = proto.getParameter;
    proto.getParameter = function (parameter) {
      const value = originalGetParameter.apply(this, arguments);
      // Only rewrite when the build reports a software renderer; a real GPU
      // string is consistent with everything else about the machine.
      if (parameter === 37445 || parameter === 37446) {
        if (/swiftshader|software|llvmpipe|basic render/i.test(String(value))) {
          return parameter === 37445 ? 'Intel Inc.' : 'Intel Iris OpenGL Engine';
        }
      }
      return value;
    };
  };
  maskWebGL(win.WebGLRenderingContext && win.WebGLRenderingContext.prototype);
  maskWebGL(win.WebGL2RenderingContext && win.WebGL2RenderingContext.prototype);

  if (navigator.hardwareConcurrency === 1) {
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8, configurable: true });
  }
})();
"""

# Desktop-only companion to STEALTH_INIT_SCRIPT: synthesizes the classic desktop
# Chromium PDF plugin collections when the build reports both empty (headless).
# NEVER applied to mobile-profile sessions — Chrome on Android exposes no such
# plugin array, and pairing it with a mobile UA + touch is an internally
# impossible fingerprint.
PLUGIN_SYNTHESIS_SCRIPT = """
(() => {
  if (!(navigator.plugins.length === 0 && navigator.mimeTypes.length === 0)) return;
  const pluginFactories = [
    ['PDF Viewer', 'Portable Document Format', 'internal-pdf-viewer'],
    ['Chrome PDF Viewer', 'Portable Document Format', 'internal-pdf-viewer'],
    ['Chromium PDF Viewer', 'Portable Document Format', 'internal-pdf-viewer'],
    ['Microsoft Edge PDF Viewer', 'Portable Document Format', 'internal-pdf-viewer'],
    ['WebKit built-in PDF', 'Portable Document Format', 'internal-pdf-viewer'],
  ];
  const mimeObj = Object.create(MimeType.prototype);
  Object.defineProperties(mimeObj, {
    type: { value: 'application/pdf' },
    suffixes: { value: 'pdf' },
    description: { value: 'Portable Document Format' },
    enabledPlugin: { value: null, writable: true },
  });
  const plugins = pluginFactories.map(([name, description, filename]) => {
    const plugin = Object.create(Plugin.prototype);
    Object.defineProperties(plugin, {
      name: { value: name },
      description: { value: description },
      filename: { value: filename },
      length: { value: 1 },
      0: { value: mimeObj },
      item: { value: (index) => (index === 0 ? mimeObj : null) },
      namedItem: { value: (kind) => (kind === mimeObj.type ? mimeObj : null) },
    });
    return plugin;
  });
  mimeObj.enabledPlugin = plugins[0];
  const pluginArray = Object.create(PluginArray.prototype);
  plugins.forEach((plugin, index) => {
    Object.defineProperty(pluginArray, index, { value: plugin, enumerable: true });
  });
  // Native PluginArray also supports named lookup (navigator.plugins['PDF Viewer']),
  // as a non-enumerable own property per name.
  plugins.forEach((plugin) => {
    Object.defineProperty(pluginArray, plugin.name, { get: () => plugin });
  });
  Object.defineProperties(pluginArray, {
    length: { value: plugins.length },
    item: { value: (index) => plugins[index] || null },
    namedItem: { value: (name) => plugins.find((plugin) => plugin.name === name) || null },
    refresh: { value: () => {} },
    [Symbol.iterator]: { value: Array.prototype[Symbol.iterator] },
  });
  const mimeTypeArray = Object.create(MimeTypeArray.prototype);
  Object.defineProperties(mimeTypeArray, {
    length: { value: 1 },
    0: { value: mimeObj, enumerable: true },
    item: { value: (index) => (index === 0 ? mimeObj : null) },
    namedItem: { value: (kind) => (kind === mimeObj.type ? mimeObj : null) },
    [Symbol.iterator]: { value: Array.prototype[Symbol.iterator] },
  });
  // Native named access ("application/pdf") is a non-enumerable own property.
  Object.defineProperty(mimeTypeArray, 'application/pdf', { get: () => mimeObj });
  try {
    Object.defineProperty(Navigator.prototype, 'plugins', { get: () => pluginArray, configurable: true });
    Object.defineProperty(Navigator.prototype, 'mimeTypes', { get: () => mimeTypeArray, configurable: true });
  } catch (err) {}
})();
"""


class RuntimeUnavailable(RuntimeError):
    pass


class StorageTooLarge(RuntimeError):
    """A jar export exceeded its byte budget. Raised by the worker so the oversized
    ``storage_state`` is never fully held in the service (memory/disk DoS backstop)."""


def origin_of(url: str | None) -> str | None:
    """Exact web origin (scheme + host + port) of a URL, or None.

    Delegates to the canonical ``jars.normalize_origin`` so navigation confinement and jar
    scope-filtering compare origins computed by the *same* code — divergent normalizers would
    be exactly the mismatch that opens a confinement bypass."""
    if not url:
        return None
    from .jars import normalize_origin

    return normalize_origin(url)


# In-page accessibility walker and ref resolver.
#
# This block is shared VERBATIM by browser-server (browser_handoff_service/runtime.py)
# and Family Assistant (src/family_assistant/tools/browser_backend.py). Family
# Assistant has a unit test asserting its copy is byte-identical to the one
# installed from browser-server, so edit both or neither.
#
# Contract (docs/design/browser-ref-identity.md in family-assistant):
# - A ref names one node and is never issued for another node in the same
#   conversation. A node keeps its ref across snapshots while its role and
#   accessible name are unchanged; anything else is stamped with a fresh number.
# - Fresh numbers come from the caller-supplied counter (``nextRef``) and never
#   go below the highest number already stamped on the document. The walker
#   reports the advanced counter as ``next_ref``.
# - ``CHECK_REF_JS`` decides whether a ref resolves: exactly when a snapshot
#   taken now would list that node under it. It shares the walker's predicate.

_WALKER_HELPERS_JS = r"""
  const REF_ATTR = 'data-fa-ref';
  const ROLE_ATTR = 'data-fa-role';
  const NAME_ATTR = 'data-fa-name';
  const REF_PATTERN = /^e[0-9]+$/;

  const ROLE_MAP = {
    A: 'link', BUTTON: 'button', SELECT: 'combobox',
    TEXTAREA: 'textbox', FORM: 'form', NAV: 'navigation',
    MAIN: 'main', ASIDE: 'complementary', HEADER: 'banner',
    FOOTER: 'contentinfo', IMG: 'img',
  };
  const INPUT_ROLES = {
    submit: 'button', button: 'button', reset: 'button',
    checkbox: 'checkbox', radio: 'radio',
    range: 'slider', file: 'textbox',
  };
  const HEADING_TAGS = new Set(['H1','H2','H3','H4','H5','H6']);
  const NAME_FROM_CONTENT = new Set([
    'A', 'BUTTON', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6',
    'P', 'LI', 'SPAN', 'LABEL', 'OPTION', 'TD', 'TH', 'CAPTION',
  ]);

  function roleFor(el) {
    const aria = el.getAttribute('role');
    if (aria) return aria;
    if (HEADING_TAGS.has(el.tagName)) return 'heading';
    if (el.tagName === 'INPUT') {
      const t = (el.getAttribute('type') || 'text').toLowerCase();
      return INPUT_ROLES[t] || 'textbox';
    }
    return ROLE_MAP[el.tagName] || null;
  }

  function accName(el) {
    const labelledBy = el.getAttribute('aria-labelledby');
    if (labelledBy) {
      const parts = [];
      for (const id of labelledBy.trim().split(/\s+/)) {
        const target = id && document.getElementById(id);
        if (target) parts.push(target.textContent.trim());
      }
      if (parts.length) return parts.join(' ');
    }
    const aria = el.getAttribute('aria-label');
    if (aria) return aria.trim();
    if (el.id) {
      const lbl = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
      if (lbl) return lbl.textContent.trim();
    }
    const parentLabel = el.closest && el.closest('label');
    if (parentLabel && parentLabel !== el) return parentLabel.textContent.trim();
    if (el.getAttribute('alt')) return el.getAttribute('alt').trim();
    if (el.getAttribute('title')) return el.getAttribute('title').trim();
    if (el.getAttribute('placeholder')) return el.getAttribute('placeholder').trim();
    if (!NAME_FROM_CONTENT.has(el.tagName)) return '';
    const txt = (el.innerText || el.textContent || '').trim();
    return txt.length > 120 ? txt.slice(0, 120) + '…' : txt;
  }

  function isVisible(el) {
    if (!el.getBoundingClientRect) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return false;
    const style = window.getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    return true;
  }

  function interesting(el) {
    const role = roleFor(el);
    if (role) return role;
    if (el.tagName === 'P' || el.tagName === 'LI') return 'text';
    return null;
  }

  // Why a snapshot taken now would not list ``el`` under its stamped ref, or
  // null when it would. This is the one eligibility predicate the walker and
  // the resolver share: the walker lists exactly the nodes for which it is
  // null, and an action resolves a ref exactly when it is null.
  function ineligible(el) {
    let inBody = false;
    for (let n = el; n; n = n.parentElement) {
      if (n.nodeType !== 1 || !isVisible(n)) return 'hidden';
      if (n === document.body) { inBody = true; break; }
    }
    if (!inBody) return 'missing';
    const role = interesting(el);
    if (role === null) return 'changed';
    if (role !== el.getAttribute(ROLE_ATTR)) return 'changed';
    if (accName(el) !== el.getAttribute(NAME_ATTR)) return 'changed';
    return null;
  }
"""

# ``(nextRef) => snapshot``. ``nextRef`` is the lowest number the caller permits
# for a fresh ref; the result's ``next_ref`` is the counter after this walk.
SNAPSHOT_JS = (
    "(nextRef) => {"
    + _WALKER_HELPERS_JS
    + r"""
  let highest = 0;
  for (const el of document.querySelectorAll('[' + REF_ATTR + ']')) {
    const stamped = el.getAttribute(REF_ATTR) || '';
    if (!REF_PATTERN.test(stamped)) continue;
    const n = parseInt(stamped.slice(1), 10);
    if (n > highest) highest = n;
  }
  let counter = Math.max(Math.floor(Number(nextRef)) || 1, highest + 1);
  const issued = new Set();

  function refFor(el, role, name) {
    const existing = el.getAttribute(REF_ATTR) || '';
    if (
      REF_PATTERN.test(existing) &&
      !issued.has(existing) &&
      el.getAttribute(ROLE_ATTR) === role &&
      el.getAttribute(NAME_ATTR) === name
    ) {
      issued.add(existing);
      return existing;
    }
    const ref = 'e' + (counter++);
    el.setAttribute(REF_ATTR, ref);
    el.setAttribute(ROLE_ATTR, role);
    el.setAttribute(NAME_ATTR, name);
    issued.add(ref);
    return ref;
  }

  let listed = 0;

  function walk(el, out) {
    if (el.nodeType !== 1) return;
    if (!isVisible(el)) return;
    const role = interesting(el);
    if (role) {
      const name = accName(el);
      const ref = refFor(el, role, name);
      listed += 1;
      const node = { ref, role, name };
      const href = el.getAttribute('href');
      if (href) node.href = href;
      const value = el.value;
      if (typeof value === 'string' && value) node.value = value;
      if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') {
        node.tag = el.tagName.toLowerCase();
        const t = el.getAttribute('type');
        if (t) node.input_type = t.toLowerCase();
      }
      out.push(node);
      node.children = [];
      for (const child of el.children) walk(child, node.children);
      if (node.children.length === 0) delete node.children;
    } else {
      for (const child of el.children) walk(child, out);
    }
  }

  const roots = [];
  walk(document.body, roots);

  const formCount = document.forms ? document.forms.length : 0;
  return {
    url: location.href,
    title: document.title,
    forms: formCount,
    elements: listed,
    next_ref: counter,
    roots,
  };
}
"""
)

# ``(ref) => {ok: true} | {ok: false, cause}``. ``cause`` is ``missing`` (no node
# carries the ref), ``hidden`` (the node or an ancestor is not visible) or
# ``changed`` (the node's role or name differs from what was snapshotted).
CHECK_REF_JS = (
    "(ref) => {"
    + _WALKER_HELPERS_JS
    + r"""
  if (typeof ref !== 'string' || !REF_PATTERN.test(ref)) return { ok: false, cause: 'missing' };
  const el = document.querySelector('[' + REF_ATTR + '="' + ref + '"]');
  if (!el) return { ok: false, cause: 'missing' };
  const cause = ineligible(el);
  if (cause !== null) return { ok: false, cause };
  return { ok: true };
}
"""
)

_REF_PATTERN = re.compile(r"^e[0-9]+$")

# What a caller is told when a ref no longer names a listable node. One sentence for the model:
# the ref is not wrong, the page moved on, and the fix is a fresh snapshot.
_STALE_REF_REASON = "ref {ref} is no longer on the page as snapshotted; the page has changed since the last snapshot"


def coerce_next_ref(raw: Any) -> int:
    """The lowest number a snapshot may issue as a fresh ref.

    Callers thread this counter through their snapshots so a number is never issued twice within a
    conversation. Anything unusable falls back to 1; the walker then raises it above the document's
    own stamps anyway.
    """
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 1
    return max(value, 1)


def invalid_ref_result(ref: str, url: str | None) -> dict[str, Any]:
    return {
        "error": True,
        "code": "invalid_ref",
        "ref": ref,
        "reason": "a ref looks like e12",
        "url": url,
    }


def stale_ref_result(ref: str, cause: str, url: str | None, title: str) -> dict[str, Any]:
    return {
        "error": True,
        "code": "stale_ref",
        "ref": ref,
        "cause": cause,
        "reason": _STALE_REF_REASON.format(ref=ref),
        "url": url,
        "title": title,
    }


def _wrap_exec_code(code: str) -> str:
    """Wrap caller-provided JS so ``page.evaluate`` runs it uniformly.

    Playwright treats a function-shaped string as callable and a bare
    expression as a value. Accept both ``document.title`` (expression) and
    ``return document.title`` (statement body).
    """
    stripped = code.strip()
    if not stripped:
        return "async () => null"
    if stripped.startswith(("(", "async ", "function ")):
        return stripped
    if stripped.startswith("{"):
        return f"async () => {stripped}"
    looks_like_statements = "return " in stripped or ";" in stripped or "\n" in stripped
    if looks_like_statements:
        return f"async () => {{ {stripped} }}"
    return f"async () => ({stripped})"


class BrowserRuntime(Protocol):
    worker_id: str
    closed: bool
    remote_url: str | None

    async def start(self) -> None: ...
    async def command(self, request: AgentCommandRequest) -> dict[str, Any]: ...
    async def close(self) -> None: ...
    async def export_storage_state(self, max_bytes: int, *, cookies_only: bool = False) -> dict[str, Any]: ...
    async def selector_present(self, selector: str) -> bool | None: ...
    def set_confinement_active(self, enabled: bool) -> None: ...
    def set_confine_origins(self, origins: list[str]) -> None: ...
    async def evict_off_scope_page(self) -> None: ...


class FakeBrowserWorker:
    def __init__(
        self,
        worker_id: str,
        *,
        storage_state: dict[str, Any] | None = None,
        confine_origins: list[str] | None = None,
        timezone_id: str | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.closed = False
        self.remote_url: str | None = None
        self.url: str | None = None
        self.title = "Blank"
        self.timezone_id = timezone_id
        self.actions: list[dict[str, Any]] = []
        # Fixture UCP profiles keyed by well-known URL ("{origin}/.well-known/ucp"),
        # so tests can simulate a merchant advertising shopping support.
        self.ucp_documents: dict[str, Any] = {}
        self._ucp = UCPDetector(self._ucp_fetch)
        # Cookie-jar test fixtures. ``storage_state`` is what an export returns (settable so a
        # test can simulate a login accumulating state); ``confine_origins`` mirrors a
        # jar-loaded context's navigation confinement; ``present_selectors`` are the selectors
        # querySelector "finds" (drives probe classification); ``redirect_map`` simulates an
        # expired session bouncing to a login origin.
        self.storage_state: dict[str, Any] = (
            storage_state if storage_state is not None else {"cookies": [], "origins": []}
        )
        self.confine_origins = [o for o in (confine_origins or [])]
        self._confinement_active = True
        self.present_selectors: set[str] = set()
        # Selectors whose evaluation "fails" (malformed/transient) -> selector_present returns None.
        self.error_selectors: set[str] = set()
        self.redirect_map: dict[str, str] = {}
        # URLs that simulate an in-scope network failure (DNS/TLS/connection outage) on navigate.
        self.nav_error_urls: set[str] = set()
        self.last_blocked: dict[str, Any] | None = None
        # Ref identity, mirrored from the real walker at fake scale: the single listed node keeps
        # its ref for as long as the fake document is unchanged, fresh numbers come from the
        # caller's counter, and no number is ever issued twice by this worker.
        self._ref: str | None = None
        self._ref_document: str | None = None
        self._highest_ref = 0

    async def _ucp_fetch(self, url: str) -> Any:
        return self.ucp_documents.get(url)

    async def start(self) -> None:
        return None

    async def export_storage_state(self, max_bytes: int, *, cookies_only: bool = False) -> dict[str, Any]:
        state = (
            {"cookies": self.storage_state.get("cookies", []), "origins": []} if cookies_only else self.storage_state
        )
        if len(json.dumps(state).encode("utf-8")) > max_bytes:
            raise StorageTooLarge(f"storage_state exceeds {max_bytes} bytes")
        return state

    async def selector_present(self, selector: str) -> bool | None:
        if selector in self.error_selectors:
            return None
        return selector in self.present_selectors

    def set_confinement_active(self, enabled: bool) -> None:
        self._confinement_active = enabled

    def set_confine_origins(self, origins: list[str]) -> None:
        self.confine_origins = [o for o in origins]

    async def evict_off_scope_page(self) -> None:
        if self._off_scope(self.url or ""):
            self.url = "about:blank"
            self.title = "Blank"

    def _off_scope(self, url: str) -> bool:
        if not self.confine_origins or not self._confinement_active:
            return False
        return origin_of(url) not in set(self.confine_origins)

    def _current_ref(self) -> str | None:
        """The ref the fake's current document carries, or None when it has not been snapshotted."""
        if self._ref is None or self._ref_document != self.title:
            return None
        return self._ref

    def _issue_ref(self, next_ref: int) -> str:
        """The ref for the fake's single node: reused while the document is unchanged, otherwise a
        fresh number at or above the caller's counter and above anything this worker has issued."""
        current = self._current_ref()
        if current is not None:
            return current
        number = max(next_ref, self._highest_ref + 1)
        self._highest_ref = number
        self._ref = f"e{number}"
        self._ref_document = self.title
        return self._ref

    async def command(self, request: AgentCommandRequest) -> dict[str, Any]:
        if self.closed:
            raise RuntimeError("worker is closed")
        if request.type == "navigate":
            url = str(request.args["url"])
            if url in self.nav_error_urls:
                # An in-scope network failure (transient outage), distinct from an off-scope block.
                return {
                    "error": True,
                    "reason": "navigation failed",
                    "url": redact_url(self.url)[0] if self.url else None,
                }
            # A configured redirect models an expired session bouncing to login/IdP.
            target = self.redirect_map.get(url, url)
            if self._off_scope(target):
                # Confinement aborts the off-scope document request pre-request; surface it as
                # a structured block rather than following it.
                self.last_blocked = {
                    "blocked": True,
                    "reason": "off-scope navigation blocked",
                    "target_origin": origin_of(target),
                }
                return {
                    "blocked": True,
                    "reason": "off-scope navigation blocked",
                    "url": redact_url(self.url)[0] if self.url else None,
                    "target_origin": origin_of(target),
                }
            self.url = target
            self.title = f"Fixture page at {redact_url(target)[1] or target}"
            return {"url": redact_url(target)[0], "title": self.title}
        if request.type in {"click", "type_text", "select", "press_key"}:
            raw_ref = request.args.get("ref") if request.type != "press_key" else None
            if raw_ref is not None:
                url = redact_url(self.url)[0] if self.url else None
                ref = str(raw_ref)
                if not _REF_PATTERN.match(ref):
                    return invalid_ref_result(ref, url)
                if ref != self._current_ref():
                    return stale_ref_result(ref, "missing", url, self.title)
            self.actions.append({"type": request.type, "args": request.args})
            return {"accepted": True, "url": redact_url(self.url)[0] if self.url else None, "title": self.title}
        if request.type == "snapshot":
            next_ref = coerce_next_ref(request.args.get("next_ref"))
            ref = self._issue_ref(next_ref)
            result: dict[str, Any] = {
                "url": redact_url(self.url)[0] if self.url else "about:blank",
                "title": self.title,
                "forms": 0,
                "elements": 1,
                "next_ref": max(next_ref, int(ref[1:]) + 1),
                "roots": [{"ref": ref, "role": "document", "name": self.title}],
            }
            hint = await self._ucp.snapshot_hint(self.url)
            if hint is not None:
                result["ucp"] = hint
            return result
        if request.type == "screenshot":
            # 1x1 transparent PNG so callers exercising the bytes path get valid image data.
            png = base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
            )
            return {"mime_type": "image/png", "image_base64": base64.b64encode(png).decode("ascii")}
        if request.type == "current_page":
            return {"url": redact_url(self.url)[0] if self.url else None, "title": self.title}
        if request.type == "extract":
            return {
                "url": redact_url(self.url)[0] if self.url else None,
                "html": f"<html><body><h1>{self.title}</h1></body></html>",
            }
        if request.type == "exec":
            return {"result": self.title, "url": redact_url(self.url)[0] if self.url else None}
        if request.type == "wait":
            return {"accepted": True, "url": redact_url(self.url)[0] if self.url else None, "title": self.title}
        if request.type in {
            "mouse_click",
            "mouse_move",
            "mouse_down",
            "mouse_up",
            "mouse_wheel",
            "keyboard_type",
            "keyboard_press",
        }:
            self.actions.append({"type": request.type, "args": request.args})
            return {"accepted": True, "url": redact_url(self.url)[0] if self.url else None}
        if request.type == "navigate_back":
            return {"accepted": True, "url": redact_url(self.url)[0] if self.url else None}
        if request.type == "navigate_forward":
            return {"accepted": True, "url": redact_url(self.url)[0] if self.url else None}
        if request.type == "close_page":
            self.url = None
            self.title = "Blank"
            return {"closed": True, "url": None, "title": self.title}
        raise ValueError(f"unsupported command {request.type}")

    async def close(self) -> None:
        self.closed = True


DEFAULT_DISPLAY_WIDTH = 1280
DEFAULT_DISPLAY_HEIGHT = 720


class PlaywrightBrowserWorker:
    def __init__(
        self,
        worker_id: str,
        *,
        headed: bool = False,
        width: int = DEFAULT_DISPLAY_WIDTH,
        height: int = DEFAULT_DISPLAY_HEIGHT,
        user_agent: str | None = None,
        storage_state: dict[str, Any] | None = None,
        confine_origins: list[str] | None = None,
        timezone_id: str | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.closed = False
        self.headed = headed
        self.stealth = stealth_enabled()
        self.width = width
        self.height = height
        self.user_agent = user_agent
        self.timezone_id = timezone_id
        # Cookie-jar load/confinement. ``storage_state`` seeds the context at creation;
        # ``confine_origins`` (exact scheme+host+port) restricts every top-level document.
        self._storage_state = storage_state
        self.confine_origins = [o for o in (confine_origins or [])]
        # Confinement gates only *agent-driven* navigation; it is disabled while a human holds
        # the control token (a human re-login may bounce through an off-scope IdP/SSO origin).
        self._confinement_active = True
        # Set by the route guard to the off-scope origin it aborted during the current navigation, so
        # a goto failure can tell an off-scope-redirect block from an in-scope network outage (both
        # can surface as net::ERR_FAILED). Reset before each navigate.
        self._nav_off_scope_block: str | None = None
        # Strong refs to fire-and-forget popup-close tasks so they are not GC'd mid-flight.
        self._popup_tasks: set[Any] = set()
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self.remote_url: str | None = None
        self._display: LocalNovncDisplay | None = None
        self._ucp = UCPDetector(self._ucp_fetch)

    async def _ucp_fetch(self, url: str) -> Any:
        """Probe a UCP well-known document with a bounded, plain HTTPS GET.

        A read-only GET to the fixed ``/.well-known/ucp`` path using a throwaway
        ``httpx`` client, independent of the browser context: a merchant-controlled
        ``Set-Cookie`` on the response can never reach the live session/cart
        cookies. Redirects are disabled so an HTTPS profile cannot be downgraded to
        a plaintext ``http://`` response and still be parsed. The response is read
        under a total deadline and a body-size cap (so a huge or slow-trickle
        response cannot block the snapshot), parsed as JSON, and never rendered
        into the page; any failure yields ``None``.
        """

        async def probe() -> Any:
            async with (
                httpx.AsyncClient(timeout=_UCP_PROBE_TIMEOUT_S, follow_redirects=False) as client,
                client.stream("GET", url) as response,
            ):
                if response.status_code // 100 != 2:
                    return None
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > _UCP_PROBE_MAX_BYTES:
                        return None
            return json.loads(body)

        try:
            return await asyncio.wait_for(probe(), timeout=_UCP_PROBE_TIMEOUT_S)
        except Exception:
            return None

    async def start(self) -> None:
        try:
            from patchright.async_api import async_playwright

            env: dict[str, str | float | bool] = dict(os.environ)
            args = [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--enable-features=NetworkService,NetworkServiceInProcess",
            ]
            # Stealth-only launch hardening: drop Playwright's --enable-automation
            # default (it drives the "controlled by automated software" infobar and a
            # distinct automation code path) and skip the first-run/default-browser
            # prompts a fresh profile would otherwise show.
            ignore_default_args = ["--enable-automation"] if self.stealth else None
            if self.stealth:
                args += ["--no-first-run", "--no-default-browser-check"]
            if self.headed:
                self._display = LocalNovncDisplay(self.worker_id, width=self.width, height=self.height)
                self.remote_url = self._display.start()
                env["DISPLAY"] = self._display.display
                # Fill the framebuffer so the noVNC view matches the session form factor.
                args.append(f"--window-size={self.width},{self.height}")
                args.append("--window-position=0,0")
            self._playwright = await async_playwright().start()
            # BROWSER_CHROMIUM_PATH lets an operator pin a system/sidecar Chrome instead
            # of the revision bundled with patchright (also how tests can drive a
            # real browser when only a different revision is installed). Unset => bundled.
            executable_path = os.environ.get("BROWSER_CHROMIUM_PATH") or None
            self._browser = await self._playwright.chromium.launch(
                headless=not self.headed,
                args=args,
                ignore_default_args=ignore_default_args,
                env=env,
                executable_path=executable_path,
            )
            # Explicit context (rather than browser.new_page) so a jar's storage_state can be
            # seeded at creation and exported back out with context.storage_state(indexed_db=True).
            context_kwargs: dict[str, Any] = {"viewport": {"width": self.width, "height": self.height}}
            if self.stealth and not self.headed:
                # Match screen to the viewport so window.screen doesn't disagree with
                # window.innerWidth/Height, a mismatch headless defaults can produce.
                context_kwargs["screen"] = {"width": self.width, "height": self.height}
                context_kwargs["device_scale_factor"] = 1
            if self.user_agent:
                # A mobile UA plus touch makes sites render their mobile layout.
                context_kwargs["user_agent"] = self.user_agent
                context_kwargs["is_mobile"] = True
                context_kwargs["has_touch"] = True
            else:
                # Otherwise leave the UA alone: the browser's own string always matches its
                # real version and its Client Hints, which a pinned override drifts away from.
                # The one exception is the headless build, whose native UA advertises
                # "HeadlessChrome" — a louder automation tell than any UA we could pin.
                demasked = await self._demasked_headless_user_agent()
                if demasked:
                    context_kwargs["user_agent"] = demasked
            # Apply the resolved IANA timezone so in-page new Date()/Intl report the
            # caller's local time. Chromium/ICU validates the id; an unknown zone
            # surfaces as a RuntimeUnavailable when the context is created.
            if self.timezone_id:
                context_kwargs["timezone_id"] = self.timezone_id
            if self.stealth:
                # A stable, common locale beats Chromium's possibly-empty default
                # (headless builds can report navigator.languages == []).
                context_kwargs["locale"] = os.environ.get("BROWSER_LOCALE", "").strip() or "en-US"
            if self._storage_state is not None:
                context_kwargs["storage_state"] = self._storage_state
            if self.confine_origins:
                # A Service Worker can serve document/form requests that context.route() never
                # sees, routing around the guard — so block SWs in confined contexts.
                context_kwargs["service_workers"] = "block"
            self._context = await self._browser.new_context(**context_kwargs)
            if self.stealth:
                script = STEALTH_INIT_SCRIPT
                if not self.user_agent:
                    # A pinned user agent means the mobile profile (UA + touch):
                    # Chrome on Android has no desktop plugin array, so injecting
                    # one would be an internally impossible fingerprint. Desktop
                    # sessions (including plain headless) get the synthesis.
                    script += "\n" + PLUGIN_SYNTHESIS_SCRIPT
                await self._context.add_init_script(script)
            if self.confine_origins:
                await self._install_confinement(self._context)
            self._page = await self._context.new_page()
        except Exception as exc:
            await self.close()
            raise RuntimeUnavailable(str(exc)) from exc

    async def _demasked_headless_user_agent(self) -> str | None:
        """Return the browser's own UA with the ``HeadlessChrome`` token rewritten to ``Chrome``,
        or ``None`` when there is nothing to rewrite (headed builds, or a probe that failed).

        Read from the live browser rather than pinned to a literal, so the version and platform
        always track the Chromium actually running instead of drifting as the image is rebuilt.
        """
        if self.headed or self._browser is None:
            return None
        try:
            context = await self._browser.new_context()
            try:
                page = await context.new_page()
                user_agent = await page.evaluate("navigator.userAgent")
            finally:
                await context.close()
        except Exception:
            # A UA probe is a nicety; never fail session start over it.
            return None
        if not isinstance(user_agent, str) or _HEADLESS_UA_TOKEN not in user_agent:
            return None
        return user_agent.replace(_HEADLESS_UA_TOKEN, "Chrome")

    async def _install_confinement(self, context: Any) -> None:
        """Confine top-level *document* requests in every frame (main, child, popup) to the jar's
        exact origins via pre-request route interception, so an off-scope navigation/redirect is
        aborted before the document request is sent. Only document/navigation requests are
        blocked — page-JavaScript subresource egress (fetch/beacon/img to an off-scope host) is a
        deliberate, documented residual deferred to the egress-proxy/CSP layer (see the design's
        "does not do" section); it is bounded meanwhile by exec default-deny.

        The confinement set is read from ``self.confine_origins`` on every request (not snapshotted),
        so a jar-loaded session that refreshes its own jar to a NARROWER scope can tighten the live
        route guard via ``set_confine_origins`` — the running worker must not keep trusting origins
        the refreshed jar dropped."""

        async def route_handler(route: Any) -> None:
            if not self._confinement_active:
                await route.continue_()
                return
            request = route.request
            off_scope = origin_of(request.url) not in set(self.confine_origins)
            try:
                is_document = request.resource_type == "document"
                is_nav = request.is_navigation_request()
            except Exception:
                # Fail closed: if the request cannot be classified, block it when off-scope
                # rather than let a possibly-credentialed document navigation through.
                if off_scope:
                    self._nav_off_scope_block = origin_of(request.url)
                    await route.abort()
                    return
                await route.continue_()
                return
            if is_document and is_nav and off_scope:
                self._nav_off_scope_block = origin_of(request.url)
                await route.abort()
                return
            await route.continue_()

        await context.route("**/*", route_handler)

        def on_page(page: Any) -> None:
            # A popup / window.open / target=_blank new top-level document off-scope is closed,
            # not left as a hole around main-frame confinement.
            if not self._confinement_active:
                return
            try:
                if page.url and page.url != "about:blank" and origin_of(page.url) not in set(self.confine_origins):
                    task = asyncio.ensure_future(page.close())
                    self._popup_tasks.add(task)
                    task.add_done_callback(self._popup_tasks.discard)
            except Exception:
                pass

        context.on("page", on_page)

    def set_confinement_active(self, enabled: bool) -> None:
        self._confinement_active = enabled

    def set_confine_origins(self, origins: list[str]) -> None:
        # The installed route handler reads self.confine_origins per request, so updating it here
        # tightens (or updates) the live confinement without re-installing the route.
        self.confine_origins = [o for o in origins]

    async def evict_off_scope_page(self) -> None:
        """After a confinement narrowing, if the current top-level page is now off-scope, navigate it
        to about:blank — the route guard only gates future *navigations*, so a non-navigation command
        (snapshot/extract/click) could otherwise still observe and act on the dropped-scope document."""
        if not self._confinement_active or self._page is None or not self.confine_origins:
            return
        if origin_of(self._page.url) not in set(self.confine_origins):
            try:
                await self._page.goto("about:blank")
            except Exception:
                pass

    async def command(self, request: AgentCommandRequest) -> dict[str, Any]:
        if self.closed or self._page is None:
            raise RuntimeError("worker is closed")
        page = self._page
        from patchright.async_api import Error as PlaywrightError

        # Any action (a click on a link, Enter submitting a form, go_back to an off-scope page) can
        # trigger a navigation the route guard aborts. Reset the flag and, if such an abort escapes
        # a non-navigate action as a Playwright error, return a controlled block instead of a 500.
        self._nav_off_scope_block = None
        try:
            return await self._dispatch_command(request, page)
        except PlaywrightError:
            if self.confine_origins and self._nav_off_scope_block is not None:
                return {
                    "blocked": True,
                    "reason": "off-scope navigation blocked",
                    "url": redact_url(page.url)[0],
                    "target_origin": self._nav_off_scope_block,
                }
            raise

    async def _resolve_action_target(self, request: AgentCommandRequest, page: Any) -> str | dict[str, Any]:
        """The selector a click/type_text/select should act on, or the error result to return instead.

        A ``ref`` is checked against the live page before Playwright is asked for anything, so a ref
        whose node a snapshot would no longer list fails immediately with a specific error rather
        than waiting out the actionability timeout. Without a ``ref`` the caller's raw ``selector``
        is used unchanged.
        """
        raw_ref = request.args.get("ref")
        if raw_ref is None:
            return str(request.args["selector"])
        ref = str(raw_ref)
        if not _REF_PATTERN.match(ref):
            return invalid_ref_result(ref, redact_url(page.url)[0])
        cause = await self._ref_ineligibility(page, ref)
        if cause is not None:
            return stale_ref_result(ref, cause, redact_url(page.url)[0], await self._safe_title(page))
        return f'[data-fa-ref="{ref}"]'

    async def _ref_ineligibility(self, page: Any, ref: str) -> str | None:
        """Why a snapshot taken now would not list ``ref``'s node, or None when it would.

        The predicate runs in the page and is the walker's own, so the two cannot drift. A document
        replaced under the check leaves nothing to act on, so an unrecoverable check reads as stale.
        """

        async def _check() -> dict[str, Any]:
            return cast(dict[str, Any], await page.evaluate(CHECK_REF_JS, ref))

        result = await self._with_navigation_recovery(page, _check, fallback=lambda: {"ok": False, "cause": "missing"})
        if result.get("ok"):
            return None
        return str(result.get("cause") or "missing")

    async def _human_pause(self, low: float, high: float) -> None:
        """Small randomized settle delay so consecutive agent commands don't land
        with machine-regular (or zero) spacing. No-op when stealth is off."""
        if self.stealth:
            await asyncio.sleep(random.uniform(low, high))

    async def _dispatch_command(self, request: AgentCommandRequest, page: Any) -> dict[str, Any]:
        if request.type == "navigate":
            from patchright.async_api import Error as PlaywrightError

            url = str(request.args["url"])
            if self.confine_origins and self._confinement_active and origin_of(url) not in set(self.confine_origins):
                # Fail fast before issuing a request the route guard would abort anyway.
                return {
                    "blocked": True,
                    "reason": "off-scope navigation blocked",
                    "url": redact_url(page.url)[0],
                    "target_origin": origin_of(url),
                }
            self._nav_off_scope_block = None
            try:
                await page.goto(url, wait_until="domcontentloaded")
            except PlaywrightError as exc:
                msg = str(exc).lower()
                # Classify by what the ROUTE GUARD actually did, not by the (generic) net:: code: an
                # aborted off-scope redirect (an expired session bouncing to an IdP/login origin) sets
                # _nav_off_scope_block, and only then is it a block. A bare net::ERR_FAILED to an
                # in-scope target with no off-scope abort is an ordinary outage.
                if self.confine_origins and self._nav_off_scope_block is not None:
                    return {
                        "blocked": True,
                        "reason": "off-scope navigation blocked",
                        "url": redact_url(page.url)[0],
                        "target_origin": self._nav_off_scope_block,
                    }
                # A net:: error to an in-scope target (DNS/TLS/connection/timeout/ERR_FAILED) is an
                # ordinary outage, NOT an off-scope block or a login-state signal — surface it as a
                # navigation error so a probe classifies it "error", not "stale".
                if "net::err_" in msg:
                    return {"error": True, "reason": "navigation failed", "url": redact_url(page.url)[0]}
                raise
            await self._human_pause(0.2, 0.7)
            # The settling interval is exactly when a confined page schedules an
            # off-scope redirect (expired sessions bounce after DOMContentLoaded):
            # goto() may have returned first, the route guard aborts the redirect
            # during the pause and sets the flag, and no exception crosses the try
            # above. Recheck, or a freshness probe could read retained authenticated-
            # looking DOM and classify a stale jar as fresh.
            if self.confine_origins and self._nav_off_scope_block is not None:
                return {
                    "blocked": True,
                    "reason": "off-scope navigation blocked",
                    "url": redact_url(page.url)[0],
                    "target_origin": self._nav_off_scope_block,
                }
            title = await self._safe_title(page)
            return {"url": redact_url(page.url)[0], "title": title}
        if request.type in {"click", "type_text", "select"}:
            target = await self._resolve_action_target(request, page)
            if isinstance(target, dict):
                return target
            if request.type == "click":
                await self._human_pause(0.05, 0.2)
                if self.stealth:
                    # A randomized mousedown->mouseup hold instead of the instant
                    # synthetic click default.
                    await page.locator(target).click(delay=random.uniform(30, 90))
                else:
                    await page.locator(target).click()
                return await self._current_page_result({"accepted": True})
            if request.type == "type_text":
                locator = page.locator(target)
                text = str(request.args["text"])
                human_typing = self.stealth and len(text) <= 200
                if human_typing:
                    # Only text-like controls take per-key delivery. Specialized
                    # inputs (date/color/range/checkbox...) have value semantics that
                    # literal keystrokes either mangle or miss entirely — keep fill()'s
                    # serialized-value behavior for those.
                    try:
                        human_typing = bool(
                            await locator.evaluate(
                                "(el) => el.isContentEditable || el.tagName === 'TEXTAREA' || "
                                "(el.tagName === 'INPUT' && ['text', 'search', 'url', 'tel', 'password', 'email', 'number']"
                                ".includes((el.type || '').toLowerCase()))"
                            )
                        )
                    except Exception:
                        # Target not resolvable to an element: fall back to fill().
                        human_typing = False
                if human_typing:
                    # Human-ish entry for short fields: per-key delivery with a FRESH
                    # jittered pause before every keystroke — a single constant delay
                    # passed to press_sequentially would produce a perfectly regular
                    # machine cadence. No synthetic mouse click — fill("")/
                    # press_sequentially focus the control themselves, and a click
                    # could fire onclick handlers (submit, navigate, clear dependent
                    # fields) that plain typing never did. fill("") first so the
                    # command keeps type_text's REPLACEMENT semantics —
                    # press_sequentially alone inserts at the caret and would splice
                    # new text into an autofilled/pre-filled value.
                    await self._human_pause(0.05, 0.2)
                    await locator.fill("")
                    for char in text:
                        await locator.press_sequentially(char)
                        await asyncio.sleep(random.uniform(0.045, 0.11))
                else:
                    await locator.fill(text)
                return await self._current_page_result({"accepted": True})
            if request.type == "select":
                await page.locator(target).select_option(str(request.args["value"]))
                return await self._current_page_result({"accepted": True})
        if request.type == "press_key":
            await page.keyboard.press(str(request.args["key"]))
            return await self._current_page_result({"accepted": True})
        if request.type == "snapshot":
            next_ref = coerce_next_ref(request.args.get("next_ref"))

            async def _walk() -> dict[str, Any]:
                return cast(dict[str, Any], await page.evaluate(SNAPSHOT_JS, next_ref))

            async def _degraded_snapshot() -> dict[str, Any]:
                # The walker could not complete because the document it was
                # reading was replaced mid-evaluate. Return a well-formed but
                # empty snapshot (marked "partial") instead of raising: the
                # agent-command endpoint would otherwise 500 while holding the
                # session lock, and clients would keep acting on refs captured
                # before the navigation.
                return {
                    "url": redact_url(page.url)[0],
                    "title": await self._safe_title(page),
                    "forms": 0,
                    "elements": 0,
                    "next_ref": next_ref,
                    "roots": [],
                    "partial": True,
                }

            result = await self._with_navigation_recovery(page, _walk, fallback=_degraded_snapshot)
            raw_url = result.get("url", "") or page.url
            result["url"] = redact_url(raw_url)[0]
            hint = await self._ucp.snapshot_hint(raw_url)
            if hint is not None:
                result["ucp"] = hint
            return result
        if request.type == "screenshot":
            png = await page.screenshot(type="png", full_page=False)
            return {"mime_type": "image/png", "image_base64": base64.b64encode(png).decode("ascii")}
        if request.type == "extract":
            selector = request.args.get("selector")
            if selector:
                html = await page.locator(str(selector)).inner_html()
            else:
                html = await page.content()
            return {"url": redact_url(page.url)[0], "html": html, "selector": selector}
        if request.type == "exec":
            from patchright.async_api import Error as PlaywrightError

            try:
                result = await page.evaluate(_wrap_exec_code(str(request.args.get("code", ""))))
            except PlaywrightError as exc:
                return {"error": str(exc), "url": redact_url(page.url)[0]}
            return {"result": result, "url": redact_url(page.url)[0]}
        if request.type == "wait":
            from typing import Literal

            from patchright.async_api import TimeoutError as PlaywrightTimeoutError

            selector = request.args.get("selector")
            timeout_ms = float(request.args.get("timeout_ms", 5000))
            raw_state = str(request.args.get("state", "domcontentloaded"))
            state: Literal["domcontentloaded", "load", "networkidle"]
            if raw_state == "load":
                state = "load"
            elif raw_state == "networkidle":
                state = "networkidle"
            else:
                state = "domcontentloaded"
            try:
                if selector:
                    await page.wait_for_selector(str(selector), timeout=timeout_ms)
                else:
                    await page.wait_for_load_state(state, timeout=timeout_ms)
            except PlaywrightTimeoutError as exc:
                return {"error": str(exc), "url": redact_url(page.url)[0], "title": await self._safe_title(page)}
            return {"accepted": True, "url": redact_url(page.url)[0], "title": await self._safe_title(page)}
        if request.type == "current_page":
            return {"url": redact_url(page.url)[0], "title": await self._safe_title(page)}
        if request.type == "mouse_click":
            await self._human_pause(0.05, 0.2)
            if self.stealth:
                await page.mouse.click(float(request.args["x"]), float(request.args["y"]), delay=random.uniform(30, 90))
            else:
                await page.mouse.click(float(request.args["x"]), float(request.args["y"]))
            return await self._current_page_result({"accepted": True})
        if request.type == "mouse_move":
            await page.mouse.move(float(request.args["x"]), float(request.args["y"]))
            return {"accepted": True, "url": redact_url(page.url)[0]}
        if request.type == "mouse_down":
            await page.mouse.down()
            return {"accepted": True, "url": redact_url(page.url)[0]}
        if request.type == "mouse_up":
            await page.mouse.up()
            return {"accepted": True, "url": redact_url(page.url)[0]}
        if request.type == "mouse_wheel":
            await page.mouse.wheel(float(request.args["delta_x"]), float(request.args["delta_y"]))
            return {"accepted": True, "url": redact_url(page.url)[0]}
        if request.type == "keyboard_type":
            text = str(request.args["text"])
            if self.stealth and len(text) <= 200:
                # Fresh jittered pause per key; a single constant delay would be a
                # perfectly regular (machine-recognizable) cadence.
                for char in text:
                    await page.keyboard.type(char)
                    await asyncio.sleep(random.uniform(0.045, 0.11))
            else:
                await page.keyboard.type(text)
            return {"accepted": True, "url": redact_url(page.url)[0]}
        if request.type == "keyboard_press":
            keys = request.args.get("keys", request.args.get("key"))
            await page.keyboard.press(str(keys))
            return await self._current_page_result({"accepted": True})
        if request.type == "navigate_back":
            await page.go_back()
            return await self._current_page_result({"accepted": True})
        if request.type == "navigate_forward":
            await page.go_forward()
            return await self._current_page_result({"accepted": True})
        if request.type == "close_page":
            await page.goto("about:blank")
            return {"closed": True, "url": None, "title": "Blank"}
        raise ValueError(f"unsupported command {request.type}")

    async def export_storage_state(self, max_bytes: int, *, cookies_only: bool = False) -> dict[str, Any]:
        """Export the context's storage_state (cookies + localStorage + IndexedDB).

        ``indexed_db=True`` is required — a bare storage_state() drops IndexedDB, silently
        producing jars that reload logged-out for the growing set of sites that keep their
        auth token there.

        ``cookies_only`` short-circuits to ``context.cookies()``: localStorage/IndexedDB are never
        read or materialized and no origins are returned. Cookies are not counted by
        ``navigator.storage.estimate()`` and a cookies_only jar discards client storage anyway, so a
        site with large client storage but small cookies must still be saveable without allocating it.

        Otherwise size is bounded twice: a **source-side** pre-check via ``navigator.storage.estimate()``
        rejects an origin whose client storage already exceeds the cap *before* the full state is
        materialized in the service (so a compromised in-scope page cannot force the oversized
        allocation), backed by a post-materialization check. A fully incremental export is the
        documented follow-up; the estimate covers the realistic IndexedDB-inflation DoS."""
        if self._context is None:
            raise RuntimeError("worker is closed")
        if cookies_only:
            # context.cookies() returns ONLY cookies — it never materializes localStorage/IndexedDB,
            # so a page with huge client storage cannot force an unbounded allocation on a save whose
            # result discards that storage anyway (storage_state() would read localStorage first).
            cookies = await self._context.cookies()
            state = {"cookies": list(cookies), "origins": []}
            if len(json.dumps(state).encode("utf-8")) > max_bytes:
                raise StorageTooLarge(f"storage_state exceeds {max_bytes} bytes")
            return state
        # Source-side bound: abort if ANY open page's origin already reports client-storage usage
        # over the cap, before the full (all-origin) state is materialized — storage_state below
        # serializes every origin in the context, not just the active page, so a single-page check
        # would miss an oversized IdP/other tab. Residual: an origin with persisted IndexedDB but no
        # open page is not measurable via navigator.storage.estimate() and is only caught by the
        # post-materialization check below; a per-origin/incremental export is the documented follow-up.
        for page in list(self._context.pages):
            try:
                usage = await page.evaluate(
                    "async () => { try { return (await navigator.storage.estimate()).usage || 0; }"
                    " catch (e) { return 0; } }"
                )
            except Exception:
                usage = 0
            if isinstance(usage, (int, float)) and usage > max_bytes:
                raise StorageTooLarge(f"origin client storage (~{int(usage)} bytes) exceeds {max_bytes} bytes")
        try:
            state = await self._context.storage_state(indexed_db=True)
        except TypeError:
            # Older Playwright without the indexed_db kwarg: fall back to cookies + localStorage.
            state = await self._context.storage_state()
        if len(json.dumps(state).encode("utf-8")) > max_bytes:
            raise StorageTooLarge(f"storage_state exceeds {max_bytes} bytes")
        # storage_state()'s return is typed as a Playwright-specific mapping across versions;
        # normalize to the plain dict the jar layer expects (copy, not alias).
        return cast(dict[str, Any], dict(state))

    async def selector_present(self, selector: str) -> bool | None:
        """True/False if the selector is present/absent; None if it could not be evaluated (a
        malformed selector or a transient error after navigation). None must NOT be read as a real
        absence — that would let a malformed selector be accepted as a discriminating signal and then
        mark a valid login stale on every probe."""
        if self._page is None:
            raise RuntimeError("worker is closed")
        try:
            return await self._page.evaluate("(sel) => document.querySelector(sel) !== null", selector)
        except Exception:
            return None

    async def _current_page_result(self, result: dict[str, Any]) -> dict[str, Any]:
        if self._page is None:
            raise RuntimeError("worker is closed")
        from patchright.async_api import TimeoutError as PlaywrightTimeoutError

        try:
            await self._page.wait_for_load_state("domcontentloaded", timeout=1000)
        except PlaywrightTimeoutError:
            pass
        result["url"] = redact_url(self._page.url)[0]
        result["title"] = await self._safe_title(self._page)
        return result

    async def _with_navigation_recovery(
        self,
        page: Any,
        operation: Callable[[], Awaitable[Any]],
        *,
        fallback: Callable[[], Any] | None = None,
    ) -> Any:
        """Await an in-page ``operation`` without letting a navigation race fail the command.

        Several commands evaluate inside the page's JS execution context
        (``page.title()``, ``page.evaluate`` of the accessibility walker, …).
        A client-side redirect (meta refresh, ``location =`` in an inline
        script) that fires while the command runs destroys that context, so the
        call raises "Execution context was destroyed, most likely because of a
        navigation" — which otherwise bubbles up as an opaque HTTP 500 from the
        agent-command endpoint while the command holds the session lock. This
        is the shared recovery used by every such read: wait for the
        replacement document to settle and retry a bounded number of times,
        then fall back rather than failing the whole command.

        Only a navigation-induced context teardown is retried; any other
        Playwright failure is a real error worth surfacing.
        """
        from inspect import isawaitable

        from patchright.async_api import Error as PlaywrightError

        attempts = 3
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                return await operation()
            except PlaywrightError as exc:
                # Only a navigation-induced context teardown is retryable; any
                # other Playwright failure is a real error worth surfacing.
                if "context was destroyed" not in str(exc):
                    raise
                last_exc = exc
                if attempt == attempts - 1:
                    break
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=5000)
                except PlaywrightError:
                    pass
        if fallback is None:
            assert last_exc is not None
            raise last_exc
        outcome = fallback()
        if isawaitable(outcome):
            return await outcome
        return outcome

    async def _safe_title(self, page: Any) -> str:
        """Read ``document.title`` without letting a navigation race fail the command.

        Thin wrapper over :meth:`_with_navigation_recovery`; see its docstring for
        the failure mechanism. Falls back to an empty title rather than failing
        the whole command.
        """
        return await self._with_navigation_recovery(page, page.title, fallback=lambda: "")

    async def close(self) -> None:
        self.closed = True
        if self._context is not None:
            try:
                await self._context.close()
            except Exception:
                pass
            self._context = None
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None
        if self._display is not None:
            self._display.close()
            self._display = None


@dataclass(frozen=True)
class RemoteDisplayStatus:
    available: bool
    reason: str | None = None
    novnc_path: str | None = None
    novnc_web_path: str | None = None
    websockify_path: str | None = None
    xvfb_path: str | None = None
    x11vnc_path: str | None = None


class LocalNovncDisplay:
    def __init__(
        self,
        worker_id: str,
        *,
        width: int = DEFAULT_DISPLAY_WIDTH,
        height: int = DEFAULT_DISPLAY_HEIGHT,
    ) -> None:
        self.worker_id = worker_id
        self.width = width
        self.height = height
        self.display = ""
        self.novnc_url: str | None = None
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._procs: list[subprocess.Popen] = []

    def start(self) -> str:
        status = remote_display_status()
        if not status.available:
            raise RuntimeUnavailable(status.reason or "remote display stack unavailable")
        self._tmpdir = tempfile.TemporaryDirectory(prefix=f"{self.worker_id}_")
        display_number = _free_display_number()
        vnc_port = _free_tcp_port()
        novnc_port = _free_tcp_port()
        self.display = f":{display_number}"
        xvfb = subprocess.Popen(
            [
                status.xvfb_path or "Xvfb",
                self.display,
                "-screen",
                "0",
                f"{self.width}x{self.height}x24",
                "-nolisten",
                "tcp",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._procs.append(xvfb)
        x11vnc = subprocess.Popen(
            [
                status.x11vnc_path or "x11vnc",
                "-display",
                self.display,
                "-localhost",
                "-nopw",
                "-forever",
                "-shared",
                "-rfbport",
                str(vnc_port),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._procs.append(x11vnc)
        if not status.novnc_web_path or not status.websockify_path:
            raise RuntimeUnavailable("noVNC web assets or websockify are unavailable")
        novnc_cmd = [
            status.websockify_path,
            "--web",
            status.novnc_web_path,
            f"127.0.0.1:{novnc_port}",
            f"127.0.0.1:{vnc_port}",
        ]
        novnc = subprocess.Popen(novnc_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._procs.append(novnc)
        # resize=scale keeps the fixed form-factor framebuffer and scales it to fit the
        # viewport container, which the UI sizes to match the session aspect ratio.
        self.novnc_url = f"http://127.0.0.1:{novnc_port}/vnc.html?autoconnect=1&resize=scale"
        return self.novnc_url

    def close(self) -> None:
        for proc in reversed(self._procs):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._procs.clear()
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None


@lru_cache(maxsize=1)
def remote_display_status() -> RemoteDisplayStatus:
    """Probe the host for the headed-session noVNC stack.

    The result is memoized: when the binaries are absent, the fallback scan in
    ``_find_file`` walks ``/usr/share``, ``/usr/local/share``, ``/opt`` and
    ``/workspace`` with a 2s timeout per root, which can cost several seconds on
    hosts with large filesystem trees (e.g. a macOS VM's /opt). That made every
    ``/health`` request take multiple seconds and broke clients polling health
    with short timeouts. Binary availability cannot change within a running
    process, so one probe per process is sufficient; tests that need to re-detect
    can call ``remote_display_status.cache_clear()`` first.
    """
    novnc_path = shutil.which("novnc_proxy") or _find_file("novnc_proxy")
    novnc_web_path = _find_novnc_web_path(novnc_path)
    websockify_path = shutil.which("websockify")
    xvfb_path = shutil.which("Xvfb")
    x11vnc_path = shutil.which("x11vnc")
    missing = [
        name
        for name, path in {
            "novnc_proxy": novnc_path,
            "noVNC web assets": novnc_web_path,
            "websockify": websockify_path,
            "Xvfb": xvfb_path,
            "x11vnc": x11vnc_path,
        }.items()
        if not path
    ]
    if missing:
        return RemoteDisplayStatus(
            available=False,
            reason=f"missing remote display binaries: {', '.join(missing)}",
            novnc_path=novnc_path,
            novnc_web_path=novnc_web_path,
            websockify_path=websockify_path,
            xvfb_path=xvfb_path,
            x11vnc_path=x11vnc_path,
        )
    return RemoteDisplayStatus(
        available=True,
        novnc_path=novnc_path,
        novnc_web_path=novnc_web_path,
        websockify_path=websockify_path,
        xvfb_path=xvfb_path,
        x11vnc_path=x11vnc_path,
    )


def make_worker(
    worker_id: str,
    *,
    width: int = DEFAULT_DISPLAY_WIDTH,
    height: int = DEFAULT_DISPLAY_HEIGHT,
    user_agent: str | None = None,
    storage_state: dict[str, Any] | None = None,
    confine_origins: list[str] | None = None,
    timezone_id: str | None = None,
) -> BrowserRuntime:
    runtime = os.environ.get("BROWSER_RUNTIME", "playwright").lower()
    # Fall back to the operator-level default timezone when the caller did not request
    # one, so sessions created without an explicit timezone still report local time.
    resolved_timezone_id = timezone_id or os.environ.get("BROWSER_TIMEZONE") or None
    if runtime == "fake":
        return FakeBrowserWorker(
            worker_id,
            storage_state=storage_state,
            confine_origins=confine_origins,
            timezone_id=resolved_timezone_id,
        )
    return PlaywrightBrowserWorker(
        worker_id,
        headed=os.environ.get("BROWSER_HEADED") == "1",
        width=width,
        height=height,
        user_agent=user_agent,
        storage_state=storage_state,
        confine_origins=confine_origins,
        timezone_id=resolved_timezone_id,
    )


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _free_display_number() -> int:
    for number in range(90, 200):
        if not os.path.exists(f"/tmp/.X11-unix/X{number}"):
            return number
    raise RuntimeUnavailable("no free X display number found")


def _find_file(name: str) -> str | None:
    for root in ("/usr/share", "/usr/local/share", "/opt", "/workspace"):
        try:
            result = subprocess.run(
                ["find", root, "-name", name, "-type", "f", "-print", "-quit"],
                text=True,
                capture_output=True,
                timeout=2,
                check=False,
            )
        except Exception:
            continue
        candidate = result.stdout.strip()
        if candidate:
            return candidate
    return None


def _find_novnc_web_path(novnc_path: str | None) -> str | None:
    if novnc_path is None:
        return None
    from pathlib import Path

    script = Path(novnc_path).resolve()
    candidates = [
        script.parent,
        script.parent.parent,
        script.parent.parent / "share" / "novnc",
        Path("/usr/share/novnc"),
        Path("/usr/local/share/novnc"),
    ]
    for candidate in candidates:
        if (candidate / "vnc.html").exists():
            return str(candidate)
    return None
