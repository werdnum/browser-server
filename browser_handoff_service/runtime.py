from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .models import AgentCommandRequest
from .security import redact_url
from .ucp import UCPDetector

# Bound the merchant-controlled UCP probe so a huge or slow-trickle
# /.well-known/ucp response cannot tie up the snapshot — which the registry
# awaits while holding the session lock — past a small fixed budget.
_UCP_PROBE_TIMEOUT_S = 5.0
_UCP_PROBE_MAX_BYTES = 256 * 1024


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


# In-page DOM walker. Tags interactive/labeled elements with a stable
# ``data-fa-ref`` attribute and returns a nested accessibility tree. The shape
# matches the ``Snapshot`` contract consumed by the Family Assistant browser
# tools, so the same rich tools work against this remote worker as against a
# local Playwright page. The ref ``e12`` always resolves to the selector
# ``[data-fa-ref="e12"]``, which agents pass straight to click/type_text/select.
_SNAPSHOT_JS = r"""
() => {
  document.querySelectorAll('[data-fa-ref]').forEach(el => el.removeAttribute('data-fa-ref'));

  let refCounter = 0;
  const allocRef = () => 'e' + (++refCounter);

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

  function walk(el, out) {
    if (el.nodeType !== 1) return;
    if (!isVisible(el)) return;
    const role = interesting(el);
    if (role) {
      const ref = allocRef();
      el.setAttribute('data-fa-ref', ref);
      const node = { ref, role, name: accName(el) };
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
    elements: refCounter,
    roots,
  };
}
"""


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
    ) -> None:
        self.worker_id = worker_id
        self.closed = False
        self.remote_url: str | None = None
        self.url: str | None = None
        self.title = "Blank"
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
            self.actions.append({"type": request.type, "args": request.args})
            return {"accepted": True, "url": redact_url(self.url)[0] if self.url else None, "title": self.title}
        if request.type == "snapshot":
            result: dict[str, Any] = {
                "url": redact_url(self.url)[0] if self.url else "about:blank",
                "title": self.title,
                "forms": 0,
                "elements": 1,
                "roots": [{"ref": "e1", "role": "document", "name": self.title}],
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
    ) -> None:
        self.worker_id = worker_id
        self.closed = False
        self.headed = headed
        self.width = width
        self.height = height
        self.user_agent = user_agent
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
            from rebrowser_playwright.async_api import async_playwright

            env: dict[str, str | float | bool] = dict(os.environ)
            args = [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--enable-features=NetworkService,NetworkServiceInProcess",
            ]
            if self.headed:
                self._display = LocalNovncDisplay(self.worker_id, width=self.width, height=self.height)
                self.remote_url = self._display.start()
                env["DISPLAY"] = self._display.display
                # Fill the framebuffer so the noVNC view matches the session form factor.
                args.append(f"--window-size={self.width},{self.height}")
                args.append("--window-position=0,0")
            self._playwright = await async_playwright().start()
            # BROWSER_CHROMIUM_PATH lets an operator pin a system/sidecar Chrome instead
            # of the revision bundled with rebrowser-playwright (also how tests can drive a
            # real browser when only a different revision is installed). Unset => bundled.
            executable_path = os.environ.get("BROWSER_CHROMIUM_PATH") or None
            self._browser = await self._playwright.chromium.launch(
                headless=not self.headed,
                args=args,
                env=env,
                executable_path=executable_path,
            )
            # Explicit context (rather than browser.new_page) so a jar's storage_state can be
            # seeded at creation and exported back out with context.storage_state(indexed_db=True).
            context_kwargs: dict[str, Any] = {"viewport": {"width": self.width, "height": self.height}}
            if self.user_agent:
                # A mobile UA plus touch makes sites render their mobile layout.
                context_kwargs["user_agent"] = self.user_agent
                context_kwargs["is_mobile"] = True
                context_kwargs["has_touch"] = True
            else:
                # Use a realistic desktop Chrome UA to avoid bot detection.
                context_kwargs["user_agent"] = (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                )
            if self._storage_state is not None:
                context_kwargs["storage_state"] = self._storage_state
            if self.confine_origins:
                # A Service Worker can serve document/form requests that context.route() never
                # sees, routing around the guard — so block SWs in confined contexts.
                context_kwargs["service_workers"] = "block"
            self._context = await self._browser.new_context(**context_kwargs)
            if self.confine_origins:
                await self._install_confinement(self._context)
            self._page = await self._context.new_page()
        except Exception as exc:
            await self.close()
            raise RuntimeUnavailable(str(exc)) from exc

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
        from rebrowser_playwright.async_api import Error as PlaywrightError

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

    async def _dispatch_command(self, request: AgentCommandRequest, page: Any) -> dict[str, Any]:
        if request.type == "navigate":
            from rebrowser_playwright.async_api import Error as PlaywrightError

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
            title = await self._safe_title(page)
            return {"url": redact_url(page.url)[0], "title": title}
        if request.type == "click":
            await page.locator(str(request.args["selector"])).click()
            return await self._current_page_result({"accepted": True})
        if request.type == "type_text":
            await page.locator(str(request.args["selector"])).fill(str(request.args["text"]))
            return await self._current_page_result({"accepted": True})
        if request.type == "select":
            await page.locator(str(request.args["selector"])).select_option(str(request.args["value"]))
            return await self._current_page_result({"accepted": True})
        if request.type == "press_key":
            await page.keyboard.press(str(request.args["key"]))
            return await self._current_page_result({"accepted": True})
        if request.type == "snapshot":
            result = await page.evaluate(_SNAPSHOT_JS)
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
            from rebrowser_playwright.async_api import Error as PlaywrightError

            try:
                result = await page.evaluate(_wrap_exec_code(str(request.args.get("code", ""))))
            except PlaywrightError as exc:
                return {"error": str(exc), "url": redact_url(page.url)[0]}
            return {"result": result, "url": redact_url(page.url)[0]}
        if request.type == "wait":
            from typing import Literal, cast

            from rebrowser_playwright.async_api import TimeoutError as PlaywrightTimeoutError

            selector = request.args.get("selector")
            timeout_ms = float(request.args.get("timeout_ms", 5000))
            raw_state = str(request.args.get("state", "domcontentloaded"))
            valid_states = ("domcontentloaded", "load", "networkidle")
            state = cast(
                'Literal["domcontentloaded", "load", "networkidle"]',
                raw_state if raw_state in valid_states else "domcontentloaded",
            )
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
            await page.keyboard.type(str(request.args["text"]))
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
        return dict(state)

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
        from rebrowser_playwright.async_api import TimeoutError as PlaywrightTimeoutError

        try:
            await self._page.wait_for_load_state("domcontentloaded", timeout=1000)
        except PlaywrightTimeoutError:
            pass
        result["url"] = redact_url(self._page.url)[0]
        result["title"] = await self._safe_title(self._page)
        return result

    async def _safe_title(self, page: Any) -> str:
        """Read ``document.title`` without letting a navigation race fail the command.

        ``page.title()`` evaluates inside the page's JS execution context. A
        client-side redirect (meta refresh, ``location =`` in an inline script)
        that fires immediately after ``goto`` resolves at ``domcontentloaded``
        destroys that context, so the call raises "Execution context was
        destroyed, most likely because of a navigation" — which otherwise
        bubbles up as an opaque HTTP 500. Wait for the replacement document to
        settle and retry a bounded number of times, falling back to an empty
        title rather than failing the whole command.
        """
        from rebrowser_playwright.async_api import Error as PlaywrightError

        attempts = 3
        for attempt in range(attempts):
            try:
                return await page.title()
            except PlaywrightError as exc:
                # Only a navigation-induced context teardown is retryable; any
                # other Playwright failure is a real error worth surfacing.
                if "context was destroyed" not in str(exc):
                    raise
                if attempt == attempts - 1:
                    break
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=5000)
                except PlaywrightError:
                    pass
        return ""

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


def remote_display_status() -> RemoteDisplayStatus:
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
) -> BrowserRuntime:
    runtime = os.environ.get("BROWSER_RUNTIME", "playwright").lower()
    if runtime == "fake":
        return FakeBrowserWorker(worker_id, storage_state=storage_state, confine_origins=confine_origins)
    return PlaywrightBrowserWorker(
        worker_id,
        headed=os.environ.get("BROWSER_HEADED") == "1",
        width=width,
        height=height,
        user_agent=user_agent,
        storage_state=storage_state,
        confine_origins=confine_origins,
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
