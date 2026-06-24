from __future__ import annotations

import base64
import os
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Protocol

from .models import AgentCommandRequest
from .security import redact_url
from .ucp import UCPDetector


class RuntimeUnavailable(RuntimeError):
    pass


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


class FakeBrowserWorker:
    def __init__(self, worker_id: str) -> None:
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

    async def _ucp_fetch(self, url: str) -> Any:
        return self.ucp_documents.get(url)

    async def start(self) -> None:
        return None

    async def command(self, request: AgentCommandRequest) -> dict[str, Any]:
        if self.closed:
            raise RuntimeError("worker is closed")
        if request.type == "navigate":
            url = str(request.args["url"])
            self.url = url
            self.title = f"Fixture page at {redact_url(url)[1] or url}"
            return {"url": redact_url(url)[0], "title": self.title}
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
    ) -> None:
        self.worker_id = worker_id
        self.closed = False
        self.headed = headed
        self.width = width
        self.height = height
        self.user_agent = user_agent
        self._playwright = None
        self._browser = None
        self._page = None
        self.remote_url: str | None = None
        self._display: LocalNovncDisplay | None = None
        self._ucp = UCPDetector(self._ucp_fetch)

    async def _ucp_fetch(self, url: str) -> Any:
        """Probe a UCP well-known document through the live browser context.

        Reuses the page's network stack (cookies, TLS, proxy) for a read-only GET
        to the fixed ``/.well-known/ucp`` path. The response is parsed as JSON and
        never rendered into the page; any failure yields ``None``.
        """
        if self._page is None:
            return None
        try:
            response = await self._page.context.request.get(url, timeout=5000)
            if not response.ok:
                return None
            return await response.json()
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
            self._browser = await self._playwright.chromium.launch(
                headless=not self.headed,
                args=args,
                env=env,
            )
            page_kwargs: dict[str, Any] = {"viewport": {"width": self.width, "height": self.height}}
            if self.user_agent:
                # A mobile UA plus touch makes sites render their mobile layout.
                page_kwargs["user_agent"] = self.user_agent
                page_kwargs["is_mobile"] = True
                page_kwargs["has_touch"] = True
            else:
                # Use a realistic desktop Chrome UA to avoid bot detection.
                page_kwargs["user_agent"] = (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                )
            self._page = await self._browser.new_page(**page_kwargs)
        except Exception as exc:
            await self.close()
            raise RuntimeUnavailable(str(exc)) from exc

    async def command(self, request: AgentCommandRequest) -> dict[str, Any]:
        if self.closed or self._page is None:
            raise RuntimeError("worker is closed")
        page = self._page
        if request.type == "navigate":
            url = str(request.args["url"])
            await page.goto(url, wait_until="domcontentloaded")
            title = await page.title()
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
                return {"error": str(exc), "url": redact_url(page.url)[0], "title": await page.title()}
            return {"accepted": True, "url": redact_url(page.url)[0], "title": await page.title()}
        if request.type == "current_page":
            return {"url": redact_url(page.url)[0], "title": await page.title()}
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

    async def _current_page_result(self, result: dict[str, Any]) -> dict[str, Any]:
        if self._page is None:
            raise RuntimeError("worker is closed")
        from rebrowser_playwright.async_api import TimeoutError as PlaywrightTimeoutError

        try:
            await self._page.wait_for_load_state("domcontentloaded", timeout=1000)
        except PlaywrightTimeoutError:
            pass
        result["url"] = redact_url(self._page.url)[0]
        result["title"] = await self._page.title()
        return result

    async def close(self) -> None:
        self.closed = True
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
) -> BrowserRuntime:
    runtime = os.environ.get("BROWSER_RUNTIME", "playwright").lower()
    if runtime == "fake":
        return FakeBrowserWorker(worker_id)
    return PlaywrightBrowserWorker(
        worker_id,
        headed=os.environ.get("BROWSER_HEADED") == "1",
        width=width,
        height=height,
        user_agent=user_agent,
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
