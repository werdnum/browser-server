from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jwt.types import Options

import os
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
import jwt
import websockets
from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from jinja2 import Environment, StrictUndefined, select_autoescape

from .models import (
    AgentCommandRequest,
    ClaimRequest,
    CreateSessionRequest,
    ExtendRequest,
    HandoffRequest,
    HandoffResponse,
    HandoverRequest,
    HumanActionRequest,
    SessionState,
    form_factor_profile,
)
from .registry import AuthorizationError, ConflictError, NotFoundError, SessionRegistry
from .runtime import remote_display_status
from .transitions import TransitionError

SERVICE_TOKEN_ENV = "BROWSER_HANDOFF_SERVICE_TOKEN"
registry = SessionRegistry()

templates = Environment(
    autoescape=select_autoescape(enabled_extensions=("html", "xml"), default_for_string=True),
    undefined=StrictUndefined,
)

BASE_CSS = """
    :root {
      --bg: #f4f6fb; --surface: #ffffff; --surface-2: #eef2f8; --border: #e3e8ef;
      --text: #1b2433; --muted: #64748b; --primary: #2563eb; --primary-hover: #1d4ed8;
      --on-primary: #ffffff; --danger: #dc2626; --danger-hover: #b91c1c;
      --radius: 14px; --radius-sm: 9px;
      --shadow: 0 1px 2px rgba(16,24,40,.06), 0 4px 12px rgba(16,24,40,.05);
      --maxw: 880px;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0b1220; --surface: #151d2e; --surface-2: #1d273b; --border: #2a3550;
        --text: #e6ecf5; --muted: #94a3b8; --primary: #3b82f6; --primary-hover: #60a5fa;
        --danger: #ef4444; --danger-hover: #f87171;
        --shadow: 0 1px 2px rgba(0,0,0,.4), 0 6px 18px rgba(0,0,0,.35);
      }
    }
    *, *::before, *::after { box-sizing: border-box; }
    html { -webkit-text-size-adjust: 100%; }
    body {
      margin: 0; background: var(--bg); color: var(--text); line-height: 1.55;
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    .wrap { max-width: var(--maxw); margin: 0 auto; padding: 1.25rem 1rem 3rem; }
    .brand { display: flex; align-items: center; gap: .6rem; margin: 1rem 0 1.5rem; }
    .brand .logo {
      width: 38px; height: 38px; border-radius: 11px; flex: none; display: grid;
      place-items: center; background: linear-gradient(135deg, var(--primary), #7c3aed);
      color: #fff; font-size: 1.15rem;
    }
    .brand .name { font-size: 1.1rem; font-weight: 650; letter-spacing: -.01em; }
    h1 { letter-spacing: -.02em; line-height: 1.2; }
    .crumbs {
      font-size: .85rem; color: var(--muted); margin: 0 0 1.25rem;
      display: flex; flex-wrap: wrap; gap: .4rem; align-items: center;
    }
    .crumbs a { color: var(--muted); text-decoration: none; }
    .crumbs a:hover { color: var(--primary); text-decoration: underline; }
    .crumbs .sep { opacity: .5; }
    .card {
      background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
      box-shadow: var(--shadow); padding: 1.5rem; margin: 0 0 1.25rem;
    }
    .lead { color: var(--muted); margin-top: .35rem; }
    .actions { display: flex; flex-wrap: wrap; gap: .55rem; margin: 1rem 0; }
    .actions:last-child { margin-bottom: 0; }
    .btn {
      font: inherit; font-weight: 560; line-height: 1; display: inline-flex; align-items: center;
      justify-content: center; gap: .4rem; padding: .7rem 1.05rem; min-height: 44px;
      border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface);
      color: var(--text); cursor: pointer; text-decoration: none;
      transition: background .15s, border-color .15s, transform .05s;
      -webkit-tap-highlight-color: transparent;
    }
    .btn:hover { background: var(--surface-2); }
    .btn:active { transform: translateY(1px); }
    .btn:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
    .btn-primary { background: var(--primary); border-color: var(--primary); color: var(--on-primary); }
    .btn-primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
    .btn-danger { color: var(--danger); border-color: var(--danger); }
    .btn-danger:hover { background: var(--danger); color: #fff; }
    input[type=text] {
      font: inherit; width: 100%; padding: .7rem .85rem; min-height: 44px;
      border: 1px solid var(--border); border-radius: var(--radius-sm);
      background: var(--surface); color: var(--text);
    }
    input[type=text]:focus-visible { outline: 2px solid var(--primary); outline-offset: 1px; border-color: var(--primary); }
    a { color: var(--primary); }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9em;
      background: var(--surface-2); padding: .15rem .4rem; border-radius: 6px; word-break: break-all;
    }
    .badge {
      display: inline-block; font-size: .8rem; font-weight: 650; padding: .25rem .65rem;
      border-radius: 999px; background: var(--surface-2); color: var(--muted); border: 1px solid var(--border);
    }
    .muted { color: var(--muted); }
    @media (max-width: 560px) {
      .wrap { padding: 1rem .85rem 2.5rem; }
      .card { padding: 1.15rem; }
      .actions .btn { flex: 1 1 calc(50% - .55rem); }
    }
"""

_BRAND = '<div class="brand"><span class="logo">\U0001f5a5️</span><span class="name">Browser Handoff</span></div>'


def _html_head(title: str, extra_css: str = "") -> str:
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n'
        '  <meta charset="utf-8" />\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1" />\n'
        '  <meta name="color-scheme" content="light dark" />\n'
        f"  <title>{title}</title>\n"
        "  <style>" + BASE_CSS + extra_css + "  </style>\n"
        "</head>\n"
    )


LANDING_PAGE_TEMPLATE = templates.from_string(
    _html_head("Browser Handoff Service")
    + """<body>
  <div class="wrap">
    """
    + _BRAND
    + """
    <main>
      <div class="card">
        <h1 style="margin-top:0">Hand off a browser, safely</h1>
        <p class="lead">Spin up a managed browser session and pass control between agents and humans without losing the thread.</p>
        <div class="actions">
          <button id="start" class="btn btn-primary">Start a browser session</button>
        </div>
        <p id="start-status" class="muted" role="status" aria-live="polite"></p>
      </div>
      <nav class="actions">
        <a class="btn" href="/sessions">View Sessions</a>
        <a class="btn" href="/docs">API Docs</a>
        <a class="btn" href="/health">Health Status</a>
      </nav>
    </main>
  </div>
  <script>
    document.querySelector("#start").onclick = async () => {
      const status = document.querySelector("#start-status");
      status.textContent = "Starting…";
      const res = await fetch("/v1/sessions", {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({
          conversation_id: `conv_${Date.now()}`,
          initial_owner: "human",
          // Detect the user's aspect ratio so the session matches their device.
          client_viewport: {
            width: window.innerWidth || screen.width,
            height: window.innerHeight || screen.height,
          },
        }),
      });
      const json = await res.json();
      if (!res.ok || !json.session_url) {
        status.textContent = json.detail || "Could not start a session";
        return;
      }
      window.location.href = json.session_url;
    };
  </script>
</body>
</html>"""
)

SESSION_LIST_TEMPLATE = templates.from_string(
    _html_head(
        "Sessions - Browser Handoff Service",
        extra_css="""
    .session-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: .6rem; }
    .session-list li {
      display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap;
      background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm);
      box-shadow: var(--shadow); padding: .85rem 1rem;
    }
    .session-list .sid { font-weight: 600; text-decoration: none; word-break: break-all; }
    .session-list .sid:hover { text-decoration: underline; }
""",
    )
    + """<body>
  <div class="wrap">
    """
    + _BRAND
    + """
    <nav class="crumbs"><a href="/">Home</a><span class="sep">›</span><span>Sessions</span></nav>
    <main>
      <h1>Sessions</h1>
      {% if sessions %}
        <ul class="session-list">
          {% for s in sessions %}
            <li>
              <a class="sid" href="/sessions/{{ s.session_id }}">{{ s.session_id }}</a>
              <span class="badge">{{ s.state }}</span>
            </li>
          {% endfor %}
        </ul>
      {% else %}
        <div class="card"><p class="empty muted" style="margin:0">No active sessions found.</p></div>
      {% endif %}
    </main>
  </div>
</body>
</html>"""
)

SESSION_DETAIL_TEMPLATE = templates.from_string(
    _html_head(
        "Browser handoff {{ session.session_id }}",
        extra_css="""
    .status { margin: 0 0 1rem; font-size: .95rem; color: var(--muted); display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
    .field { margin: 1.25rem 0; }
    .field label { display: block; font-weight: 600; font-size: .9rem; margin-bottom: .4rem; }
    .field .actions { margin-bottom: 0; }
    .notice {
      background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius-sm);
      padding: .9rem 1rem; margin: 1rem 0 0; font-size: .92rem;
    }
    .notice p { margin: .4rem 0; }
    .notice p:first-child { margin-top: 0; }
    .notice p:last-child { margin-bottom: 0; }
    .error { border-color: var(--danger); color: var(--danger); background: var(--surface); }
    .viewport {
      width: {{ viewport_width }}px; height: {{ viewport_height }}px; max-width: 100%;
      margin: 0 auto; border: 1px solid var(--border); border-radius: var(--radius);
      display: grid; place-items: center; background: var(--surface-2); color: var(--muted);
      overflow: hidden; box-shadow: var(--shadow);
    }
    .viewport.connected { display: block; }
    .viewport iframe { width: 100%; height: 100%; border: 0; display: block; }
""",
    )
    + """<body data-session-id="{{ session.session_id }}" data-token="{{ token }}">
  <div class="wrap">
    """
    + _BRAND
    + """
    <nav class="crumbs">
      <a href="/">Home</a><span class="sep">›</span>
      <a href="/sessions">Sessions</a><span class="sep">›</span>
      <span>{{ session.session_id }}</span>
    </nav>
    <main>
      <div class="card">
        <h1 style="margin-top:0">Browser handoff</h1>
        <p class="status">State: <strong id="state" class="badge">{{ session.state }}</strong></p>
        <p id="handoff-note" class="lead">{{ session.handoff_note }}</p>
        <div class="actions">
          <button id="claim" class="btn btn-primary">Claim</button>
          <button id="extend" class="btn">Extend</button>
          <button id="sensitive" class="btn">Mark sensitive</button>
        </div>
        <div class="field">
          <label for="handover-note">Hand over to an agent</label>
          <input id="handover-note" type="text" placeholder="What should the agent do next?" />
          <div class="actions">
            <button id="handover" class="btn btn-primary">Hand over to agent</button>
          </div>
        </div>
        <div class="actions">
          <button id="complete" class="btn">Complete</button>
          <button id="cancel" class="btn btn-danger">Cancel</button>
        </div>
        <div id="handover-result" class="notice" hidden>
          <p>Give this one-time token to your agent so it can take over the session:</p>
          <p><code id="handover-token"></code></p>
          <p class="muted">The agent claims it with <code>POST <span id="handover-claim-url"></span></code> and <code>{"token": "&lt;token&gt;"}</code>.</p>
        </div>
        <p id="handover-pending" class="notice" hidden>Handover pending — the one-time token was shown once and cannot be redisplayed. Click Cancel to abort and start over.</p>
      </div>
      <div class="viewport" id="viewport">Remote viewport not connected</div>
    </main>
  </div>
  <script>
    const sid = document.body.dataset.sessionId;
    let token = document.body.dataset.token;
    async function post(path, body) {
      const res = await fetch(path, {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(body)});
      const json = await res.json();
      if (!res.ok) throw new Error(json.detail || res.statusText);
      document.querySelector("#state").textContent = json.state;
      return json;
    }
    async function connectViewport() {
      const viewport = document.querySelector("#viewport");
      viewport.classList.remove("connected");
      viewport.textContent = "Connecting remote viewport...";
      const remote = await fetch(`/v1/sessions/${sid}/remote?token=${encodeURIComponent(token)}`);
      let json = {};
      try {
        json = await remote.json();
      } catch {
        json = {};
      }
      if (!remote.ok || !json.novnc_url) {
        viewport.textContent = json.detail || "Remote viewport unavailable";
        return;
      }
      const frame = document.createElement("iframe");
      frame.title = "noVNC remote browser session";
      frame.src = json.novnc_url;
      frame.allow = "clipboard-read; clipboard-write";
      viewport.replaceChildren(frame);
      viewport.classList.add("connected");
    }
    document.querySelector("#claim").onclick = async () => {
      const claim = await post(`/v1/sessions/${sid}/claim`, {token});
      token = claim.control_token;
      document.body.dataset.token = token;
      await connectViewport();
    };
    document.querySelector("#extend").onclick = () => post(`/v1/sessions/${sid}/extend`, {token, minutes: 5});
    document.querySelector("#sensitive").onclick = () => post(`/v1/sessions/${sid}/mark-sensitive`, {token});
    document.querySelector("#handover").onclick = async () => {
      const result = await post(`/v1/sessions/${sid}/handover`, {token, handoff_note: document.querySelector("#handover-note").value});
      document.querySelector("#handover-token").textContent = result.handover_token;
      document.querySelector("#handover-claim-url").textContent = result.agent_claim_url;
      document.querySelector("#handover-result").hidden = false;
    };
    document.querySelector("#complete").onclick = () => post(`/v1/sessions/${sid}/complete`, {token, outcome: "done"});
    document.querySelector("#cancel").onclick = () => post(`/v1/sessions/${sid}/cancel`, {token, outcome: "cancelled"});
    const initialState = document.querySelector("#state").textContent.trim();
    if (token && initialState === "human_active") {
      connectViewport();
    }
    if (initialState === "handover_requested") {
      document.querySelector("#handover-pending").hidden = false;
    }
  </script>
</body>
</html>"""
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    reaper = asyncio.create_task(_expiry_loop())
    try:
        yield
    finally:
        reaper.cancel()
        for session in list(registry.sessions):
            await registry.close(session)


app = FastAPI(title="Browser Handoff Service", lifespan=lifespan)


OIDC_JWKS_URL_ENV = "BROWSER_HANDOFF_OIDC_JWKS_URL"
OIDC_AUDIENCE_ENV = "BROWSER_HANDOFF_OIDC_AUDIENCE"
OIDC_ISSUER_ENV = "BROWSER_HANDOFF_OIDC_ISSUER"

_jwks_client = None


def _get_jwks_client() -> jwt.PyJWKClient | None:
    global _jwks_client
    url = os.environ.get(OIDC_JWKS_URL_ENV)
    if url and _jwks_client is None:
        _jwks_client = jwt.PyJWKClient(url)
    return _jwks_client


def require_service_auth(authorization: str | None = Header(default=None)) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid authorization header format")

    token = authorization[len("Bearer ") :]

    jwks_client = _get_jwks_client()
    if jwks_client:
        issuer = os.environ.get(OIDC_ISSUER_ENV)
        if not issuer:
            raise HTTPException(status_code=503, detail="OIDC issuer is not configured")

        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            audience = os.environ.get(OIDC_AUDIENCE_ENV)
            options: Options | None = {"verify_aud": False} if not audience else None

            jwt.decode(token, signing_key.key, algorithms=["RS256"], audience=audience, issuer=issuer, options=options)
            return  # OIDC valid
        except jwt.PyJWTError as e:
            logging.debug(f"OIDC token invalid: {e}")
            pass  # Try fallback
        except Exception as e:
            logging.error(f"Unexpected error during OIDC validation: {e}")
            raise HTTPException(status_code=500, detail="Internal server error during auth") from e

    service_token = os.environ.get(SERVICE_TOKEN_ENV)
    if not service_token:
        if jwks_client:
            raise HTTPException(status_code=401, detail="invalid OIDC token and no fallback service token configured")
        raise HTTPException(status_code=503, detail="service token is not configured")
    if token != service_token:
        raise HTTPException(status_code=401, detail="invalid service token")


def map_errors(exc: Exception) -> HTTPException:
    if isinstance(exc, NotFoundError):
        return HTTPException(status_code=404, detail="unknown session")
    if isinstance(exc, AuthorizationError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, (ConflictError, TransitionError)):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


def public_base_url(request: Request) -> str:
    scheme = _first_forwarded_value(request.headers.get("x-forwarded-proto")) or request.url.scheme
    host = _first_forwarded_value(request.headers.get("x-forwarded-host")) or request.url.netloc
    prefix = _first_forwarded_value(request.headers.get("x-forwarded-prefix")) or request.scope.get("root_path", "")
    normalized_prefix = prefix.strip("/") if prefix else ""
    path = f"/{normalized_prefix}/" if normalized_prefix else "/"
    return urlunsplit((scheme, host, path, "", ""))


def _first_forwarded_value(value: str | None) -> str | None:
    if not value:
        return None
    first = value.split(",", 1)[0].strip()
    return first or None


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_service_auth)])
async def landing_page():
    return LANDING_PAGE_TEMPLATE.render()


@app.get("/health")
@app.get("/healthz")
async def health():
    return {"ok": True, "remote_display": remote_display_status().__dict__}


@app.post("/v1/sessions", dependencies=[Depends(require_service_auth)])
async def create_session(req: CreateSessionRequest, request: Request):
    session, control_token = await registry.create_session(req)
    if session.state == SessionState.FAILED:
        raise HTTPException(status_code=503, detail="browser runtime unavailable")
    if control_token is None:
        return session
    response = session.model_dump(mode="json")
    response["control_token"] = control_token
    response["session_url"] = (
        f"{public_base_url(request).rstrip('/')}/sessions/{session.session_id}?token={control_token}"
    )
    return response


@app.get("/v1/sessions/{session_id}", dependencies=[Depends(require_service_auth)])
async def get_session(session_id: str):
    try:
        return registry.get(session_id)
    except Exception as exc:
        raise map_errors(exc) from exc


@app.post("/v1/sessions/{session_id}/agent-command", dependencies=[Depends(require_service_auth)])
async def agent_command(session_id: str, req: AgentCommandRequest):
    try:
        return await registry.agent_command(session_id, req)
    except Exception as exc:
        raise map_errors(exc) from exc


@app.post(
    "/v1/sessions/{session_id}/handoff", response_model=HandoffResponse, dependencies=[Depends(require_service_auth)]
)
async def handoff(session_id: str, req: HandoffRequest, request: Request):
    try:
        session, url = await registry.handoff(session_id, req, public_base_url(request))
        return {
            "session_id": session.session_id,
            "state": session.state,
            "handoff_url": url,
            "expires_at": session.idle_expires_at,
        }
    except Exception as exc:
        raise map_errors(exc) from exc


@app.post("/v1/sessions/{session_id}/close", dependencies=[Depends(require_service_auth)])
async def close(session_id: str):
    try:
        return await registry.close(session_id)
    except Exception as exc:
        raise map_errors(exc) from exc


@app.get("/v1/sessions/{session_id}/events", dependencies=[Depends(require_service_auth)])
async def events(session_id: str):
    try:
        registry.get(session_id)
    except Exception as exc:
        raise map_errors(exc) from exc

    async def stream():
        cursor = 0
        while True:
            items = registry.events.get(session_id, [])
            while cursor < len(items):
                yield f"data: {items[cursor].model_dump_json()}\n\n"
                cursor += 1
            await asyncio.sleep(0.2)

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.post("/v1/sessions/{session_id}/claim")
async def claim(session_id: str, req: ClaimRequest):
    try:
        session, control_token = await registry.claim(session_id, req.token)
        response = session.model_dump(mode="json")
        response["control_token"] = control_token
        return response
    except Exception as exc:
        raise map_errors(exc) from exc


@app.post("/v1/sessions/{session_id}/complete")
async def complete(session_id: str, req: HumanActionRequest):
    try:
        return await registry.human_complete(session_id, req.token, req.outcome)
    except Exception as exc:
        raise map_errors(exc) from exc


@app.post("/v1/sessions/{session_id}/cancel")
async def cancel(session_id: str, req: HumanActionRequest):
    try:
        return await registry.human_cancel(session_id, req.token, req.outcome)
    except Exception as exc:
        raise map_errors(exc) from exc


@app.post("/v1/sessions/{session_id}/handover")
async def handover(session_id: str, req: HandoverRequest, request: Request):
    try:
        session, handover_token = await registry.handover(session_id, req.token, req.handoff_note)
        base_url = public_base_url(request).rstrip("/")
        return {
            "session_id": session.session_id,
            "state": session.state,
            "handover_token": handover_token,
            "agent_claim_url": f"{base_url}/v1/sessions/{session.session_id}/agent-claim",
            "expires_at": session.idle_expires_at,
        }
    except Exception as exc:
        raise map_errors(exc) from exc


@app.post("/v1/sessions/{session_id}/agent-claim", dependencies=[Depends(require_service_auth)])
async def agent_claim(session_id: str, req: ClaimRequest):
    try:
        return await registry.agent_claim(session_id, req.token)
    except Exception as exc:
        raise map_errors(exc) from exc


@app.post("/v1/sessions/{session_id}/extend")
async def extend(session_id: str, req: ExtendRequest):
    try:
        return await registry.extend(session_id, req.token, req.minutes)
    except Exception as exc:
        raise map_errors(exc) from exc


@app.post("/v1/sessions/{session_id}/mark-sensitive")
async def mark_sensitive(session_id: str, req: HumanActionRequest):
    try:
        return await registry.mark_sensitive(session_id, req.token)
    except Exception as exc:
        raise map_errors(exc) from exc


@app.get("/v1/sessions/{session_id}/remote")
async def remote(session_id: str, token: str, request: Request):
    try:
        session = await registry.authorize_remote(session_id, token)
    except Exception as exc:
        raise map_errors(exc) from exc
    status = remote_display_status()
    if not status.available:
        raise HTTPException(status_code=503, detail=status.reason)
    worker = registry.workers.get(session.worker_id or "")
    remote_url = getattr(worker, "remote_url", None)
    if not remote_url:
        raise HTTPException(status_code=503, detail="session was not started with headed noVNC runtime")
    base_url = public_base_url(request)
    response = JSONResponse(
        {
            "session_id": session_id,
            "novnc_url": novnc_proxy_url(session_id, base_url, remote_url),
        }
    )
    secure_cookie = urlsplit(base_url).scheme == "https"
    response.set_cookie(
        _novnc_cookie_name(session_id),
        token,
        httponly=True,
        samesite="lax",
        secure=secure_cookie,
        path=f"/v1/sessions/{session_id}/novnc",
    )
    return response


@app.get("/v1/sessions/{session_id}/novnc/{asset_path:path}")
async def novnc_http_proxy(session_id: str, asset_path: str, request: Request, token: str | None = None):
    try:
        session = await _authorize_novnc_request(session_id, token, request.cookies.get(_novnc_cookie_name(session_id)))
    except Exception as exc:
        raise map_errors(exc) from exc
    worker = registry.workers.get(session.worker_id or "")
    remote_url = getattr(worker, "remote_url", None)
    if not remote_url:
        raise HTTPException(status_code=503, detail="session was not started with headed noVNC runtime")
    query_items = [(key, value) for key, value in request.query_params.multi_items() if key != "token"]
    response = await _proxy_novnc_http(remote_url, asset_path, query_items)
    if token:
        secure_cookie = urlsplit(public_base_url(request)).scheme == "https"
        response.set_cookie(
            _novnc_cookie_name(session_id),
            token,
            httponly=True,
            samesite="lax",
            secure=secure_cookie,
            path=f"/v1/sessions/{session_id}/novnc",
        )
    return response


@app.websocket("/v1/sessions/{session_id}/novnc/websockify")
async def novnc_websocket_proxy(session_id: str, websocket: WebSocket):
    try:
        session = await _authorize_novnc_request(
            session_id,
            websocket.query_params.get("token"),
            websocket.cookies.get(_novnc_cookie_name(session_id)),
        )
    except Exception:
        await websocket.close(code=1008)
        return
    worker = registry.workers.get(session.worker_id or "")
    remote_url = getattr(worker, "remote_url", None)
    if not remote_url:
        await websocket.close(code=1011)
        return

    upstream_url = _novnc_upstream_websocket_url(remote_url)
    subprotocols = websocket.scope.get("subprotocols") or []
    try:
        async with websockets.connect(upstream_url, subprotocols=subprotocols, max_size=None) as upstream:
            await websocket.accept(subprotocol=upstream.subprotocol)
            await _bridge_websockets(websocket, upstream)
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            pass


@app.get("/sessions", response_class=HTMLResponse, dependencies=[Depends(require_service_auth)])
async def session_list():
    return SESSION_LIST_TEMPLATE.render(sessions=registry.list_sessions())


@app.get("/sessions/{session_id}", response_class=HTMLResponse)
async def session_detail(session_id: str, token: str | None = None):
    try:
        session = await registry.authorize_handoff_page(session_id, token or "")
    except Exception as exc:
        raise map_errors(exc) from exc
    profile = form_factor_profile(session.form_factor)
    box_width, box_height = _viewport_box(profile.width, profile.height)
    return SESSION_DETAIL_TEMPLATE.render(
        session=session,
        token=token or "",
        viewport_width=box_width,
        viewport_height=box_height,
    )


def _viewport_box(width: int, height: int, max_width: int = 760, max_height: int = 620) -> tuple[int, int]:
    """Scale the session framebuffer into a bounding box, preserving its aspect ratio.

    Keeps the on-page viewport matching the session form factor (portrait for mobile,
    landscape for desktop) without exceeding the page layout.
    """
    scale = min(max_width / width, max_height / height, 1.0)
    return round(width * scale), round(height * scale)


async def _expiry_loop() -> None:
    while True:
        await asyncio.sleep(1)
        await registry.reap_expired()


def novnc_proxy_url(session_id: str, public_base_url: str, remote_url: str) -> str:
    public = urlsplit(public_base_url)
    prefix = public.path.rstrip("/")
    novnc_path = f"{prefix}/v1/sessions/{session_id}/novnc/vnc.html"
    websockify_path = f"{prefix}/v1/sessions/{session_id}/novnc/websockify"
    remote_query = dict(parse_qsl(urlsplit(remote_url).query, keep_blank_values=True))
    query = {
        "autoconnect": remote_query.get("autoconnect", "1"),
        "resize": remote_query.get("resize", "scale"),
        "path": websockify_path,
    }
    return urlunsplit((public.scheme, public.netloc, novnc_path, urlencode(query), ""))


def _novnc_cookie_name(session_id: str) -> str:
    return f"novnc_{session_id}"


async def _authorize_novnc_request(session_id: str, token: str | None, cookie_token: str | None):
    auth_token = token or cookie_token or ""
    return await registry.authorize_remote(session_id, auth_token)


async def _proxy_novnc_http(remote_url: str, asset_path: str, query_items: list[tuple[str, str]]) -> Response:
    upstream_url = _novnc_upstream_http_url(remote_url, asset_path, query_items)
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        upstream = await client.get(upstream_url)
    headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() in {"content-type", "cache-control", "etag", "last-modified"}
    }
    return Response(content=upstream.content, status_code=upstream.status_code, headers=headers)


def _novnc_upstream_http_url(remote_url: str, asset_path: str, query_items: list[tuple[str, str]]) -> str:
    remote = urlsplit(remote_url)
    path = f"/{asset_path.lstrip('/') or 'vnc.html'}"
    return urlunsplit((remote.scheme, remote.netloc, path, urlencode(query_items), ""))


def _novnc_upstream_websocket_url(remote_url: str) -> str:
    remote = urlsplit(remote_url)
    scheme = "wss" if remote.scheme == "https" else "ws"
    return urlunsplit((scheme, remote.netloc, "/websockify", "", ""))


async def _bridge_websockets(client: WebSocket, upstream) -> None:
    async def client_to_upstream() -> None:
        while True:
            message = await client.receive()
            if message["type"] == "websocket.disconnect":
                await upstream.close()
                return
            if message.get("bytes") is not None:
                await upstream.send(message["bytes"])
            elif message.get("text") is not None:
                await upstream.send(message["text"])

    async def upstream_to_client() -> None:
        async for message in upstream:
            if isinstance(message, bytes):
                await client.send_bytes(message)
            else:
                await client.send_text(message)

    tasks = {
        asyncio.create_task(client_to_upstream()),
        asyncio.create_task(upstream_to_client()),
    }
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    for task in done:
        task.result()
