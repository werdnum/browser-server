from __future__ import annotations

import asyncio
import logging
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
    HumanActionRequest,
    SessionState,
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

LANDING_PAGE_TEMPLATE = templates.from_string(
    """<!doctype html>
<html>
<head>
  <title>Browser Handoff Service</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; max-width: 820px; line-height: 1.5; }
    nav { margin-bottom: 2rem; }
    nav a { margin-right: 1rem; }
  </style>
</head>
<body>
  <main>
    <h1>Browser Handoff Service</h1>
    <p>This service manages browser sessions and hands them off between agents and humans safely.</p>
    <nav>
      <a href="/sessions">View Sessions</a>
      <a href="/docs">API Docs</a>
      <a href="/health">Health Status</a>
    </nav>
  </main>
</body>
</html>"""
)

SESSION_LIST_TEMPLATE = templates.from_string(
    """<!doctype html>
<html>
<head>
  <title>Sessions - Browser Handoff Service</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; max-width: 820px; line-height: 1.5; }
    nav { margin-bottom: 2rem; font-size: 0.9em; }
    nav a { text-decoration: none; color: #0066cc; }
    nav a:hover { text-decoration: underline; }
    ul { list-style: none; padding: 0; }
    li { padding: 0.5rem 0; border-bottom: 1px solid #eee; }
    li a { font-weight: bold; text-decoration: none; color: #0066cc; margin-right: 1rem; }
    li a:hover { text-decoration: underline; }
    .empty { color: #666; font-style: italic; }
  </style>
</head>
<body>
  <nav>
    <a href="/">← Home</a>
  </nav>
  <main>
    <h1>Sessions</h1>
    {% if sessions %}
      <ul>
        {% for s in sessions %}
          <li>
            <a href="/sessions/{{ s.session_id }}">{{ s.session_id }}</a>
            <span class="state">{{ s.state }}</span>
          </li>
        {% endfor %}
      </ul>
    {% else %}
      <p class="empty">No active sessions found.</p>
    {% endif %}
  </main>
</body>
</html>"""
)

SESSION_DETAIL_TEMPLATE = templates.from_string(
    """<!doctype html>
<html>
<head>
  <title>Browser handoff {{ session.session_id }}</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 820px; line-height: 1.5; color: #333; }
    nav { margin-bottom: 2rem; font-size: 0.9em; }
    nav a { text-decoration: none; color: #0066cc; }
    nav a:hover { text-decoration: underline; }
    button, input { font: inherit; padding: .55rem .75rem; margin: .25rem; border: 1px solid #ccc; border-radius: 4px; background: #fff; cursor: pointer; }
    button:hover { background: #f0f0f0; }
    .viewport { height: 480px; border: 1px solid #bbb; border-radius: 8px; display: grid; place-items: center; margin-top: 1.5rem; background: #fafafa; }
    .status { padding: .75rem; background: #eef2f5; border-radius: 4px; border: 1px solid #d0d7de; }
  </style>
</head>
<body data-session-id="{{ session.session_id }}" data-token="{{ token }}">
  <nav>
    <a href="/">Home</a> &gt; <a href="/sessions">Sessions</a> &gt; {{ session.session_id }}
  </nav>
  <main>
    <h1>Browser handoff</h1>
    <p class="status">State: <strong id="state">{{ session.state }}</strong></p>
    <p id="handoff-note">{{ session.handoff_note }}</p>
    <button id="claim">Claim</button>
    <button id="extend">Extend</button>
    <button id="sensitive">Mark sensitive</button>
    <button id="complete">Complete</button>
    <button id="cancel">Cancel</button>
    <div class="viewport" id="viewport">Remote viewport not connected</div>
  </main>
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
    document.querySelector("#claim").onclick = async () => {
      const claim = await post(`/v1/sessions/${sid}/claim`, {token});
      token = claim.control_token;
      document.body.dataset.token = token;
      const remote = await fetch(`/v1/sessions/${sid}/remote?token=${encodeURIComponent(token)}`);
      document.querySelector("#viewport").textContent = remote.ok ? "noVNC viewport authorized" : "Remote viewport unavailable";
    };
    document.querySelector("#extend").onclick = () => post(`/v1/sessions/${sid}/extend`, {token, minutes: 5});
    document.querySelector("#sensitive").onclick = () => post(`/v1/sessions/${sid}/mark-sensitive`, {token});
    document.querySelector("#complete").onclick = () => post(`/v1/sessions/${sid}/complete`, {token, outcome: "done"});
    document.querySelector("#cancel").onclick = () => post(`/v1/sessions/${sid}/cancel`, {token, outcome: "cancelled"});
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
            options = {"verify_aud": False} if not audience else {}

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


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_service_auth)])
async def landing_page():
    return LANDING_PAGE_TEMPLATE.render()


@app.get("/health")
@app.get("/healthz")
async def health():
    return {"ok": True, "remote_display": remote_display_status().__dict__}


@app.post("/v1/sessions", dependencies=[Depends(require_service_auth)])
async def create_session(req: CreateSessionRequest):
    session = await registry.create_session(req)
    if session.state == SessionState.FAILED:
        raise HTTPException(status_code=503, detail="browser runtime unavailable")
    return session


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
        session, url = await registry.handoff(session_id, req, str(request.base_url))
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
    response = JSONResponse(
        {
            "session_id": session_id,
            "novnc_url": novnc_proxy_url(session_id, str(request.base_url), remote_url),
        }
    )
    response.set_cookie(
        _novnc_cookie_name(session_id),
        token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
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
        response.set_cookie(
            _novnc_cookie_name(session_id),
            token,
            httponly=True,
            samesite="lax",
            secure=request.url.scheme == "https",
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
    return SESSION_DETAIL_TEMPLATE.render(session=session, token=token or "")


async def _expiry_loop() -> None:
    while True:
        await asyncio.sleep(1)
        await registry.reap_expired()


def novnc_proxy_url(session_id: str, public_base_url: str, remote_url: str) -> str:
    remote_query = dict(parse_qsl(urlsplit(remote_url).query, keep_blank_values=True))
    query = {
        "autoconnect": remote_query.get("autoconnect", "1"),
        "resize": remote_query.get("resize", "remote"),
        "path": f"/v1/sessions/{session_id}/novnc/websockify",
    }
    public = urlsplit(public_base_url)
    path = f"/v1/sessions/{session_id}/novnc/vnc.html"
    return urlunsplit((public.scheme, public.netloc, path, urlencode(query), ""))


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
