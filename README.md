# Browser Handoff Service MVP

Standalone FastAPI MVP for browser handoff sessions.

Implemented:

- In-memory session registry with per-session locks.
- Explicit state and lease transitions.
- Service-authenticated agent API.
- No human user identity model; handoff URL/control tokens are the human authorization primitive.
- Human claim, complete, cancel, extend, and mark-sensitive flows.
- One-time handoff URL tokens; claim returns a separate human control token for remote/actions.
- Optional `expected_origin` validation before minting a handoff URL.
- Fail-closed command authorization after handoff starts.
- Sanitized resume for low-risk handoffs closes the human-controlled page before returning the lease.
- Real Playwright Chromium runtime by default.
- Headed Chromium plus Xvfb/x11vnc/noVNC launch path when host binaries are installed.
- noVNC access is exposed through the authenticated service proxy; raw worker noVNC ports stay loopback-only.
- Minimal human UI at `/sessions/{session_id}`.
- SSE lifecycle event stream.
- Agent-side smoke client in `scripts/agent_client_smoke.py`.
- Python and Playwright e2e tests.

## Setup

```bash
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m playwright install chromium
npm install
npx playwright install chromium
```

For real local Chromium/noVNC e2e, the host also needs browser and display packages:

```bash
sudo bash scripts/install_system_deps.sh
```

After installing those system packages, the real Chromium smoke, headed noVNC runtime smoke, and browser UI e2e can run without the earlier local sysroot workaround.

## Run

Real Chromium runtime:

```bash
export BROWSER_HANDOFF_SERVICE_TOKEN="$(openssl rand -hex 32)"
.venv/bin/python -m uvicorn browser_handoff_service.main:app --host 127.0.0.1 --port 8000
```

Headed Chromium with noVNC, when Xvfb/x11vnc/noVNC are installed:

```bash
BROWSER_HANDOFF_SERVICE_TOKEN="$BROWSER_HANDOFF_SERVICE_TOKEN" BROWSER_HEADED=1 .venv/bin/python -m uvicorn browser_handoff_service.main:app --host 127.0.0.1 --port 8000
```

Deterministic test runtime:

```bash
BROWSER_HANDOFF_SERVICE_TOKEN="$BROWSER_HANDOFF_SERVICE_TOKEN" BROWSER_RUNTIME=fake .venv/bin/python -m uvicorn browser_handoff_service.main:app --host 127.0.0.1 --port 8000
```

## Test

```bash
.venv/bin/python -m pytest -q
npm run test:user
```

Agent-side smoke against a running service:

```bash
BROWSER_HANDOFF_SERVICE_TOKEN="$BROWSER_HANDOFF_SERVICE_TOKEN" .venv/bin/python scripts/agent_client_smoke.py --base-url http://127.0.0.1:8000
```

## Quality

```bash
.venv/bin/python -m pip install -e '.[dev]'
make lint
make typecheck
make check
.venv/bin/pre-commit install
make pre-commit
```
