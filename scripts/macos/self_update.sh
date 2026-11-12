#!/usr/bin/env bash
set -euo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${BROWSER_SERVER_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
ENV_FILE="${BROWSER_SERVER_ENV_FILE:-$HOME/.config/browser-server/env}"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

STATE_DIR="${BROWSER_SERVER_STATE_DIR:-$HOME/Library/Application Support/browser-server}"
LOCK_DIR="$STATE_DIR/update.lock"
BRANCH="${BROWSER_SERVER_UPDATE_BRANCH:-main}"
PORT="${UVICORN_PORT:-8000}"
HEALTH_URL="${BROWSER_SERVER_HEALTH_URL:-http://127.0.0.1:${PORT}/healthz}"
SERVICE_LABEL="${BROWSER_SERVER_LABEL:-dev.andrewgarrett.browser-server}"

mkdir -p "$STATE_DIR"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  if [[ -f "$LOCK_DIR/pid" ]]; then
    LOCK_PID="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
    if [[ -n "$LOCK_PID" ]] && kill -0 "$LOCK_PID" 2>/dev/null; then
      exit 0
    fi
  fi
  rm -rf "$LOCK_DIR"
  mkdir "$LOCK_DIR"
fi
echo "$$" > "$LOCK_DIR/pid"
trap 'rm -rf "$LOCK_DIR"' EXIT

cd "$REPO_ROOT"

CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ "$CURRENT_BRANCH" != "$BRANCH" ]]; then
  echo "browser-server-updater: skipping update on non-${BRANCH} branch (${CURRENT_BRANCH:-detached})"
  exit 0
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "browser-server-updater: skipping update due to local modifications in $REPO_ROOT"
  exit 0
fi

git fetch --quiet origin "$BRANCH"
LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse "origin/$BRANCH")"

if [[ "$LOCAL_SHA" == "$REMOTE_SHA" ]]; then
  exit 0
fi

if ! git merge-base --is-ancestor "$LOCAL_SHA" "$REMOTE_SHA"; then
  echo "browser-server-updater: origin/$BRANCH ($REMOTE_SHA) is not a fast-forward of $LOCAL_SHA; skipping" >&2
  exit 1
fi

PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi

if HEALTH_JSON="$(curl -fsS --max-time 3 "$HEALTH_URL" 2>/dev/null)"; then
  ACTIVE_SESSIONS="$(
    printf '%s' "$HEALTH_JSON" | "$PYTHON_BIN" -c '
import json, sys
try:
    data = json.load(sys.stdin)
    val = data.get("active_sessions", 0)
    print(int(val) if isinstance(val, (int, float)) else 0)
except Exception:
    print(0)
'
  )"
  if [[ "${ACTIVE_SESSIONS}" -gt 0 ]]; then
    echo "browser-server-updater: deferring update (${LOCAL_SHA:0:7} -> ${REMOTE_SHA:0:7}) while ${ACTIVE_SESSIONS} session(s) active"
    exit 0
  fi
fi

echo "browser-server-updater: updating ${LOCAL_SHA:0:7} -> ${REMOTE_SHA:0:7}"
git merge --ff-only --quiet "$REMOTE_SHA"

sync_deps() {
  if [[ "${BROWSER_SERVER_SKIP_DEP_SYNC:-0}" == "1" ]]; then
    return 0
  fi
  if command -v uv >/dev/null 2>&1 && [[ -f "$REPO_ROOT/uv.lock" ]]; then
    uv sync --frozen --no-dev --quiet
  else
    "$REPO_ROOT/.venv/bin/python" -m pip install --quiet -e "$REPO_ROOT"
  fi
}

if ! sync_deps; then
  echo "browser-server-updater: dependency sync failed; rolling back to $LOCAL_SHA" >&2
  git reset --hard "$LOCAL_SHA" >&2
  exit 1
fi

launchctl kickstart -k "gui/$(id -u)/${SERVICE_LABEL}"
echo "browser-server-updater: restarted ${SERVICE_LABEL} at ${REMOTE_SHA:0:7}"
