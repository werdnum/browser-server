#!/usr/bin/env bash
set -euo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="${BROWSER_SERVER_ENV_FILE:-$HOME/.config/browser-server/env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "browser-server: missing configuration file $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

if [[ -z "${BROWSER_HANDOFF_SERVICE_TOKEN:-}" || "${BROWSER_HANDOFF_SERVICE_TOKEN}" == "REPLACE_WITH_SERVICE_TOKEN" ]]; then
  echo "browser-server: BROWSER_HANDOFF_SERVICE_TOKEN is not configured in $ENV_FILE" >&2
  exit 1
fi

export BROWSER_HEADED="${BROWSER_HEADED:-1}"
export BROWSER_CONTEXT_PERSISTENT="${BROWSER_CONTEXT_PERSISTENT:-1}"
export BROWSER_CHROMIUM_CHANNEL="${BROWSER_CHROMIUM_CHANNEL:-chrome}"
export BROWSER_TIMEZONE="${BROWSER_TIMEZONE:-Australia/Sydney}"
export BROWSER_HANDOFF_PUBLIC_URL="${BROWSER_HANDOFF_PUBLIC_URL:-https://browser.andrewgarrett.dev}"
export BROWSER_HANDOFF_OIDC_ISSUER="${BROWSER_HANDOFF_OIDC_ISSUER:-https://id.andrewgarrett.dev/realms/master}"
export BROWSER_HANDOFF_OIDC_JWKS_URL="${BROWSER_HANDOFF_OIDC_JWKS_URL:-https://id.andrewgarrett.dev/realms/master/protocol/openid-connect/certs}"
export BROWSER_HANDOFF_OIDC_AUDIENCE="${BROWSER_HANDOFF_OIDC_AUDIENCE:-sso}"
export BROWSER_KEYCHUTE_URL="${BROWSER_KEYCHUTE_URL:-https://keychute.andrewgarrett.dev}"
export BROWSER_KEYCHUTE_EXTERNAL_URL="${BROWSER_KEYCHUTE_EXTERNAL_URL:-https://keychute.andrewgarrett.dev}"
export WEBSOCKETS_MAX_LINE_LENGTH="${WEBSOCKETS_MAX_LINE_LENGTH:-65536}"

DEFAULT_KEYCHUTE_TOKEN_FILE="$HOME/.config/browser-server/keychute.token"
if [[ -z "${BROWSER_KEYCHUTE_TOKEN_FILE:-}" && -z "${BROWSER_KEYCHUTE_TOKEN:-}" && -f "$DEFAULT_KEYCHUTE_TOKEN_FILE" ]]; then
  export BROWSER_KEYCHUTE_TOKEN_FILE="$DEFAULT_KEYCHUTE_TOKEN_FILE"
fi

cd "$REPO_ROOT"
exec "$REPO_ROOT/.venv/bin/uvicorn" browser_handoff_service.main:app \
  --host "${UVICORN_HOST:-0.0.0.0}" \
  --port "${UVICORN_PORT:-8000}"
