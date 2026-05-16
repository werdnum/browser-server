#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root, for example: sudo bash scripts/install_system_deps.sh" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  fontconfig \
  fonts-dejavu-core \
  libasound2 \
  libatk-bridge2.0-0 \
  libatk1.0-0 \
  libatspi2.0-0 \
  libcairo2 \
  libcups2 \
  libdbus-1-3 \
  libdrm2 \
  libgbm1 \
  libglib2.0-0 \
  libnspr4 \
  libnss3 \
  libpango-1.0-0 \
  libwayland-client0 \
  libx11-6 \
  libx11-xcb1 \
  libxcb1 \
  libxcomposite1 \
  libxdamage1 \
  libxext6 \
  libxfixes3 \
  libxkbcommon0 \
  libxrandr2 \
  novnc \
  websockify \
  x11-xkb-utils \
  x11vnc \
  xauth \
  xfonts-base \
  xkb-data \
  xvfb

if [[ -d /tmp/.X11-unix ]]; then
  chown root:root /tmp/.X11-unix || true
  chmod 1777 /tmp/.X11-unix || true
fi

echo "System browser/noVNC dependencies installed."
echo "Next, as the workspace user, run:"
echo "  .venv/bin/python -m playwright install chromium"
echo "  npx playwright install chromium"
