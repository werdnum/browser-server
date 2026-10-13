FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
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
    xvfb \
  && rm -rf /var/lib/apt/lists/*

# Branded Google Chrome: the launch target of BROWSER_CHROMIUM_CHANNEL=chrome
# (the strongest stealth posture; see README "Persistent real-profile mode").
# Google's apt repository serves both amd64 and arm64 debs (the production
# cluster's nodes are arm64); apt resolves the native arch on each build leg.
RUN mkdir -p /etc/apt/keyrings \
  && curl -fsSL https://dl.google.com/linux/linux_signing_key.pub -o /etc/apt/keyrings/google-chrome.asc \
  && echo "deb [signed-by=/etc/apt/keyrings/google-chrome.asc] https://dl.google.com/linux/chrome/deb stable main" > /etc/apt/sources.list.d/google-chrome.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends google-chrome-stable \
  && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY browser_handoff_service ./browser_handoff_service

RUN python -m pip install --no-cache-dir --upgrade pip \
  && python -m pip install --no-cache-dir . \
  && patchright install chromium \
  && useradd --create-home --shell /usr/sbin/nologin appuser \
  && mkdir -p /var/lib/browser-handoff/jars \
  && chown -R appuser:appuser /app /ms-playwright /var/lib/browser-handoff

USER appuser

# Cookie-jar durable state (opt-in via BROWSER_JAR_KEY). Created and owned by appuser so the
# default BROWSER_JAR_DIR is writable out of the box; mount a volume here in a real deployment.
VOLUME ["/var/lib/browser-handoff"]

EXPOSE 8000

CMD ["uvicorn", "browser_handoff_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
