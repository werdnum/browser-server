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

COPY pyproject.toml README.md ./
COPY browser_handoff_service ./browser_handoff_service

RUN python -m pip install --no-cache-dir --upgrade pip \
  && python -m pip install --no-cache-dir . \
  && python -m playwright install chromium \
  && useradd --create-home --shell /usr/sbin/nologin appuser \
  && chown -R appuser:appuser /app /ms-playwright

USER appuser

EXPOSE 8000

CMD ["uvicorn", "browser_handoff_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
