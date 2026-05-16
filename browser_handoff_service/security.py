from __future__ import annotations

import hashlib
import secrets
from urllib.parse import urlsplit, urlunsplit


def mint_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def redact_url(url: str) -> tuple[str, str | None]:
    parsed = urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None
    redacted = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return redacted, origin
