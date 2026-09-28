"""Web Bot Auth: sign outbound browser requests with HTTP Message Signatures (RFC 9421).

Implements the signing half of draft-meunier-web-bot-auth-architecture as Cloudflare verifies
it (https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/): an Ed25519
signature over ``@authority`` (and ``Signature-Agent`` when configured), tagged ``web-bot-auth``,
with a short ``created``/``expires`` window and a fresh nonce per request.

The feature is off unless ``BROWSER_WEB_BOT_AUTH`` is truthy, and turning it on without a usable
key is a startup error rather than a silently unsigned browser. Signing announces the browser as
an automated agent, which is the opposite of the stealth hardening, so it is an operator's
deliberate choice and only useful once the key is registered with the verifier.

The module also produces the signed key directory (``/.well-known/http-message-signatures-
directory``) that verifiers fetch. It is not served from here: browser-server sits behind edge
authentication, and the directory must be public, so the CLI below emits the directory body and
its signature headers for publication elsewhere (a static edge Worker in the reference
deployment).

    python -m browser_handoff_service.web_bot_auth sign-directory \\
        --authority bot.example.com --validity-days 365
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ENABLED_ENV = "BROWSER_WEB_BOT_AUTH"
KEY_FILE_ENV = "BROWSER_WEB_BOT_AUTH_KEY_FILE"
SIGNATURE_AGENT_ENV = "BROWSER_WEB_BOT_AUTH_SIGNATURE_AGENT"
VALIDITY_ENV = "BROWSER_WEB_BOT_AUTH_VALIDITY_SECONDS"

REQUEST_TAG = "web-bot-auth"
DIRECTORY_TAG = "http-message-signatures-directory"
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
SIGNATURE_LABEL = "sig1"
NONCE_BYTES = 64
# Cloudflare recommends a short window as its replay defence ("a minute is often sufficient").
DEFAULT_VALIDITY_SECONDS = 60

_DEFAULT_PORTS = {"http": 80, "https": 443}
_TRUTHY = {"1", "true", "yes", "on"}


class WebBotAuthConfigError(RuntimeError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sf_string(value: str) -> str:
    """Serialize an RFC 8941 sf-string; only printable ASCII is representable."""
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
        raise ValueError(f"not representable as a structured-field string: {value!r}")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def public_jwk(public_key: Ed25519PublicKey) -> dict[str, str]:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


def jwk_thumbprint(public_key: Ed25519PublicKey) -> str:
    """RFC 7638 thumbprint of an OKP key (RFC 8037 A.3): required members, sorted, no whitespace."""
    jwk = public_jwk(public_key)
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x")}, separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def authority_of(url: str) -> str:
    """RFC 9421 ``@authority``: lowercase host, port only when not the scheme default."""
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        raise ValueError(f"URL has no authority: {url!r}")
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port is not None and port != _DEFAULT_PORTS.get(parts.scheme.lower()):
        return f"{host}:{port}"
    return host


@dataclass(frozen=True)
class WebBotAuthSigner:
    private_key: Ed25519PrivateKey
    signature_agent: str | None = None
    validity_seconds: int = DEFAULT_VALIDITY_SECONDS

    @cached_property
    def keyid(self) -> str:
        return jwk_thumbprint(self.private_key.public_key())

    def _sign(self, lines: list[str], inner_list: str, params: list[tuple[str, str | int]]) -> tuple[str, str]:
        serialized = inner_list + "".join(
            f";{name}={value if isinstance(value, int) else _sf_string(value)}" for name, value in params
        )
        base = "\n".join([*lines, f'"@signature-params": {serialized}'])
        signature = base64.b64encode(self.private_key.sign(base.encode("ascii"))).decode("ascii")
        return f"{SIGNATURE_LABEL}={serialized}", f"{SIGNATURE_LABEL}=:{signature}:"

    def request_headers(self, url: str, *, created: int | None = None, nonce: str | None = None) -> dict[str, str]:
        """``Signature``/``Signature-Input`` (and ``Signature-Agent``) for a request to ``url``.

        ``Signature-Agent`` is sent in the sf-string form of directory draft 03, the one Cloudflare
        verifies; the later dictionary form fails verification there.
        """
        created = int(time.time()) if created is None else created
        nonce = base64.b64encode(secrets.token_bytes(NONCE_BYTES)).decode("ascii") if nonce is None else nonce
        headers: dict[str, str] = {}
        lines = [f'"@authority": {authority_of(url)}']
        components = ['"@authority"']
        if self.signature_agent is not None:
            agent_value = _sf_string(self.signature_agent)
            headers["Signature-Agent"] = agent_value
            lines.append(f'"signature-agent": {agent_value}')
            components.append('"signature-agent"')
        signature_input, signature = self._sign(
            lines,
            f"({' '.join(components)})",
            [
                ("created", created),
                ("keyid", self.keyid),
                ("alg", "ed25519"),
                ("expires", created + self.validity_seconds),
                ("nonce", nonce),
                ("tag", REQUEST_TAG),
            ],
        )
        headers["Signature-Input"] = signature_input
        headers["Signature"] = signature
        return headers

    def directory_response(
        self, authority: str, *, validity_seconds: int, created: int | None = None, nonce: str | None = None
    ) -> dict[str, object]:
        """The key directory body plus the response signature binding it to ``authority``.

        The signature covers only the request's ``@authority`` (``req`` flag), so the response is
        static for a given host until ``expires`` and can be published as a fixed file.
        """
        created = int(time.time()) if created is None else created
        nonce = base64.b64encode(secrets.token_bytes(NONCE_BYTES)).decode("ascii") if nonce is None else nonce
        signature_input, signature = self._sign(
            [f'"@authority";req: {authority}'],
            '("@authority";req)',
            [
                ("created", created),
                ("keyid", self.keyid),
                ("alg", "ed25519"),
                ("expires", created + validity_seconds),
                ("nonce", nonce),
                ("tag", DIRECTORY_TAG),
            ],
        )
        return {
            "authority": authority,
            "expires": created + validity_seconds,
            "body": {"keys": [public_jwk(self.private_key.public_key())]},
            "headers": {
                "Content-Type": DIRECTORY_MEDIA_TYPE,
                "Signature-Input": signature_input,
                "Signature": signature,
            },
        }


def load_private_key(path: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise WebBotAuthConfigError(f"cannot load Web Bot Auth key from {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise WebBotAuthConfigError(f"Web Bot Auth key in {path} is not an Ed25519 private key")
    return key


def signer_from_env() -> WebBotAuthSigner | None:
    """The configured signer, or ``None`` when the feature is off. Misconfiguration raises."""
    if os.environ.get(ENABLED_ENV, "").strip().lower() not in _TRUTHY:
        return None
    key_file = os.environ.get(KEY_FILE_ENV, "").strip()
    if not key_file:
        raise WebBotAuthConfigError(f"{ENABLED_ENV} is on but {KEY_FILE_ENV} is not set")
    agent = os.environ.get(SIGNATURE_AGENT_ENV, "").strip() or None
    if agent is not None:
        if urlsplit(agent).scheme != "https":
            raise WebBotAuthConfigError(f"{SIGNATURE_AGENT_ENV} must be an https:// URL")
        try:
            _sf_string(agent)
        except ValueError as exc:
            raise WebBotAuthConfigError(f"{SIGNATURE_AGENT_ENV} must be printable ASCII (punycode the host)") from exc
    raw_validity = os.environ.get(VALIDITY_ENV, "").strip()
    try:
        validity = int(raw_validity) if raw_validity else DEFAULT_VALIDITY_SECONDS
    except ValueError as exc:
        raise WebBotAuthConfigError(f"{VALIDITY_ENV} must be an integer number of seconds") from exc
    if validity <= 0:
        raise WebBotAuthConfigError(f"{VALIDITY_ENV} must be positive")
    return WebBotAuthSigner(load_private_key(key_file), signature_agent=agent, validity_seconds=validity)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m browser_handoff_service.web_bot_auth")
    parser.add_argument(
        "--key-file",
        default=os.environ.get(KEY_FILE_ENV),
        help=f"Ed25519 private key (PKCS#8 PEM); defaults to ${KEY_FILE_ENV}",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("public-key", help="print the public JWK and its keyid")
    directory = sub.add_parser("sign-directory", help="print the signed key directory as JSON")
    directory.add_argument("--authority", required=True, help="host the directory is served from")
    directory.add_argument("--validity-days", type=int, default=365)
    args = parser.parse_args(argv)
    if not args.key_file:
        parser.error(f"--key-file or ${KEY_FILE_ENV} is required")
    signer = WebBotAuthSigner(load_private_key(args.key_file))
    if args.command == "public-key":
        output: dict[str, object] = {"keyid": signer.keyid, "jwk": public_jwk(signer.private_key.public_key())}
    else:
        output = signer.directory_response(args.authority, validity_seconds=args.validity_days * 86400)
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
