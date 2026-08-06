import time

import jwt
import pytest
from browser_handoff_service import main
from browser_handoff_service.main import require_service_auth
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

TEST_SERVICE_TOKEN = "test-service-token"


@pytest.fixture(autouse=True)
def cleanup():
    main._jwks_client = None
    yield
    main._jwks_client = None


def test_require_service_auth_missing_header(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    with pytest.raises(HTTPException) as exc:
        require_service_auth(None)
    assert exc.value.status_code == 401
    assert exc.value.detail == "missing or invalid authorization header format"


def test_require_service_auth_invalid_header_format(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    with pytest.raises(HTTPException) as exc:
        require_service_auth("Basic something")
    assert exc.value.status_code == 401
    assert exc.value.detail == "missing or invalid authorization header format"


def test_require_service_auth_static_token_success(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    auth = require_service_auth(f"Bearer {TEST_SERVICE_TOKEN}")

    assert auth.actor_type == "agent"


def test_require_service_auth_static_token_failure(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    with pytest.raises(HTTPException) as exc:
        require_service_auth("Bearer wrong-token")
    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid service token"


def test_require_service_auth_static_token_unconfigured(monkeypatch):
    monkeypatch.delenv("BROWSER_HANDOFF_SERVICE_TOKEN", raising=False)
    with pytest.raises(HTTPException) as exc:
        require_service_auth("Bearer random")
    assert exc.value.status_code == 503
    assert exc.value.detail == "service token is not configured"


def test_require_service_auth_oidc_success(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_ISSUER", "test-issuer")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience, issuer, options, leeway):
        if token == "valid-oidc-token":
            return {"sub": "user123"}
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    auth = require_service_auth("Bearer valid-oidc-token")

    assert auth.actor_type == "human"
    assert auth.subject == "user123"


def test_require_service_auth_oidc_failure_fallback_success(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_ISSUER", "test-issuer")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience, issuer, options, leeway):
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    # OIDC fails, but static token matches.
    auth = require_service_auth("Bearer fallback-token")

    assert auth.actor_type == "agent"


def test_require_service_auth_oidc_failure_fallback_failure(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_ISSUER", "test-issuer")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience, issuer, options, leeway):
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    with pytest.raises(HTTPException) as exc:
        require_service_auth("Bearer invalid-token")
    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid service token"


def test_require_service_auth_oidc_missing_issuer(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")
    monkeypatch.delenv("BROWSER_HANDOFF_OIDC_ISSUER", raising=False)

    with pytest.raises(HTTPException) as exc:
        require_service_auth("Bearer valid-oidc-token")
    assert exc.value.status_code == 503
    assert exc.value.detail == "OIDC issuer is not configured"


def test_require_service_auth_oidc_success_no_audience(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_ISSUER", "test-issuer")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")
    monkeypatch.delenv("BROWSER_HANDOFF_OIDC_AUDIENCE", raising=False)

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience, issuer, options, leeway):
        if token == "valid-oidc-token":
            assert options.get("verify_aud") is False
            assert audience is None
            assert issuer == "test-issuer"
            return {"sub": "user123", "iss": "test-issuer"}
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    auth = require_service_auth("Bearer valid-oidc-token")

    assert auth.actor_type == "human"


@pytest.fixture(scope="module")
def rsa_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def _configure_oidc(monkeypatch, public_key):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_ISSUER", "test-issuer")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")
    monkeypatch.delenv("BROWSER_HANDOFF_OIDC_LEEWAY_SECONDS", raising=False)

    class MockSigningKey:
        key = public_key

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())


def _issue(private_key, **overrides):
    now = int(time.time())
    claims = {
        "sub": "user123",
        "iss": "test-issuer",
        "aud": "test-audience",
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256")


def test_require_service_auth_oidc_tolerates_future_iat(monkeypatch, rsa_keypair):
    """A token minted on a host whose clock is marginally ahead still authenticates.

    PyJWT compares iat against the local clock with zero tolerance by default, so
    without leeway this raises ImmatureSignatureError, the caller falls through to
    the service-token branch, and starting a browser session fails.
    """
    private_key, public_key = rsa_keypair
    _configure_oidc(monkeypatch, public_key)

    token = _issue(private_key, iat=int(time.time()) + 30)

    auth = require_service_auth(f"Bearer {token}")

    assert auth.actor_type == "human"
    assert auth.subject == "user123"


def test_require_service_auth_oidc_rejects_iat_beyond_leeway(monkeypatch, rsa_keypair):
    private_key, public_key = rsa_keypair
    _configure_oidc(monkeypatch, public_key)
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_LEEWAY_SECONDS", "5")

    token = _issue(private_key, iat=int(time.time()) + 600)

    with pytest.raises(HTTPException) as exc:
        require_service_auth(f"Bearer {token}")
    assert exc.value.status_code == 401
    assert "not yet valid" in exc.value.detail


def test_require_service_auth_oidc_still_rejects_expired_token(monkeypatch, rsa_keypair):
    """Leeway must not become an open-ended grace period for stale tokens."""
    private_key, public_key = rsa_keypair
    _configure_oidc(monkeypatch, public_key)

    now = int(time.time())
    token = _issue(private_key, iat=now - 3600, exp=now - 600)

    with pytest.raises(HTTPException) as exc:
        require_service_auth(f"Bearer {token}")
    assert exc.value.status_code == 401
    assert "invalid OIDC token" in exc.value.detail


def test_require_service_auth_jwt_failure_reports_oidc_not_service_token(monkeypatch, rsa_keypair):
    """A caller presenting a JWT was never trying to use the service token."""
    private_key, public_key = rsa_keypair
    _configure_oidc(monkeypatch, public_key)

    token = _issue(private_key, iss="some-other-issuer")

    with pytest.raises(HTTPException) as exc:
        require_service_auth(f"Bearer {token}")
    assert exc.value.status_code == 401
    assert exc.value.detail.startswith("invalid OIDC token: ")
    assert "invalid service token" not in exc.value.detail


def test_require_service_auth_jwt_failure_still_allows_service_token(monkeypatch, rsa_keypair):
    """The agent path is unaffected: a matching service token still wins."""
    _, public_key = rsa_keypair
    _configure_oidc(monkeypatch, public_key)

    auth = require_service_auth("Bearer fallback-token")

    assert auth.actor_type == "agent"


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, main.DEFAULT_OIDC_LEEWAY_SECONDS),
        ("", main.DEFAULT_OIDC_LEEWAY_SECONDS),
        ("0", 0.0),
        ("30", 30.0),
        ("2.5", 2.5),
        ("not-a-number", main.DEFAULT_OIDC_LEEWAY_SECONDS),
        ("-1", main.DEFAULT_OIDC_LEEWAY_SECONDS),
    ],
)
def test_oidc_leeway_parsing(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("BROWSER_HANDOFF_OIDC_LEEWAY_SECONDS", raising=False)
    else:
        monkeypatch.setenv("BROWSER_HANDOFF_OIDC_LEEWAY_SECONDS", raw)
    assert main._oidc_leeway() == expected
