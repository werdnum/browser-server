import jwt
import pytest
from browser_handoff_service import main
from browser_handoff_service.main import require_service_auth
from fastapi import HTTPException
from starlette.requests import Request

TEST_SERVICE_TOKEN = "test-service-token"


def auth_request(cookies: dict[str, str] | None = None) -> Request:
    headers = []
    if cookies:
        cookie_header = "; ".join(f"{name}={value}" for name, value in cookies.items())
        headers.append((b"cookie", cookie_header.encode()))
    return Request({"type": "http", "headers": headers})


@pytest.fixture(autouse=True)
def cleanup():
    main._jwks_client = None
    yield
    main._jwks_client = None


def test_require_service_auth_missing_header(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    with pytest.raises(HTTPException) as exc:
        require_service_auth(auth_request(), None)
    assert exc.value.status_code == 401
    assert exc.value.detail == "missing or invalid authorization header format"


def test_require_service_auth_invalid_header_format(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    with pytest.raises(HTTPException) as exc:
        require_service_auth(auth_request(), "Basic something")
    assert exc.value.status_code == 401
    assert exc.value.detail == "missing or invalid authorization header format"


def test_require_service_auth_static_token_success(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    # Should not raise
    require_service_auth(auth_request(), f"Bearer {TEST_SERVICE_TOKEN}")


def test_require_service_auth_static_token_failure(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)
    with pytest.raises(HTTPException) as exc:
        require_service_auth(auth_request(), "Bearer wrong-token")
    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid service token"


def test_require_service_auth_static_token_unconfigured(monkeypatch):
    monkeypatch.delenv("BROWSER_HANDOFF_SERVICE_TOKEN", raising=False)
    with pytest.raises(HTTPException) as exc:
        require_service_auth(auth_request(), "Bearer random")
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

    def mock_decode(token, key, algorithms, audience, issuer, options):
        if token == "valid-oidc-token":
            return {"sub": "user123"}
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    # Should not raise
    require_service_auth(auth_request(), "Bearer valid-oidc-token")


def test_require_service_auth_envoy_access_token_cookie_success(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_ISSUER", "test-issuer")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience, issuer, options):
        if token == "valid-oidc-token":
            return {"sub": "user123"}
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    require_service_auth(auth_request({"AccessToken-ffe7bc3e": "valid-oidc-token"}), None)


def test_require_service_auth_envoy_access_token_cookie_does_not_fallback_to_service_token(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_ISSUER", "test-issuer")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience, issuer, options):
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    with pytest.raises(HTTPException) as exc:
        require_service_auth(auth_request({"AccessToken-ffe7bc3e": "fallback-token"}), None)

    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid OIDC token"


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

    def mock_decode(token, key, algorithms, audience, issuer, options):
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    # OIDC fails, but static token matches
    require_service_auth(auth_request(), "Bearer fallback-token")


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

    def mock_decode(token, key, algorithms, audience, issuer, options):
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    with pytest.raises(HTTPException) as exc:
        require_service_auth(auth_request(), "Bearer invalid-token")
    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid service token"


def test_require_service_auth_oidc_missing_issuer(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")
    monkeypatch.delenv("BROWSER_HANDOFF_OIDC_ISSUER", raising=False)

    with pytest.raises(HTTPException) as exc:
        require_service_auth(auth_request(), "Bearer valid-oidc-token")
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

    def mock_decode(token, key, algorithms, audience, issuer, options):
        if token == "valid-oidc-token":
            assert options.get("verify_aud") is False
            assert audience is None
            assert issuer == "test-issuer"
            return {"sub": "user123", "iss": "test-issuer"}
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    # Should not raise
    require_service_auth(auth_request(), "Bearer valid-oidc-token")
