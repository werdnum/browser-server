
import jwt
import pytest
from browser_handoff_service import main
from browser_handoff_service.main import require_service_auth
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
    # Should not raise
    require_service_auth(f"Bearer {TEST_SERVICE_TOKEN}")

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
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience):
        if token == "valid-oidc-token":
            return {"sub": "user123"}
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    # Should not raise
    require_service_auth("Bearer valid-oidc-token")

def test_require_service_auth_oidc_failure_fallback_success(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience):
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    # OIDC fails, but static token matches
    require_service_auth("Bearer fallback-token")

def test_require_service_auth_oidc_failure_fallback_failure(monkeypatch):
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_JWKS_URL", "http://testserver/.well-known/jwks.json")
    monkeypatch.setenv("BROWSER_HANDOFF_OIDC_AUDIENCE", "test-audience")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", "fallback-token")

    class MockSigningKey:
        key = "secret_key"

    class MockJWKClient:
        def get_signing_key_from_jwt(self, token):
            return MockSigningKey()

    def mock_decode(token, key, algorithms, audience):
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(main.jwt, "PyJWKClient", lambda url: MockJWKClient())
    monkeypatch.setattr(main.jwt, "decode", mock_decode)

    with pytest.raises(HTTPException) as exc:
        require_service_auth("Bearer invalid-token")
    assert exc.value.status_code == 401
    assert exc.value.detail == "invalid service token"
