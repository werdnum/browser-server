import base64
import json

import pytest
from browser_handoff_service import web_bot_auth
from browser_handoff_service.web_bot_auth import (
    WebBotAuthConfigError,
    WebBotAuthSigner,
    authority_of,
    signer_from_env,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The published RFC 9421 Appendix B.1.4 test key ("test-key-ed25519"), which the Web Bot Auth
# architecture draft's Appendix A.2 test vectors are signed with. Public test material only.
RFC9421_TEST_KEY_D = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"
RFC9421_TEST_KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"


def _test_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(RFC9421_TEST_KEY_D + "="))


def test_keyid_is_rfc8037_thumbprint():
    assert WebBotAuthSigner(_test_key()).keyid == RFC9421_TEST_KEYID


def test_matches_draft_vector_without_signature_agent():
    # draft-meunier-web-bot-auth-architecture-05, Appendix A.2.1.
    signer = WebBotAuthSigner(_test_key(), validity_seconds=4889289600 - 1735689600)
    headers = signer.request_headers(
        "https://example.com/foo?param=Value&Pet=dog",
        created=1735689600,
        nonce="g0iqFa9e1ffijlyOScDkXpfSmTbYpRNSGPJrQ1It20ahwgzB3jOUcdgLgFxUg7RMtW4V8IILaKKtA+YuSyIgJQ==",
    )
    assert "Signature-Agent" not in headers
    assert headers["Signature-Input"] == (
        'sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"'
        ';alg="ed25519";expires=4889289600'
        ';nonce="g0iqFa9e1ffijlyOScDkXpfSmTbYpRNSGPJrQ1It20ahwgzB3jOUcdgLgFxUg7RMtW4V8IILaKKtA+YuSyIgJQ=="'
        ';tag="web-bot-auth"'
    )
    assert headers["Signature"] == (
        "sig1=:FFASViSdcgsyaqqYiCnkHreeZzbNKcTzDvZC5uVlP/dn9IbWj8j0o4wKFTH3rBnUiSUBduwm1Gp5VlIPCp01Ag==:"
    )


def test_matches_cloudflare_signature_agent_vector():
    # Appendix A.2.3: the sf-string Signature-Agent form, the one Cloudflare verifies.
    signer = WebBotAuthSigner(_test_key(), signature_agent="https://signature-agent.test", validity_seconds=3600)
    headers = signer.request_headers(
        "https://example.com/",
        created=1735689600,
        nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==",
    )
    assert headers["Signature-Agent"] == '"https://signature-agent.test"'
    assert headers["Signature-Input"].startswith('sig1=("@authority" "signature-agent");created=1735689600;')
    assert headers["Signature"] == (
        "sig1=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:"
    )


def test_fresh_nonce_and_window_per_request():
    signer = WebBotAuthSigner(_test_key())
    first = signer.request_headers("https://example.com/", created=100)
    second = signer.request_headers("https://example.com/", created=100)
    assert first["Signature-Input"] != second["Signature-Input"]
    assert ";created=100;" in first["Signature-Input"]
    assert f";expires={100 + web_bot_auth.DEFAULT_VALIDITY_SECONDS};" in first["Signature-Input"]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://Example.COM/path", "example.com"),
        ("https://example.com:443/", "example.com"),
        ("http://example.com:80/", "example.com"),
        ("https://example.com:8443/", "example.com:8443"),
        ("http://example.com:443/", "example.com:443"),
        ("http://[::1]:8080/", "[::1]:8080"),
        ("https://user:pw@example.com/", "example.com"),
    ],
)
def test_authority_of(url, expected):
    assert authority_of(url) == expected


def test_authority_of_rejects_url_without_host():
    with pytest.raises(ValueError):
        authority_of("about:blank")


def test_directory_response_signature_binds_authority():
    key = _test_key()
    directory = WebBotAuthSigner(key).directory_response(
        "bot.example.com",
        validity_seconds=86400,
        created=1735689600,
        nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==",
    )
    assert directory["body"] == {
        "keys": [{"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]
    }
    headers = directory["headers"]
    assert isinstance(headers, dict)
    assert headers["Content-Type"] == "application/http-message-signatures-directory+json"
    params = headers["Signature-Input"].removeprefix("sig1=")
    assert params.startswith('("@authority";req);created=1735689600;')
    assert params.endswith(';tag="http-message-signatures-directory"')
    base = f'"@authority";req: bot.example.com\n"@signature-params": {params}'
    signature = base64.b64decode(headers["Signature"].removeprefix("sig1=:").removesuffix(":"))
    key.public_key().verify(signature, base.encode("ascii"))


def _write_key(tmp_path) -> str:
    path = tmp_path / "key.pem"
    path.write_bytes(
        _test_key().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return str(path)


def test_signer_from_env_off_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("BROWSER_WEB_BOT_AUTH", raising=False)
    # A configured key does not turn signing on by itself.
    monkeypatch.setenv("BROWSER_WEB_BOT_AUTH_KEY_FILE", _write_key(tmp_path))
    assert signer_from_env() is None
    monkeypatch.setenv("BROWSER_WEB_BOT_AUTH", "0")
    assert signer_from_env() is None


def test_signer_from_env_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("BROWSER_WEB_BOT_AUTH", "1")
    monkeypatch.setenv("BROWSER_WEB_BOT_AUTH_KEY_FILE", _write_key(tmp_path))
    monkeypatch.setenv("BROWSER_WEB_BOT_AUTH_SIGNATURE_AGENT", "https://bot.example.com")
    monkeypatch.setenv("BROWSER_WEB_BOT_AUTH_VALIDITY_SECONDS", "120")
    signer = signer_from_env()
    assert signer is not None
    assert signer.keyid == RFC9421_TEST_KEYID
    assert signer.signature_agent == "https://bot.example.com"
    assert signer.validity_seconds == 120


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({}, "BROWSER_WEB_BOT_AUTH_KEY_FILE is not set"),
        ({"BROWSER_WEB_BOT_AUTH_KEY_FILE": "/nonexistent/key.pem"}, "cannot load"),
        ({"BROWSER_WEB_BOT_AUTH_SIGNATURE_AGENT": "http://bot.example.com"}, "https://"),
        ({"BROWSER_WEB_BOT_AUTH_SIGNATURE_AGENT": "https:///bot"}, "with a host"),
        ({"BROWSER_WEB_BOT_AUTH_SIGNATURE_AGENT": "https://böt.example.com"}, "printable ASCII"),
        ({"BROWSER_WEB_BOT_AUTH_VALIDITY_SECONDS": "0"}, "positive"),
    ],
)
def test_signer_from_env_misconfigured_fails_closed(monkeypatch, tmp_path, env, message):
    monkeypatch.setenv("BROWSER_WEB_BOT_AUTH", "1")
    monkeypatch.delenv("BROWSER_WEB_BOT_AUTH_KEY_FILE", raising=False)
    if "BROWSER_WEB_BOT_AUTH_KEY_FILE" not in env and env:
        monkeypatch.setenv("BROWSER_WEB_BOT_AUTH_KEY_FILE", _write_key(tmp_path))
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(WebBotAuthConfigError, match=message):
        signer_from_env()


def test_signer_rejects_non_ed25519_key(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec

    path = tmp_path / "ec.pem"
    path.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    monkeypatch.setenv("BROWSER_WEB_BOT_AUTH", "1")
    monkeypatch.setenv("BROWSER_WEB_BOT_AUTH_KEY_FILE", str(path))
    with pytest.raises(WebBotAuthConfigError, match="not an Ed25519"):
        signer_from_env()


def test_cli_sign_directory(tmp_path, capsys):
    assert web_bot_auth.main(["--key-file", _write_key(tmp_path), "sign-directory", "--authority", "bot.test"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["authority"] == "bot.test"
    assert output["body"]["keys"][0]["x"] == "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    assert "d" not in output["body"]["keys"][0]
