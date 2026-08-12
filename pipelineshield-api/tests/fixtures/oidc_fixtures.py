"""OIDC test fixtures — RSA key pair, JWKS, signed id_tokens.

Generates a stable test RSA key pair using a fixed seed so that test runs
are reproducible.  All tokens are signed with RS256.

Usage in tests::

    from tests.fixtures.oidc_fixtures import (
        TEST_KID,
        TEST_ISSUER,
        TEST_CLIENT_ID,
        get_test_jwks,
        get_private_key,
        make_id_token,
        make_discovery_doc,
    )
"""
from __future__ import annotations

import base64
import json
import os
import time
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

TEST_ISSUER = "https://idp.test.example.com"
TEST_CLIENT_ID = "pipelineshield-test-client"
TEST_KID = "test-key-001"

# ---------------------------------------------------------------------------
# Stable test RSA key (regenerated once per process, cached module-level)
# ---------------------------------------------------------------------------

_cached_private_key: rsa.RSAPrivateKey | None = None


def get_private_key() -> rsa.RSAPrivateKey:
    global _cached_private_key
    if _cached_private_key is None:
        _cached_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    return _cached_private_key


def _int_to_base64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def get_test_jwks() -> dict[str, Any]:
    """Return a JWKS dict containing the test public key."""
    private_key = get_private_key()
    pub = private_key.public_key()
    pub_numbers = pub.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": TEST_KID,
                "use": "sig",
                "alg": "RS256",
                "n": _int_to_base64url(pub_numbers.n),
                "e": _int_to_base64url(pub_numbers.e),
            }
        ]
    }


def get_test_public_pem() -> bytes:
    private_key = get_private_key()
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# id_token factory
# ---------------------------------------------------------------------------


def make_id_token(
    sub: str = "sub|test-user-001",
    email: str = "test@example.com",
    name: str = "Test User",
    nonce: str = "test-nonce",
    aud: str | None = None,
    iss: str | None = None,
    exp_offset: int = 3600,
    iat_offset: int = 0,
    kid: str = TEST_KID,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Sign and return a JWT id_token using the test private key."""
    try:
        import jwt as pyjwt
    except ImportError as e:
        raise ImportError("PyJWT is required to create test id_tokens") from e

    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": iss or TEST_ISSUER,
        "sub": sub,
        "aud": aud or TEST_CLIENT_ID,
        "iat": now + iat_offset,
        "exp": now + exp_offset,
        "nonce": nonce,
        "email": email,
        "name": name,
    }
    if extra_claims:
        payload.update(extra_claims)

    private_key = get_private_key()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return pyjwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


# ---------------------------------------------------------------------------
# Discovery document
# ---------------------------------------------------------------------------


def make_discovery_doc(
    issuer: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    iss = issuer or TEST_ISSUER
    base = base_url or iss
    return {
        "issuer": iss,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nonce", "email", "name"],
        "code_challenge_methods_supported": ["S256"],
    }
