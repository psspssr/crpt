from __future__ import annotations

import json
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from a2a_sdl.identity import IdentityError, OIDCVerifier
from a2a_sdl.utils import b64url_encode


def _encode_segment(value: dict[str, object]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b64url_encode(raw)


def _rsa_jwk(private_key: rsa.RSAPrivateKey, *, kid: str, extra: dict[str, object] | None = None) -> dict[str, object]:
    numbers = private_key.public_key().public_numbers()
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    jwk: dict[str, object] = {
        "kty": "RSA",
        "kid": kid,
        "n": b64url_encode(n_bytes),
        "e": b64url_encode(e_bytes),
    }
    if extra:
        jwk.update(extra)
    return jwk


def _rs256_token(private_key: rsa.RSAPrivateKey, *, kid: str) -> str:
    header = {"alg": "RS256", "kid": kid}
    payload = {
        "sub": "did:key:agent-a",
        "exp": int(time.time()) + 300,
    }
    encoded_header = _encode_segment(header)
    encoded_payload = _encode_segment(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    encoded_signature = b64url_encode(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


class IdentityTests(unittest.TestCase):
    def test_oidc_verifier_accepts_valid_rs256_token(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = "kid-rs256"
        token = _rs256_token(key, kid=kid)
        jwks = {"keys": [_rsa_jwk(key, kid=kid, extra={"use": "sig", "key_ops": ["verify"], "alg": "RS256"})]}
        verifier = OIDCVerifier(jwks=jwks)

        claims = verifier.verify(token)

        self.assertEqual(claims["sub"], "did:key:agent-a")

    def test_oidc_verifier_rejects_jwk_use_not_sig(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = "kid-rs256"
        token = _rs256_token(key, kid=kid)
        jwks = {"keys": [_rsa_jwk(key, kid=kid, extra={"use": "enc"})]}
        verifier = OIDCVerifier(jwks=jwks)

        with self.assertRaises(IdentityError):
            verifier.verify(token)

    def test_oidc_verifier_rejects_jwk_key_ops_without_verify(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = "kid-rs256"
        token = _rs256_token(key, kid=kid)
        jwks = {"keys": [_rsa_jwk(key, kid=kid, extra={"key_ops": ["sign"]})]}
        verifier = OIDCVerifier(jwks=jwks)

        with self.assertRaises(IdentityError):
            verifier.verify(token)

    def test_oidc_verifier_rejects_jwk_alg_mismatch(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = "kid-rs256"
        token = _rs256_token(key, kid=kid)
        jwks = {"keys": [_rsa_jwk(key, kid=kid, extra={"alg": "EdDSA"})]}
        verifier = OIDCVerifier(jwks=jwks)

        with self.assertRaises(IdentityError):
            verifier.verify(token)


if __name__ == "__main__":
    unittest.main()
