"""External identity verification helpers (OIDC/JWT)."""

from __future__ import annotations

import json
import pathlib
import time
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from .utils import b64url_decode


class IdentityError(ValueError):
    """Raised when identity verification fails."""


class OIDCVerifierProtocol(Protocol):
    """JWT verifier contract for policy enforcement."""

    def verify(self, token: str) -> dict[str, Any]:
        """Verify a JWT and return claims."""


@dataclass(frozen=True, slots=True)
class OIDCVerifier:
    """Minimal OIDC JWT verifier backed by JWKS."""

    jwks: dict[str, Any]
    issuer: str | None = None
    audience: str | None = None
    leeway_s: int = 30

    @classmethod
    def from_jwks_file(
        cls,
        path: str,
        *,
        issuer: str | None = None,
        audience: str | None = None,
        leeway_s: int = 30,
    ) -> OIDCVerifier:
        raw = pathlib.Path(path).read_text(encoding="utf-8")
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise IdentityError("jwks must be an object")
        return cls(jwks=decoded, issuer=issuer, audience=audience, leeway_s=leeway_s)

    def verify(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token:
            raise IdentityError("oidc token must be a non-empty string")

        parts = token.split(".")
        if len(parts) != 3:
            raise IdentityError("oidc token must be JWT compact format")
        encoded_header, encoded_payload, encoded_signature = parts
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")

        header = _decode_jwt_json(encoded_header, field_name="header")
        payload = _decode_jwt_json(encoded_payload, field_name="payload")
        if not isinstance(payload, dict):
            raise IdentityError("oidc payload must be an object")
        signature = b64url_decode(encoded_signature)

        alg = header.get("alg")
        kid = header.get("kid")
        if not isinstance(alg, str) or not alg:
            raise IdentityError("oidc token missing header.alg")
        if not isinstance(kid, str) or not kid:
            raise IdentityError("oidc token missing header.kid")

        key_jwk = _find_jwk(self.jwks, kid=kid, alg=alg)
        _verify_signature(alg=alg, jwk=key_jwk, signing_input=signing_input, signature=signature)
        _verify_registered_claims(payload, issuer=self.issuer, audience=self.audience, leeway_s=self.leeway_s)
        return payload


def _decode_jwt_json(segment: str, *, field_name: str) -> dict[str, Any]:
    try:
        raw = b64url_decode(segment)
        decoded = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise IdentityError(f"invalid oidc token {field_name}") from exc
    if not isinstance(decoded, dict):
        raise IdentityError(f"oidc token {field_name} must be an object")
    return decoded


def _find_jwk(jwks: dict[str, Any], *, kid: str, alg: str) -> dict[str, Any]:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise IdentityError("jwks.keys must be an array")
    for item in keys:
        if isinstance(item, dict) and item.get("kid") == kid:
            _validate_jwk_constraints(item, alg=alg)
            return item
    raise IdentityError(f"oidc key not found for kid: {kid}")


def _validate_jwk_constraints(jwk: dict[str, Any], *, alg: str) -> None:
    # Prevent key confusion when metadata is present.
    use_value = jwk.get("use")
    if use_value is not None and use_value != "sig":
        raise IdentityError("oidc jwk use must be 'sig'")

    key_ops = jwk.get("key_ops")
    if key_ops is not None:
        if not isinstance(key_ops, list) or not all(isinstance(item, str) for item in key_ops):
            raise IdentityError("oidc jwk key_ops must be string[] when present")
        if "verify" not in key_ops:
            raise IdentityError("oidc jwk key_ops must include 'verify'")

    jwk_alg = jwk.get("alg")
    if jwk_alg is not None and jwk_alg != alg:
        raise IdentityError("oidc jwk alg does not match token alg")


def _verify_signature(*, alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
    try:
        if alg == "RS256":
            rsa_public_key = _rsa_public_key_from_jwk(jwk)
            rsa_public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return
        if alg == "EdDSA":
            ed25519_public_key = _ed25519_public_key_from_jwk(jwk)
            ed25519_public_key.verify(signature, signing_input)
            return
    except InvalidSignature as exc:
        raise IdentityError("oidc signature verification failed") from exc
    except Exception as exc:
        raise IdentityError(f"oidc signature verification failed: {exc}") from exc
    raise IdentityError(f"unsupported oidc alg: {alg}")


def _rsa_public_key_from_jwk(jwk: dict[str, Any]) -> rsa.RSAPublicKey:
    if jwk.get("kty") != "RSA":
        raise IdentityError("oidc jwk kty must be RSA for RS256")
    n_raw = jwk.get("n")
    e_raw = jwk.get("e")
    if not isinstance(n_raw, str) or not isinstance(e_raw, str):
        raise IdentityError("oidc RSA jwk requires n/e")
    n = int.from_bytes(b64url_decode(n_raw), "big")
    e = int.from_bytes(b64url_decode(e_raw), "big")
    return rsa.RSAPublicNumbers(e=e, n=n).public_key()


def _ed25519_public_key_from_jwk(jwk: dict[str, Any]) -> ed25519.Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise IdentityError("oidc jwk must be OKP/Ed25519 for EdDSA")
    x_raw = jwk.get("x")
    if not isinstance(x_raw, str):
        raise IdentityError("oidc Ed25519 jwk requires x")
    return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(x_raw))


def _verify_registered_claims(
    claims: dict[str, Any],
    *,
    issuer: str | None,
    audience: str | None,
    leeway_s: int,
) -> None:
    now = int(time.time())

    exp_raw = claims.get("exp")
    if not isinstance(exp_raw, (int, float)):
        raise IdentityError("oidc token missing exp")
    exp = int(exp_raw)
    if now > exp + max(0, leeway_s):
        raise IdentityError("oidc token expired")

    nbf_raw = claims.get("nbf")
    if nbf_raw is not None:
        if not isinstance(nbf_raw, (int, float)):
            raise IdentityError("oidc token nbf must be numeric")
        nbf = int(nbf_raw)
        if now + max(0, leeway_s) < nbf:
            raise IdentityError("oidc token not yet valid (nbf)")

    if issuer is not None:
        iss = claims.get("iss")
        if not isinstance(iss, str) or iss != issuer:
            raise IdentityError("oidc issuer mismatch")

    if audience is not None:
        aud = claims.get("aud")
        if isinstance(aud, str):
            if aud != audience:
                raise IdentityError("oidc audience mismatch")
        elif isinstance(aud, list):
            if audience not in aud:
                raise IdentityError("oidc audience mismatch")
        else:
            raise IdentityError("oidc token aud claim missing or invalid")
