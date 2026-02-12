"""Cryptographic helpers for A2A-SDL envelopes."""

from __future__ import annotations

import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .codec import canonical_bytes_for_signing
from .utils import b64url_decode, b64url_encode, deep_copy


class SecurityError(ValueError):
    """Raised when security operations fail."""


def generate_signing_keypair() -> dict[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return {
        "private_key_b64": b64url_encode(private_raw),
        "public_key_b64": b64url_encode(public_raw),
        "private_key_pem": private_pem,
        "public_key_pem": public_pem,
    }


def generate_x25519_keypair() -> dict[str, str]:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return {
        "private_key_b64": b64url_encode(private_raw),
        "public_key_b64": b64url_encode(public_raw),
        "private_key_pem": private_pem,
        "public_key_pem": public_pem,
    }


def sign_envelope(
    envelope: dict[str, Any],
    private_key: str | bytes | Ed25519PrivateKey,
    *,
    preferred_encoding: str = "cbor",
    kid: str | None = None,
) -> dict[str, Any]:
    signing_key = _load_ed25519_private_key(private_key)

    sec = envelope.setdefault("sec", {})
    current_mode = sec.get("mode")
    if current_mode == "enc":
        sec["mode"] = "enc+sig"
    else:
        sec["mode"] = "sig" if current_mode != "enc+sig" else "enc+sig"

    if kid is not None:
        sec["kid"] = kid

    sig = sec.setdefault("sig", {})
    sig["alg"] = "ed25519"
    sig["value"] = ""

    signing_input = _canonical_signing_input(envelope, preferred_encoding=preferred_encoding)
    signature = signing_key.sign(signing_input)
    sig["value"] = b64url_encode(signature)
    return envelope


def verify_envelope_signature(
    envelope: dict[str, Any],
    public_key: str | bytes | Ed25519PublicKey,
    *,
    preferred_encoding: str = "cbor",
) -> bool:
    sec = envelope.get("sec")
    if not isinstance(sec, dict):
        raise SecurityError("envelope.sec missing")

    sig = sec.get("sig")
    if not isinstance(sig, dict):
        raise SecurityError("envelope.sec.sig missing")

    value = sig.get("value")
    if not isinstance(value, str) or not value:
        raise SecurityError("signature value missing")

    signature = b64url_decode(value)
    verify_key = _load_ed25519_public_key(public_key)
    signing_input = _canonical_signing_input(envelope, preferred_encoding=preferred_encoding)

    try:
        verify_key.verify(signature, signing_input)
        return True
    except InvalidSignature as exc:
        raise SecurityError("signature verification failed") from exc


def encrypt_payload(
    envelope: dict[str, Any],
    recipients: list[dict[str, str | bytes | X25519PublicKey]],
) -> dict[str, Any]:
    if not recipients:
        raise SecurityError("at least one recipient is required")

    plaintext = json.dumps(
        envelope.get("payload"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    content_key = os.urandom(32)
    content_nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(content_key).encrypt(content_nonce, plaintext, None)

    recipient_entries: list[dict[str, str]] = []
    for recipient in recipients:
        kid = recipient.get("kid")
        if not isinstance(kid, str) or not kid:
            raise SecurityError("recipient kid is required")

        public_key = _load_x25519_public_key(recipient.get("public_key"))
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        shared = ephemeral_private.exchange(public_key)
        wrap_key = _derive_key(shared, b"a2a-sdl-key-wrap-v1")
        wrap_nonce = os.urandom(12)
        wrapped_key = ChaCha20Poly1305(wrap_key).encrypt(wrap_nonce, content_key, None)

        recipient_entries.append(
            {
                "kid": kid,
                "ek": b64url_encode(wrapped_key),
                "eph": b64url_encode(ephemeral_public),
                "wn": b64url_encode(wrap_nonce),
            }
        )

    sec = envelope.setdefault("sec", {})
    current_mode = sec.get("mode")
    if current_mode in {"sig", "enc+sig"}:
        sec["mode"] = "enc+sig"
    else:
        sec["mode"] = "enc"

    sec["enc"] = {
        "alg": "x25519-chacha20poly1305",
        "recipients": recipient_entries,
        "nonce": b64url_encode(content_nonce),
        "ciphertext": b64url_encode(ciphertext),
    }

    envelope["payload"] = None
    return envelope


def decrypt_payload(
    envelope: dict[str, Any],
    recipient_private_key: str | bytes | X25519PrivateKey,
    *,
    kid: str | None = None,
) -> Any:
    sec = envelope.get("sec")
    if not isinstance(sec, dict):
        raise SecurityError("envelope.sec missing")

    enc = sec.get("enc")
    if not isinstance(enc, dict):
        raise SecurityError("envelope.sec.enc missing")

    recipients = enc.get("recipients")
    if not isinstance(recipients, list) or not recipients:
        raise SecurityError("no recipients present")

    recipient_key = _load_x25519_private_key(recipient_private_key)
    encrypted_key: bytes | None = None

    for entry in recipients:
        if not isinstance(entry, dict):
            continue

        entry_kid = entry.get("kid")
        if kid is not None and entry_kid != kid:
            continue

        candidate = _try_unwrap_entry(entry, recipient_key)
        if candidate is not None:
            encrypted_key = candidate
            break

    if encrypted_key is None:
        raise SecurityError("unable to unwrap content key for recipient")

    nonce = b64url_decode(_expect_str(enc, "nonce"))
    ciphertext = b64url_decode(_expect_str(enc, "ciphertext"))

    try:
        plaintext = ChaCha20Poly1305(encrypted_key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise SecurityError("payload decryption failed") from exc

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise SecurityError("decrypted payload is not valid JSON") from exc

    envelope["payload"] = payload
    return payload


def _canonical_signing_input(envelope: dict[str, Any], *, preferred_encoding: str = "cbor") -> bytes:
    signing_doc = deep_copy(envelope)
    sec = signing_doc.setdefault("sec", {})
    sig = sec.setdefault("sig", {})
    sig["value"] = ""
    return canonical_bytes_for_signing(signing_doc, preferred=preferred_encoding)


def _derive_key(shared_secret: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)


def _try_unwrap_entry(entry: dict[str, Any], recipient_key: X25519PrivateKey) -> bytes | None:
    try:
        eph_public_raw = b64url_decode(_expect_str(entry, "eph"))
        wrapped_key = b64url_decode(_expect_str(entry, "ek"))
        wrap_nonce = b64url_decode(_expect_str(entry, "wn"))
        eph_public = X25519PublicKey.from_public_bytes(eph_public_raw)
        shared = recipient_key.exchange(eph_public)
        wrap_key = _derive_key(shared, b"a2a-sdl-key-wrap-v1")
        return ChaCha20Poly1305(wrap_key).decrypt(wrap_nonce, wrapped_key, None)
    except Exception:
        return None


def _load_ed25519_private_key(value: str | bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value

    if isinstance(value, str):
        if value.startswith("-----BEGIN"):
            loaded = serialization.load_pem_private_key(value.encode("ascii"), password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise SecurityError("PEM is not an Ed25519 private key")
            return loaded
        raw = b64url_decode(value)
        return Ed25519PrivateKey.from_private_bytes(raw)

    if isinstance(value, bytes):
        if value.startswith(b"-----BEGIN"):
            loaded = serialization.load_pem_private_key(value, password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise SecurityError("PEM is not an Ed25519 private key")
            return loaded
        return Ed25519PrivateKey.from_private_bytes(value)

    raise SecurityError("unsupported Ed25519 private key format")


def _load_ed25519_public_key(value: str | bytes | Ed25519PublicKey) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value

    if isinstance(value, str):
        if value.startswith("-----BEGIN"):
            loaded = serialization.load_pem_public_key(value.encode("ascii"))
            if not isinstance(loaded, Ed25519PublicKey):
                raise SecurityError("PEM is not an Ed25519 public key")
            return loaded
        raw = b64url_decode(value)
        return Ed25519PublicKey.from_public_bytes(raw)

    if isinstance(value, bytes):
        if value.startswith(b"-----BEGIN"):
            loaded = serialization.load_pem_public_key(value)
            if not isinstance(loaded, Ed25519PublicKey):
                raise SecurityError("PEM is not an Ed25519 public key")
            return loaded
        return Ed25519PublicKey.from_public_bytes(value)

    raise SecurityError("unsupported Ed25519 public key format")


def _load_x25519_private_key(value: str | bytes | X25519PrivateKey) -> X25519PrivateKey:
    if isinstance(value, X25519PrivateKey):
        return value

    if isinstance(value, str):
        if value.startswith("-----BEGIN"):
            loaded = serialization.load_pem_private_key(value.encode("ascii"), password=None)
            if not isinstance(loaded, X25519PrivateKey):
                raise SecurityError("PEM is not an X25519 private key")
            return loaded
        raw = b64url_decode(value)
        return X25519PrivateKey.from_private_bytes(raw)

    if isinstance(value, bytes):
        if value.startswith(b"-----BEGIN"):
            loaded = serialization.load_pem_private_key(value, password=None)
            if not isinstance(loaded, X25519PrivateKey):
                raise SecurityError("PEM is not an X25519 private key")
            return loaded
        return X25519PrivateKey.from_private_bytes(value)

    raise SecurityError("unsupported X25519 private key format")


def _load_x25519_public_key(value: Any) -> X25519PublicKey:
    if isinstance(value, X25519PublicKey):
        return value

    if isinstance(value, str):
        if value.startswith("-----BEGIN"):
            loaded = serialization.load_pem_public_key(value.encode("ascii"))
            if not isinstance(loaded, X25519PublicKey):
                raise SecurityError("PEM is not an X25519 public key")
            return loaded
        raw = b64url_decode(value)
        return X25519PublicKey.from_public_bytes(raw)

    if isinstance(value, bytes):
        if value.startswith(b"-----BEGIN"):
            loaded = serialization.load_pem_public_key(value)
            if not isinstance(loaded, X25519PublicKey):
                raise SecurityError("PEM is not an X25519 public key")
            return loaded
        return X25519PublicKey.from_public_bytes(value)

    raise SecurityError("unsupported X25519 public key format")


def _expect_str(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise SecurityError(f"expected string field: {key}")
    return item
