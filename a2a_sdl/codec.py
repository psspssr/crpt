"""Encoding/decoding and canonicalization."""

from __future__ import annotations

import json
from typing import Any

from .utils import canonical_json_bytes

try:
    import cbor2
except Exception:  # pragma: no cover - optional dependency
    cbor2 = None


class CodecError(ValueError):
    """Raised on encoding/decoding failures."""


def has_cbor_support() -> bool:
    return cbor2 is not None


def encode_json(message: dict[str, Any], *, canonical: bool = True) -> bytes:
    if canonical:
        return canonical_json_bytes(message)
    return json.dumps(message, ensure_ascii=False).encode("utf-8")


def decode_json(data: bytes | str) -> dict[str, Any]:
    try:
        if isinstance(data, bytes):
            decoded = json.loads(data.decode("utf-8"))
        else:
            decoded = json.loads(data)
    except Exception as exc:
        raise CodecError(f"invalid JSON payload: {exc}") from exc

    if not isinstance(decoded, dict):
        raise CodecError("decoded JSON must be an object")
    return decoded


def encode_cbor(message: dict[str, Any], *, canonical: bool = True) -> bytes:
    if cbor2 is None:
        raise CodecError("CBOR support unavailable: install 'cbor2'")
    try:
        return cbor2.dumps(message, canonical=canonical)
    except Exception as exc:
        raise CodecError(f"failed to encode CBOR: {exc}") from exc


def decode_cbor(data: bytes) -> dict[str, Any]:
    if cbor2 is None:
        raise CodecError("CBOR support unavailable: install 'cbor2'")
    try:
        decoded = cbor2.loads(data)
    except Exception as exc:
        raise CodecError(f"invalid CBOR payload: {exc}") from exc
    if not isinstance(decoded, dict):
        raise CodecError("decoded CBOR must be a map/object")
    return decoded


def encode_bytes(message: dict[str, Any], encoding: str = "json") -> bytes:
    if encoding == "json":
        return encode_json(message, canonical=True)
    if encoding == "cbor":
        return encode_cbor(message, canonical=True)
    raise CodecError(f"unsupported encoding: {encoding}")


def decode_bytes(data: bytes, encoding: str = "json") -> dict[str, Any]:
    if encoding == "json":
        return decode_json(data)
    if encoding == "cbor":
        return decode_cbor(data)
    raise CodecError(f"unsupported encoding: {encoding}")


def canonical_bytes_for_signing(message: dict[str, Any], preferred: str = "cbor") -> bytes:
    if preferred == "cbor" and has_cbor_support():
        return encode_cbor(message, canonical=True)
    return encode_json(message, canonical=True)


def detect_encoding_from_content_type(content_type: str | None) -> str:
    if not content_type:
        return "json"
    ct = content_type.lower()
    if "application/cbor" in ct:
        return "cbor"
    return "json"
