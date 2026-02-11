"""Envelope construction and validation."""

from __future__ import annotations

from typing import Any

from .constants import (
    DEFAULT_LIMITS,
    ERROR_CODES,
    PROTOCOL_VERSION,
    SUPPORTED_CONTENT_TYPES,
    SUPPORTED_ENC_ALGS,
    SUPPORTED_MESSAGE_TYPES,
    SUPPORTED_SECURITY_MODES,
    SUPPORTED_SIG_ALGS,
)
from .schema import (
    SchemaValidationError,
    get_builtin_descriptor,
    make_embedded_schema,
    validate_payload,
    validate_schema_descriptor,
)
from .utils import canonical_json_bytes, ensure_iso_utc, new_message_id, now_iso_utc, sha256_prefixed


class EnvelopeValidationError(ValueError):
    """Raised when an envelope violates protocol requirements."""


def build_envelope(
    *,
    msg_type: str,
    from_identity: dict[str, Any],
    to_identity: dict[str, Any],
    content_type: str,
    payload: Any,
    cap: dict[str, Any] | None = None,
    schema: dict[str, Any] | None = None,
    trace: dict[str, Any] | None = None,
) -> dict[str, Any]:
    descriptor = schema
    if descriptor is None:
        descriptor = get_builtin_descriptor(content_type) or make_embedded_schema({"type": "object"})

    envelope: dict[str, Any] = {
        "v": PROTOCOL_VERSION,
        "id": new_message_id(),
        "ts": now_iso_utc(),
        "type": msg_type,
        "from": from_identity,
        "to": to_identity,
        "cap": cap or {
            "a2a_sdl": {
                "v": PROTOCOL_VERSION,
                "enc": ["json"],
                "sig": ["ed25519"],
                "kex": ["x25519"],
                "comp": [],
            },
            "tools": [],
            "modalities": ["text"],
            "limits": DEFAULT_LIMITS,
        },
        "ct": content_type,
        "schema": descriptor,
        "payload": payload,
    }
    if trace is not None:
        envelope["trace"] = trace
    return envelope


def derive_response_trace(request_trace: Any) -> dict[str, Any] | None:
    """Create a response trace derived from a request trace."""
    if not isinstance(request_trace, dict):
        return None

    root_id_raw = request_trace.get("root_id")
    span_id_raw = request_trace.get("span_id")
    parent_span_id = span_id_raw if isinstance(span_id_raw, str) and span_id_raw else None
    root_id = root_id_raw if isinstance(root_id_raw, str) and root_id_raw else parent_span_id or new_message_id()

    hops_raw = request_trace.get("hops")
    hops = hops_raw + 1 if isinstance(hops_raw, int) and hops_raw >= 0 else 1

    trace: dict[str, Any] = {
        "root_id": root_id,
        "span_id": new_message_id(),
        "hops": hops,
    }
    if parent_span_id is not None:
        trace["parent_span_id"] = parent_span_id
    return trace


def validate_envelope(
    envelope: dict[str, Any],
    *,
    limits: dict[str, int] | None = None,
    validate_payload_schema: bool = True,
    allow_schema_uri: bool = True,
) -> None:
    if not isinstance(envelope, dict):
        raise EnvelopeValidationError("envelope must be an object")

    required = ["v", "id", "ts", "type", "from", "to", "cap", "ct", "schema", "payload"]
    missing = [key for key in required if key not in envelope]
    if missing:
        raise EnvelopeValidationError(f"missing required fields: {missing}")

    if envelope["v"] != PROTOCOL_VERSION:
        raise EnvelopeValidationError(f"unsupported protocol version: {envelope['v']}")

    if not isinstance(envelope["id"], str) or not envelope["id"]:
        raise EnvelopeValidationError("id must be a non-empty string")

    if not isinstance(envelope["ts"], str):
        raise EnvelopeValidationError("ts must be a string")
    ensure_iso_utc(envelope["ts"])

    if envelope["type"] not in SUPPORTED_MESSAGE_TYPES:
        raise EnvelopeValidationError("type must be one of req/res/evt")

    _validate_identity(envelope["from"], "from")
    _validate_identity(envelope["to"], "to")

    if not isinstance(envelope["cap"], dict):
        raise EnvelopeValidationError("cap must be an object")

    ct = envelope["ct"]
    if not isinstance(ct, str):
        raise EnvelopeValidationError("ct must be a string")
    if ct not in SUPPORTED_CONTENT_TYPES:
        raise EnvelopeValidationError(f"unsupported ct: {ct}")

    try:
        validate_schema_descriptor(envelope["schema"])
    except SchemaValidationError as exc:
        raise EnvelopeValidationError(f"schema invalid: {exc}") from exc

    active_limits = dict(DEFAULT_LIMITS)
    if limits:
        active_limits.update(limits)

    security_mode = _validate_security(envelope.get("sec"))
    _validate_trace(envelope.get("trace"), max_hops=active_limits["max_hops"])
    _validate_limits(envelope, active_limits)

    if validate_payload_schema and security_mode not in {"enc", "enc+sig"}:
        descriptor = envelope["schema"]
        if not allow_schema_uri and isinstance(descriptor, dict) and descriptor.get("kind") == "uri":
            raise EnvelopeValidationError("schema invalid: uri descriptors are not allowed in this context")
        try:
            validate_payload(envelope["payload"], envelope["schema"])
        except SchemaValidationError as exc:
            raise EnvelopeValidationError(f"payload validation failed: {exc}") from exc


def make_error_response(
    *,
    request: dict[str, Any],
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    retryable: bool = False,
) -> dict[str, Any]:
    if code not in ERROR_CODES:
        code = "INTERNAL"

    payload = {
        "code": code,
        "message": message,
        "details": details or {},
        "retryable": retryable,
    }
    return build_envelope(
        msg_type="res",
        from_identity=request.get("to", _anonymous_identity("receiver")),
        to_identity=request.get("from", _anonymous_identity("sender")),
        content_type="error.v1",
        payload=payload,
        schema=get_builtin_descriptor("error.v1"),
        trace=derive_response_trace(request.get("trace")),
    )


def _anonymous_identity(name: str) -> dict[str, str]:
    return {
        "agent_id": f"did:key:{sha256_prefixed(name.encode())}",
        "name": name,
        "instance": "unknown",
        "role": name,
    }


def _validate_identity(identity: Any, field_name: str) -> None:
    if not isinstance(identity, dict):
        raise EnvelopeValidationError(f"{field_name} must be an object")

    for key in ("agent_id", "name", "instance", "role"):
        value = identity.get(key)
        if not isinstance(value, str) or not value:
            raise EnvelopeValidationError(f"{field_name}.{key} must be a non-empty string")


def _validate_security(sec: Any) -> str | None:
    if sec is None:
        return None
    if not isinstance(sec, dict):
        raise EnvelopeValidationError("sec must be an object")

    mode = sec.get("mode")
    if mode not in SUPPORTED_SECURITY_MODES:
        raise EnvelopeValidationError("sec.mode unsupported")

    if mode in {"sig", "enc+sig"}:
        sig = sec.get("sig")
        if not isinstance(sig, dict):
            raise EnvelopeValidationError("sec.sig must be present for signing modes")
        alg = sig.get("alg")
        if alg not in SUPPORTED_SIG_ALGS:
            raise EnvelopeValidationError("unsupported sec.sig.alg")
        value = sig.get("value")
        if not isinstance(value, str):
            raise EnvelopeValidationError("sec.sig.value must be a string")

    if mode in {"enc", "enc+sig"}:
        enc = sec.get("enc")
        if not isinstance(enc, dict):
            raise EnvelopeValidationError("sec.enc must be present for encryption modes")
        alg = enc.get("alg")
        if alg not in SUPPORTED_ENC_ALGS:
            raise EnvelopeValidationError("unsupported sec.enc.alg")
        if not isinstance(enc.get("recipients"), list):
            raise EnvelopeValidationError("sec.enc.recipients must be an array")
        if not isinstance(enc.get("nonce"), str):
            raise EnvelopeValidationError("sec.enc.nonce must be a string")
        if not isinstance(enc.get("ciphertext"), str):
            raise EnvelopeValidationError("sec.enc.ciphertext must be a string")

    replay = sec.get("replay")
    if replay is not None:
        if not isinstance(replay, dict):
            raise EnvelopeValidationError("sec.replay must be an object")
        nonce = replay.get("nonce")
        exp = replay.get("exp")
        if not isinstance(nonce, str) or not nonce:
            raise EnvelopeValidationError("sec.replay.nonce must be a non-empty string")
        if not isinstance(exp, str):
            raise EnvelopeValidationError("sec.replay.exp must be a string")
        ensure_iso_utc(exp)

    return mode


def _validate_trace(trace: Any, *, max_hops: int) -> None:
    if trace is None:
        return
    if not isinstance(trace, dict):
        raise EnvelopeValidationError("trace must be an object")

    root_id = trace.get("root_id")
    if not isinstance(root_id, str) or not root_id:
        raise EnvelopeValidationError("trace.root_id must be a non-empty string")

    span_id = trace.get("span_id")
    if not isinstance(span_id, str) or not span_id:
        raise EnvelopeValidationError("trace.span_id must be a non-empty string")

    parent_span_id = trace.get("parent_span_id")
    if parent_span_id is not None and (not isinstance(parent_span_id, str) or not parent_span_id):
        raise EnvelopeValidationError("trace.parent_span_id must be a non-empty string")

    hops = trace.get("hops")
    if not isinstance(hops, int):
        raise EnvelopeValidationError("trace.hops must be an integer")
    if hops < 0:
        raise EnvelopeValidationError("trace.hops must be >= 0")
    if hops > max_hops:
        raise EnvelopeValidationError("trace.hops exceeds max_hops")


def _validate_limits(envelope: dict[str, Any], limits: dict[str, int]) -> None:
    raw = canonical_json_bytes(envelope)
    if len(raw) > limits["max_bytes"]:
        raise EnvelopeValidationError("envelope exceeds max_bytes")

    depth = _depth(envelope)
    if depth > limits["max_depth"]:
        raise EnvelopeValidationError("envelope exceeds max_depth")

    _check_array_lengths(envelope, limits["max_array_len"])



def _depth(value: Any, current: int = 0) -> int:
    if isinstance(value, dict):
        if not value:
            return current + 1
        return max(_depth(item, current + 1) for item in value.values())
    if isinstance(value, list):
        if not value:
            return current + 1
        return max(_depth(item, current + 1) for item in value)
    return current + 1


def _check_array_lengths(value: Any, max_len: int) -> None:
    if isinstance(value, list):
        if len(value) > max_len:
            raise EnvelopeValidationError("array length exceeds max_array_len")
        for item in value:
            _check_array_lengths(item, max_len)
    elif isinstance(value, dict):
        for item in value.values():
            _check_array_lengths(item, max_len)
