"""Optional WebSocket transport binding with protocol parity checks."""

from __future__ import annotations

import asyncio
import importlib
from typing import Any, Callable

from .codec import CodecError, decode_bytes, encode_bytes
from .envelope import EnvelopeValidationError, make_error_response, validate_envelope
from .policy import SecurityPolicy, enforce_request_security
from .replay import ReplayCache, ReplayCacheProtocol
from .transport_http import _enforce_replay, _fallback_request_envelope, _validation_error_response

websockets: Any
try:
    websockets = importlib.import_module("websockets")
except Exception:  # pragma: no cover - optional dependency
    websockets = None


MessageHandler = Callable[[dict[str, Any]], dict[str, Any]]


async def ws_send(
    uri: str,
    envelope: dict[str, Any],
    *,
    encoding: str = "json",
    timeout: float = 10.0,
    retry_attempts: int = 0,
    retry_backoff_s: float = 0.0,
) -> dict[str, Any]:
    if websockets is None:
        raise RuntimeError("websockets is not installed; install with a2a-sdl[ws]")

    validate_envelope(envelope, allow_schema_uri=False)
    payload = encode_bytes(envelope, encoding=encoding)

    attempts = max(0, int(retry_attempts))
    last_error: Exception | None = None

    for attempt in range(attempts + 1):
        try:
            async with websockets.connect(uri) as connection:
                await asyncio.wait_for(connection.send(payload), timeout=timeout)
                response = await asyncio.wait_for(connection.recv(), timeout=timeout)
            break
        except Exception as exc:
            last_error = exc
            if attempt >= attempts:
                raise
            if retry_backoff_s > 0:
                await asyncio.sleep(retry_backoff_s * (2**attempt))
    else:  # pragma: no cover
        if last_error is not None:
            raise last_error
        raise RuntimeError("ws_send failed")

    if isinstance(response, str):
        response_bytes = response.encode("utf-8")
    else:
        response_bytes = response

    decoded = decode_bytes(response_bytes, encoding=encoding)
    validate_envelope(decoded, allow_schema_uri=False)
    return decoded


async def ws_serve(
    handler: MessageHandler,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    encoding: str = "json",
    replay_cache: ReplayCacheProtocol | None = None,
    enforce_replay: bool = False,
    security_policy: SecurityPolicy | None = None,
):
    if websockets is None:
        raise RuntimeError("websockets is not installed; install with a2a-sdl[ws]")

    needs_replay = enforce_replay or bool(security_policy and security_policy.require_replay)
    cache = replay_cache or (ReplayCache() if needs_replay else None)

    async def _handle(connection):
        async for payload in connection:
            out = process_ws_payload(
                payload,
                encoding=encoding,
                handler=handler,
                enforce_replay=enforce_replay,
                replay_cache=cache,
                security_policy=security_policy,
            )
            await connection.send(out)

    return await websockets.serve(_handle, host, port)



def process_ws_payload(
    payload: bytes | str,
    *,
    encoding: str,
    handler: MessageHandler,
    enforce_replay: bool = False,
    replay_cache: ReplayCacheProtocol | None = None,
    security_policy: SecurityPolicy | None = None,
) -> bytes:
    """Process one websocket frame into one websocket frame."""
    if isinstance(payload, str):
        raw_payload = payload.encode("utf-8")
    else:
        raw_payload = payload

    request_envelope: dict[str, Any] | None = None
    try:
        request_envelope = decode_bytes(raw_payload, encoding=encoding)
    except CodecError as exc:
        response_envelope = make_error_response(
            request=_fallback_request_envelope(),
            code="UNSUPPORTED_ENCODING",
            message=str(exc),
        )
        return encode_bytes(response_envelope, encoding=encoding)

    try:
        validate_envelope(request_envelope, allow_schema_uri=False)
        if security_policy is not None:
            if enforce_replay and replay_cache is not None and not security_policy.require_replay:
                _enforce_replay(request_envelope, replay_cache)
            enforce_request_security(request_envelope, security_policy, replay_cache)
        elif enforce_replay and replay_cache is not None:
            _enforce_replay(request_envelope, replay_cache)
    except EnvelopeValidationError as exc:
        response_envelope = _validation_error_response(request_envelope, exc)
        return encode_bytes(response_envelope, encoding=encoding)
    except Exception as exc:
        response_envelope = make_error_response(
            request=request_envelope,
            code="BAD_REQUEST",
            message=str(exc),
        )
        return encode_bytes(response_envelope, encoding=encoding)

    try:
        response_envelope = handler(request_envelope)
        validate_envelope(response_envelope)
    except EnvelopeValidationError as exc:
        response_envelope = make_error_response(
            request=request_envelope,
            code="INTERNAL",
            message=f"handler returned invalid envelope: {exc}",
        )
    except Exception as exc:
        response_envelope = make_error_response(
            request=request_envelope,
            code="INTERNAL",
            message=str(exc),
        )

    return encode_bytes(response_envelope, encoding=encoding)
