"""HTTP transport bindings (stdlib + optional FastAPI adapter)."""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .audit import AuditChain
from .codec import CodecError, decode_bytes, detect_encoding_from_content_type, encode_bytes
from .constants import (
    DEFAULT_LIMITS,
    SUPPORTED_CONTENT_TYPES,
    SUPPORTED_ENC_ALGS,
    SUPPORTED_SECURITY_MODES,
    SUPPORTED_SIG_ALGS,
)
from .envelope import (
    EnvelopeValidationError,
    build_envelope,
    derive_response_trace,
    make_error_response,
    validate_envelope,
)
from .policy import SecurityPolicy, enforce_request_security
from .replay import ReplayCache, ReplayCacheProtocol
from .schema import get_builtin_descriptor
from .utils import new_message_id


MessageHandler = Callable[[dict[str, Any]], dict[str, Any]]


class AdmissionController:
    """Simple token-bucket + concurrency gate for inbound requests."""

    def __init__(self, *, max_concurrent: int, rate_limit_rps: float, burst: int) -> None:
        self.max_concurrent = max(1, int(max_concurrent))
        self.rate_limit_rps = max(0.0, float(rate_limit_rps))
        self.burst = max(1, int(burst))
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent)
        self._lock = threading.Lock()
        self._tokens = float(self.burst)
        self._last_refill = time.monotonic()

    def acquire(self) -> tuple[bool, str | None]:
        if not self._semaphore.acquire(blocking=False):
            return False, "concurrency_limit"

        with self._lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self._last_refill)
            self._last_refill = now
            self._tokens = min(self.burst, self._tokens + (elapsed * self.rate_limit_rps))

            if self._tokens < 1.0:
                self._semaphore.release()
                return False, "rate_limit"

            self._tokens -= 1.0
        return True, None

    def release(self) -> None:
        self._semaphore.release()


class A2AHTTPServer:
    """Threaded stdlib HTTP server for `/a2a` requests."""

    def __init__(
        self,
        host: str,
        port: int,
        handler: MessageHandler,
        *,
        replay_cache: ReplayCacheProtocol | None = None,
        enforce_replay: bool = False,
        security_policy: SecurityPolicy | None = None,
        audit_chain: AuditChain | None = None,
        tls_certfile: str | None = None,
        tls_keyfile: str | None = None,
        tls_ca_file: str | None = None,
        tls_require_client_cert: bool = False,
        admission_controller: AdmissionController | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.handler = handler
        self.enforce_replay = enforce_replay
        self.security_policy = security_policy
        self.audit_chain = audit_chain
        self.tls_certfile = tls_certfile
        self.tls_keyfile = tls_keyfile
        self.tls_ca_file = tls_ca_file
        self.tls_require_client_cert = tls_require_client_cert
        self.admission_controller = admission_controller

        needs_replay = enforce_replay or bool(security_policy and security_policy.require_replay)
        self.replay_cache = replay_cache or (ReplayCache() if needs_replay else None)
        self._validate_tls_config()
        self._server = self._build_server()
        self._wrap_server_socket_with_tls()

    def _validate_tls_config(self) -> None:
        has_cert = bool(self.tls_certfile)
        has_key = bool(self.tls_keyfile)
        if has_cert != has_key:
            raise ValueError("tls_certfile and tls_keyfile must be provided together")
        if self.tls_require_client_cert and not has_cert:
            raise ValueError("tls_require_client_cert requires tls_certfile/tls_keyfile")

    def _wrap_server_socket_with_tls(self) -> None:
        if not self.tls_certfile or not self.tls_keyfile:
            return

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=self.tls_certfile, keyfile=self.tls_keyfile)
        if self.tls_ca_file:
            context.load_verify_locations(cafile=self.tls_ca_file)
        if self.tls_require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_NONE
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)

    def _build_server(self) -> ThreadingHTTPServer:
        handler_fn = self.handler
        enforce_replay = self.enforce_replay
        replay_cache = self.replay_cache
        security_policy = self.security_policy
        audit_chain = self.audit_chain
        admission_controller = self.admission_controller

        class RequestHandler(BaseHTTPRequestHandler):
            _READ_TIMEOUT_S = 15.0

            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/a2a":
                    self.send_error(404, "Not Found")
                    return

                content_type = self.headers.get("Content-Type")
                encoding = detect_encoding_from_content_type(content_type)
                accept = self.headers.get("Accept", "")

                def _send_protocol_response(response_envelope: dict[str, Any], *, status_code: int = 200) -> None:
                    response_encoding = "cbor" if "application/cbor" in accept else encoding
                    try:
                        response_bytes = encode_bytes(response_envelope, encoding=response_encoding)
                        response_ct = "application/cbor" if response_encoding == "cbor" else "application/json"
                    except Exception:
                        response_bytes = encode_bytes(response_envelope, encoding="json")
                        response_ct = "application/json"

                    try:
                        self.send_response(status_code)
                        self.send_header("Content-Type", response_ct)
                        self.send_header("Content-Length", str(len(response_bytes)))
                        self.end_headers()
                        self.wfile.write(response_bytes)
                    except (BrokenPipeError, ConnectionResetError):
                        return

                admission_acquired = False
                if admission_controller is not None:
                    allowed, reason = admission_controller.acquire()
                    if not allowed:
                        response_envelope = make_error_response(
                            request=_fallback_request_envelope(),
                            code="BAD_REQUEST",
                            message="request rejected by admission controller",
                            details={"reason": reason},
                            retryable=True,
                        )
                        _send_protocol_response(response_envelope, status_code=429)
                        return
                    admission_acquired = True

                try:
                    length_header = self.headers.get("Content-Length", "0")
                    try:
                        length = int(length_header)
                    except ValueError:
                        response_envelope = make_error_response(
                            request=_fallback_request_envelope(),
                            code="BAD_REQUEST",
                            message="invalid Content-Length",
                        )
                        _send_protocol_response(response_envelope)
                        return

                    if length < 0:
                        response_envelope = make_error_response(
                            request=_fallback_request_envelope(),
                            code="BAD_REQUEST",
                            message="negative Content-Length",
                        )
                        _send_protocol_response(response_envelope)
                        return

                    max_bytes = int(DEFAULT_LIMITS["max_bytes"])
                    if length > max_bytes:
                        response_envelope = make_error_response(
                            request=_fallback_request_envelope(),
                            code="BAD_REQUEST",
                            message=f"content-length exceeds max_bytes ({max_bytes})",
                            details={"max_bytes": max_bytes},
                        )
                        _send_protocol_response(response_envelope)
                        return

                    try:
                        self.connection.settimeout(self._READ_TIMEOUT_S)
                        body = self.rfile.read(length)
                    except (TimeoutError, socket.timeout):
                        response_envelope = make_error_response(
                            request=_fallback_request_envelope(),
                            code="BAD_REQUEST",
                            message="request read timeout",
                        )
                        _send_protocol_response(response_envelope)
                        return

                    request_envelope: dict[str, Any] | None = None
                    try:
                        request_envelope = decode_bytes(body, encoding=encoding)
                    except CodecError as exc:
                        response_envelope = make_error_response(
                            request=_fallback_request_envelope(),
                            code="UNSUPPORTED_ENCODING",
                            message=str(exc),
                        )
                    else:
                        response_envelope = self._process_request(request_envelope)

                    if audit_chain is not None:
                        response_envelope = _attach_audit_receipt(
                            request_envelope=request_envelope,
                            response_envelope=response_envelope,
                            audit_chain=audit_chain,
                        )
                        try:
                            validate_envelope(response_envelope)
                        except Exception as exc:
                            response_envelope = make_error_response(
                                request=request_envelope or _fallback_request_envelope(),
                                code="INTERNAL",
                                message=f"audit response invalid: {exc}",
                            )

                    _send_protocol_response(response_envelope)
                finally:
                    if admission_acquired and admission_controller is not None:
                        admission_controller.release()

            def _process_request(self, request_envelope: dict[str, Any]) -> dict[str, Any]:
                try:
                    validate_envelope(request_envelope, allow_schema_uri=False)
                    if security_policy is not None:
                        if enforce_replay and replay_cache is not None and not security_policy.require_replay:
                            _enforce_replay(request_envelope, replay_cache)
                        enforce_request_security(request_envelope, security_policy, replay_cache)
                    elif enforce_replay and replay_cache is not None:
                        _enforce_replay(request_envelope, replay_cache)
                except EnvelopeValidationError as exc:
                    return _validation_error_response(request_envelope, exc)
                except Exception as exc:
                    return make_error_response(
                        request=request_envelope,
                        code="BAD_REQUEST",
                        message=str(exc),
                    )

                try:
                    response_envelope = handler_fn(request_envelope)
                    validate_envelope(response_envelope)
                    return response_envelope
                except EnvelopeValidationError as exc:
                    return make_error_response(
                        request=request_envelope,
                        code="INTERNAL",
                        message=f"handler returned invalid envelope: {exc}",
                    )
                except Exception as exc:
                    return make_error_response(
                        request=request_envelope,
                        code="INTERNAL",
                        message=str(exc),
                    )

            def log_message(self, format: str, *args: object) -> None:
                return

        class ReusableServer(ThreadingHTTPServer):
            allow_reuse_address = True

        return ReusableServer((self.host, self.port), RequestHandler)

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()



def send_http(
    url: str,
    envelope: dict[str, Any],
    *,
    encoding: str = "json",
    timeout: float = 10.0,
    retry_attempts: int = 0,
    retry_backoff_s: float = 0.0,
) -> dict[str, Any]:
    validate_envelope(envelope, allow_schema_uri=False)
    payload = encode_bytes(envelope, encoding=encoding)

    content_type = "application/cbor" if encoding == "cbor" else "application/json"
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": content_type, "Accept": content_type},
        method="POST",
    )

    attempts = max(0, int(retry_attempts))
    body: bytes | None = None
    response_content_type: str | None = None
    last_network_error: Exception | None = None

    for attempt in range(attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()
                response_content_type = response.headers.get("Content-Type")
            break
        except urllib.error.HTTPError as exc:
            body = exc.read()
            response_content_type = exc.headers.get("Content-Type") if exc.headers else None
            break
        except (
            TimeoutError,
            urllib.error.URLError,
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
        ) as exc:
            last_network_error = exc
            if attempt >= attempts:
                raise
            if retry_backoff_s > 0:
                time.sleep(retry_backoff_s * (2**attempt))

    if body is None:
        if last_network_error is not None:
            raise last_network_error
        raise RuntimeError("send_http failed without response body")

    response_encoding = detect_encoding_from_content_type(response_content_type)
    decoded = decode_bytes(body, encoding=response_encoding)
    validate_envelope(decoded, allow_schema_uri=False)
    return decoded


def send_http_with_auto_downgrade(
    url: str,
    envelope: dict[str, Any],
    *,
    encoding: str = "json",
    timeout: float = 10.0,
    retry_attempts: int = 0,
    retry_backoff_s: float = 0.0,
) -> dict[str, Any]:
    """Send and, on UNSUPPORTED_CT, retry with negotiated downgrade behavior."""
    first_response = send_http(
        url,
        envelope,
        encoding=encoding,
        timeout=timeout,
        retry_attempts=retry_attempts,
        retry_backoff_s=retry_backoff_s,
    )

    action = _extract_unsupported_ct_action(first_response)
    if action is None:
        return first_response

    requested_ct = envelope.get("ct")
    if not isinstance(requested_ct, str):
        return first_response

    supported_ct = action
    candidate_ct = _pick_downgrade_ct(requested_ct, supported_ct)
    if candidate_ct is not None:
        downgraded = _rebuild_request_for_content_type(envelope, candidate_ct)
        try:
            return send_http(
                url,
                downgraded,
                encoding=encoding,
                timeout=timeout,
                retry_attempts=retry_attempts,
                retry_backoff_s=retry_backoff_s,
            )
        except EnvelopeValidationError:
            # Fallback to explicit negotiation if downgrade payload is incompatible.
            pass

    if "negotiation.v1" in supported_ct:
        negotiation_request = _build_negotiation_request(envelope, requested_ct)
        return send_http(
            url,
            negotiation_request,
            encoding=encoding,
            timeout=timeout,
            retry_attempts=retry_attempts,
            retry_backoff_s=retry_backoff_s,
        )

    return first_response


def create_fastapi_app(handler: MessageHandler):
    """Create FastAPI app if fastapi is installed."""

    try:
        from fastapi import FastAPI, Request, Response
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("fastapi is not installed; install with a2a-sdl[http]") from exc

    app = FastAPI()

    @app.post("/a2a")
    async def a2a_endpoint(request: Request) -> Response:
        body = await request.body()
        content_type = request.headers.get("content-type")
        encoding = detect_encoding_from_content_type(content_type)

        try:
            decoded = decode_bytes(body, encoding=encoding)
            try:
                validate_envelope(decoded, allow_schema_uri=False)
            except EnvelopeValidationError as exc:
                result = _validation_error_response(decoded, exc)
            else:
                result = handler(decoded)
                validate_envelope(result)
        except CodecError as exc:
            result = make_error_response(
                request=_fallback_request_envelope(),
                code="UNSUPPORTED_ENCODING",
                message=str(exc),
            )
        except Exception as exc:
            result = make_error_response(
                request=_fallback_request_envelope(),
                code="BAD_REQUEST",
                message=str(exc),
            )

        try:
            response_payload = encode_bytes(result, encoding=encoding)
            response_ct = "application/cbor" if encoding == "cbor" else "application/json"
        except Exception:
            response_payload = encode_bytes(result, encoding="json")
            response_ct = "application/json"

        return Response(content=response_payload, media_type=response_ct)

    return app



def _fallback_identity() -> dict[str, str]:
    return {
        "agent_id": "did:key:unknown",
        "name": "unknown",
        "instance": "unknown",
        "role": "unknown",
    }



def _fallback_request_envelope() -> dict[str, Any]:
    unknown = _fallback_identity()
    return build_envelope(
        msg_type="req",
        from_identity=unknown,
        to_identity=unknown,
        content_type="error.v1",
        payload={
            "code": "BAD_REQUEST",
            "message": "failed to parse request",
            "details": {},
            "retryable": False,
        },
        schema=get_builtin_descriptor("error.v1"),
    )



def _validation_error_response(request_envelope: dict[str, Any], exc: EnvelopeValidationError) -> dict[str, Any]:
    message = str(exc)

    if message.startswith("unsupported ct:"):
        return make_error_response(
            request=request_envelope,
            code="UNSUPPORTED_CT",
            message=message,
            details={"supported_ct": sorted(SUPPORTED_CONTENT_TYPES)},
            retryable=True,
        )

    if message.startswith("schema invalid:") or message.startswith("payload validation failed:"):
        return make_error_response(
            request=request_envelope,
            code="SCHEMA_INVALID",
            message=message,
            retryable=True,
        )

    if message in {"sec.replay expired", "sec.replay nonce already seen"}:
        return make_error_response(
            request=request_envelope,
            code="BAD_REQUEST",
            message=message,
            details={"reason": "replay_expired" if message.endswith("expired") else "replay_detected"},
            retryable=False,
        )

    if (
        message.startswith("security policy")
        or message.startswith("signature verification failed")
        or message.startswith("decryption failed")
    ):
        return make_error_response(
            request=request_envelope,
            code="SECURITY_UNSUPPORTED",
            message=message,
            details={
                "supported": {
                    "modes": sorted(SUPPORTED_SECURITY_MODES),
                    "sig": sorted(SUPPORTED_SIG_ALGS),
                    "enc": sorted(SUPPORTED_ENC_ALGS),
                }
            },
            retryable=False,
        )

    if message.startswith("unsupported sec") or message.startswith("sec."):
        return make_error_response(
            request=request_envelope,
            code="SECURITY_UNSUPPORTED",
            message=message,
            details={
                "supported": {
                    "modes": sorted(SUPPORTED_SECURITY_MODES),
                    "sig": sorted(SUPPORTED_SIG_ALGS),
                    "enc": sorted(SUPPORTED_ENC_ALGS),
                }
            },
            retryable=True,
        )

    return make_error_response(
        request=request_envelope,
        code="BAD_REQUEST",
        message=message,
        retryable=False,
    )



def _enforce_replay(request_envelope: dict[str, Any], replay_cache: ReplayCacheProtocol) -> None:
    sec = request_envelope.get("sec")
    if not isinstance(sec, dict):
        return

    replay = sec.get("replay")
    if not isinstance(replay, dict):
        return

    nonce = replay.get("nonce")
    exp = replay.get("exp")
    if not isinstance(nonce, str) or not isinstance(exp, str):
        return

    exp_ts = dt.datetime.fromisoformat(exp.replace("Z", "+00:00"))
    now = dt.datetime.now(dt.timezone.utc)
    if exp_ts <= now:
        raise EnvelopeValidationError("sec.replay expired")

    from_identity = request_envelope.get("from")
    if isinstance(from_identity, dict):
        agent_id = from_identity.get("agent_id", "did:key:unknown")
    else:
        agent_id = "did:key:unknown"

    if replay_cache.seen_or_add(str(agent_id), nonce):
        raise EnvelopeValidationError("sec.replay nonce already seen")


def _extract_unsupported_ct_action(response: dict[str, Any]) -> list[str] | None:
    if response.get("ct") != "error.v1":
        return None

    payload = response.get("payload")
    if not isinstance(payload, dict):
        return None
    if payload.get("code") != "UNSUPPORTED_CT":
        return None

    details = payload.get("details")
    if not isinstance(details, dict):
        return None

    supported = details.get("supported_ct")
    if not isinstance(supported, list):
        return None
    if not all(isinstance(item, str) for item in supported):
        return None
    return [item for item in supported if isinstance(item, str)]


def _pick_downgrade_ct(requested_ct: str, supported_ct: list[str]) -> str | None:
    req = _split_ct_version(requested_ct)
    if req is None:
        return None
    family, version = req

    candidates: list[tuple[int, str]] = []
    for item in supported_ct:
        parsed = _split_ct_version(item)
        if parsed is None:
            continue
        cand_family, cand_version = parsed
        if cand_family == family and cand_version < version:
            candidates.append((cand_version, item))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _split_ct_version(content_type: str) -> tuple[str, int] | None:
    marker = ".v"
    if marker not in content_type:
        return None
    base, version_raw = content_type.rsplit(marker, 1)
    if not base or not version_raw.isdigit():
        return None
    return base, int(version_raw)


def _rebuild_request_for_content_type(request: dict[str, Any], content_type: str) -> dict[str, Any]:
    schema = get_builtin_descriptor(content_type) or request.get("schema")
    return build_envelope(
        msg_type=str(request.get("type", "req")),
        from_identity=request["from"],
        to_identity=request["to"],
        content_type=content_type,
        payload=request.get("payload"),
        cap=request.get("cap"),
        schema=schema if isinstance(schema, dict) else None,
        trace=request.get("trace"),
    )


def _build_negotiation_request(request: dict[str, Any], requested_ct: str) -> dict[str, Any]:
    payload = {
        "need": {"ct": [requested_ct]},
        "have": {"ct": [requested_ct]},
        "ask": ["downgrade_ct", "send_embedded_schema"],
        "supported_ct": sorted(SUPPORTED_CONTENT_TYPES),
    }
    return build_envelope(
        msg_type=str(request.get("type", "req")),
        from_identity=request["from"],
        to_identity=request["to"],
        content_type="negotiation.v1",
        payload=payload,
        cap=request.get("cap"),
        schema=get_builtin_descriptor("negotiation.v1"),
        trace=request.get("trace"),
    )


def _attach_audit_receipt(
    *,
    request_envelope: dict[str, Any] | None,
    response_envelope: dict[str, Any],
    audit_chain: AuditChain,
) -> dict[str, Any]:
    request_payload = request_envelope.get("payload") if isinstance(request_envelope, dict) else None
    response_payload = response_envelope.get("payload")

    event = {
        "request_id": request_envelope.get("id") if isinstance(request_envelope, dict) else None,
        "request_ct": request_envelope.get("ct") if isinstance(request_envelope, dict) else None,
        "request_from": request_envelope.get("from", {}).get("agent_id")
        if isinstance(request_envelope, dict) and isinstance(request_envelope.get("from"), dict)
        else None,
        "response_id": response_envelope.get("id"),
        "response_ct": response_envelope.get("ct"),
        "response_error_code": response_payload.get("code")
        if isinstance(response_payload, dict) and response_envelope.get("ct") == "error.v1"
        else None,
        "request_payload_present": request_payload is not None,
    }
    receipt = audit_chain.append(event)

    trace = response_envelope.get("trace")
    if not isinstance(trace, dict):
        request_trace = request_envelope.get("trace") if isinstance(request_envelope, dict) else None
        trace = derive_response_trace(request_trace)
        if trace is None:
            trace = {
                "root_id": str(response_envelope.get("id", "unknown")),
                "span_id": new_message_id(),
                "hops": 0,
            }
        response_envelope["trace"] = trace

    trace["audit"] = receipt
    return response_envelope
