"""HTTP transport bindings (stdlib + optional FastAPI adapter)."""

from __future__ import annotations

import datetime as dt
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
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


class ServerMetrics:
    """Thread-safe operational counters exposed via admin endpoints."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_at = time.monotonic()
        self._requests_total = 0
        self._requests_ok_total = 0
        self._requests_error_total = 0
        self._admission_reject_total = 0
        self._admission_reject_rate_limit_total = 0
        self._admission_reject_concurrency_total = 0
        self._decode_error_total = 0
        self._validation_error_total = 0
        self._handler_error_total = 0
        self._inflight = 0

    def on_request_start(self) -> None:
        with self._lock:
            self._requests_total += 1
            self._inflight += 1

    def on_request_end(self, response_envelope: dict[str, Any] | None) -> None:
        with self._lock:
            self._inflight = max(0, self._inflight - 1)
            if isinstance(response_envelope, dict) and response_envelope.get("ct") != "error.v1":
                self._requests_ok_total += 1
            else:
                self._requests_error_total += 1

    def on_admission_reject(self, reason: str | None) -> None:
        with self._lock:
            self._admission_reject_total += 1
            if reason == "rate_limit":
                self._admission_reject_rate_limit_total += 1
            elif reason == "concurrency_limit":
                self._admission_reject_concurrency_total += 1

    def on_decode_error(self) -> None:
        with self._lock:
            self._decode_error_total += 1

    def on_validation_error(self) -> None:
        with self._lock:
            self._validation_error_total += 1

    def on_handler_error(self) -> None:
        with self._lock:
            self._handler_error_total += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "requests_total": self._requests_total,
                "requests_ok_total": self._requests_ok_total,
                "requests_error_total": self._requests_error_total,
                "admission_reject_total": self._admission_reject_total,
                "admission_reject_rate_limit_total": self._admission_reject_rate_limit_total,
                "admission_reject_concurrency_total": self._admission_reject_concurrency_total,
                "decode_error_total": self._decode_error_total,
                "validation_error_total": self._validation_error_total,
                "handler_error_total": self._handler_error_total,
                "inflight": self._inflight,
                "uptime_s": round(max(0.0, time.monotonic() - self._started_at), 3),
            }

    def render_prometheus(self) -> str:
        snap = self.snapshot()
        lines = [
            "# HELP a2a_requests_total Total A2A POST requests received.",
            "# TYPE a2a_requests_total counter",
            f"a2a_requests_total {snap['requests_total']}",
            "# HELP a2a_requests_ok_total Successful (non-error envelope) requests.",
            "# TYPE a2a_requests_ok_total counter",
            f"a2a_requests_ok_total {snap['requests_ok_total']}",
            "# HELP a2a_requests_error_total Error-envelope requests.",
            "# TYPE a2a_requests_error_total counter",
            f"a2a_requests_error_total {snap['requests_error_total']}",
            "# HELP a2a_admission_reject_total Requests rejected by admission controller.",
            "# TYPE a2a_admission_reject_total counter",
            f"a2a_admission_reject_total {snap['admission_reject_total']}",
            "# HELP a2a_admission_reject_rate_limit_total Requests rejected due to rate limit.",
            "# TYPE a2a_admission_reject_rate_limit_total counter",
            f"a2a_admission_reject_rate_limit_total {snap['admission_reject_rate_limit_total']}",
            "# HELP a2a_admission_reject_concurrency_total Requests rejected due to concurrency limit.",
            "# TYPE a2a_admission_reject_concurrency_total counter",
            f"a2a_admission_reject_concurrency_total {snap['admission_reject_concurrency_total']}",
            "# HELP a2a_decode_error_total Request decode failures.",
            "# TYPE a2a_decode_error_total counter",
            f"a2a_decode_error_total {snap['decode_error_total']}",
            "# HELP a2a_validation_error_total Envelope validation/security failures.",
            "# TYPE a2a_validation_error_total counter",
            f"a2a_validation_error_total {snap['validation_error_total']}",
            "# HELP a2a_handler_error_total Handler/runtime failures.",
            "# TYPE a2a_handler_error_total counter",
            f"a2a_handler_error_total {snap['handler_error_total']}",
            "# HELP a2a_inflight_requests Current in-flight A2A requests.",
            "# TYPE a2a_inflight_requests gauge",
            f"a2a_inflight_requests {snap['inflight']}",
            "# HELP a2a_uptime_seconds Server uptime in seconds.",
            "# TYPE a2a_uptime_seconds gauge",
            f"a2a_uptime_seconds {snap['uptime_s']}",
        ]
        return "\n".join(lines) + "\n"


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
        admin_enabled: bool = False,
        admin_token: str | None = None,
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
        self.admin_enabled = admin_enabled
        self.admin_token = admin_token

        needs_replay = enforce_replay or bool(security_policy and security_policy.require_replay)
        self.replay_cache = replay_cache or (ReplayCache() if needs_replay else None)
        self._metrics = ServerMetrics()
        self._ready = True
        self._validate_tls_config()
        self._server = self._build_server()
        try:
            self._wrap_server_socket_with_tls()
        except Exception:
            self._server.server_close()
            raise

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
        admin_enabled = self.admin_enabled
        admin_token = self.admin_token
        metrics = self._metrics
        server_ref = self

        class RequestHandler(BaseHTTPRequestHandler):
            _READ_TIMEOUT_S = 15.0

            def do_GET(self) -> None:  # noqa: N802
                if not admin_enabled:
                    self.send_error(404, "Not Found")
                    return

                if self.path == "/healthz":
                    payload: dict[str, Any] = {
                        "status": "ok",
                        "service": "a2a-sdl-http",
                        "ts": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                    }
                    self._send_json(payload, status_code=200)
                    return

                if self.path in {"/readyz", "/metrics"} and not self._is_admin_authorized(admin_token):
                    self._send_json({"error": "unauthorized"}, status_code=401)
                    return

                if self.path == "/readyz":
                    snap = metrics.snapshot()
                    ready_payload: dict[str, Any] = {
                        "ready": bool(server_ref._ready),
                        "secure_mode": bool(security_policy is not None),
                        "replay_enforced": bool(enforce_replay),
                        "tls_enabled": bool(server_ref.tls_certfile and server_ref.tls_keyfile),
                        "admission_enabled": bool(admission_controller is not None),
                        "metrics": snap,
                    }
                    self._send_json(ready_payload, status_code=200)
                    return

                if self.path == "/metrics":
                    body = metrics.render_prometheus().encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                self.send_error(404, "Not Found")

            def _is_admin_authorized(self, token: str | None) -> bool:
                if not token:
                    return True
                auth = self.headers.get("Authorization", "").strip()
                if auth == f"Bearer {token}":
                    return True
                alt = self.headers.get("X-A2A-Admin-Token", "").strip()
                return alt == token

            def _send_json(self, payload: dict[str, Any], *, status_code: int = 200) -> None:
                body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/a2a":
                    self.send_error(404, "Not Found")
                    return

                metrics.on_request_start()

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
                response_envelope: dict[str, Any] | None = None
                if admission_controller is not None:
                    allowed, reason = admission_controller.acquire()
                    if not allowed:
                        metrics.on_admission_reject(reason)
                        response_envelope = make_error_response(
                            request=_fallback_request_envelope(),
                            code="BAD_REQUEST",
                            message="request rejected by admission controller",
                            details={"reason": reason},
                            retryable=True,
                        )
                        _send_protocol_response(response_envelope, status_code=429)
                        metrics.on_request_end(response_envelope)
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
                        metrics.on_decode_error()
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
                    if admission_controller is None or admission_acquired:
                        metrics.on_request_end(response_envelope)

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
                    metrics.on_validation_error()
                    return _validation_error_response(request_envelope, exc)
                except Exception as exc:
                    metrics.on_validation_error()
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
                    metrics.on_handler_error()
                    return make_error_response(
                        request=request_envelope,
                        code="INTERNAL",
                        message=f"handler returned invalid envelope: {exc}",
                    )
                except Exception as exc:
                    metrics.on_handler_error()
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
        self._ready = False
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
    _validate_http_url(url)
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
            # URL scheme/host are validated via _validate_http_url.
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
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


def _validate_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("url scheme must be http or https")
    if not parsed.netloc:
        raise ValueError("url must include host and optional port")
    if parsed.fragment:
        raise ValueError("url must not include a fragment")
    if parsed.path and not parsed.path.startswith("/"):
        raise ValueError("url path must be absolute")


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
