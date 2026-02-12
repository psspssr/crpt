"""Protocol conformance runner for A2A-SDL."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable

from .codec import decode_bytes, encode_bytes
from .envelope import EnvelopeValidationError, build_envelope, validate_envelope
from .handlers import default_handler
from .policy import SecurityPolicy
from .replay import ReplayCache
from .schema import get_builtin_descriptor, make_embedded_schema
from .security import encrypt_payload, generate_signing_keypair, generate_x25519_keypair, sign_envelope
from .transport_http import A2AHTTPServer, send_http
from .transport_ipc import IPCServer, encode_ipc_frame, send_ipc
from .transport_ws import process_ws_payload
from .utils import new_message_id

CONFORMANCE_VERSION = "v1"
SUPPORTED_TRANSPORTS = {"core", "http", "ipc", "ws"}
SUPPORTED_MODES = {"dev", "secure"}


@dataclass(slots=True)
class ConformanceCaseResult:
    case_id: str
    category: str
    transport: str
    mode: str
    ok: bool
    detail: str
    duration_ms: int


@dataclass(frozen=True, slots=True)
class _SecureContext:
    sender_agent_id: str
    receiver_agent_id: str
    sign_kid: str
    sign_private_key: str
    sign_public_key: str
    decrypt_kid: str
    decrypt_private_key: str
    decrypt_public_key: str

    def policy(self) -> SecurityPolicy:
        return SecurityPolicy(
            require_mode="enc+sig",
            require_replay=True,
            allowed_agents={self.sender_agent_id},
            trusted_signing_keys={self.sign_kid: self.sign_public_key},
            required_kid_by_agent={self.sender_agent_id: self.sign_kid},
            decrypt_private_keys={self.decrypt_kid: self.decrypt_private_key},
        )


def run_conformance_suite(
    *,
    transports: Iterable[str] | None = None,
    modes: Iterable[str] | None = None,
    include_load: bool = True,
    load_requests: int = 24,
    timeout_s: float = 10.0,
) -> dict[str, Any]:
    selected_transports = _normalize_transports(transports)
    selected_modes = _normalize_modes(modes)

    started = dt.datetime.now(dt.timezone.utc)
    started_perf = time.perf_counter()
    results: list[ConformanceCaseResult] = []

    def record(
        *,
        case_id: str,
        category: str,
        transport: str,
        mode: str,
        fn: Callable[[], str | None],
    ) -> None:
        case_started = time.perf_counter()
        try:
            detail = fn() or "ok"
            ok = True
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            ok = False
        elapsed_ms = int((time.perf_counter() - case_started) * 1000)
        results.append(
            ConformanceCaseResult(
                case_id=case_id,
                category=category,
                transport=transport,
                mode=mode,
                ok=ok,
                detail=detail,
                duration_ms=elapsed_ms,
            )
        )

    if "core" in selected_transports:
        _run_core_cases(record=record)

    if "http" in selected_transports:
        for mode in sorted(selected_modes):
            _run_http_cases(
                record=record,
                mode=mode,
                include_load=include_load,
                load_requests=load_requests,
                timeout_s=timeout_s,
            )

    if "ipc" in selected_transports:
        for mode in sorted(selected_modes):
            _run_ipc_cases(
                record=record,
                mode=mode,
                include_load=include_load,
                load_requests=load_requests,
                timeout_s=timeout_s,
            )

    if "ws" in selected_transports:
        for mode in sorted(selected_modes):
            _run_ws_cases(
                record=record,
                mode=mode,
                include_load=include_load,
                load_requests=load_requests,
            )

    total_ms = int((time.perf_counter() - started_perf) * 1000)
    total = len(results)
    passed_count = sum(1 for item in results if item.ok)
    failed = total - passed_count
    return {
        "protocol": CONFORMANCE_VERSION,
        "started_at": started.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "duration_ms": total_ms,
        "passed": failed == 0,
        "summary": {
            "total": total,
            "passed": passed_count,
            "failed": failed,
            "transports": sorted(selected_transports),
            "modes": sorted(selected_modes),
            "include_load": bool(include_load),
            "load_requests": int(load_requests),
        },
        "results": [asdict(item) for item in results],
    }


def _run_core_cases(
    *,
    record: Callable[..., None],
) -> None:
    record(
        case_id="core.valid.task_envelope",
        category="golden",
        transport="core",
        mode="dev",
        fn=_case_core_valid_task_envelope,
    )
    record(
        case_id="core.invalid.missing_ct",
        category="negative",
        transport="core",
        mode="dev",
        fn=_case_core_missing_ct_rejected,
    )
    record(
        case_id="core.invalid.schema_hash_mismatch",
        category="negative",
        transport="core",
        mode="dev",
        fn=_case_core_schema_hash_mismatch_rejected,
    )


def _run_http_cases(
    *,
    record: Callable[..., None],
    mode: str,
    include_load: bool,
    load_requests: int,
    timeout_s: float,
) -> None:
    secure_context = _make_secure_context() if mode == "secure" else None
    security_policy = secure_context.policy() if secure_context is not None else None
    replay_cache = ReplayCache() if security_policy is not None else None
    server = A2AHTTPServer(
        "127.0.0.1",
        0,
        handler=default_handler,
        security_policy=security_policy,
        replay_cache=replay_cache,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    port = int(server._server.server_address[1])  # noqa: SLF001 - test/conformance plumbing
    url = f"http://127.0.0.1:{port}/a2a"

    def _case_roundtrip() -> str:
        request = _make_secure_task_request(secure_context) if secure_context is not None else _make_task_request()
        response = send_http(
            url,
            request,
            timeout=timeout_s,
            retry_attempts=1,
            retry_backoff_s=0.01,
        )
        _assert(response.get("ct") == "state.v1", "expected state.v1 response")
        return "roundtrip ok"

    def _case_unsupported_ct_error() -> str:
        request = _make_task_request()
        request["ct"] = "unknown.v9"
        request["schema"] = make_embedded_schema({"type": "object"})
        response = _send_http_raw_envelope(url, request, timeout_s=timeout_s)
        _assert(response.get("ct") == "error.v1", "expected error envelope")
        payload = response.get("payload")
        if not isinstance(payload, dict):
            raise AssertionError("expected error payload object")
        _assert(payload.get("code") == "UNSUPPORTED_CT", "expected UNSUPPORTED_CT")
        return "unsupported ct mapped"

    def _case_invalid_encoding_error() -> str:
        response = _send_http_raw_bytes(url, b"not-json", timeout_s=timeout_s)
        _assert(response.get("ct") == "error.v1", "expected error envelope")
        payload = response.get("payload")
        if not isinstance(payload, dict):
            raise AssertionError("expected error payload object")
        _assert(payload.get("code") == "UNSUPPORTED_ENCODING", "expected UNSUPPORTED_ENCODING")
        return "invalid encoding mapped"

    def _case_load_roundtrip() -> str:
        total = max(1, int(load_requests))

        def send_one(_: int) -> str:
            request = _make_secure_task_request(secure_context) if secure_context is not None else _make_task_request()
            response = send_http(
                url,
                request,
                timeout=timeout_s,
                retry_attempts=1,
                retry_backoff_s=0.01,
            )
            return str(response.get("ct"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, total)) as executor:
            futures = [executor.submit(send_one, idx) for idx in range(total)]
            values = [future.result(timeout=timeout_s * 2) for future in futures]
        _assert(len(values) == total, "load result count mismatch")
        _assert(all(item == "state.v1" for item in values), "load responses must be state.v1")
        return f"load ok ({total} requests)"

    try:
        record(
            case_id=f"http.{mode}.roundtrip",
            category="golden",
            transport="http",
            mode=mode,
            fn=_case_roundtrip,
        )
        record(
            case_id=f"http.{mode}.unsupported_ct_error",
            category="failure",
            transport="http",
            mode=mode,
            fn=_case_unsupported_ct_error,
        )
        record(
            case_id=f"http.{mode}.invalid_encoding_error",
            category="failure",
            transport="http",
            mode=mode,
            fn=_case_invalid_encoding_error,
        )
        if include_load:
            record(
                case_id=f"http.{mode}.load_roundtrip",
                category="load",
                transport="http",
                mode=mode,
                fn=_case_load_roundtrip,
            )
    finally:
        server.shutdown()
        thread.join(timeout=1)


def _run_ipc_cases(
    *,
    record: Callable[..., None],
    mode: str,
    include_load: bool,
    load_requests: int,
    timeout_s: float,
) -> None:
    secure_context = _make_secure_context() if mode == "secure" else None
    security_policy = secure_context.policy() if secure_context is not None else None
    replay_cache = ReplayCache() if security_policy is not None else None
    server = IPCServer(
        "127.0.0.1",
        0,
        handler=default_handler,
        security_policy=security_policy,
        replay_cache=replay_cache,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    server_address = server._server.server_address  # noqa: SLF001 - test/conformance plumbing
    host = str(server_address[0])
    port = int(server_address[1])

    def _case_roundtrip() -> str:
        request = _make_secure_task_request(secure_context) if secure_context is not None else _make_task_request()
        response = send_ipc(host, port, request, timeout=timeout_s)
        _assert(response.get("ct") == "state.v1", "expected state.v1 response")
        return "roundtrip ok"

    def _case_unsupported_ct_error() -> str:
        request = _make_task_request()
        request["ct"] = "unknown.v9"
        request["schema"] = make_embedded_schema({"type": "object"})
        response = _send_ipc_raw_envelope(host, port, request, timeout_s=timeout_s)
        _assert(response.get("ct") == "error.v1", "expected error envelope")
        payload = response.get("payload")
        if not isinstance(payload, dict):
            raise AssertionError("expected error payload object")
        _assert(payload.get("code") == "UNSUPPORTED_CT", "expected UNSUPPORTED_CT")
        return "unsupported ct mapped"

    def _case_invalid_encoding_error() -> str:
        response = _send_ipc_raw_bytes(host, port, b"not-json", timeout_s=timeout_s)
        _assert(response.get("ct") == "error.v1", "expected error envelope")
        payload = response.get("payload")
        if not isinstance(payload, dict):
            raise AssertionError("expected error payload object")
        _assert(payload.get("code") == "UNSUPPORTED_ENCODING", "expected UNSUPPORTED_ENCODING")
        return "invalid encoding mapped"

    def _case_load_roundtrip() -> str:
        total = max(1, int(load_requests))

        def send_one(_: int) -> str:
            request = _make_secure_task_request(secure_context) if secure_context is not None else _make_task_request()
            response = send_ipc(host, port, request, timeout=timeout_s)
            return str(response.get("ct"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, total)) as executor:
            futures = [executor.submit(send_one, idx) for idx in range(total)]
            values = [future.result(timeout=timeout_s * 2) for future in futures]
        _assert(len(values) == total, "load result count mismatch")
        _assert(all(item == "state.v1" for item in values), "load responses must be state.v1")
        return f"load ok ({total} requests)"

    try:
        record(
            case_id=f"ipc.{mode}.roundtrip",
            category="golden",
            transport="ipc",
            mode=mode,
            fn=_case_roundtrip,
        )
        record(
            case_id=f"ipc.{mode}.unsupported_ct_error",
            category="failure",
            transport="ipc",
            mode=mode,
            fn=_case_unsupported_ct_error,
        )
        record(
            case_id=f"ipc.{mode}.invalid_encoding_error",
            category="failure",
            transport="ipc",
            mode=mode,
            fn=_case_invalid_encoding_error,
        )
        if include_load:
            record(
                case_id=f"ipc.{mode}.load_roundtrip",
                category="load",
                transport="ipc",
                mode=mode,
                fn=_case_load_roundtrip,
            )
    finally:
        server.shutdown()
        thread.join(timeout=1)


def _run_ws_cases(
    *,
    record: Callable[..., None],
    mode: str,
    include_load: bool,
    load_requests: int,
) -> None:
    secure_context = _make_secure_context() if mode == "secure" else None
    security_policy = secure_context.policy() if secure_context is not None else None
    replay_cache = ReplayCache() if security_policy is not None else None

    def _case_roundtrip() -> str:
        request = _make_secure_task_request(secure_context) if secure_context is not None else _make_task_request()
        encoded = encode_bytes(request, encoding="json")
        out = process_ws_payload(
            encoded,
            encoding="json",
            handler=default_handler,
            security_policy=security_policy,
            replay_cache=replay_cache,
        )
        response = decode_bytes(out, encoding="json")
        _assert(response.get("ct") == "state.v1", "expected state.v1 response")
        return "roundtrip ok"

    def _case_unsupported_ct_error() -> str:
        request = _make_task_request()
        request["ct"] = "unknown.v9"
        request["schema"] = make_embedded_schema({"type": "object"})
        encoded = encode_bytes(request, encoding="json")
        out = process_ws_payload(encoded, encoding="json", handler=default_handler)
        response = decode_bytes(out, encoding="json")
        _assert(response.get("ct") == "error.v1", "expected error envelope")
        payload = response.get("payload")
        if not isinstance(payload, dict):
            raise AssertionError("expected error payload object")
        _assert(payload.get("code") == "UNSUPPORTED_CT", "expected UNSUPPORTED_CT")
        return "unsupported ct mapped"

    def _case_invalid_encoding_error() -> str:
        out = process_ws_payload(b"not-json", encoding="json", handler=default_handler)
        response = decode_bytes(out, encoding="json")
        _assert(response.get("ct") == "error.v1", "expected error envelope")
        payload = response.get("payload")
        if not isinstance(payload, dict):
            raise AssertionError("expected error payload object")
        _assert(payload.get("code") == "UNSUPPORTED_ENCODING", "expected UNSUPPORTED_ENCODING")
        return "invalid encoding mapped"

    def _case_load_roundtrip() -> str:
        total = max(1, int(load_requests))

        def send_one(_: int) -> str:
            request = _make_secure_task_request(secure_context) if secure_context is not None else _make_task_request()
            encoded = encode_bytes(request, encoding="json")
            out = process_ws_payload(
                encoded,
                encoding="json",
                handler=default_handler,
                security_policy=security_policy,
                replay_cache=replay_cache,
            )
            response = decode_bytes(out, encoding="json")
            return str(response.get("ct"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, total)) as executor:
            futures = [executor.submit(send_one, idx) for idx in range(total)]
            values = [future.result(timeout=15) for future in futures]
        _assert(len(values) == total, "load result count mismatch")
        _assert(all(item == "state.v1" for item in values), "load responses must be state.v1")
        return f"load ok ({total} requests)"

    record(
        case_id=f"ws.{mode}.roundtrip",
        category="golden",
        transport="ws",
        mode=mode,
        fn=_case_roundtrip,
    )
    record(
        case_id=f"ws.{mode}.unsupported_ct_error",
        category="failure",
        transport="ws",
        mode=mode,
        fn=_case_unsupported_ct_error,
    )
    record(
        case_id=f"ws.{mode}.invalid_encoding_error",
        category="failure",
        transport="ws",
        mode=mode,
        fn=_case_invalid_encoding_error,
    )
    if include_load:
        record(
            case_id=f"ws.{mode}.load_roundtrip",
            category="load",
            transport="ws",
            mode=mode,
            fn=_case_load_roundtrip,
        )


def _case_core_valid_task_envelope() -> str:
    request = _make_task_request()
    validate_envelope(request, allow_schema_uri=False)
    return "task envelope valid"


def _case_core_missing_ct_rejected() -> str:
    request = _make_task_request()
    request.pop("ct", None)
    _assert_raises_validation(request)
    return "missing ct rejected"


def _case_core_schema_hash_mismatch_rejected() -> str:
    request = _make_task_request()
    schema_obj = request.get("schema")
    if not isinstance(schema_obj, dict):
        raise AssertionError("schema must be object")
    schema_obj["id"] = "sha256:deadbeef"
    _assert_raises_validation(request)
    return "schema mismatch rejected"


def _assert_raises_validation(envelope: dict[str, Any]) -> None:
    try:
        validate_envelope(envelope, allow_schema_uri=False)
    except EnvelopeValidationError:
        return
    raise AssertionError("expected EnvelopeValidationError")


def _normalize_transports(transports: Iterable[str] | None) -> set[str]:
    if transports is None:
        return set(SUPPORTED_TRANSPORTS)
    values = {item.strip().lower() for item in transports if isinstance(item, str) and item.strip()}
    if not values:
        return set(SUPPORTED_TRANSPORTS)
    if "all" in values:
        return set(SUPPORTED_TRANSPORTS)
    unknown = values - SUPPORTED_TRANSPORTS
    if unknown:
        raise ValueError(f"unsupported transport values: {sorted(unknown)}")
    return values


def _normalize_modes(modes: Iterable[str] | None) -> set[str]:
    if modes is None:
        return set(SUPPORTED_MODES)
    values = {item.strip().lower() for item in modes if isinstance(item, str) and item.strip()}
    if not values:
        return set(SUPPORTED_MODES)
    if "all" in values:
        return set(SUPPORTED_MODES)
    unknown = values - SUPPORTED_MODES
    if unknown:
        raise ValueError(f"unsupported mode values: {sorted(unknown)}")
    return values


def _make_task_request(
    *,
    from_agent_id: str = "did:key:conformance-client",
    to_agent_id: str = "did:key:conformance-server",
) -> dict[str, Any]:
    payload = {
        "kind": "task.v1",
        "goal": "Conformance probe",
        "inputs": {},
        "constraints": {"time_budget_s": 5, "compute_budget": "low", "safety": {}},
        "deliverables": [{"type": "text", "description": "Short confirmation"}],
        "acceptance": ["Respond with a valid envelope"],
        "context": {},
    }
    return build_envelope(
        msg_type="req",
        from_identity={
            "agent_id": from_agent_id,
            "name": "conformance-client",
            "instance": "suite",
            "role": "planner",
        },
        to_identity={
            "agent_id": to_agent_id,
            "name": "conformance-server",
            "instance": "suite",
            "role": "executor",
        },
        content_type="task.v1",
        payload=payload,
        schema=get_builtin_descriptor("task.v1"),
    )


def _make_secure_context() -> _SecureContext:
    signing = generate_signing_keypair()
    decrypt = generate_x25519_keypair()
    sender_agent_id = "did:key:conformance-client"
    receiver_agent_id = "did:key:conformance-server"
    return _SecureContext(
        sender_agent_id=sender_agent_id,
        receiver_agent_id=receiver_agent_id,
        sign_kid=f"{sender_agent_id}#sig1",
        sign_private_key=signing["private_key_b64"],
        sign_public_key=signing["public_key_b64"],
        decrypt_kid=f"{receiver_agent_id}#enc1",
        decrypt_private_key=decrypt["private_key_b64"],
        decrypt_public_key=decrypt["public_key_b64"],
    )


def _make_secure_task_request(context: _SecureContext | None) -> dict[str, Any]:
    if context is None:
        raise ValueError("secure context is required")
    request = _make_task_request(from_agent_id=context.sender_agent_id, to_agent_id=context.receiver_agent_id)
    encrypt_payload(
        request,
        recipients=[{"kid": context.decrypt_kid, "public_key": context.decrypt_public_key}],
    )
    sec = request.setdefault("sec", {})
    sec["replay"] = {
        "nonce": new_message_id(),
        "exp": (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=2)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    sign_envelope(request, context.sign_private_key, kid=context.sign_kid)
    return request


def _send_http_raw_envelope(url: str, envelope: dict[str, Any], *, timeout_s: float) -> dict[str, Any]:
    return _send_http_raw_bytes(url, encode_bytes(envelope, encoding="json"), timeout_s=timeout_s)


def _send_http_raw_bytes(url: str, body: bytes, *, timeout_s: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:  # nosec B310
            response_body = response.read()
    except urllib.error.HTTPError as exc:
        response_body = exc.read()
    return decode_bytes(response_body, encoding="json")


def _send_ipc_raw_envelope(host: str, port: int, envelope: dict[str, Any], *, timeout_s: float) -> dict[str, Any]:
    return _send_ipc_raw_bytes(host, port, encode_bytes(envelope, encoding="json"), timeout_s=timeout_s)


def _send_ipc_raw_bytes(host: str, port: int, body: bytes, *, timeout_s: float) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout_s) as conn:
        conn.sendall(encode_ipc_frame(body))
        response_payload = _read_ipc_frame(conn, timeout_s=timeout_s)
    return decode_bytes(response_payload, encoding="json")


def _read_ipc_frame(conn: socket.socket, *, timeout_s: float) -> bytes:
    conn.settimeout(timeout_s)
    header = _read_exact(conn, 4)
    size = int.from_bytes(header, "big", signed=False)
    if size == 0:
        return b""
    return _read_exact(conn, size)


def _read_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed while reading frame")
        data.extend(chunk)
    return bytes(data)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def render_conformance_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    summary = report.get("summary", {})
    lines.append(f"Protocol: {report.get('protocol')}")
    lines.append(
        "Summary: total={total} passed={passed} failed={failed} duration_ms={duration_ms}".format(
            total=summary.get("total"),
            passed=summary.get("passed"),
            failed=summary.get("failed"),
            duration_ms=report.get("duration_ms"),
        )
    )
    lines.append(
        "Profile: transports={transports} modes={modes} include_load={include_load} load_requests={load_requests}".format(
            transports=",".join(summary.get("transports", [])),
            modes=",".join(summary.get("modes", [])),
            include_load=summary.get("include_load"),
            load_requests=summary.get("load_requests"),
        )
    )
    lines.append("Cases:")

    results = report.get("results", [])
    if isinstance(results, list):
        for item in results:
            if not isinstance(item, dict):
                continue
            marker = "PASS" if bool(item.get("ok")) else "FAIL"
            lines.append(
                "[{marker}] {case_id} ({transport}/{mode}, {category}) - {detail} [{duration}ms]".format(
                    marker=marker,
                    case_id=item.get("case_id"),
                    transport=item.get("transport"),
                    mode=item.get("mode"),
                    category=item.get("category"),
                    detail=item.get("detail"),
                    duration=item.get("duration_ms"),
                )
            )
    return "\n".join(lines)


def render_conformance_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True)
