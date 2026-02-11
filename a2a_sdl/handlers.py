"""Default message handlers used by CLI/server."""

from __future__ import annotations

from typing import Any

from .constants import SUPPORTED_CONTENT_TYPES
from .envelope import build_envelope, derive_response_trace, make_error_response
from .schema import get_builtin_descriptor
from .utils import sha256_prefixed


def default_handler(request: dict[str, Any]) -> dict[str, Any]:
    ct = request.get("ct")
    if ct not in SUPPORTED_CONTENT_TYPES:
        return make_error_response(
            request=request,
            code="UNSUPPORTED_CT",
            message=f"ct '{ct}' not supported",
            details={"supported_ct": sorted(SUPPORTED_CONTENT_TYPES)},
            retryable=False,
        )

    if ct == "task.v1":
        payload = request.get("payload") if isinstance(request.get("payload"), dict) else {}
        state_payload = {
            "base": sha256_prefixed(b""),
            "patch": [
                {"op": "add", "path": "/status", "value": "accepted"},
                {"op": "add", "path": "/goal", "value": payload.get("goal", "")},
            ],
        }
        return build_envelope(
            msg_type="res",
            from_identity=request["to"],
            to_identity=request["from"],
            content_type="state.v1",
            payload=state_payload,
            schema=get_builtin_descriptor("state.v1"),
            trace=derive_response_trace(request.get("trace")),
        )

    if ct == "toolcall.v1":
        payload = request.get("payload") if isinstance(request.get("payload"), dict) else {}
        result_payload = {
            "call_id": payload.get("call_id", "unknown"),
            "ok": False,
            "result": {},
            "logs": ["default handler has no registered tools"],
            "metrics": {"latency_ms": 0},
        }
        return build_envelope(
            msg_type="res",
            from_identity=request["to"],
            to_identity=request["from"],
            content_type="toolresult.v1",
            payload=result_payload,
            schema=get_builtin_descriptor("toolresult.v1"),
            trace=derive_response_trace(request.get("trace")),
        )

    if ct == "negotiation.v1":
        negotiation_payload = {
            "need": {},
            "have": request.get("cap", {}),
            "ask": [],
            "supported_ct": sorted(SUPPORTED_CONTENT_TYPES),
        }
        return build_envelope(
            msg_type="res",
            from_identity=request["to"],
            to_identity=request["from"],
            content_type="negotiation.v1",
            payload=negotiation_payload,
            schema=get_builtin_descriptor("negotiation.v1"),
            trace=derive_response_trace(request.get("trace")),
        )

    return make_error_response(
        request=request,
        code="UNSUPPORTED_CT",
        message=f"ct '{ct}' accepted by protocol but not implemented by default handler",
        details={"implemented": ["task.v1", "toolcall.v1", "negotiation.v1"]},
        retryable=True,
    )
