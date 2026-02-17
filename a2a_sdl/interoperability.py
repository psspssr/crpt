"""Canonical interoperability vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .envelope import build_envelope, validate_envelope
from .handlers import default_handler
from .schema import get_builtin_descriptor

_FROM = {
    "agent_id": "did:key:vector-sender",
    "name": "vector-sender",
    "instance": "interop",
    "role": "planner",
}

_TO = {
    "agent_id": "did:key:vector-receiver",
    "name": "vector-receiver",
    "instance": "interop",
    "role": "executor",
}


def build_interop_vectors() -> dict[str, dict[str, Any]]:
    """Build deterministic request/response vectors for protocol interop testing."""
    task_request = build_envelope(
        msg_type="req",
        from_identity=_FROM,
        to_identity=_TO,
        content_type="task.v1",
        payload={
            "kind": "task.v1",
            "goal": "Return protocol status",
            "inputs": {"query": "status"},
            "constraints": {"time_budget_s": 10, "compute_budget": "low", "safety": {}},
            "deliverables": [{"type": "text", "description": "status line"}],
            "acceptance": ["Return one-line status"],
            "context": {},
        },
        schema=get_builtin_descriptor("task.v1"),
    )
    _stabilize_envelope(task_request, envelope_id="vector-task-req", span_id="vector-span-task-req")

    task_response = default_handler(task_request)
    _stabilize_envelope(task_response, envelope_id="vector-task-res", span_id="vector-span-task-res")

    negotiation_request = build_envelope(
        msg_type="req",
        from_identity=_FROM,
        to_identity=_TO,
        content_type="negotiation.v1",
        payload={
            "need": {"ct": ["task.v2"]},
            "have": {"ct": ["task.v1"]},
            "ask": ["downgrade_ct", "send_embedded_schema"],
            "supported_ct": ["task.v1", "negotiation.v1", "error.v1"],
        },
        schema=get_builtin_descriptor("negotiation.v1"),
    )
    _stabilize_envelope(
        negotiation_request,
        envelope_id="vector-negotiation-req",
        span_id="vector-span-negotiation-req",
    )

    negotiation_response = default_handler(negotiation_request)
    _stabilize_envelope(
        negotiation_response,
        envelope_id="vector-negotiation-res",
        span_id="vector-span-negotiation-res",
    )

    vectors = {
        "task.request.json": task_request,
        "task.response.json": task_response,
        "negotiation.request.json": negotiation_request,
        "negotiation.response.json": negotiation_response,
    }
    for envelope in vectors.values():
        validate_envelope(envelope, allow_schema_uri=False)
    return vectors


def write_interop_vectors(out_dir: str | Path) -> list[str]:
    """Write canonical interoperability vectors and return written file paths."""
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    vectors = build_interop_vectors()
    written: list[str] = []
    for file_name, envelope in vectors.items():
        path = target / file_name
        path.write_text(json.dumps(envelope, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(str(path))
    return written


def _stabilize_envelope(envelope: dict[str, Any], *, envelope_id: str, span_id: str) -> None:
    envelope["id"] = envelope_id
    envelope["ts"] = "2026-01-01T00:00:00Z"
    trace = envelope.get("trace")
    if isinstance(trace, dict):
        trace["root_id"] = "vector-root"
        trace["span_id"] = span_id
        if "parent_span_id" in trace:
            trace["parent_span_id"] = "vector-parent"

