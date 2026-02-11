from __future__ import annotations

from typing import Any

from a2a_sdl.envelope import build_envelope
from a2a_sdl.schema import get_builtin_descriptor


SENDER = {
    "agent_id": "did:key:z6Msender",
    "name": "planner-01",
    "instance": "pod-a",
    "role": "planner",
}

RECEIVER = {
    "agent_id": "did:key:z6Mreceiver",
    "name": "executor-01",
    "instance": "pod-b",
    "role": "executor",
}


def make_trace(*, hops: int = 0) -> dict[str, Any]:
    return {
        "root_id": "trace-root-1",
        "span_id": "trace-span-1",
        "hops": hops,
    }


def make_task_envelope() -> dict[str, Any]:
    payload = {
        "kind": "task.v1",
        "goal": "Summarize the attached markdown into 5 bullets",
        "inputs": {"doc": "# Title\\nHello"},
        "constraints": {
            "time_budget_s": 30,
            "compute_budget": "low",
            "safety": {"no_secrets": True, "no_external_calls": False},
        },
        "deliverables": [{"type": "text", "description": "5 bullets"}],
        "acceptance": ["Exactly 5 bullets"],
        "context": {},
    }
    return build_envelope(
        msg_type="req",
        from_identity=SENDER,
        to_identity=RECEIVER,
        content_type="task.v1",
        payload=payload,
        schema=get_builtin_descriptor("task.v1"),
    )
