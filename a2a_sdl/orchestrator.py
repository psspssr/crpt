"""DAG-style workflow orchestration using A2A envelopes."""

from __future__ import annotations

import copy
import datetime as dt
import time
from typing import Any, Callable

from .envelope import build_envelope, validate_envelope
from .transport_http import send_http
from .utils import new_message_id

SenderFn = Callable[..., dict[str, Any]]


def execute_workflow_plan(
    plan: dict[str, Any],
    *,
    default_url: str | None = None,
    default_timeout: float = 10.0,
    default_retry_attempts: int = 1,
    default_retry_backoff_s: float = 0.05,
    fail_fast: bool = True,
    sender: SenderFn | None = None,
) -> dict[str, Any]:
    """Execute a workflow plan and return a deterministic run report."""
    if not isinstance(plan, dict):
        raise ValueError("workflow plan must be an object")
    steps_raw = plan.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise ValueError("workflow plan requires non-empty steps[]")

    steps_by_id: dict[str, dict[str, Any]] = {}
    deps_by_id: dict[str, list[str]] = {}
    for raw_step in steps_raw:
        if not isinstance(raw_step, dict):
            raise ValueError("each workflow step must be an object")
        step_id = raw_step.get("id")
        if not isinstance(step_id, str) or not step_id:
            raise ValueError("each workflow step requires non-empty id")
        if step_id in steps_by_id:
            raise ValueError(f"duplicate workflow step id: {step_id}")
        depends_on_raw = raw_step.get("depends_on", [])
        if not isinstance(depends_on_raw, list) or not all(isinstance(item, str) and item for item in depends_on_raw):
            raise ValueError(f"workflow step {step_id} depends_on must be string[]")
        steps_by_id[step_id] = raw_step
        deps_by_id[step_id] = list(dict.fromkeys(depends_on_raw))

    for step_id, dependencies in deps_by_id.items():
        for dep in dependencies:
            if dep not in steps_by_id:
                raise ValueError(f"workflow step {step_id} depends on unknown step {dep}")

    order = _topological_order(steps_by_id, deps_by_id)
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    run_id = f"workflow:{new_message_id()}"
    send = sender or send_http
    execution_order: list[str] = []
    step_results: dict[str, dict[str, Any]] = {}
    halted = False

    for step_id in order:
        step = steps_by_id[step_id]
        deps = deps_by_id[step_id]
        if halted:
            step_results[step_id] = {
                "status": "skipped",
                "depends_on": deps,
                "reason": "workflow halted",
            }
            continue

        dependency_failures = [dep for dep in deps if step_results.get(dep, {}).get("status") != "success"]
        if dependency_failures:
            step_results[step_id] = {
                "status": "skipped",
                "depends_on": deps,
                "reason": f"dependency failure: {', '.join(dependency_failures)}",
            }
            continue

        on_error = step.get("on_error", "fail")
        if on_error not in {"fail", "continue"}:
            raise ValueError(f"workflow step {step_id} has invalid on_error value")

        step_started = time.perf_counter()
        execution_order.append(step_id)
        try:
            envelope = _build_step_request(
                step_id=step_id,
                step=step,
                deps=deps,
                run_id=run_id,
                step_results=step_results,
            )
            url = step.get("url", default_url)
            if not isinstance(url, str) or not url:
                raise ValueError(f"workflow step {step_id} requires url or --default-url")
            timeout = float(step.get("timeout", default_timeout))
            retry_attempts = int(step.get("retry_attempts", default_retry_attempts))
            retry_backoff_s = float(step.get("retry_backoff_s", default_retry_backoff_s))
            response = send(
                url,
                envelope,
                timeout=max(0.1, timeout),
                retry_attempts=max(0, retry_attempts),
                retry_backoff_s=max(0.0, retry_backoff_s),
            )
            validate_envelope(response, allow_schema_uri=False)
            step_results[step_id] = {
                "status": "success",
                "depends_on": deps,
                "duration_ms": int((time.perf_counter() - step_started) * 1000),
                "url": url,
                "request_ct": envelope.get("ct"),
                "response_ct": response.get("ct"),
                "response_id": response.get("id"),
                "response_payload": response.get("payload"),
            }
        except Exception as exc:
            step_results[step_id] = {
                "status": "failed",
                "depends_on": deps,
                "duration_ms": int((time.perf_counter() - step_started) * 1000),
                "error": f"{type(exc).__name__}: {exc}",
            }
            if fail_fast and on_error != "continue":
                halted = True

    finished = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    statuses = [item.get("status") for item in step_results.values()]
    has_failed = any(status == "failed" for status in statuses)
    has_success = any(status == "success" for status in statuses)
    if has_failed and has_success:
        workflow_status = "partial"
    elif has_failed:
        workflow_status = "failed"
    else:
        workflow_status = "success"

    return {
        "run_id": run_id,
        "name": plan.get("name", "workflow"),
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": finished.isoformat().replace("+00:00", "Z"),
        "duration_ms": int((finished - started).total_seconds() * 1000),
        "status": workflow_status,
        "summary": {
            "steps_total": len(steps_by_id),
            "steps_success": statuses.count("success"),
            "steps_failed": statuses.count("failed"),
            "steps_skipped": statuses.count("skipped"),
            "execution_order": execution_order,
        },
        "steps": step_results,
    }


def render_workflow_text(report: dict[str, Any]) -> str:
    lines = [
        f"Workflow: {report.get('name')}",
        f"Run ID: {report.get('run_id')}",
        f"Status: {report.get('status')}",
        (
            "Summary: total={steps_total} success={steps_success} failed={steps_failed} skipped={steps_skipped}"
        ).format(**report.get("summary", {})),
        "Steps:",
    ]
    steps = report.get("steps")
    if isinstance(steps, dict):
        for step_id in sorted(steps.keys()):
            step = steps[step_id]
            if not isinstance(step, dict):
                continue
            lines.append(
                "[{status}] {step_id} - {detail}".format(
                    status=str(step.get("status", "unknown")).upper(),
                    step_id=step_id,
                    detail=step.get("error")
                    or step.get("reason")
                    or f"response_ct={step.get('response_ct')} duration_ms={step.get('duration_ms')}",
                )
            )
    return "\n".join(lines)


def _topological_order(
    steps_by_id: dict[str, dict[str, Any]],
    deps_by_id: dict[str, list[str]],
) -> list[str]:
    remaining = {step_id: set(deps) for step_id, deps in deps_by_id.items()}
    ready = sorted(step_id for step_id, deps in remaining.items() if not deps)
    order: list[str] = []

    while ready:
        current = ready.pop(0)
        order.append(current)
        for step_id, deps in remaining.items():
            if current in deps:
                deps.remove(current)
                if not deps and step_id not in order and step_id not in ready:
                    ready.append(step_id)
        ready.sort()

    if len(order) != len(steps_by_id):
        unresolved = sorted(set(steps_by_id.keys()) - set(order))
        raise ValueError(f"workflow plan has dependency cycle or unresolved nodes: {unresolved}")
    return order


def _build_step_request(
    *,
    step_id: str,
    step: dict[str, Any],
    deps: list[str],
    run_id: str,
    step_results: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    content_type = step.get("ct")
    if not isinstance(content_type, str) or not content_type:
        raise ValueError(f"workflow step {step_id} requires ct")

    raw_payload = step.get("payload")
    if raw_payload is None:
        raise ValueError(f"workflow step {step_id} requires payload")
    payload = copy.deepcopy(raw_payload)
    if isinstance(payload, dict):
        context_raw = payload.get("context")
        context_obj = context_raw if isinstance(context_raw, dict) else {}
        context_obj["workflow"] = {
            "run_id": run_id,
            "step_id": step_id,
            "depends_on": deps,
            "step_outputs": {
                dep: step_results[dep].get("response_payload")
                for dep in deps
                if isinstance(step_results.get(dep), dict) and step_results[dep].get("status") == "success"
            },
        }
        payload["context"] = context_obj

    from_identity = _identity_from_obj(
        step.get("from"),
        default={
            "agent_id": "did:key:workflow-orchestrator",
            "name": "workflow-orchestrator",
            "instance": "orchestrator",
            "role": "orchestrator",
        },
    )
    to_identity = _identity_from_obj(
        step.get("to"),
        default={
            "agent_id": "did:key:workflow-target",
            "name": f"step-{step_id}",
            "instance": "target",
            "role": "executor",
        },
    )

    trace: dict[str, Any] = {
        "root_id": run_id,
        "span_id": new_message_id(),
        "hops": 0,
    }
    if deps:
        parent = step_results.get(deps[-1], {})
        parent_id = parent.get("response_id")
        if isinstance(parent_id, str) and parent_id:
            trace["parent_span_id"] = parent_id

    return build_envelope(
        msg_type="req",
        from_identity=from_identity,
        to_identity=to_identity,
        content_type=content_type,
        payload=payload,
        trace=trace,
    )


def _identity_from_obj(raw: Any, *, default: dict[str, str]) -> dict[str, str]:
    if not isinstance(raw, dict):
        return dict(default)
    keys = ("agent_id", "name", "instance", "role")
    result: dict[str, str] = {}
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value:
            result[key] = value
        else:
            result[key] = default[key]
    return result

