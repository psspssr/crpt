"""Default message handlers used by CLI/server."""

from __future__ import annotations

import datetime as dt
import json
import time
from dataclasses import dataclass, field
from collections.abc import Callable, Mapping
from typing import Any

from .constants import DEFAULT_LIMITS, PROTOCOL_VERSION, SUPPORTED_CONTENT_TYPES
from .envelope import build_envelope, derive_response_trace, make_error_response
from .schema import get_builtin_descriptor
from .utils import sha256_prefixed
from .versioning import versioning_payload_metadata

HandlerFn = Callable[[dict[str, Any]], dict[str, Any]]
ToolFn = Callable[[dict[str, Any]], Any]


@dataclass(slots=True)
class ToolExecutionPolicy:
    """Policy guard for tool execution safety."""

    allowed_tools: set[str] = field(default_factory=set)
    max_args_bytes: int = 4096

    def is_allowed(self, tool_name: str) -> bool:
        return tool_name in self.allowed_tools


class ToolRegistry:
    """Simple registry for `toolcall.v1` execution."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolFn] = {}

    def register(self, name: str, fn: ToolFn) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("tool name must be a non-empty string")
        if not callable(fn):
            raise TypeError("tool function must be callable")
        self._tools[name.strip()] = fn

    def has(self, name: str) -> bool:
        return name in self._tools

    def execute(self, name: str, args: dict[str, Any]) -> Any:
        tool = self._tools[name]
        return tool(args)

    def names(self) -> list[str]:
        return sorted(self._tools.keys())


class ContentTypeRouter:
    """Dispatches requests by content type while preserving protocol errors."""

    def __init__(self, handlers: Mapping[str, HandlerFn] | None = None) -> None:
        self._handlers: dict[str, HandlerFn] = dict(handlers or {})

    def register(self, content_type: str, handler: HandlerFn) -> None:
        if not isinstance(content_type, str) or not content_type.strip():
            raise ValueError("content_type must be a non-empty string")
        if not callable(handler):
            raise TypeError("handler must be callable")
        self._handlers[content_type.strip()] = handler

    def implemented_types(self) -> list[str]:
        return sorted(self._handlers.keys())

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        ct = request.get("ct")
        if ct not in SUPPORTED_CONTENT_TYPES:
            return make_error_response(
                request=request,
                code="UNSUPPORTED_CT",
                message=f"ct '{ct}' not supported",
                details={"supported_ct": sorted(SUPPORTED_CONTENT_TYPES)},
                retryable=False,
            )

        handler = self._handlers.get(str(ct))
        if handler is None:
            return make_error_response(
                request=request,
                code="UNSUPPORTED_CT",
                message=f"ct '{ct}' accepted by protocol but not implemented by handler",
                details={"implemented": self.implemented_types()},
                retryable=True,
            )

        try:
            return handler(request)
        except Exception as exc:
            return make_error_response(
                request=request,
                code="INTERNAL",
                message="handler execution failed",
                details={"error": f"{type(exc).__name__}: {exc}"},
                retryable=True,
            )


def _tool_sys_ping(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "pong": True,
        "ts_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "echo": args,
    }


def _tool_math_add(args: dict[str, Any]) -> dict[str, Any]:
    values = args.get("values")
    if not isinstance(values, list) or not values:
        raise ValueError("args.values must be a non-empty array of numbers")
    total = 0.0
    for value in values:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError("args.values must contain only numbers")
        total += float(value)
    return {"sum": total}


def _cap_with_tools(tools: list[str]) -> dict[str, Any]:
    return {
        "a2a_sdl": {
            "v": PROTOCOL_VERSION,
            "enc": ["json"],
            "sig": ["ed25519"],
            "kex": ["x25519"],
            "comp": [],
        },
        "tools": tools,
        "modalities": ["text"],
        "limits": DEFAULT_LIMITS,
    }


def make_default_tool_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register("sys.ping", _tool_sys_ping)
    registry.register("math.add", _tool_math_add)
    return registry


def _make_task_handler(tools: list[str]) -> HandlerFn:
    def _handle_task(request: dict[str, Any]) -> dict[str, Any]:
        payload_any = request.get("payload")
        payload: dict[str, Any] = payload_any if isinstance(payload_any, dict) else {}
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
            cap=_cap_with_tools(tools),
            schema=get_builtin_descriptor("state.v1"),
            trace=derive_response_trace(request.get("trace")),
        )

    return _handle_task


def _make_toolcall_handler(
    tool_registry: ToolRegistry,
    tools: list[str],
    *,
    execution_policy: ToolExecutionPolicy | None = None,
) -> HandlerFn:
    def _handle_toolcall(request: dict[str, Any]) -> dict[str, Any]:
        payload_any = request.get("payload")
        payload: dict[str, Any] = payload_any if isinstance(payload_any, dict) else {}
        tool_name = payload.get("tool")
        args = payload.get("args")
        call_id = payload.get("call_id", "unknown")
        start = time.perf_counter()

        ok = False
        result: Any = {}
        logs: list[str] = []

        if not isinstance(tool_name, str) or not tool_name.strip():
            logs.append("missing or invalid payload.tool")
        elif not isinstance(args, dict):
            logs.append("missing or invalid payload.args")
        elif execution_policy is not None and not execution_policy.is_allowed(tool_name):
            logs.append(f"tool '{tool_name}' denied by execution policy")
        elif execution_policy is not None and len(json.dumps(args, sort_keys=True)) > execution_policy.max_args_bytes:
            logs.append(f"tool '{tool_name}' args exceed max_args_bytes")
        elif not tool_registry.has(tool_name):
            logs.append(f"unknown tool '{tool_name}'")
        else:
            try:
                result = tool_registry.execute(tool_name, args)
                ok = True
                logs.append(f"tool '{tool_name}' executed")
            except Exception as exc:
                logs.append(f"tool '{tool_name}' failed: {type(exc).__name__}: {exc}")

        latency_ms = int((time.perf_counter() - start) * 1000)
        result_payload = {
            "call_id": call_id,
            "ok": ok,
            "result": result,
            "logs": logs,
            "metrics": {"latency_ms": latency_ms, "tool": tool_name if isinstance(tool_name, str) else ""},
        }
        return build_envelope(
            msg_type="res",
            from_identity=request["to"],
            to_identity=request["from"],
            content_type="toolresult.v1",
            payload=result_payload,
            cap=_cap_with_tools(tools),
            schema=get_builtin_descriptor("toolresult.v1"),
            trace=derive_response_trace(request.get("trace")),
        )

    return _handle_toolcall


def _make_negotiation_handler(tools: list[str]) -> HandlerFn:
    def _handle_negotiation(request: dict[str, Any]) -> dict[str, Any]:
        negotiation_payload = {
            "need": {},
            "have": request.get("cap", {}),
            "ask": [],
            "supported_ct": sorted(SUPPORTED_CONTENT_TYPES),
            "available_tools": tools,
            "versioning": versioning_payload_metadata(),
        }
        return build_envelope(
            msg_type="res",
            from_identity=request["to"],
            to_identity=request["from"],
            content_type="negotiation.v1",
            payload=negotiation_payload,
            cap=_cap_with_tools(tools),
            schema=get_builtin_descriptor("negotiation.v1"),
            trace=derive_response_trace(request.get("trace")),
        )

    return _handle_negotiation


def make_default_handler(
    *,
    extra_handlers: Mapping[str, HandlerFn] | None = None,
    tool_registry: ToolRegistry | None = None,
    tool_execution_policy: ToolExecutionPolicy | None = None,
) -> HandlerFn:
    registry = tool_registry or make_default_tool_registry()
    tools = registry.names()
    router = ContentTypeRouter(
        {
            "task.v1": _make_task_handler(tools),
            "toolcall.v1": _make_toolcall_handler(registry, tools, execution_policy=tool_execution_policy),
            "negotiation.v1": _make_negotiation_handler(tools),
        }
    )

    for content_type, handler in (extra_handlers or {}).items():
        router.register(content_type, handler)
    return router


def default_handler(request: dict[str, Any]) -> dict[str, Any]:
    return _DEFAULT_HANDLER(request)


_DEFAULT_HANDLER = make_default_handler()
