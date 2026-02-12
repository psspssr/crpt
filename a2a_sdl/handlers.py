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
from .policy import SecurityPolicyManager
from .session import SessionBindingStoreProtocol, build_session_binding_doc, compute_session_binding_id
from .schema import get_builtin_descriptor
from .security import SecurityError, sign_detached_json, verify_detached_json
from .utils import canonical_json_bytes, sha256_prefixed
from .versioning import versioning_payload_metadata

HandlerFn = Callable[[dict[str, Any]], dict[str, Any]]
ToolFn = Callable[[dict[str, Any]], Any]


@dataclass(slots=True)
class ToolExecutionPolicy:
    """Policy guard for tool execution safety."""

    allowed_tools: set[str] = field(default_factory=set)
    allowed_tools_by_agent: dict[str, set[str]] = field(default_factory=dict)
    required_scopes_by_tool: dict[str, str] = field(default_factory=dict)
    max_args_bytes: int = 4096

    def is_allowed(self, tool_name: str) -> bool:
        if self.allowed_tools:
            return tool_name in self.allowed_tools
        return bool(self.allowed_tools_by_agent)

    def check(
        self,
        *,
        tool_name: str,
        agent_id: str,
        scopes: set[str] | None,
    ) -> tuple[bool, str | None]:
        if not self.is_allowed(tool_name):
            return False, f"tool '{tool_name}' denied by execution policy"

        if self.allowed_tools_by_agent:
            allowed_for_agent = self.allowed_tools_by_agent.get(agent_id)
            if allowed_for_agent is None:
                return False, f"agent '{agent_id}' has no tool grants"
            if tool_name not in allowed_for_agent:
                return False, f"agent '{agent_id}' is not allowed to use tool '{tool_name}'"

        required_scope = self.required_scopes_by_tool.get(tool_name)
        if required_scope is not None:
            scope_set = scopes or set()
            if required_scope not in scope_set:
                return False, f"tool '{tool_name}' requires scope '{required_scope}'"

        return True, None


@dataclass(frozen=True, slots=True)
class TrustGovernancePolicy:
    """Quorum-based approval policy for trustsync propose operations."""

    approver_keys: dict[str, str]
    threshold: int = 1

    def validate(self) -> None:
        if not self.approver_keys:
            raise ValueError("trust governance approver_keys cannot be empty")
        if self.threshold < 1:
            raise ValueError("trust governance threshold must be >= 1")
        if self.threshold > len(self.approver_keys):
            raise ValueError("trust governance threshold cannot exceed approver key count")


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
        from_identity = request.get("from")
        agent_id = (
            str(from_identity.get("agent_id"))
            if isinstance(from_identity, dict) and isinstance(from_identity.get("agent_id"), str)
            else "did:key:unknown"
        )
        scopes = _extract_authz_scopes(payload.get("authz"))

        ok = False
        result: Any = {}
        logs: list[str] = []

        if not isinstance(tool_name, str) or not tool_name.strip():
            logs.append("missing or invalid payload.tool")
        elif not isinstance(args, dict):
            logs.append("missing or invalid payload.args")
        elif execution_policy is not None and len(json.dumps(args, sort_keys=True)) > execution_policy.max_args_bytes:
            logs.append(f"tool '{tool_name}' args exceed max_args_bytes")
        elif not tool_registry.has(tool_name):
            logs.append(f"unknown tool '{tool_name}'")
        else:
            if execution_policy is not None:
                allowed, reason = execution_policy.check(tool_name=tool_name, agent_id=agent_id, scopes=scopes)
                if not allowed:
                    logs.append(reason or f"tool '{tool_name}' denied by execution policy")
                else:
                    try:
                        result = tool_registry.execute(tool_name, args)
                        ok = True
                        logs.append(f"tool '{tool_name}' executed")
                    except Exception as exc:
                        logs.append(f"tool '{tool_name}' failed: {type(exc).__name__}: {exc}")
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
            "metrics": {
                "latency_ms": latency_ms,
                "tool": tool_name if isinstance(tool_name, str) else "",
                "agent_id": agent_id,
            },
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


def _make_trustsync_handler(
    *,
    tools: list[str],
    policy_manager: SecurityPolicyManager | None,
    update_verify_key: str | None,
    governance_policy: TrustGovernancePolicy | None,
) -> HandlerFn:
    def _handle_trustsync(request: dict[str, Any]) -> dict[str, Any]:
        payload_any = request.get("payload")
        payload = payload_any if isinstance(payload_any, dict) else {}
        op = payload.get("op")
        op_value = op if isinstance(op, str) else "discover"
        source_agent = (
            request.get("from", {}).get("agent_id")
            if isinstance(request.get("from"), dict)
            else "did:key:unknown"
        )

        if op_value == "discover":
            snapshot = policy_manager.snapshot(include_private=False) if policy_manager is not None else {}
            registry_hash = (
                policy_manager.snapshot_hash(include_private=False)
                if policy_manager is not None
                else sha256_prefixed(canonical_json_bytes(snapshot))
            )
            trust_payload = {
                "op": "discover",
                "status": "snapshot",
                "message": "trust snapshot",
                "snapshot": snapshot,
                "registry_hash": registry_hash,
                "source_agent": source_agent,
            }
            return build_envelope(
                msg_type="res",
                from_identity=request["to"],
                to_identity=request["from"],
                content_type="trustsync.v1",
                payload=trust_payload,
                cap=_cap_with_tools(tools),
                schema=get_builtin_descriptor("trustsync.v1"),
                trace=derive_response_trace(request.get("trace")),
            )

        if op_value != "propose":
            return make_error_response(
                request=request,
                code="BAD_REQUEST",
                message="trustsync.v1 op must be discover or propose",
                retryable=False,
            )

        if policy_manager is None:
            result_payload = {
                "op": "propose",
                "status": "rejected",
                "message": "trust policy manager is not configured",
                "source_agent": source_agent,
            }
            return build_envelope(
                msg_type="res",
                from_identity=request["to"],
                to_identity=request["from"],
                content_type="trustsync.v1",
                payload=result_payload,
                cap=_cap_with_tools(tools),
                schema=get_builtin_descriptor("trustsync.v1"),
                trace=derive_response_trace(request.get("trace")),
            )

        if update_verify_key is None and governance_policy is None:
            result_payload = {
                "op": "propose",
                "status": "rejected",
                "message": "trust update verification is not configured",
                "source_agent": source_agent,
            }
            return build_envelope(
                msg_type="res",
                from_identity=request["to"],
                to_identity=request["from"],
                content_type="trustsync.v1",
                payload=result_payload,
                cap=_cap_with_tools(tools),
                schema=get_builtin_descriptor("trustsync.v1"),
                trace=derive_response_trace(request.get("trace")),
            )

        registry = payload.get("registry")
        merge = bool(payload.get("merge", True))
        proposal_id_raw = payload.get("proposal_id")
        if not isinstance(registry, dict):
            return make_error_response(
                request=request,
                code="BAD_REQUEST",
                message="trustsync.v1 propose requires registry object",
                retryable=False,
            )
        if isinstance(proposal_id_raw, str) and proposal_id_raw.strip():
            proposal_id = proposal_id_raw.strip()
        else:
            proposal_id = sha256_prefixed(canonical_json_bytes({"registry": registry, "merge": merge}))

        if policy_manager.has_applied_proposal(proposal_id):
            snapshot = policy_manager.snapshot(include_private=False)
            result_payload = {
                "op": "propose",
                "status": "accepted",
                "message": "registry update already applied",
                "snapshot": snapshot,
                "registry_hash": policy_manager.snapshot_hash(include_private=False),
                "source_agent": source_agent,
                "proposal_id": proposal_id,
            }
            return build_envelope(
                msg_type="res",
                from_identity=request["to"],
                to_identity=request["from"],
                content_type="trustsync.v1",
                payload=result_payload,
                cap=_cap_with_tools(tools),
                schema=get_builtin_descriptor("trustsync.v1"),
                trace=derive_response_trace(request.get("trace")),
            )

        signed_doc = _build_trustsync_proposal_doc(registry=registry, merge=merge, proposal_id=proposal_id)

        try:
            approved_by: list[str] = []
            if governance_policy is not None:
                approved_by = _verify_trustsync_quorum(payload=payload, signed_doc=signed_doc, policy=governance_policy)
            else:
                signature = payload.get("signature")
                if not isinstance(signature, str) or not signature:
                    raise ValueError("trustsync.v1 propose requires signature")
                verify_key = update_verify_key
                if verify_key is None:
                    raise ValueError("trust update verify key is not configured")
                verify_detached_json(registry, signature, verify_key)

            registry_hash = policy_manager.apply_registry(registry, merge=merge)
            policy_manager.mark_applied_proposal(proposal_id)
            snapshot = policy_manager.snapshot(include_private=False)
            result_payload = {
                "op": "propose",
                "status": "accepted",
                "message": "registry update accepted",
                "snapshot": snapshot,
                "registry_hash": registry_hash,
                "source_agent": source_agent,
                "proposal_id": proposal_id,
            }
            if approved_by:
                result_payload["approved_by"] = approved_by
                result_payload["quorum"] = {
                    "threshold": governance_policy.threshold if governance_policy is not None else 1,
                    "count": len(approved_by),
                }
        except (SecurityError, ValueError) as exc:
            result_payload = {
                "op": "propose",
                "status": "rejected",
                "message": f"registry update rejected: {exc}",
                "source_agent": source_agent,
                "proposal_id": proposal_id,
            }
        return build_envelope(
            msg_type="res",
            from_identity=request["to"],
            to_identity=request["from"],
            content_type="trustsync.v1",
            payload=result_payload,
            cap=_cap_with_tools(tools),
            schema=get_builtin_descriptor("trustsync.v1"),
            trace=derive_response_trace(request.get("trace")),
        )

    return _handle_trustsync


def _make_session_handler(
    *,
    tools: list[str],
    signing_key: str | None,
    session_binding_store: SessionBindingStoreProtocol | None,
) -> HandlerFn:
    def _handle_session(request: dict[str, Any]) -> dict[str, Any]:
        payload_any = request.get("payload")
        payload: dict[str, Any] = payload_any if isinstance(payload_any, dict) else {}
        op = payload.get("op")
        op_value = op if isinstance(op, str) else ""
        profile = payload.get("profile")
        nonce = payload.get("nonce")
        expires = payload.get("expires")
        if not isinstance(profile, dict) or not isinstance(nonce, str) or len(nonce) < 8:
            return make_error_response(
                request=request,
                code="BAD_REQUEST",
                message="session.v1 requires profile object and nonce string (len >= 8)",
                retryable=False,
            )

        if op_value not in {"open", "ack"}:
            return make_error_response(
                request=request,
                code="BAD_REQUEST",
                message="session.v1 op must be open or ack",
                retryable=False,
            )

        exp = expires
        if not isinstance(exp, str):
            exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).replace(microsecond=0).isoformat()
            exp = exp.replace("+00:00", "Z")

        from_agent = (
            request.get("from", {}).get("agent_id")
            if isinstance(request.get("from"), dict)
            else "did:key:unknown"
        )
        to_agent = (
            request.get("to", {}).get("agent_id")
            if isinstance(request.get("to"), dict)
            else "did:key:unknown"
        )
        if not isinstance(from_agent, str):
            from_agent = "did:key:unknown"
        if not isinstance(to_agent, str):
            to_agent = "did:key:unknown"
        try:
            binding_doc = build_session_binding_doc(
                from_agent=from_agent,
                to_agent=to_agent,
                profile=profile,
                nonce=nonce,
                expires=exp,
            )
        except ValueError as exc:
            return make_error_response(
                request=request,
                code="BAD_REQUEST",
                message=str(exc),
                retryable=False,
            )
        binding_id = compute_session_binding_id(
            from_agent=from_agent,
            to_agent=to_agent,
            profile=profile,
            nonce=nonce,
            expires=exp,
        )

        if session_binding_store is not None:
            try:
                session_binding_store.register(
                    binding_id=binding_id,
                    from_agent=from_agent,
                    to_agent=to_agent,
                    expires=exp,
                    profile=profile,
                )
            except ValueError as exc:
                return make_error_response(
                    request=request,
                    code="BAD_REQUEST",
                    message=f"session binding rejected: {exc}",
                    retryable=False,
                )

        response_payload: dict[str, Any] = {
            "op": "ack",
            "accepted": True,
            "profile": profile,
            "nonce": nonce,
            "expires": exp,
            "binding_id": binding_id,
            "message": "session binding established",
        }
        if signing_key is not None:
            response_payload["binding_alg"] = "ed25519"
            response_payload["binding_sig"] = sign_detached_json(binding_doc, signing_key)

        return build_envelope(
            msg_type="res",
            from_identity=request["to"],
            to_identity=request["from"],
            content_type="session.v1",
            payload=response_payload,
            cap=_cap_with_tools(tools),
            schema=get_builtin_descriptor("session.v1"),
            trace=derive_response_trace(request.get("trace")),
        )

    return _handle_session


def _make_negotiation_handler(tools: list[str], *, session_binding_enabled: bool) -> HandlerFn:
    def _handle_negotiation(request: dict[str, Any]) -> dict[str, Any]:
        negotiation_payload = {
            "need": {},
            "have": request.get("cap", {}),
            "ask": [],
            "supported_ct": sorted(SUPPORTED_CONTENT_TYPES),
            "available_tools": tools,
            "versioning": versioning_payload_metadata(),
            "session_binding": {
                "supported": session_binding_enabled,
                "content_type": "session.v1",
                "alg": "ed25519",
            },
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
    trust_policy_manager: SecurityPolicyManager | None = None,
    trust_update_verify_key: str | None = None,
    trust_governance_policy: TrustGovernancePolicy | None = None,
    session_binding_signing_key: str | None = None,
    session_binding_store: SessionBindingStoreProtocol | None = None,
) -> HandlerFn:
    registry = tool_registry or make_default_tool_registry()
    tools = registry.names()
    router = ContentTypeRouter(
        {
            "task.v1": _make_task_handler(tools),
            "toolcall.v1": _make_toolcall_handler(registry, tools, execution_policy=tool_execution_policy),
            "negotiation.v1": _make_negotiation_handler(
                tools,
                session_binding_enabled=session_binding_signing_key is not None,
            ),
            "trustsync.v1": _make_trustsync_handler(
                tools=tools,
                policy_manager=trust_policy_manager,
                update_verify_key=trust_update_verify_key,
                governance_policy=trust_governance_policy,
            ),
            "session.v1": _make_session_handler(
                tools=tools,
                signing_key=session_binding_signing_key,
                session_binding_store=session_binding_store,
            ),
        }
    )

    for content_type, handler in (extra_handlers or {}).items():
        router.register(content_type, handler)
    return router


def default_handler(request: dict[str, Any]) -> dict[str, Any]:
    return _DEFAULT_HANDLER(request)


_DEFAULT_HANDLER = make_default_handler()


def _extract_authz_scopes(raw: Any) -> set[str]:
    if not isinstance(raw, dict):
        return set()
    scopes = raw.get("scopes")
    if not isinstance(scopes, list):
        return set()
    normalized: set[str] = set()
    for item in scopes:
        if isinstance(item, str) and item:
            normalized.add(item)
    return normalized


def _build_trustsync_proposal_doc(
    *,
    registry: dict[str, Any],
    merge: bool,
    proposal_id: str,
) -> dict[str, Any]:
    return {
        "op": "propose",
        "proposal_id": proposal_id,
        "merge": bool(merge),
        "registry": registry,
    }


def _verify_trustsync_quorum(
    *,
    payload: dict[str, Any],
    signed_doc: dict[str, Any],
    policy: TrustGovernancePolicy,
) -> list[str]:
    policy.validate()
    approvals = payload.get("approvals")
    if not isinstance(approvals, list) or not approvals:
        raise ValueError("trustsync quorum mode requires approvals[]")

    approved_by: list[str] = []
    seen: set[str] = set()
    for item in approvals:
        if not isinstance(item, dict):
            raise ValueError("approvals entries must be objects")
        approver = item.get("approver")
        signature = item.get("signature")
        if not isinstance(approver, str) or not approver:
            raise ValueError("approval approver must be a non-empty string")
        if not isinstance(signature, str) or not signature:
            raise ValueError("approval signature must be a non-empty string")
        if approver in seen:
            continue
        verify_key = policy.approver_keys.get(approver)
        if verify_key is None:
            raise ValueError(f"approval from unknown approver: {approver}")
        verify_detached_json(signed_doc, signature, verify_key)
        seen.add(approver)
        approved_by.append(approver)

    if len(approved_by) < policy.threshold:
        raise ValueError(
            f"quorum not met: approved={len(approved_by)} required={policy.threshold}"
        )
    return sorted(approved_by)
