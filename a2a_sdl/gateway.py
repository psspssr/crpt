"""Session-aware edge gateway utilities for A2A traffic."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from .envelope import make_error_response
from .handlers import HandlerFn, make_default_handler
from .session import SessionBindingStore
from .transport_http import send_http


@dataclass(slots=True)
class GatewayConfig:
    """Runtime configuration for forwarding and local control handling."""

    upstream_url: str
    timeout: float = 10.0
    retry_attempts: int = 1
    retry_backoff_s: float = 0.05
    handle_negotiation_locally: bool = True


def make_gateway_handler(
    *,
    config: GatewayConfig,
    session_binding_signing_key: str | None = None,
    session_binding_store: SessionBindingStore | None = None,
) -> HandlerFn:
    """Build a gateway handler that keeps control-plane CT local and forwards data-plane CT upstream."""
    binding_store = session_binding_store or SessionBindingStore()
    local_handler = make_default_handler(
        session_binding_signing_key=session_binding_signing_key,
        session_binding_store=binding_store,
    )
    local_control_ct = {"session.v1"}
    if config.handle_negotiation_locally:
        local_control_ct.add("negotiation.v1")

    def _handle(request: dict[str, Any]) -> dict[str, Any]:
        content_type = request.get("ct")
        if isinstance(content_type, str) and content_type in local_control_ct:
            return local_handler(request)

        forwarded = copy.deepcopy(request)
        _increment_trace_hop(forwarded)
        try:
            return send_http(
                config.upstream_url,
                forwarded,
                timeout=config.timeout,
                retry_attempts=config.retry_attempts,
                retry_backoff_s=config.retry_backoff_s,
            )
        except Exception as exc:
            return make_error_response(
                request=request,
                code="INTERNAL",
                message="gateway upstream forwarding failed",
                details={"error": f"{type(exc).__name__}: {exc}", "upstream_url": config.upstream_url},
                retryable=True,
            )

    return _handle


def _increment_trace_hop(envelope: dict[str, Any]) -> None:
    trace = envelope.get("trace")
    if not isinstance(trace, dict):
        return
    hops = trace.get("hops")
    if isinstance(hops, int) and hops >= 0:
        trace["hops"] = hops + 1

