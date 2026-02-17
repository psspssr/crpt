from __future__ import annotations

import threading
import time
import unittest
from typing import Any

from a2a_sdl.envelope import build_envelope, make_error_response
from a2a_sdl.gateway import GatewayConfig, make_gateway_handler
from a2a_sdl.handlers import default_handler
from a2a_sdl.schema import get_builtin_descriptor
from a2a_sdl.session import SessionBindingStore
from a2a_sdl.transport_http import A2AHTTPServer, send_http

from tests.test_helpers import RECEIVER, SENDER, make_task_envelope


def _make_session_open_request() -> dict[str, Any]:
    return build_envelope(
        msg_type="req",
        from_identity=SENDER,
        to_identity=RECEIVER,
        content_type="session.v1",
        payload={"op": "open", "profile": {"mode": "test"}, "nonce": "nonce-12345678"},
        schema=get_builtin_descriptor("session.v1"),
    )


class GatewayTests(unittest.TestCase):
    def test_gateway_forwards_data_plane_requests(self) -> None:
        upstream = A2AHTTPServer("127.0.0.1", 0, handler=default_handler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        time.sleep(0.05)

        try:
            upstream_port = upstream._server.server_address[1]
            gateway_handler = make_gateway_handler(
                config=GatewayConfig(upstream_url=f"http://127.0.0.1:{upstream_port}/a2a"),
                session_binding_store=SessionBindingStore(),
            )
            gateway = A2AHTTPServer("127.0.0.1", 0, handler=gateway_handler)
            gateway_thread = threading.Thread(target=gateway.serve_forever, daemon=True)
            gateway_thread.start()
            time.sleep(0.05)
            try:
                gateway_port = gateway._server.server_address[1]
                response = send_http(f"http://127.0.0.1:{gateway_port}/a2a", make_task_envelope(), timeout=10.0)
                self.assertEqual(response["ct"], "state.v1")
            finally:
                gateway.shutdown()
                gateway_thread.join(timeout=1)
        finally:
            upstream.shutdown()
            upstream_thread.join(timeout=1)

    def test_gateway_handles_session_locally(self) -> None:
        calls = {"session": 0}

        def upstream_handler(request: dict[str, Any]) -> dict[str, Any]:
            if request.get("ct") == "session.v1":
                calls["session"] += 1
                return make_error_response(
                    request=request,
                    code="INTERNAL",
                    message="session should not be forwarded",
                )
            return default_handler(request)

        upstream = A2AHTTPServer("127.0.0.1", 0, handler=upstream_handler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        time.sleep(0.05)

        try:
            upstream_port = upstream._server.server_address[1]
            gateway_handler = make_gateway_handler(
                config=GatewayConfig(upstream_url=f"http://127.0.0.1:{upstream_port}/a2a"),
                session_binding_store=SessionBindingStore(),
            )
            gateway = A2AHTTPServer("127.0.0.1", 0, handler=gateway_handler)
            gateway_thread = threading.Thread(target=gateway.serve_forever, daemon=True)
            gateway_thread.start()
            time.sleep(0.05)
            try:
                gateway_port = gateway._server.server_address[1]
                response = send_http(
                    f"http://127.0.0.1:{gateway_port}/a2a",
                    _make_session_open_request(),
                    timeout=10.0,
                )
                self.assertEqual(response["ct"], "session.v1")
                self.assertTrue(response["payload"]["accepted"])
                self.assertEqual(calls["session"], 0)
            finally:
                gateway.shutdown()
                gateway_thread.join(timeout=1)
        finally:
            upstream.shutdown()
            upstream_thread.join(timeout=1)

    def test_gateway_returns_protocol_error_on_upstream_failure(self) -> None:
        gateway_handler = make_gateway_handler(
            config=GatewayConfig(upstream_url="http://127.0.0.1:9/a2a", timeout=0.1, retry_attempts=0),
            session_binding_store=SessionBindingStore(),
        )
        response = gateway_handler(make_task_envelope())
        self.assertEqual(response["ct"], "error.v1")
        self.assertEqual(response["payload"]["code"], "INTERNAL")
        self.assertIn("upstream_url", response["payload"]["details"])


if __name__ == "__main__":
    unittest.main()

