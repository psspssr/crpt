from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
import unittest

from a2a_sdl.handlers import default_handler
from a2a_sdl.transport_http import AdmissionController, A2AHTTPServer, send_http

from tests.test_helpers import make_task_envelope


class HTTPAdminTests(unittest.TestCase):
    def test_healthz_is_available_when_admin_enabled(self) -> None:
        server = A2AHTTPServer("127.0.0.1", 0, handler=default_handler, admin_enabled=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["service"], "a2a-sdl-http")
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_readyz_and_metrics_require_token_when_configured(self) -> None:
        server = A2AHTTPServer(
            "127.0.0.1",
            0,
            handler=default_handler,
            admin_enabled=True,
            admin_token="secret-token",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            ready_url = f"http://127.0.0.1:{port}/readyz"

            with self.assertRaises(urllib.error.HTTPError) as unauth_exc:
                urllib.request.urlopen(ready_url, timeout=10)
            self.assertEqual(unauth_exc.exception.code, 401)

            req = urllib.request.Request(ready_url, headers={"Authorization": "Bearer secret-token"})
            with urllib.request.urlopen(req, timeout=10) as response:
                ready_payload = json.loads(response.read().decode("utf-8"))
            self.assertTrue(ready_payload["ready"])
            self.assertIn("metrics", ready_payload)

            metrics_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/metrics",
                headers={"X-A2A-Admin-Token": "secret-token"},
            )
            with urllib.request.urlopen(metrics_req, timeout=10) as response:
                metrics_text = response.read().decode("utf-8")
            self.assertIn("a2a_requests_total", metrics_text)
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_metrics_count_requests_and_rejections(self) -> None:
        limiter = AdmissionController(max_concurrent=8, rate_limit_rps=0.0, burst=1)
        server = A2AHTTPServer(
            "127.0.0.1",
            0,
            handler=default_handler,
            admission_controller=limiter,
            admin_enabled=True,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            url = f"http://127.0.0.1:{port}/a2a"
            first = send_http(url, make_task_envelope(), encoding="json", timeout=10.0)
            self.assertEqual(first["ct"], "state.v1")

            second_req = make_task_envelope()
            second_req["id"] = "metrics-rate-limit-2"
            second = send_http(url, second_req, encoding="json", timeout=10.0)
            self.assertEqual(second["ct"], "error.v1")

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=10) as response:
                metrics_text = response.read().decode("utf-8")

            metric_values: dict[str, float] = {}
            for line in metrics_text.splitlines():
                if not line or line.startswith("#"):
                    continue
                name, raw_value = line.split(" ", 1)
                metric_values[name.strip()] = float(raw_value.strip())

            self.assertGreaterEqual(metric_values.get("a2a_requests_total", 0.0), 2.0)
            self.assertGreaterEqual(metric_values.get("a2a_requests_ok_total", 0.0), 1.0)
            self.assertGreaterEqual(metric_values.get("a2a_requests_error_total", 0.0), 1.0)
            self.assertGreaterEqual(metric_values.get("a2a_admission_reject_total", 0.0), 1.0)
            self.assertGreaterEqual(metric_values.get("a2a_admission_reject_rate_limit_total", 0.0), 1.0)
        finally:
            server.shutdown()
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
