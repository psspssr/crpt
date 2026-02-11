from __future__ import annotations

import unittest

from a2a_sdl.handlers import default_handler, make_default_handler
from a2a_sdl.envelope import validate_envelope
from a2a_sdl.schema import get_builtin_descriptor

from tests.test_helpers import make_task_envelope, make_trace


class HandlerTests(unittest.TestCase):
    def test_task_handler_returns_state(self) -> None:
        req = make_task_envelope()
        res = default_handler(req)
        self.assertEqual(res["type"], "res")
        self.assertEqual(res["ct"], "state.v1")
        self.assertTrue(isinstance(res["payload"].get("patch"), list))

    def test_toolcall_handler_returns_toolresult(self) -> None:
        req = make_task_envelope()
        req["ct"] = "toolcall.v1"
        req["schema"] = {
            "kind": "embedded",
            "id": "sha256:e6f2dba9ee68f6d2f2ec70be4f0559ecfbc70c0ed89f3f8ec16bb845eec07f6a",
            "embedded": {
                "type": "object",
                "required": ["tool", "call_id", "args", "expect"],
                "properties": {
                    "tool": {"type": "string"},
                    "call_id": {"type": "string"},
                    "args": {"type": "object"},
                    "expect": {"type": "object"}
                }
            }
        }
        req["payload"] = {"tool": "x", "call_id": "1", "args": {}, "expect": {}}
        res = default_handler(req)
        self.assertEqual(res["ct"], "toolresult.v1")
        self.assertEqual(res["payload"]["call_id"], "1")

    def test_negotiation_response_contains_supported_ct(self) -> None:
        req = make_task_envelope()
        req["ct"] = "negotiation.v1"
        req["schema"] = {
            "kind": "embedded",
            "id": "sha256:9e8d374f8ca170ca44234d4647f6f0f72d9a602bfd4f4588ae86921b853f57ef",
            "embedded": {
                "type": "object",
                "required": ["need", "have", "ask", "supported_ct"],
                "properties": {
                    "need": {"type": "object"},
                    "have": {"type": "object"},
                    "ask": {"type": "array", "items": {"type": "string"}},
                    "supported_ct": {"type": "array", "items": {"type": "string"}}
                }
            }
        }
        req["payload"] = {"need": {}, "have": {}, "ask": [], "supported_ct": []}
        res = default_handler(req)
        self.assertEqual(res["ct"], "negotiation.v1")
        self.assertIn("task.v1", res["payload"]["supported_ct"])
        self.assertIn("math.add", res["cap"]["tools"])
        self.assertIn("sys.ping", res["payload"]["available_tools"])

    def test_handler_derives_response_trace(self) -> None:
        req = make_task_envelope()
        req["trace"] = make_trace(hops=1)
        res = default_handler(req)

        trace = res.get("trace")
        self.assertIsInstance(trace, dict)
        assert isinstance(trace, dict)
        self.assertEqual(trace["root_id"], "trace-root-1")
        self.assertEqual(trace["parent_span_id"], "trace-span-1")
        self.assertEqual(trace["hops"], 2)
        self.assertNotEqual(trace["span_id"], "trace-span-1")
        validate_envelope(res)

    def test_toolcall_executes_builtin_tool(self) -> None:
        req = make_task_envelope()
        req["ct"] = "toolcall.v1"
        req["schema"] = get_builtin_descriptor("toolcall.v1")
        req["payload"] = {"tool": "math.add", "call_id": "sum-1", "args": {"values": [1, 2.5, 3]}, "expect": {}}
        res = default_handler(req)
        self.assertEqual(res["ct"], "toolresult.v1")
        self.assertTrue(res["payload"]["ok"])
        self.assertEqual(res["payload"]["result"]["sum"], 6.5)
        self.assertIn("math.add", res["cap"]["tools"])

    def test_custom_handler_registration(self) -> None:
        def _artifact_handler(request: dict[str, object]) -> dict[str, object]:
            return {
                "v": 1,
                "type": "res",
                "ts": request["ts"],
                "id": "artifact-resp-1",
                "from": request["to"],
                "to": request["from"],
                "ct": "artifact.v1",
                "payload": {"items": [{"name": "x"}], "refs": []},
                "schema": get_builtin_descriptor("artifact.v1"),
                "sec": {"mode": "none"},
            }

        handler = make_default_handler(extra_handlers={"artifact.v1": _artifact_handler})
        req = make_task_envelope()
        req["ct"] = "artifact.v1"
        req["schema"] = get_builtin_descriptor("artifact.v1")
        req["payload"] = {"items": [], "refs": []}
        res = handler(req)
        self.assertEqual(res["ct"], "artifact.v1")


if __name__ == "__main__":
    unittest.main()
