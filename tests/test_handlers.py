from __future__ import annotations

import unittest

from a2a_sdl.handlers import ToolExecutionPolicy, default_handler, make_default_handler
from a2a_sdl.envelope import validate_envelope
from a2a_sdl.policy import SecurityPolicy, SecurityPolicyManager
from a2a_sdl.schema import get_builtin_descriptor
from a2a_sdl.security import generate_signing_keypair, sign_detached_json, verify_detached_json

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
        self.assertIn("versioning", res["payload"])

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

    def test_tool_execution_policy_denies_unallowed_tool(self) -> None:
        handler = make_default_handler(
            tool_execution_policy=ToolExecutionPolicy(
                allowed_tools={"sys.ping"},
                max_args_bytes=1024,
            )
        )
        req = make_task_envelope()
        req["ct"] = "toolcall.v1"
        req["schema"] = get_builtin_descriptor("toolcall.v1")
        req["payload"] = {"tool": "math.add", "call_id": "sum-deny", "args": {"values": [1, 2]}, "expect": {}}
        res = handler(req)
        self.assertEqual(res["ct"], "toolresult.v1")
        self.assertFalse(res["payload"]["ok"])
        self.assertIn("denied by execution policy", " ".join(res["payload"]["logs"]))

    def test_tool_execution_policy_agent_scope(self) -> None:
        handler = make_default_handler(
            tool_execution_policy=ToolExecutionPolicy(
                allowed_tools_by_agent={"did:key:agent-a": {"math.add"}},
                required_scopes_by_tool={"math.add": "tool:math.add"},
                max_args_bytes=1024,
            )
        )
        req = make_task_envelope()
        req["from"]["agent_id"] = "did:key:agent-a"
        req["ct"] = "toolcall.v1"
        req["schema"] = get_builtin_descriptor("toolcall.v1")
        req["payload"] = {
            "tool": "math.add",
            "call_id": "scope-ok",
            "args": {"values": [1, 2]},
            "expect": {},
            "authz": {"scopes": ["tool:math.add"]},
        }
        ok = handler(req)
        self.assertTrue(ok["payload"]["ok"])

        denied_req = make_task_envelope()
        denied_req["from"]["agent_id"] = "did:key:agent-a"
        denied_req["ct"] = "toolcall.v1"
        denied_req["schema"] = get_builtin_descriptor("toolcall.v1")
        denied_req["payload"] = {
            "tool": "math.add",
            "call_id": "scope-miss",
            "args": {"values": [1, 2]},
            "expect": {},
            "authz": {"scopes": []},
        }
        denied = handler(denied_req)
        self.assertFalse(denied["payload"]["ok"])
        self.assertIn("requires scope", " ".join(denied["payload"]["logs"]))

    def test_trustsync_discover_returns_snapshot(self) -> None:
        manager = SecurityPolicyManager(
            SecurityPolicy(
                trusted_signing_keys={"kid-1": "pub-1"},
                required_kid_by_agent={"did:key:agent-a": "kid-1"},
            )
        )
        handler = make_default_handler(trust_policy_manager=manager)

        req = make_task_envelope()
        req["ct"] = "trustsync.v1"
        req["schema"] = get_builtin_descriptor("trustsync.v1")
        req["payload"] = {"op": "discover"}
        res = handler(req)
        self.assertEqual(res["ct"], "trustsync.v1")
        self.assertEqual(res["payload"]["status"], "snapshot")
        self.assertIn("trusted_signing_keys", res["payload"]["snapshot"])
        self.assertTrue(res["payload"]["registry_hash"].startswith("sha256:"))

    def test_trustsync_propose_applies_update(self) -> None:
        keys = generate_signing_keypair()
        manager = SecurityPolicyManager(SecurityPolicy())
        handler = make_default_handler(
            trust_policy_manager=manager,
            trust_update_verify_key=keys["public_key_b64"],
        )
        registry = {
            "trusted_signing_keys": {"kid-new": "pub-new"},
            "revoked_kids": ["kid-old"],
        }
        signature = sign_detached_json(registry, keys["private_key_b64"])

        req = make_task_envelope()
        req["ct"] = "trustsync.v1"
        req["schema"] = get_builtin_descriptor("trustsync.v1")
        req["payload"] = {"op": "propose", "registry": registry, "signature": signature, "merge": True}
        res = handler(req)
        self.assertEqual(res["ct"], "trustsync.v1")
        self.assertEqual(res["payload"]["status"], "accepted")
        self.assertIn("kid-new", res["payload"]["snapshot"]["trusted_signing_keys"])

    def test_session_open_returns_signed_binding(self) -> None:
        keys = generate_signing_keypair()
        handler = make_default_handler(session_binding_signing_key=keys["private_key_b64"])

        req = make_task_envelope()
        req["ct"] = "session.v1"
        req["schema"] = get_builtin_descriptor("session.v1")
        req["payload"] = {
            "op": "open",
            "profile": {"ct": ["task.v1"], "mode": "enc+sig"},
            "nonce": "nonce-1234",
        }
        res = handler(req)
        self.assertEqual(res["ct"], "session.v1")
        self.assertTrue(res["payload"]["accepted"])
        self.assertIn("binding_sig", res["payload"])

        binding_doc = {
            "from_agent": req["from"]["agent_id"],
            "to_agent": req["to"]["agent_id"],
            "profile": req["payload"]["profile"],
            "nonce": req["payload"]["nonce"],
            "expires": res["payload"]["expires"],
        }
        self.assertTrue(
            verify_detached_json(
                binding_doc,
                res["payload"]["binding_sig"],
                keys["public_key_b64"],
            )
        )


if __name__ == "__main__":
    unittest.main()
