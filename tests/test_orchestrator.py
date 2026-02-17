from __future__ import annotations

import tempfile
import unittest
from typing import Any

from a2a_sdl.envelope import build_envelope
from a2a_sdl.orchestrator import execute_workflow_plan
from a2a_sdl.schema import get_builtin_descriptor
from a2a_sdl.workflow_state import SQLiteWorkflowStateStore


def _task_payload(goal: str) -> dict[str, Any]:
    return {
        "kind": "task.v1",
        "goal": goal,
        "inputs": {},
        "constraints": {"time_budget_s": 10, "compute_budget": "low", "safety": {}},
        "deliverables": [{"type": "text", "description": "status"}],
        "acceptance": ["ok"],
        "context": {},
    }


def _ok_response(request: dict[str, Any], *, step_id: str) -> dict[str, Any]:
    return build_envelope(
        msg_type="res",
        from_identity=request["to"],
        to_identity=request["from"],
        content_type="state.v1",
        payload={"base": "sha256:e3b0c44298fc1c149afbf4c8996fb924", "patch": [{"op": "add", "path": "/step", "value": step_id}]},
        schema=get_builtin_descriptor("state.v1"),
    )


class OrchestratorTests(unittest.TestCase):
    def test_execute_workflow_plan_success_with_dependencies(self) -> None:
        observed: dict[str, dict[str, Any]] = {}

        def sender(url: str, envelope: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            _ = url, kwargs
            payload = envelope.get("payload")
            assert isinstance(payload, dict)
            workflow = payload.get("context", {}).get("workflow", {})
            assert isinstance(workflow, dict)
            step_id = workflow["step_id"]
            observed[step_id] = workflow
            return _ok_response(envelope, step_id=step_id)

        plan = {
            "name": "linear",
            "steps": [
                {"id": "step-1", "ct": "task.v1", "payload": _task_payload("one"), "url": "http://example/a2a"},
                {
                    "id": "step-2",
                    "ct": "task.v1",
                    "payload": _task_payload("two"),
                    "url": "http://example/a2a",
                    "depends_on": ["step-1"],
                },
            ],
        }
        report = execute_workflow_plan(plan, sender=sender)
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["summary"]["steps_success"], 2)
        self.assertEqual(report["summary"]["execution_order"], ["step-1", "step-2"])
        self.assertEqual(observed["step-2"]["step_outputs"]["step-1"]["patch"][0]["value"], "step-1")

    def test_execute_workflow_plan_fail_fast_halts(self) -> None:
        def sender(url: str, envelope: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            _ = url, kwargs
            payload = envelope.get("payload")
            assert isinstance(payload, dict)
            workflow = payload.get("context", {}).get("workflow", {})
            assert isinstance(workflow, dict)
            if workflow["step_id"] == "step-1":
                raise RuntimeError("boom")
            return _ok_response(envelope, step_id=workflow["step_id"])

        plan = {
            "steps": [
                {"id": "step-1", "ct": "task.v1", "payload": _task_payload("one"), "url": "http://example/a2a"},
                {"id": "step-2", "ct": "task.v1", "payload": _task_payload("two"), "url": "http://example/a2a"},
            ]
        }
        report = execute_workflow_plan(plan, sender=sender)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["steps"]["step-1"]["status"], "failed")
        self.assertEqual(report["steps"]["step-2"]["status"], "skipped")

    def test_execute_workflow_plan_continue_on_error(self) -> None:
        def sender(url: str, envelope: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            _ = url, kwargs
            payload = envelope.get("payload")
            assert isinstance(payload, dict)
            workflow = payload.get("context", {}).get("workflow", {})
            assert isinstance(workflow, dict)
            if workflow["step_id"] == "step-1":
                raise RuntimeError("boom")
            return _ok_response(envelope, step_id=workflow["step_id"])

        plan = {
            "steps": [
                {
                    "id": "step-1",
                    "ct": "task.v1",
                    "payload": _task_payload("one"),
                    "url": "http://example/a2a",
                    "on_error": "continue",
                },
                {"id": "step-2", "ct": "task.v1", "payload": _task_payload("two"), "url": "http://example/a2a"},
            ]
        }
        report = execute_workflow_plan(plan, sender=sender)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["steps"]["step-1"]["status"], "failed")
        self.assertEqual(report["steps"]["step-2"]["status"], "success")

    def test_execute_workflow_plan_rejects_cycles(self) -> None:
        plan = {
            "steps": [
                {"id": "a", "ct": "task.v1", "payload": _task_payload("a"), "depends_on": ["b"], "url": "http://example/a2a"},
                {"id": "b", "ct": "task.v1", "payload": _task_payload("b"), "depends_on": ["a"], "url": "http://example/a2a"},
            ]
        }
        with self.assertRaises(ValueError):
            execute_workflow_plan(plan)

    def test_execute_workflow_plan_persists_and_resumes(self) -> None:
        plan = {
            "name": "resume-demo",
            "steps": [
                {"id": "step-1", "ct": "task.v1", "payload": _task_payload("one"), "url": "http://example/a2a"},
                {
                    "id": "step-2",
                    "ct": "task.v1",
                    "payload": _task_payload("two"),
                    "url": "http://example/a2a",
                    "depends_on": ["step-1"],
                },
                {
                    "id": "step-3",
                    "ct": "task.v1",
                    "payload": _task_payload("three"),
                    "url": "http://example/a2a",
                    "depends_on": ["step-2"],
                },
            ],
        }

        def sender_first(url: str, envelope: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            _ = url, kwargs
            payload = envelope.get("payload")
            assert isinstance(payload, dict)
            workflow = payload.get("context", {}).get("workflow", {})
            assert isinstance(workflow, dict)
            step_id = workflow["step_id"]
            if step_id == "step-2":
                raise RuntimeError("boom")
            return _ok_response(envelope, step_id=step_id)

        second_calls: list[str] = []

        def sender_second(url: str, envelope: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            _ = url, kwargs
            payload = envelope.get("payload")
            assert isinstance(payload, dict)
            workflow = payload.get("context", {}).get("workflow", {})
            assert isinstance(workflow, dict)
            step_id = workflow["step_id"]
            second_calls.append(step_id)
            return _ok_response(envelope, step_id=step_id)

        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteWorkflowStateStore(f"{tmpdir}/workflow_state.db")
            try:
                report1 = execute_workflow_plan(plan, sender=sender_first, state_store=store)
                self.assertEqual(report1["status"], "partial")
                run_id = report1["run_id"]

                report2 = execute_workflow_plan(
                    plan,
                    sender=sender_second,
                    state_store=store,
                    resume_run_id=run_id,
                )
            finally:
                store.close()

        self.assertEqual(report2["status"], "success")
        self.assertEqual(report2["resumed_from"], run_id)
        self.assertEqual(second_calls, ["step-2", "step-3"])


if __name__ == "__main__":
    unittest.main()
