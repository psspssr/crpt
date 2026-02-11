from __future__ import annotations

import unittest

from a2a_sdl.envelope import EnvelopeValidationError, make_error_response, validate_envelope

from tests.test_helpers import make_task_envelope, make_trace


class EnvelopeTests(unittest.TestCase):
    def test_valid_envelope(self) -> None:
        env = make_task_envelope()
        validate_envelope(env)

    def test_missing_required_field(self) -> None:
        env = make_task_envelope()
        del env["id"]
        with self.assertRaises(EnvelopeValidationError):
            validate_envelope(env)

    def test_max_depth_limit(self) -> None:
        env = make_task_envelope()
        env["payload"]["context"] = {"a": {"b": {"c": {"d": 1}}}}
        with self.assertRaises(EnvelopeValidationError):
            validate_envelope(env, limits={"max_depth": 3})

    def test_trace_validation_requires_fields(self) -> None:
        env = make_task_envelope()
        env["trace"] = {"root_id": "r1", "hops": 0}
        with self.assertRaises(EnvelopeValidationError):
            validate_envelope(env)

    def test_trace_hops_respects_max_hops(self) -> None:
        env = make_task_envelope()
        env["trace"] = make_trace(hops=9)
        with self.assertRaises(EnvelopeValidationError):
            validate_envelope(env, limits={"max_hops": 8})

    def test_make_error_response_derives_child_trace(self) -> None:
        req = make_task_envelope()
        req["trace"] = make_trace(hops=2)

        res = make_error_response(request=req, code="BAD_REQUEST", message="x")
        trace = res.get("trace")

        self.assertIsInstance(trace, dict)
        assert isinstance(trace, dict)
        self.assertEqual(trace["root_id"], "trace-root-1")
        self.assertEqual(trace["parent_span_id"], "trace-span-1")
        self.assertEqual(trace["hops"], 3)
        self.assertNotEqual(trace["span_id"], "trace-span-1")
        validate_envelope(res)


if __name__ == "__main__":
    unittest.main()
