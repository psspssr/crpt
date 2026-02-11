from __future__ import annotations

import unittest

from a2a_sdl.schema import (
    SchemaValidationError,
    TASK_V1_SCHEMA,
    make_embedded_schema,
    schema_id,
    validate_payload,
    validate_schema_descriptor,
)


class SchemaTests(unittest.TestCase):
    def test_schema_hash_is_stable(self) -> None:
        first = schema_id(TASK_V1_SCHEMA)
        second = schema_id(TASK_V1_SCHEMA)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("sha256:"))

    def test_valid_payload_passes(self) -> None:
        descriptor = make_embedded_schema(TASK_V1_SCHEMA)
        payload = {
            "kind": "task.v1",
            "goal": "Do a task",
            "inputs": {},
            "constraints": {
                "time_budget_s": 1,
                "compute_budget": "low",
                "safety": {},
            },
            "deliverables": [{"type": "text", "description": "output"}],
            "acceptance": ["ok"],
            "context": {},
        }
        validate_schema_descriptor(descriptor)
        validate_payload(payload, descriptor)

    def test_invalid_payload_rejected(self) -> None:
        descriptor = make_embedded_schema(TASK_V1_SCHEMA)
        payload = {
            "kind": "task.v1",
            "goal": "Do a task",
        }
        with self.assertRaises(SchemaValidationError):
            validate_payload(payload, descriptor)


if __name__ == "__main__":
    unittest.main()
