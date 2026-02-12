from __future__ import annotations

import unittest

from a2a_sdl.schema import (
    SchemaValidationError,
    TASK_V1_SCHEMA,
    make_embedded_schema,
    resolve_schema,
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

    def test_uri_schema_rejects_non_http_scheme(self) -> None:
        descriptor = {
            "kind": "uri",
            "id": "sha256:deadbeef",
            "uri": "file:///etc/passwd",
        }
        with self.assertRaises(SchemaValidationError):
            resolve_schema(descriptor)

    def test_uri_schema_rejects_localhost_target(self) -> None:
        descriptor = {
            "kind": "uri",
            "id": "sha256:deadbeef",
            "uri": "http://127.0.0.1/schema.json",
        }
        with self.assertRaises(SchemaValidationError):
            resolve_schema(descriptor)

    def test_uri_schema_custom_fetcher_still_supported(self) -> None:
        schema = {"type": "object", "required": ["x"], "properties": {"x": {"type": "integer"}}}
        descriptor = {
            "kind": "uri",
            "id": schema_id(schema),
            "uri": "https://schemas.example.test/task.json",
        }

        def fetcher(uri: str) -> dict:
            self.assertEqual(uri, "https://schemas.example.test/task.json")
            return schema

        validate_payload({"x": 1}, descriptor, fetcher=fetcher)


if __name__ == "__main__":
    unittest.main()
