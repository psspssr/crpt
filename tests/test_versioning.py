from __future__ import annotations

import unittest

from a2a_sdl.constants import PROTOCOL_VERSION
from a2a_sdl.versioning import (
    RuntimeVersionPolicy,
    enforce_content_type_version_policy,
    enforce_capability_version_compatibility,
    is_protocol_version_compatible,
    parse_content_type_version,
    parse_runtime_version_policy,
    versioning_payload_metadata,
)


class VersioningTests(unittest.TestCase):
    def test_parse_content_type_version(self) -> None:
        self.assertEqual(parse_content_type_version("task.v3"), ("task", 3))
        self.assertIsNone(parse_content_type_version("task"))
        self.assertIsNone(parse_content_type_version("task.vx"))

    def test_protocol_version_compatibility(self) -> None:
        self.assertTrue(is_protocol_version_compatible(PROTOCOL_VERSION))
        self.assertFalse(is_protocol_version_compatible(PROTOCOL_VERSION + 1))

    def test_versioning_payload_metadata_shape(self) -> None:
        payload = versioning_payload_metadata()
        self.assertIn("protocol", payload)
        self.assertIn("semver_policy", payload)
        self.assertIn("migration", payload)
        self.assertEqual(payload["protocol"]["current"], PROTOCOL_VERSION)

    def test_enforce_capability_version_compatibility(self) -> None:
        cap = {"a2a_sdl": {"v": PROTOCOL_VERSION}}
        enforce_capability_version_compatibility(cap)
        with self.assertRaises(ValueError):
            enforce_capability_version_compatibility({"a2a_sdl": {"v": PROTOCOL_VERSION + 1}})

    def test_parse_runtime_version_policy(self) -> None:
        policy = parse_runtime_version_policy(
            {
                "min_peer_protocol": 1,
                "max_peer_protocol": 1,
                "require_peer_version": True,
                "deprecated_content_types": {"task.v1": "2099-01-01T00:00:00Z"},
                "allowed_content_type_versions": {"task": {"min": 1, "max": 2}},
            }
        )
        self.assertEqual(policy.min_peer_protocol, 1)
        self.assertTrue(policy.require_peer_version)
        self.assertIn("task.v1", policy.deprecated_content_types)
        self.assertEqual(policy.allowed_content_type_versions["task"], (1, 2))

    def test_enforce_content_type_version_policy(self) -> None:
        policy = RuntimeVersionPolicy(
            deprecated_content_types={"task.v1": "2099-01-01T00:00:00Z"},
            allowed_content_type_versions={"task": (1, 2)},
        )
        enforce_content_type_version_policy("task.v1", runtime_policy=policy)
        enforce_content_type_version_policy("task.v2", runtime_policy=policy)
        with self.assertRaises(ValueError):
            enforce_content_type_version_policy("task.v3", runtime_policy=policy)

    def test_enforce_capability_runtime_policy_bounds(self) -> None:
        policy = RuntimeVersionPolicy(min_peer_protocol=1, max_peer_protocol=1, require_peer_version=True)
        enforce_capability_version_compatibility({"a2a_sdl": {"v": 1}}, runtime_policy=policy)
        with self.assertRaises(ValueError):
            enforce_capability_version_compatibility({}, runtime_policy=policy)


if __name__ == "__main__":
    unittest.main()
