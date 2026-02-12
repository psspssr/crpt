from __future__ import annotations

import unittest

from a2a_sdl.constants import PROTOCOL_VERSION
from a2a_sdl.versioning import (
    enforce_capability_version_compatibility,
    is_protocol_version_compatible,
    parse_content_type_version,
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


if __name__ == "__main__":
    unittest.main()
