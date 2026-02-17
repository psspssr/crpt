from __future__ import annotations

import json
import tempfile
import unittest

from a2a_sdl.envelope import validate_envelope
from a2a_sdl.interoperability import build_interop_vectors, write_interop_vectors


class InteroperabilityTests(unittest.TestCase):
    def test_build_interop_vectors_are_valid(self) -> None:
        vectors = build_interop_vectors()
        self.assertIn("task.request.json", vectors)
        self.assertIn("task.response.json", vectors)
        for envelope in vectors.values():
            validate_envelope(envelope, allow_schema_uri=False)

    def test_write_interop_vectors_writes_json_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            written = write_interop_vectors(tmpdir)
            self.assertGreaterEqual(len(written), 4)
            for path in written:
                with open(path, "r", encoding="utf-8") as handle:
                    decoded = json.load(handle)
                self.assertIsInstance(decoded, dict)


if __name__ == "__main__":
    unittest.main()

