from __future__ import annotations

import unittest

from a2a_sdl.codec import CodecError, decode_bytes, encode_bytes, has_cbor_support
from a2a_sdl.envelope import validate_envelope

from tests.test_helpers import make_task_envelope


class CodecTests(unittest.TestCase):
    def test_json_roundtrip(self) -> None:
        env = make_task_envelope()
        encoded = encode_bytes(env, encoding="json")
        decoded = decode_bytes(encoded, encoding="json")
        validate_envelope(decoded)
        self.assertEqual(decoded["ct"], "task.v1")

    def test_json_is_deterministic(self) -> None:
        env = make_task_envelope()
        a = encode_bytes(env, encoding="json")
        b = encode_bytes(env, encoding="json")
        self.assertEqual(a, b)

    def test_cbor_roundtrip_if_available(self) -> None:
        if not has_cbor_support():
            self.skipTest("cbor2 not installed")

        env = make_task_envelope()
        encoded = encode_bytes(env, encoding="cbor")
        decoded = decode_bytes(encoded, encoding="cbor")
        validate_envelope(decoded)
        self.assertEqual(decoded["id"], env["id"])

    def test_unknown_encoding_rejected(self) -> None:
        with self.assertRaises(CodecError):
            encode_bytes({}, encoding="yaml")


if __name__ == "__main__":
    unittest.main()
