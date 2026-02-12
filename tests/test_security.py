from __future__ import annotations

import copy
import unittest
from concurrent.futures import ThreadPoolExecutor

from a2a_sdl.replay import ReplayCache
from a2a_sdl.security import (
    SecurityError,
    decrypt_payload,
    encrypt_payload,
    generate_signing_keypair,
    generate_x25519_keypair,
    sign_envelope,
    verify_envelope_signature,
)

from tests.test_helpers import make_task_envelope


class SecurityTests(unittest.TestCase):
    def test_sign_and_verify(self) -> None:
        env = make_task_envelope()
        keys = generate_signing_keypair()
        sign_envelope(env, keys["private_key_b64"], kid="did:key:z6M#k1")
        self.assertTrue(verify_envelope_signature(env, keys["public_key_b64"]))

    def test_signature_tamper_fails(self) -> None:
        env = make_task_envelope()
        keys = generate_signing_keypair()
        sign_envelope(env, keys["private_key_b64"])

        tampered = copy.deepcopy(env)
        tampered["payload"]["goal"] = "changed"

        with self.assertRaises(SecurityError):
            verify_envelope_signature(tampered, keys["public_key_b64"])

    def test_encrypt_and_decrypt_payload(self) -> None:
        env = make_task_envelope()
        original = copy.deepcopy(env["payload"])
        keys = generate_x25519_keypair()

        encrypt_payload(
            env,
            recipients=[
                {
                    "kid": "did:key:z6Mreceiver#k1",
                    "public_key": keys["public_key_b64"],
                }
            ],
        )
        self.assertIsNone(env["payload"])

        decrypted = decrypt_payload(env, keys["private_key_b64"], kid="did:key:z6Mreceiver#k1")
        self.assertEqual(decrypted, original)

    def test_replay_cache(self) -> None:
        cache = ReplayCache(max_entries=2, ttl_seconds=1)
        self.assertFalse(cache.seen_or_add("a", "n1", now=0))
        self.assertTrue(cache.seen_or_add("a", "n1", now=0.1))
        self.assertFalse(cache.seen_or_add("a", "n2", now=0.2))
        self.assertFalse(cache.seen_or_add("a", "n3", now=2.0))

    def test_replay_cache_thread_safety(self) -> None:
        cache = ReplayCache(max_entries=1000, ttl_seconds=60)

        def mark(_: int) -> bool:
            return cache.seen_or_add("agent-a", "nonce-shared")

        with ThreadPoolExecutor(max_workers=32) as executor:
            results = list(executor.map(mark, range(128)))

        self.assertEqual(results.count(False), 1)
        self.assertEqual(results.count(True), 127)


if __name__ == "__main__":
    unittest.main()
