from __future__ import annotations

import copy
import datetime as dt
import unittest

from a2a_sdl.codec import decode_bytes, encode_bytes
from a2a_sdl.handlers import default_handler
from a2a_sdl.policy import SecurityPolicy
from a2a_sdl.replay import ReplayCache
from a2a_sdl.security import encrypt_payload, generate_signing_keypair, generate_x25519_keypair, sign_envelope
from a2a_sdl.transport_ws import process_ws_payload
from a2a_sdl.versioning import parse_runtime_version_policy

from tests.test_helpers import make_task_envelope


class WSTransportTests(unittest.TestCase):
    def test_process_ws_payload_invalid_encoding_returns_error_envelope(self) -> None:
        out = process_ws_payload(b"not-json", encoding="json", handler=default_handler)
        decoded = decode_bytes(out, encoding="json")
        self.assertEqual(decoded["ct"], "error.v1")
        self.assertEqual(decoded["payload"]["code"], "UNSUPPORTED_ENCODING")

    def test_process_ws_payload_unsupported_ct_maps_to_protocol_error(self) -> None:
        req = make_task_envelope()
        req["ct"] = "foo.v9"
        out = process_ws_payload(encode_bytes(req, encoding="json"), encoding="json", handler=default_handler)
        decoded = decode_bytes(out, encoding="json")
        self.assertEqual(decoded["ct"], "error.v1")
        self.assertEqual(decoded["payload"]["code"], "UNSUPPORTED_CT")

    def test_process_ws_payload_rejects_uri_schema_descriptor(self) -> None:
        req = make_task_envelope()
        req["schema"] = {
            "kind": "uri",
            "id": "sha256:0123456789abcdef",
            "uri": "http://127.0.0.1:9/schema.json",
        }
        out = process_ws_payload(encode_bytes(req, encoding="json"), encoding="json", handler=default_handler)
        decoded = decode_bytes(out, encoding="json")
        self.assertEqual(decoded["ct"], "error.v1")
        self.assertEqual(decoded["payload"]["code"], "SCHEMA_INVALID")
        self.assertIn("uri descriptors are not allowed", decoded["payload"]["message"])

    def test_process_ws_payload_enforce_replay_rejects_duplicate_nonce(self) -> None:
        cache = ReplayCache()

        req = make_task_envelope()
        future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
        req["sec"] = {
            "mode": "none",
            "replay": {"nonce": "ws-nonce-1", "exp": future.isoformat().replace("+00:00", "Z")},
        }

        first = process_ws_payload(
            encode_bytes(req, encoding="json"),
            encoding="json",
            handler=default_handler,
            enforce_replay=True,
            replay_cache=cache,
        )
        first_decoded = decode_bytes(first, encoding="json")
        self.assertEqual(first_decoded["ct"], "state.v1")

        second = process_ws_payload(
            encode_bytes(copy.deepcopy(req), encoding="json"),
            encoding="json",
            handler=default_handler,
            enforce_replay=True,
            replay_cache=cache,
        )
        second_decoded = decode_bytes(second, encoding="json")
        self.assertEqual(second_decoded["ct"], "error.v1")
        self.assertEqual(second_decoded["payload"]["code"], "BAD_REQUEST")
        self.assertEqual(second_decoded["payload"]["details"]["reason"], "replay_detected")

    def test_process_ws_payload_security_policy_accepts_signed_encrypted(self) -> None:
        signing_keys = generate_signing_keypair()
        decrypt_keys = generate_x25519_keypair()
        policy = SecurityPolicy(
            require_mode="enc+sig",
            require_replay=True,
            allowed_agents={"did:key:ws-sender"},
            trusted_signing_keys={"did:key:ws-sender#sig1": signing_keys["public_key_b64"]},
            required_kid_by_agent={"did:key:ws-sender": "did:key:ws-sender#sig1"},
            decrypt_private_keys={"did:key:ws-server#enc1": decrypt_keys["private_key_b64"]},
        )

        req = make_task_envelope()
        req["from"]["agent_id"] = "did:key:ws-sender"
        encrypt_payload(
            req,
            recipients=[{"kid": "did:key:ws-server#enc1", "public_key": decrypt_keys["public_key_b64"]}],
        )
        future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
        req.setdefault("sec", {})["replay"] = {
            "nonce": "ws-secure-nonce-1",
            "exp": future.isoformat().replace("+00:00", "Z"),
        }
        sign_envelope(req, signing_keys["private_key_b64"], kid="did:key:ws-sender#sig1")

        out = process_ws_payload(
            encode_bytes(req, encoding="json"),
            encoding="json",
            handler=default_handler,
            security_policy=policy,
            replay_cache=ReplayCache(),
        )
        decoded = decode_bytes(out, encoding="json")
        self.assertEqual(decoded["ct"], "state.v1")

    def test_process_ws_payload_security_policy_rejects_untrusted_kid(self) -> None:
        signing_keys = generate_signing_keypair()
        decrypt_keys = generate_x25519_keypair()
        policy = SecurityPolicy(
            require_mode="enc+sig",
            require_replay=True,
            allowed_agents={"did:key:ws-sender"},
            trusted_signing_keys={},
            required_kid_by_agent={"did:key:ws-sender": "did:key:ws-sender#sig1"},
            decrypt_private_keys={"did:key:ws-server#enc1": decrypt_keys["private_key_b64"]},
        )

        req = make_task_envelope()
        req["from"]["agent_id"] = "did:key:ws-sender"
        encrypt_payload(
            req,
            recipients=[{"kid": "did:key:ws-server#enc1", "public_key": decrypt_keys["public_key_b64"]}],
        )
        future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
        req.setdefault("sec", {})["replay"] = {
            "nonce": "ws-secure-nonce-2",
            "exp": future.isoformat().replace("+00:00", "Z"),
        }
        sign_envelope(req, signing_keys["private_key_b64"], kid="did:key:ws-sender#sig1")

        out = process_ws_payload(
            encode_bytes(req, encoding="json"),
            encoding="json",
            handler=default_handler,
            security_policy=policy,
            replay_cache=ReplayCache(),
        )
        decoded = decode_bytes(out, encoding="json")
        self.assertEqual(decoded["ct"], "error.v1")
        self.assertEqual(decoded["payload"]["code"], "SECURITY_UNSUPPORTED")

    def test_process_ws_payload_respects_runtime_version_policy(self) -> None:
        req = make_task_envelope()
        version_policy = parse_runtime_version_policy(
            {"deprecated_content_types": {"task.v1": "2000-01-01T00:00:00Z"}}
        )
        out = process_ws_payload(
            encode_bytes(req, encoding="json"),
            encoding="json",
            handler=default_handler,
            version_policy=version_policy,
        )
        decoded = decode_bytes(out, encoding="json")
        self.assertEqual(decoded["ct"], "error.v1")
        self.assertIn("deprecated", decoded["payload"]["message"])


if __name__ == "__main__":
    unittest.main()
