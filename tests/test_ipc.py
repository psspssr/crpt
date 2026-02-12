from __future__ import annotations

import copy
import datetime as dt
import socket
import threading
import time
import unittest

from a2a_sdl.codec import decode_bytes, encode_bytes
from a2a_sdl.envelope import EnvelopeValidationError
from a2a_sdl.handlers import default_handler
from a2a_sdl.policy import SecurityPolicy
from a2a_sdl.replay import ReplayCache
from a2a_sdl.security import encrypt_payload, generate_signing_keypair, generate_x25519_keypair, sign_envelope
from a2a_sdl.transport_ipc import IPCServer, decode_ipc_frames, encode_ipc_frame, send_ipc
from a2a_sdl.versioning import parse_runtime_version_policy

from tests.test_helpers import make_task_envelope


class IPCTransportTests(unittest.TestCase):
    def test_encode_decode_ipc_frames_roundtrip(self) -> None:
        a = b"hello"
        b = b"world!!"
        stream = encode_ipc_frame(a) + encode_ipc_frame(b)
        frames, remainder = decode_ipc_frames(stream)
        self.assertEqual(frames, [a, b])
        self.assertEqual(remainder, b"")

    def test_send_ipc_roundtrip(self) -> None:
        server = IPCServer("127.0.0.1", 0, handler=default_handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            req = make_task_envelope()
            res = send_ipc("127.0.0.1", port, req, encoding="json")
            self.assertEqual(res["type"], "res")
            self.assertEqual(res["ct"], "state.v1")
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_send_ipc_rejects_uri_schema_descriptor(self) -> None:
        req = make_task_envelope()
        req["schema"] = {
            "kind": "uri",
            "id": "sha256:0123456789abcdef",
            "uri": "http://127.0.0.1:9/schema.json",
        }
        with self.assertRaises(EnvelopeValidationError):
            send_ipc("127.0.0.1", 9, req, encoding="json")

    def test_ipc_server_rejects_uri_schema_descriptor(self) -> None:
        server = IPCServer("127.0.0.1", 0, handler=default_handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            req = make_task_envelope()
            req["schema"] = {
                "kind": "uri",
                "id": "sha256:0123456789abcdef",
                "uri": "http://127.0.0.1:9/schema.json",
            }
            raw_req = encode_bytes(req, encoding="json")
            with socket.create_connection(("127.0.0.1", port), timeout=10.0) as conn:
                conn.sendall(encode_ipc_frame(raw_req))
                header = conn.recv(4)
                self.assertEqual(len(header), 4)
                size = int.from_bytes(header, "big")
                payload = b""
                while len(payload) < size:
                    payload += conn.recv(size - len(payload))
            frames, rem = decode_ipc_frames(header + payload)
            self.assertFalse(rem)
            res = decode_bytes(frames[0], encoding="json")
            self.assertEqual(res["ct"], "error.v1")
            self.assertEqual(res["payload"]["code"], "SCHEMA_INVALID")
            self.assertIn("uri descriptors are not allowed", res["payload"]["message"])
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_ipc_enforce_replay_rejects_duplicate_nonce(self) -> None:
        cache = ReplayCache()
        server = IPCServer("127.0.0.1", 0, handler=default_handler, enforce_replay=True, replay_cache=cache)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            req = make_task_envelope()
            future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
            req["sec"] = {
                "mode": "none",
                "replay": {"nonce": "ipc-nonce-1", "exp": future.isoformat().replace("+00:00", "Z")},
            }

            first = send_ipc("127.0.0.1", port, req, encoding="json")
            self.assertEqual(first["ct"], "state.v1")

            second = send_ipc("127.0.0.1", port, copy.deepcopy(req), encoding="json")
            self.assertEqual(second["ct"], "error.v1")
            self.assertEqual(second["payload"]["details"]["reason"], "replay_detected")
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_ipc_security_policy_accepts_signed_encrypted(self) -> None:
        signing_keys = generate_signing_keypair()
        decrypt_keys = generate_x25519_keypair()
        policy = SecurityPolicy(
            require_mode="enc+sig",
            require_replay=True,
            allowed_agents={"did:key:ipc-sender"},
            trusted_signing_keys={"did:key:ipc-sender#sig1": signing_keys["public_key_b64"]},
            required_kid_by_agent={"did:key:ipc-sender": "did:key:ipc-sender#sig1"},
            decrypt_private_keys={"did:key:ipc-server#enc1": decrypt_keys["private_key_b64"]},
        )

        server = IPCServer("127.0.0.1", 0, handler=default_handler, security_policy=policy, replay_cache=ReplayCache())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            req = make_task_envelope()
            req["from"]["agent_id"] = "did:key:ipc-sender"
            encrypt_payload(
                req,
                recipients=[{"kid": "did:key:ipc-server#enc1", "public_key": decrypt_keys["public_key_b64"]}],
            )
            exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
            req.setdefault("sec", {})["replay"] = {
                "nonce": "ipc-secure-nonce-1",
                "exp": exp.isoformat().replace("+00:00", "Z"),
            }
            sign_envelope(req, signing_keys["private_key_b64"], kid="did:key:ipc-sender#sig1")

            res = send_ipc("127.0.0.1", port, req, encoding="json")
            self.assertEqual(res["ct"], "state.v1")
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_ipc_runtime_version_policy_deprecates_content_type(self) -> None:
        version_policy = parse_runtime_version_policy(
            {"deprecated_content_types": {"task.v1": "2000-01-01T00:00:00Z"}}
        )
        server = IPCServer("127.0.0.1", 0, handler=default_handler, version_policy=version_policy)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            res = send_ipc("127.0.0.1", port, make_task_envelope(), encoding="json")
            self.assertEqual(res["ct"], "error.v1")
            self.assertIn("deprecated", res["payload"]["message"])
        finally:
            server.shutdown()
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
