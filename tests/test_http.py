from __future__ import annotations

import copy
import datetime as dt
import threading
import time
import urllib.request
import unittest
import tempfile
from pathlib import Path

from a2a_sdl.codec import decode_bytes, encode_bytes
from a2a_sdl.envelope import build_envelope, make_error_response
from a2a_sdl.audit import AuditChain, verify_audit_chain
from a2a_sdl.policy import SecurityPolicy
from a2a_sdl.replay import ReplayCache
from a2a_sdl.schema import get_builtin_descriptor
from a2a_sdl.security import encrypt_payload, generate_signing_keypair, generate_x25519_keypair, sign_envelope
from a2a_sdl.transport_http import A2AHTTPServer, _pick_downgrade_ct, send_http, send_http_with_auto_downgrade

from tests.test_helpers import make_task_envelope


class HTTPTests(unittest.TestCase):
    def test_roundtrip_request_response(self) -> None:
        from a2a_sdl.handlers import default_handler

        server = A2AHTTPServer("127.0.0.1", 0, handler=default_handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            url = f"http://127.0.0.1:{port}/a2a"
            req = make_task_envelope()
            res = send_http(url, req, encoding="json", timeout=10.0, retry_attempts=1, retry_backoff_s=0.01)
            self.assertEqual(res["type"], "res")
            self.assertEqual(res["ct"], "state.v1")
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_unsupported_ct_maps_to_protocol_error(self) -> None:
        from a2a_sdl.handlers import default_handler

        server = A2AHTTPServer("127.0.0.1", 0, handler=default_handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            url = f"http://127.0.0.1:{port}/a2a"

            req = make_task_envelope()
            req["ct"] = "foo.v9"
            body = encode_bytes(req, encoding="json")

            http_req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(http_req, timeout=10) as response:
                raw = response.read()
            decoded = decode_bytes(raw, encoding="json")

            self.assertEqual(decoded["ct"], "error.v1")
            self.assertEqual(decoded["payload"]["code"], "UNSUPPORTED_CT")
            self.assertIn("task.v1", decoded["payload"]["details"]["supported_ct"])
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_replay_protection_rejects_duplicate_nonce(self) -> None:
        from a2a_sdl.handlers import default_handler

        server = A2AHTTPServer("127.0.0.1", 0, handler=default_handler, enforce_replay=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            url = f"http://127.0.0.1:{port}/a2a"

            req = make_task_envelope()
            future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
            req["sec"] = {
                "mode": "none",
                "replay": {"nonce": "n-123", "exp": future.isoformat().replace("+00:00", "Z")},
            }
            first = send_http(url, req, encoding="json")
            self.assertEqual(first["ct"], "state.v1")

            second_req = copy.deepcopy(req)
            second = send_http(url, second_req, encoding="json")
            self.assertEqual(second["ct"], "error.v1")
            self.assertEqual(second["payload"]["code"], "BAD_REQUEST")
            self.assertEqual(second["payload"]["details"]["reason"], "replay_detected")
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_replay_protection_rejects_expired_nonce(self) -> None:
        from a2a_sdl.handlers import default_handler

        server = A2AHTTPServer("127.0.0.1", 0, handler=default_handler, enforce_replay=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            url = f"http://127.0.0.1:{port}/a2a"

            req = make_task_envelope()
            past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).replace(microsecond=0)
            req["sec"] = {
                "mode": "none",
                "replay": {"nonce": "n-expired", "exp": past.isoformat().replace("+00:00", "Z")},
            }
            res = send_http(url, req, encoding="json")
            self.assertEqual(res["ct"], "error.v1")
            self.assertEqual(res["payload"]["code"], "BAD_REQUEST")
            self.assertEqual(res["payload"]["details"]["reason"], "replay_expired")
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_auto_negotiate_falls_back_to_negotiation_ct(self) -> None:
        def handler(req: dict):
            if req["ct"] == "task.v1":
                return make_error_response(
                    request=req,
                    code="UNSUPPORTED_CT",
                    message="task.v1 unsupported by this peer",
                    details={"supported_ct": ["negotiation.v1"]},
                    retryable=True,
                )

            if req["ct"] == "negotiation.v1":
                payload = {
                    "need": {},
                    "have": {"peer_mode": "negotiation-only"},
                    "ask": [],
                    "supported_ct": ["negotiation.v1"],
                }
                return build_envelope(
                    msg_type="res",
                    from_identity=req["to"],
                    to_identity=req["from"],
                    content_type="negotiation.v1",
                    payload=payload,
                    schema=get_builtin_descriptor("negotiation.v1"),
                )

            return make_error_response(
                request=req,
                code="UNSUPPORTED_CT",
                message=f"unsupported {req['ct']}",
                details={"supported_ct": ["negotiation.v1"]},
                retryable=True,
            )

        server = A2AHTTPServer("127.0.0.1", 0, handler=handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            url = f"http://127.0.0.1:{port}/a2a"
            req = make_task_envelope()
            res = send_http_with_auto_downgrade(url, req, encoding="json")
            self.assertEqual(res["ct"], "negotiation.v1")
            self.assertEqual(res["payload"]["have"]["peer_mode"], "negotiation-only")
        finally:
            server.shutdown()
            thread.join(timeout=1)

    def test_pick_downgrade_ct_prefers_highest_lower_version(self) -> None:
        selected = _pick_downgrade_ct("task.v4", ["task.v1", "task.v3", "task.v2", "state.v1"])
        self.assertEqual(selected, "task.v3")

    def test_secure_policy_accepts_signed_encrypted_request_and_audits(self) -> None:
        from a2a_sdl.handlers import default_handler

        signing_keys = generate_signing_keypair()
        decrypt_keys = generate_x25519_keypair()
        policy = SecurityPolicy(
            require_mode="enc+sig",
            require_replay=True,
            allowed_agents={"did:key:secure-sender"},
            trusted_signing_keys={"did:key:secure-sender#sig1": signing_keys["public_key_b64"]},
            required_kid_by_agent={"did:key:secure-sender": "did:key:secure-sender#sig1"},
            decrypt_private_keys={"did:key:server#enc1": decrypt_keys["private_key_b64"]},
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.log"
            server = A2AHTTPServer(
                "127.0.0.1",
                0,
                handler=default_handler,
                replay_cache=ReplayCache(),
                security_policy=policy,
                audit_chain=AuditChain(audit_path),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            time.sleep(0.05)

            try:
                port = server._server.server_address[1]
                url = f"http://127.0.0.1:{port}/a2a"

                req = make_task_envelope()
                req["from"]["agent_id"] = "did:key:secure-sender"
                encrypt_payload(
                    req,
                    recipients=[{"kid": "did:key:server#enc1", "public_key": decrypt_keys["public_key_b64"]}],
                )

                exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
                req.setdefault("sec", {})["replay"] = {
                    "nonce": "secure-nonce-1",
                    "exp": exp.isoformat().replace("+00:00", "Z"),
                }
                sign_envelope(req, signing_keys["private_key_b64"], kid="did:key:secure-sender#sig1")

                first = send_http(url, req, encoding="json")
                self.assertEqual(first["ct"], "state.v1")
                self.assertTrue(isinstance(first.get("trace"), dict))
                self.assertIn("audit", first["trace"])

                second = send_http(url, copy.deepcopy(req), encoding="json")
                self.assertEqual(second["ct"], "error.v1")
                self.assertEqual(second["payload"]["code"], "BAD_REQUEST")
                self.assertEqual(second["payload"]["details"]["reason"], "replay_detected")

                verify_audit_chain(audit_path)
            finally:
                server.shutdown()
                thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
