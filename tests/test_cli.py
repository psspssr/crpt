from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from a2a_sdl.cli import _load_handler_spec, main
from a2a_sdl.envelope import build_envelope
from a2a_sdl.schema import get_builtin_descriptor


class CLITests(unittest.TestCase):
    def test_send_passes_timeout_and_retry_options(self) -> None:
        captured: dict[str, object] = {}

        def fake_send_http(url: str, envelope: dict, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return build_envelope(
                msg_type="res",
                from_identity=envelope["to"],
                to_identity=envelope["from"],
                content_type="error.v1",
                payload={
                    "code": "BAD_REQUEST",
                    "message": "stub",
                    "details": {},
                    "retryable": False,
                },
                schema=get_builtin_descriptor("error.v1"),
            )

        payload_json = (
            '{"kind":"task.v1","goal":"x","inputs":{},"constraints":{"time_budget_s":1,'
            '"compute_budget":"low","safety":{}},"deliverables":[{"type":"text",'
            '"description":"d"}],"acceptance":["ok"],"context":{}}'
        )

        argv = [
            "send",
            "--url",
            "http://127.0.0.1:9999/a2a",
            "--ct",
            "task.v1",
            "--payload-json",
            payload_json,
            "--timeout",
            "33",
            "--retry-attempts",
            "2",
            "--retry-backoff-s",
            "0.25",
        ]

        with patch("a2a_sdl.cli.send_http", side_effect=fake_send_http):
            with redirect_stdout(io.StringIO()):
                code = main(argv)

        self.assertEqual(code, 0)
        self.assertEqual(captured["url"], "http://127.0.0.1:9999/a2a")
        kwargs = captured["kwargs"]
        assert isinstance(kwargs, dict)
        self.assertEqual(kwargs["timeout"], 33.0)
        self.assertEqual(kwargs["retry_attempts"], 2)
        self.assertEqual(kwargs["retry_backoff_s"], 0.25)

    def test_send_uses_auto_negotiate_sender(self) -> None:
        calls: dict[str, int] = {"send_http": 0, "send_http_with_auto_downgrade": 0}

        def fake_send_http(url: str, envelope: dict, **kwargs):
            calls["send_http"] += 1
            return build_envelope(
                msg_type="res",
                from_identity=envelope["to"],
                to_identity=envelope["from"],
                content_type="error.v1",
                payload={
                    "code": "BAD_REQUEST",
                    "message": "stub",
                    "details": {},
                    "retryable": False,
                },
                schema=get_builtin_descriptor("error.v1"),
            )

        def fake_send_http_with_auto_downgrade(url: str, envelope: dict, **kwargs):
            calls["send_http_with_auto_downgrade"] += 1
            return build_envelope(
                msg_type="res",
                from_identity=envelope["to"],
                to_identity=envelope["from"],
                content_type="negotiation.v1",
                payload={"need": {}, "have": {}, "ask": [], "supported_ct": ["negotiation.v1"]},
                schema=get_builtin_descriptor("negotiation.v1"),
            )

        payload_json = (
            '{"kind":"task.v1","goal":"x","inputs":{},"constraints":{"time_budget_s":1,'
            '"compute_budget":"low","safety":{}},"deliverables":[{"type":"text",'
            '"description":"d"}],"acceptance":["ok"],"context":{}}'
        )

        argv = [
            "send",
            "--url",
            "http://127.0.0.1:9999/a2a",
            "--ct",
            "task.v1",
            "--payload-json",
            payload_json,
            "--auto-negotiate",
        ]

        with patch("a2a_sdl.cli.send_http", side_effect=fake_send_http):
            with patch("a2a_sdl.cli.send_http_with_auto_downgrade", side_effect=fake_send_http_with_auto_downgrade):
                with redirect_stdout(io.StringIO()):
                    code = main(argv)

        self.assertEqual(code, 0)
        self.assertEqual(calls["send_http"], 0)
        self.assertEqual(calls["send_http_with_auto_downgrade"], 1)

    def test_send_secure_adds_enc_sig_and_replay(self) -> None:
        captured: dict[str, object] = {}

        def fake_send_http(url: str, envelope: dict, **kwargs):
            captured["envelope"] = envelope
            return build_envelope(
                msg_type="res",
                from_identity=envelope["to"],
                to_identity=envelope["from"],
                content_type="error.v1",
                payload={
                    "code": "BAD_REQUEST",
                    "message": "stub",
                    "details": {},
                    "retryable": False,
                },
                schema=get_builtin_descriptor("error.v1"),
            )

        payload_json = (
            '{"kind":"task.v1","goal":"x","inputs":{},"constraints":{"time_budget_s":1,'
            '"compute_budget":"low","safety":{}},"deliverables":[{"type":"text",'
            '"description":"d"}],"acceptance":["ok"],"context":{}}'
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            from a2a_sdl.security import generate_signing_keypair, generate_x25519_keypair

            signing = generate_signing_keypair()
            x25519 = generate_x25519_keypair()
            sign_path = f"{tmpdir}/sign.pem"
            with open(sign_path, "w", encoding="utf-8") as f:
                f.write(signing["private_key_pem"])

            argv = [
                "send",
                "--url",
                "http://127.0.0.1:9999/a2a",
                "--ct",
                "task.v1",
                "--payload-json",
                payload_json,
                "--secure",
                "--sign-key",
                sign_path,
                "--sign-kid",
                "did:key:sender#sig1",
                "--encrypt-kid",
                "did:key:receiver#enc1",
                "--encrypt-pub",
                x25519["public_key_b64"],
            ]

            with patch("a2a_sdl.cli.send_http", side_effect=fake_send_http):
                with redirect_stdout(io.StringIO()):
                    code = main(argv)

        self.assertEqual(code, 0)
        envelope = captured["envelope"]
        assert isinstance(envelope, dict)
        sec = envelope["sec"]
        self.assertEqual(sec["mode"], "enc+sig")
        self.assertTrue(isinstance(sec.get("replay"), dict))
        self.assertEqual(sec["sig"]["alg"], "ed25519")

    def test_serve_secure_required_needs_key_files(self) -> None:
        with redirect_stdout(io.StringIO()):
            with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                code = main(["serve", "--secure-required"])
        self.assertEqual(code, 2)
        self.assertIn("--secure-required needs", stderr.getvalue())

    def test_swarm_requires_three_ports(self) -> None:
        with redirect_stdout(io.StringIO()):
            with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                code = main(["swarm", "--ports", "9001,9002"])
        self.assertEqual(code, 2)
        self.assertIn("exactly 3 ports", stderr.getvalue())

    def test_load_handler_spec_valid(self) -> None:
        ct, handler = _load_handler_spec("artifact.v1=json:loads")
        self.assertEqual(ct, "artifact.v1")
        self.assertTrue(callable(handler))

    def test_load_handler_spec_invalid_format(self) -> None:
        with self.assertRaises(ValueError):
            _load_handler_spec("artifact.v1-json:loads")


if __name__ == "__main__":
    unittest.main()
