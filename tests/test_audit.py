from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from a2a_sdl.audit import AuditChain, AuditError, verify_audit_chain
from a2a_sdl.security import generate_signing_keypair


class AuditTests(unittest.TestCase):
    def test_audit_chain_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.log"
            chain = AuditChain(path)
            r1 = chain.append({"event": "request", "id": "1"})
            r2 = chain.append({"event": "response", "id": "2"})

            self.assertTrue(r1["entry_hash"].startswith("sha256:"))
            self.assertEqual(r2["prev_hash"], r1["entry_hash"])
            verify_audit_chain(path)

    def test_audit_chain_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.log"
            chain = AuditChain(path)
            chain.append({"event": "request", "id": "1"})
            chain.append({"event": "response", "id": "2"})

            lines = path.read_text(encoding="utf-8").splitlines()
            second = json.loads(lines[1])
            second["event"]["id"] = "tampered"
            lines[1] = json.dumps(second, sort_keys=True)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            with self.assertRaises(AuditError):
                verify_audit_chain(path)

    def test_audit_chain_signature_verification(self) -> None:
        keys = generate_signing_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.log"
            chain = AuditChain(path, signing_private_key=keys["private_key_pem"])
            chain.append({"event": "request", "id": "1"})
            chain.append({"event": "response", "id": "2"})

            verify_audit_chain(path, signing_public_key=keys["public_key_pem"], require_signatures=True)

    def test_audit_chain_signature_verification_detects_tamper(self) -> None:
        keys = generate_signing_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.log"
            chain = AuditChain(path, signing_private_key=keys["private_key_pem"])
            chain.append({"event": "request", "id": "1"})

            lines = path.read_text(encoding="utf-8").splitlines()
            record = json.loads(lines[0])
            record["sig"]["value"] = "AAAA"
            lines[0] = json.dumps(record, sort_keys=True)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            with self.assertRaises(AuditError):
                verify_audit_chain(path, signing_public_key=keys["public_key_pem"], require_signatures=True)


if __name__ == "__main__":
    unittest.main()
