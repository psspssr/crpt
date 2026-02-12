from __future__ import annotations

import datetime as dt
import unittest

from a2a_sdl.envelope import EnvelopeValidationError
from a2a_sdl.policy import SecurityPolicy, SecurityPolicyManager, enforce_request_security
from a2a_sdl.replay import ReplayCache
from a2a_sdl.security import (
    encrypt_payload,
    generate_signing_keypair,
    generate_x25519_keypair,
    sign_envelope,
)
from a2a_sdl.session import SessionBindingStore

from tests.test_helpers import make_task_envelope


class SecurityPolicyTests(unittest.TestCase):
    def _make_secure_request(
        self,
        *,
        session_binding_id: str | None = None,
        session_exp: str | None = None,
    ):
        env = make_task_envelope()
        env["from"]["agent_id"] = "did:key:agent-a"

        signing_keys = generate_signing_keypair()
        decrypt_keys = generate_x25519_keypair()

        encrypt_payload(
            env,
            recipients=[{"kid": "did:key:server#enc1", "public_key": decrypt_keys["public_key_b64"]}],
        )

        exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
        sec = env.setdefault("sec", {})
        sec["replay"] = {
            "nonce": "nonce-1",
            "exp": exp.isoformat().replace("+00:00", "Z"),
        }
        if session_binding_id is not None:
            sec_session: dict[str, str] = {"binding_id": session_binding_id}
            if session_exp is not None:
                sec_session["exp"] = session_exp
            sec["session"] = sec_session
        sign_envelope(env, signing_keys["private_key_b64"], kid="did:key:agent-a#sig1")

        policy = SecurityPolicy(
            require_mode="enc+sig",
            require_replay=True,
            allowed_agents={"did:key:agent-a"},
            trusted_signing_keys={"did:key:agent-a#sig1": signing_keys["public_key_b64"]},
            required_kid_by_agent={"did:key:agent-a": "did:key:agent-a#sig1"},
            decrypt_private_keys={"did:key:server#enc1": decrypt_keys["private_key_b64"]},
        )
        return env, policy

    def test_enforce_request_security_success(self) -> None:
        env, policy = self._make_secure_request()
        replay_cache = ReplayCache()

        enforce_request_security(env, policy, replay_cache)
        self.assertEqual(env["payload"]["kind"], "task.v1")

    def test_enforce_request_security_replay_rejected(self) -> None:
        env, policy = self._make_secure_request()
        replay_cache = ReplayCache()

        enforce_request_security(env, policy, replay_cache)
        with self.assertRaises(EnvelopeValidationError):
            enforce_request_security(env, policy, replay_cache)

    def test_enforce_request_security_rejects_untrusted_kid(self) -> None:
        env, policy = self._make_secure_request()
        policy.trusted_signing_keys = {}

        with self.assertRaises(EnvelopeValidationError):
            enforce_request_security(env, policy, ReplayCache())

    def test_enforce_request_security_rejects_revoked_kid(self) -> None:
        env, policy = self._make_secure_request()
        policy.revoked_kids = {"did:key:agent-a#sig1"}

        with self.assertRaises(EnvelopeValidationError):
            enforce_request_security(env, policy, ReplayCache())

    def test_enforce_request_security_supports_allowed_rotation_set(self) -> None:
        env, policy = self._make_secure_request()
        policy.required_kid_by_agent = {}
        policy.allowed_kids_by_agent = {"did:key:agent-a": {"did:key:agent-a#sig1", "did:key:agent-a#sig2"}}

        enforce_request_security(env, policy, ReplayCache())

    def test_enforce_request_security_rejects_kid_outside_rotation_set(self) -> None:
        env, policy = self._make_secure_request()
        policy.required_kid_by_agent = {}
        policy.allowed_kids_by_agent = {"did:key:agent-a": {"did:key:agent-a#sig2"}}

        with self.assertRaises(EnvelopeValidationError):
            enforce_request_security(env, policy, ReplayCache())

    def test_enforce_request_security_rejects_expired_kid(self) -> None:
        env, policy = self._make_secure_request()
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).replace(microsecond=0)
        policy.kid_not_after = {"did:key:agent-a#sig1": past.isoformat().replace("+00:00", "Z")}

        with self.assertRaises(EnvelopeValidationError):
            enforce_request_security(env, policy, ReplayCache())

    def test_security_policy_manager_apply_registry(self) -> None:
        manager = SecurityPolicyManager(SecurityPolicy())
        before = manager.snapshot_hash()
        updated_hash = manager.apply_registry(
            {
                "trusted_signing_keys": {"kid-1": "pub-1"},
                "required_kid_by_agent": {"did:key:agent-a": "kid-1"},
                "allowed_kids_by_agent": {"did:key:agent-a": ["kid-1", "kid-2"]},
                "revoked_kids": ["kid-old"],
                "kid_not_after": {"kid-1": "2099-01-01T00:00:00Z"},
            },
            merge=True,
        )
        self.assertTrue(updated_hash.startswith("sha256:"))
        self.assertNotEqual(before, updated_hash)
        snapshot = manager.snapshot()
        self.assertIn("kid-1", snapshot["trusted_signing_keys"])
        self.assertIn("kid-old", snapshot["revoked_kids"])

    def test_session_binding_required_rejects_missing_sec_session(self) -> None:
        env, policy = self._make_secure_request()
        policy.require_session_binding = True
        policy.session_binding_store = SessionBindingStore()

        with self.assertRaises(EnvelopeValidationError):
            enforce_request_security(env, policy, ReplayCache())

    def test_session_binding_required_accepts_registered_binding(self) -> None:
        exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
        exp_str = exp.isoformat().replace("+00:00", "Z")
        env, policy = self._make_secure_request(
            session_binding_id="sha256:binding-1",
            session_exp=exp_str,
        )

        store = SessionBindingStore()
        store.register(
            binding_id="sha256:binding-1",
            from_agent=env["from"]["agent_id"],
            to_agent=env["to"]["agent_id"],
            expires=exp_str,
            profile={"ct": ["task.v1"], "mode": "enc+sig"},
        )
        policy.require_session_binding = True
        policy.session_binding_store = store

        enforce_request_security(env, policy, ReplayCache())

    def test_session_binding_required_rejects_unknown_binding(self) -> None:
        exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
        exp_str = exp.isoformat().replace("+00:00", "Z")
        env, policy = self._make_secure_request(
            session_binding_id="sha256:unknown",
            session_exp=exp_str,
        )
        policy.require_session_binding = True
        policy.session_binding_store = SessionBindingStore()

        with self.assertRaises(EnvelopeValidationError):
            enforce_request_security(env, policy, ReplayCache())

    def test_session_binding_exempt_content_type_skips_requirement(self) -> None:
        env, policy = self._make_secure_request()
        policy.require_session_binding = True
        policy.session_binding_store = SessionBindingStore()
        policy.session_binding_exempt_ct = {"task.v1", "session.v1", "error.v1"}

        enforce_request_security(env, policy, ReplayCache())


if __name__ == "__main__":
    unittest.main()
