from __future__ import annotations

import datetime as dt
import unittest

from a2a_sdl.session import SessionBindingStore, compute_session_binding_id


class SessionBindingTests(unittest.TestCase):
    def test_compute_binding_id_is_deterministic(self) -> None:
        params = {
            "from_agent": "did:key:agent-a",
            "to_agent": "did:key:agent-b",
            "profile": {"ct": ["task.v1"], "mode": "enc+sig"},
            "nonce": "nonce-1234",
            "expires": "2099-01-01T00:00:00Z",
        }
        first = compute_session_binding_id(**params)
        second = compute_session_binding_id(**params)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("sha256:"))

    def test_store_register_and_validate_active_binding(self) -> None:
        store = SessionBindingStore()
        exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).replace(microsecond=0)
        exp_str = exp.isoformat().replace("+00:00", "Z")
        record = store.register(
            binding_id="sha256:binding-1",
            from_agent="did:key:agent-a",
            to_agent="did:key:agent-b",
            expires=exp_str,
            profile={"ct": ["task.v1"]},
        )
        self.assertEqual(record.binding_id, "sha256:binding-1")
        self.assertTrue(
            store.is_active(
                binding_id="sha256:binding-1",
                from_agent="did:key:agent-a",
                to_agent="did:key:agent-b",
            )
        )
        self.assertFalse(
            store.is_active(
                binding_id="sha256:binding-1",
                from_agent="did:key:agent-x",
                to_agent="did:key:agent-b",
            )
        )

    def test_store_rejects_expired_registration(self) -> None:
        store = SessionBindingStore()
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).replace(microsecond=0)
        past_str = past.isoformat().replace("+00:00", "Z")
        with self.assertRaises(ValueError):
            store.register(
                binding_id="sha256:binding-old",
                from_agent="did:key:agent-a",
                to_agent="did:key:agent-b",
                expires=past_str,
                profile={"ct": ["task.v1"]},
            )

    def test_store_expires_records(self) -> None:
        store = SessionBindingStore()
        exp = "2099-01-01T00:00:00Z"
        store.register(
            binding_id="sha256:binding-keep",
            from_agent="did:key:agent-a",
            to_agent="did:key:agent-b",
            expires=exp,
            profile={"ct": ["task.v1"]},
        )
        future = dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc)
        self.assertFalse(
            store.is_active(
                binding_id="sha256:binding-keep",
                from_agent="did:key:agent-a",
                to_agent="did:key:agent-b",
                now=future,
            )
        )


if __name__ == "__main__":
    unittest.main()
