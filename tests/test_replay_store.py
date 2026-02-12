from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from a2a_sdl.replay import SQLiteReplayCache


class SQLiteReplayCacheTests(unittest.TestCase):
    def test_seen_or_add_persists_across_instances(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "replay.db"
            cache1 = SQLiteReplayCache(db_path)
            try:
                self.assertFalse(cache1.seen_or_add("agent-a", "nonce-1", now=1000.0))
            finally:
                cache1.close()

            cache2 = SQLiteReplayCache(db_path)
            try:
                self.assertTrue(cache2.seen_or_add("agent-a", "nonce-1", now=1001.0))
            finally:
                cache2.close()

    def test_ttl_expiration_allows_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "replay.db"
            cache = SQLiteReplayCache(db_path, ttl_seconds=5)
            try:
                self.assertFalse(cache.seen_or_add("agent-a", "nonce-1", now=1000.0))
                self.assertTrue(cache.seen_or_add("agent-a", "nonce-1", now=1001.0))
                self.assertFalse(cache.seen_or_add("agent-a", "nonce-1", now=1007.0))
            finally:
                cache.close()


if __name__ == "__main__":
    unittest.main()
