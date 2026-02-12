"""Replay protection cache."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Protocol


class ReplayCacheProtocol(Protocol):
    """Minimal protocol for replay nonce stores."""

    def seen_or_add(self, agent_id: str, nonce: str, now: float | None = None) -> bool:
        """Return True when nonce already exists, else store and return False."""


class ReplayCache:
    """LRU cache keyed by (agent_id, nonce) with TTL expiration."""

    def __init__(self, max_entries: int = 10_000, ttl_seconds: int = 600) -> None:
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._store: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._lock = threading.Lock()

    def seen_or_add(self, agent_id: str, nonce: str, now: float | None = None) -> bool:
        ts = now if now is not None else time.time()
        with self._lock:
            self._purge_expired(ts)

            key = (agent_id, nonce)
            if key in self._store:
                return True

            self._store[key] = ts
            self._store.move_to_end(key)

            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)

            return False

    def _purge_expired(self, now: float) -> None:
        threshold = now - self.ttl_seconds
        while self._store:
            _, created = next(iter(self._store.items()))
            if created >= threshold:
                break
            self._store.popitem(last=False)


class SQLiteReplayCache:
    """SQLite-backed replay store for process restart durability."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_entries: int = 100_000,
        ttl_seconds: int = 600,
    ) -> None:
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), timeout=30.0, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS replay_nonces (
                agent_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                created REAL NOT NULL,
                PRIMARY KEY(agent_id, nonce)
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_replay_created ON replay_nonces(created)")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def seen_or_add(self, agent_id: str, nonce: str, now: float | None = None) -> bool:
        ts = now if now is not None else time.time()
        with self._lock:
            self._purge_expired(ts)
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO replay_nonces(agent_id, nonce, created) VALUES (?, ?, ?)",
                (agent_id, nonce, ts),
            )
            inserted = cursor.rowcount > 0
            self._evict_if_needed()
            return not inserted

    def _purge_expired(self, now: float) -> None:
        threshold = now - self.ttl_seconds
        self._conn.execute("DELETE FROM replay_nonces WHERE created < ?", (threshold,))

    def _evict_if_needed(self) -> None:
        row = self._conn.execute("SELECT COUNT(*) FROM replay_nonces").fetchone()
        count = int(row[0]) if row else 0
        overflow = count - self.max_entries
        if overflow <= 0:
            return
        self._conn.execute(
            """
            DELETE FROM replay_nonces
            WHERE rowid IN (
                SELECT rowid FROM replay_nonces ORDER BY created ASC LIMIT ?
            )
            """,
            (overflow,),
        )
