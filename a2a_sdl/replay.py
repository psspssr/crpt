"""Replay protection cache."""

from __future__ import annotations

import time
from collections import OrderedDict


class ReplayCache:
    """LRU cache keyed by (agent_id, nonce) with TTL expiration."""

    def __init__(self, max_entries: int = 10_000, ttl_seconds: int = 600) -> None:
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._store: OrderedDict[tuple[str, str], float] = OrderedDict()

    def seen_or_add(self, agent_id: str, nonce: str, now: float | None = None) -> bool:
        ts = now if now is not None else time.time()
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
