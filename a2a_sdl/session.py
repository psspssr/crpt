"""Session binding helpers and in-memory runtime store."""

from __future__ import annotations

import datetime as dt
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Protocol

from .utils import canonical_json_bytes, sha256_prefixed


@dataclass(frozen=True, slots=True)
class SessionBindingRecord:
    """Stored session binding metadata."""

    binding_id: str
    from_agent: str
    to_agent: str
    expires: str
    profile_hash: str


class SessionBindingStoreProtocol(Protocol):
    """Minimal protocol for active session-binding stores."""

    def register(
        self,
        *,
        binding_id: str,
        from_agent: str,
        to_agent: str,
        expires: str,
        profile: dict[str, Any],
    ) -> SessionBindingRecord:
        """Register or refresh an active binding."""

    def is_active(
        self,
        *,
        binding_id: str,
        from_agent: str,
        to_agent: str,
        now: dt.datetime | None = None,
    ) -> bool:
        """Return True when a binding is currently active for agent pair."""


def build_session_binding_doc(
    *,
    from_agent: str,
    to_agent: str,
    profile: dict[str, Any],
    nonce: str,
    expires: str,
) -> dict[str, Any]:
    """Build and validate the canonical session-binding document."""
    if not isinstance(from_agent, str) or not from_agent:
        raise ValueError("session from_agent must be a non-empty string")
    if not isinstance(to_agent, str) or not to_agent:
        raise ValueError("session to_agent must be a non-empty string")
    if not isinstance(profile, dict):
        raise ValueError("session profile must be an object")
    if not isinstance(nonce, str) or len(nonce) < 8:
        raise ValueError("session nonce must be a string with length >= 8")
    if not isinstance(expires, str):
        raise ValueError("session expires must be a string")
    _parse_iso_utc(expires)

    return {
        "from_agent": from_agent,
        "to_agent": to_agent,
        "profile": profile,
        "nonce": nonce,
        "expires": expires,
    }


def compute_session_binding_id(
    *,
    from_agent: str,
    to_agent: str,
    profile: dict[str, Any],
    nonce: str,
    expires: str,
) -> str:
    """Compute deterministic binding id from canonical session doc."""
    doc = build_session_binding_doc(
        from_agent=from_agent,
        to_agent=to_agent,
        profile=profile,
        nonce=nonce,
        expires=expires,
    )
    return sha256_prefixed(canonical_json_bytes(doc))


class SessionBindingStore:
    """Thread-safe in-memory binding registry with expiry + LRU eviction."""

    def __init__(self, *, max_entries: int = 10_000) -> None:
        self.max_entries = max(1, int(max_entries))
        self._lock = threading.Lock()
        self._records: dict[str, SessionBindingRecord] = {}
        self._order: OrderedDict[str, None] = OrderedDict()

    def register(
        self,
        *,
        binding_id: str,
        from_agent: str,
        to_agent: str,
        expires: str,
        profile: dict[str, Any],
    ) -> SessionBindingRecord:
        if not isinstance(binding_id, str) or not binding_id:
            raise ValueError("binding_id must be a non-empty string")
        if not isinstance(profile, dict):
            raise ValueError("profile must be an object")

        exp_ts = _parse_iso_utc(expires)
        now = dt.datetime.now(dt.timezone.utc)
        if exp_ts <= now:
            raise ValueError("session binding expiry must be in the future")

        record = SessionBindingRecord(
            binding_id=binding_id,
            from_agent=from_agent,
            to_agent=to_agent,
            expires=expires,
            profile_hash=sha256_prefixed(canonical_json_bytes(profile)),
        )

        with self._lock:
            self._purge_expired(now)
            existing = self._records.get(binding_id)
            if existing is not None and (
                existing.from_agent != from_agent or existing.to_agent != to_agent
            ):
                raise ValueError("binding_id collision for different agents")
            self._records[binding_id] = record
            self._order.pop(binding_id, None)
            self._order[binding_id] = None

            while len(self._order) > self.max_entries:
                oldest, _ = self._order.popitem(last=False)
                self._records.pop(oldest, None)

        return record

    def is_active(
        self,
        *,
        binding_id: str,
        from_agent: str,
        to_agent: str,
        now: dt.datetime | None = None,
    ) -> bool:
        if not isinstance(binding_id, str) or not binding_id:
            return False
        check_time = now.astimezone(dt.timezone.utc) if now is not None else dt.datetime.now(dt.timezone.utc)
        with self._lock:
            self._purge_expired(check_time)
            record = self._records.get(binding_id)
            if record is None:
                return False
            if record.from_agent != from_agent or record.to_agent != to_agent:
                return False
            self._order.pop(binding_id, None)
            self._order[binding_id] = None
            return True

    def _purge_expired(self, now: dt.datetime) -> None:
        expired: list[str] = []
        for binding_id, record in self._records.items():
            if _parse_iso_utc(record.expires) <= now:
                expired.append(binding_id)
        for binding_id in expired:
            self._records.pop(binding_id, None)
            self._order.pop(binding_id, None)


def _parse_iso_utc(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)
