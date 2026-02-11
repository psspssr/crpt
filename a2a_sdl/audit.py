"""Tamper-evident audit chain with optional signing."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .utils import b64url_encode, canonical_json_bytes, now_iso_utc, sha256_prefixed


class AuditError(ValueError):
    """Raised when audit chain is invalid."""


class AuditChain:
    """Append-only hash-chained audit log."""

    def __init__(self, path: str | Path, signing_private_key: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._signing_key = _load_signing_private_key(signing_private_key)
        self._last_hash = self._read_last_hash()

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry_base = {
                "ts": now_iso_utc(),
                "event": event,
                "prev_hash": self._last_hash,
            }
            entry_hash = sha256_prefixed(canonical_json_bytes(entry_base))
            entry = dict(entry_base)
            entry["entry_hash"] = entry_hash

            if self._signing_key is not None:
                signature = self._signing_key.sign(canonical_json_bytes(entry))
                entry["sig"] = {"alg": "ed25519", "value": b64url_encode(signature)}

            line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

            self._last_hash = entry_hash
            receipt: dict[str, Any] = {
                "entry_hash": entry_hash,
                "prev_hash": entry_base["prev_hash"],
            }
            if "sig" in entry:
                receipt["sig"] = entry["sig"]
            return receipt

    def _read_last_hash(self) -> str | None:
        if not self.path.exists():
            return None

        last_line = ""
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line

        if not last_line:
            return None

        try:
            decoded = json.loads(last_line)
        except json.JSONDecodeError as exc:  # pragma: no cover
            raise AuditError("invalid audit log JSON line") from exc

        entry_hash = decoded.get("entry_hash")
        if not isinstance(entry_hash, str) or not entry_hash.startswith("sha256:"):
            raise AuditError("invalid audit log entry_hash")
        return entry_hash



def verify_audit_chain(path: str | Path) -> None:
    file_path = Path(path)
    if not file_path.exists():
        return

    prev_hash: str | None = None
    with file_path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue

            try:
                entry = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AuditError(f"line {line_no}: invalid JSON") from exc

            entry_hash = entry.get("entry_hash")
            if not isinstance(entry_hash, str) or not entry_hash.startswith("sha256:"):
                raise AuditError(f"line {line_no}: missing entry_hash")

            if entry.get("prev_hash") != prev_hash:
                raise AuditError(f"line {line_no}: prev_hash mismatch")

            base = {
                "ts": entry.get("ts"),
                "event": entry.get("event"),
                "prev_hash": entry.get("prev_hash"),
            }
            expected_hash = sha256_prefixed(canonical_json_bytes(base))
            if expected_hash != entry_hash:
                raise AuditError(f"line {line_no}: entry hash mismatch")

            prev_hash = entry_hash



def _load_signing_private_key(value: str | None) -> Ed25519PrivateKey | None:
    if value is None:
        return None

    text = value.strip()
    if not text:
        return None

    if text.startswith("-----BEGIN"):
        loaded = serialization.load_pem_private_key(text.encode("ascii"), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise AuditError("audit signing key is not Ed25519")
        return loaded

    raise AuditError("audit signing key must be PEM")
