"""Small utility helpers."""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import uuid
from typing import Any


def now_iso_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_iso_utc(value: str) -> None:
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO timestamp: {value}") from exc


def new_message_id() -> str:
    # UUIDv7 is preferred by spec, but uuid module may not expose it depending on runtime.
    # Use uuid4 as a stable fallback.
    return str(uuid.uuid4())


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_prefixed(data: bytes) -> str:
    return f"sha256:{sha256_hex(data)}"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def deep_copy(value: Any) -> Any:
    return copy.deepcopy(value)


def json_dumps_pretty(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)
