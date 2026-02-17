"""Observability helpers for metric export sinks."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Protocol

from .utils import now_iso_utc


class MetricsExporterProtocol(Protocol):
    """Contract for exporting server metric snapshots."""

    def export(self, snapshot: dict[str, Any]) -> None:
        """Export one metrics snapshot."""

    def close(self) -> None:
        """Release exporter resources."""


class JSONLMetricsExporter:
    """Append metric snapshots as JSON lines for external collectors."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._file = self.path.open("a", encoding="utf-8")
        self._closed = False

    def export(self, snapshot: dict[str, Any]) -> None:
        record = {
            "ts": now_iso_utc(),
            "metrics": snapshot,
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            if self._closed:
                return
            self._file.write(line)
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._file.close()
            self._closed = True

