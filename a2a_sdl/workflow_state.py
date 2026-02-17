"""Durable workflow run state storage."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class WorkflowRunSnapshot:
    """Snapshot of one persisted workflow run."""

    run_id: str
    name: str
    plan: dict[str, Any]
    status: str
    started_at: str
    finished_at: str | None
    duration_ms: int | None
    summary: dict[str, Any]
    execution_order: list[str]
    steps: dict[str, dict[str, Any]]


class WorkflowStateStoreProtocol(Protocol):
    """Persistent run-state contract used by orchestrator resume flow."""

    def create_run(self, *, run_id: str, name: str, plan: dict[str, Any], started_at: str) -> None:
        """Create a run record."""

    def load_run(self, *, run_id: str) -> WorkflowRunSnapshot | None:
        """Load one run snapshot."""

    def save_step(self, *, run_id: str, step_id: str, result: dict[str, Any], execution_order: list[str]) -> None:
        """Persist one step result and latest execution order."""

    def finalize_run(
        self,
        *,
        run_id: str,
        status: str,
        finished_at: str,
        duration_ms: int,
        summary: dict[str, Any],
        execution_order: list[str],
    ) -> None:
        """Mark run finalized."""


class SQLiteWorkflowStateStore:
    """SQLite-backed persistent store for workflow run progress and recovery."""

    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        created = not self.path.exists()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        if created:
            try:
                self.path.chmod(0o600)
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def create_run(self, *, run_id: str, name: str, plan: dict[str, Any], started_at: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO workflow_runs (
                    run_id, name, plan_json, status, started_at, updated_at
                ) VALUES (?, ?, ?, 'running', ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                """,
                (run_id, name, _dump_json(plan), started_at),
            )
            self._conn.commit()

    def load_run(self, *, run_id: str) -> WorkflowRunSnapshot | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT run_id, name, plan_json, status, started_at, finished_at, duration_ms, summary_json, execution_order_json
                FROM workflow_runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if row is None:
                return None

            step_rows = self._conn.execute(
                """
                SELECT step_id, result_json
                FROM workflow_steps
                WHERE run_id = ?
                ORDER BY step_id ASC
                """,
                (run_id,),
            ).fetchall()

        steps: dict[str, dict[str, Any]] = {}
        for step_row in step_rows:
            step_id_raw = step_row["step_id"]
            result_raw = step_row["result_json"]
            if isinstance(step_id_raw, str):
                decoded = _load_json_obj(result_raw)
                if decoded is not None:
                    steps[step_id_raw] = decoded

        plan = _load_json_obj(row["plan_json"]) or {}
        summary = _load_json_obj(row["summary_json"]) or {}
        execution_order = _load_json_str_list(row["execution_order_json"]) or []
        duration_ms_value = row["duration_ms"]
        duration_ms = int(duration_ms_value) if isinstance(duration_ms_value, int) else None
        finished_at_value = row["finished_at"]
        finished_at = finished_at_value if isinstance(finished_at_value, str) and finished_at_value else None
        status_value = row["status"]
        started_at_value = row["started_at"]
        return WorkflowRunSnapshot(
            run_id=str(row["run_id"]),
            name=str(row["name"]),
            plan=plan,
            status=str(status_value) if isinstance(status_value, str) else "running",
            started_at=str(started_at_value) if isinstance(started_at_value, str) else "",
            finished_at=finished_at,
            duration_ms=duration_ms,
            summary=summary,
            execution_order=execution_order,
            steps=steps,
        )

    def save_step(self, *, run_id: str, step_id: str, result: dict[str, Any], execution_order: list[str]) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO workflow_steps (run_id, step_id, result_json, updated_at)
                VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                ON CONFLICT(run_id, step_id) DO UPDATE SET
                    result_json = excluded.result_json,
                    updated_at = excluded.updated_at
                """,
                (run_id, step_id, _dump_json(result)),
            )
            self._conn.execute(
                """
                UPDATE workflow_runs
                SET
                    execution_order_json = ?,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                WHERE run_id = ?
                """,
                (_dump_json(execution_order), run_id),
            )
            self._conn.commit()

    def finalize_run(
        self,
        *,
        run_id: str,
        status: str,
        finished_at: str,
        duration_ms: int,
        summary: dict[str, Any],
        execution_order: list[str],
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE workflow_runs
                SET
                    status = ?,
                    finished_at = ?,
                    duration_ms = ?,
                    summary_json = ?,
                    execution_order_json = ?,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                WHERE run_id = ?
                """,
                (
                    status,
                    finished_at,
                    int(duration_ms),
                    _dump_json(summary),
                    _dump_json(execution_order),
                    run_id,
                ),
            )
            self._conn.commit()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workflow_runs (
                    run_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    duration_ms INTEGER,
                    summary_json TEXT,
                    execution_order_json TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS workflow_steps (
                    run_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, step_id),
                    FOREIGN KEY (run_id) REFERENCES workflow_runs(run_id) ON DELETE CASCADE
                );
                """
            )
            self._conn.commit()


def _dump_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load_json_obj(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _load_json_str_list(raw: Any) -> list[str] | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(decoded, list):
        return None
    out: list[str] = []
    for item in decoded:
        if isinstance(item, str) and item:
            out.append(item)
    return out
