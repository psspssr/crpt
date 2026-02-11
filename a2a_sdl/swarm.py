"""Codex buddy swarm orchestration over A2A HTTP transport."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

from .envelope import build_envelope
from .schema import get_builtin_descriptor
from .transport_http import A2AHTTPServer, send_http
from .utils import new_message_id


class SwarmError(ValueError):
    """Raised when swarm orchestration fails."""


class BuddyBackend(Protocol):
    def run(self, prompt: str) -> str:
        """Return one model response text."""


class CodexBackend:
    """Backend that executes `codex exec` for each buddy turn."""

    def __init__(self, *, workdir: str, timeout_s: int = 120, model: str | None = None) -> None:
        self.workdir = workdir
        self.timeout_s = timeout_s
        self.model = model

    def run(self, prompt: str) -> str:
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt") as tmp:
            out_path = tmp.name

        cmd = [
            "codex",
            "exec",
            "--skip-git-repo-check",
            "-C",
            self.workdir,
            "--color",
            "never",
            "-o",
            out_path,
            "-",
        ]
        if self.model:
            cmd.extend(["--model", self.model])

        try:
            proc = subprocess.run(
                cmd,
                input=prompt,
                text=True,
                capture_output=True,
                timeout=self.timeout_s,
                check=False,
            )
        except Exception as exc:
            return json.dumps(
                {
                    "status": "working",
                    "summary": f"backend execution exception: {exc}",
                    "handoff": "Continue iterating toward near_final status.",
                }
            )

        try:
            with open(out_path, "r", encoding="utf-8") as f:
                result = f.read().strip()
        except Exception:
            result = ""

        if proc.returncode != 0 and not result:
            err = proc.stderr.strip() or proc.stdout.strip() or "codex exec failure"
            return json.dumps(
                {
                    "status": "working",
                    "summary": f"backend returned error: {err[:500]}",
                    "handoff": "Continue iterating toward near_final status.",
                }
            )

        return result or proc.stdout.strip() or ""


@dataclass(slots=True)
class BuddyEndpoint:
    name: str
    url: str


class CodexBuddyServer:
    """A2A HTTP server wrapping one buddy backend."""

    def __init__(self, *, name: str, host: str, port: int, backend: BuddyBackend) -> None:
        self.name = name
        self.host = host
        self.port = port
        self.backend = backend
        self._history: list[dict[str, Any]] = []
        self._server = A2AHTTPServer(host, port, handler=self._handler)
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        port = self._server._server.server_address[1]
        return f"http://{self.host}:{port}/a2a"

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=1)

    def _handler(self, request: dict[str, Any]) -> dict[str, Any]:
        payload = request.get("payload") if isinstance(request.get("payload"), dict) else {}
        args = payload.get("args") if isinstance(payload.get("args"), dict) else {}

        message = str(args.get("message", "")).strip()
        goal = str(args.get("goal", "")).strip()
        round_index = int(args.get("round", 0)) if str(args.get("round", "")).isdigit() else 0

        prompt = _build_buddy_prompt(
            name=self.name,
            goal=goal,
            message=message,
            round_index=round_index,
            history=self._history[-6:],
        )
        raw = self.backend.run(prompt)
        parsed = _parse_buddy_output(raw)

        self._history.append(
            {
                "round": round_index,
                "incoming": message,
                "status": parsed["status"],
                "summary": parsed["summary"],
                "handoff": parsed["handoff"],
            }
        )

        result_payload = {
            "call_id": payload.get("call_id", "unknown"),
            "ok": True,
            "result": {
                "reply": parsed,
                "buddy": self.name,
                "turn": len(self._history),
            },
            "logs": [f"buddy={self.name}", f"turn={len(self._history)}"],
            "metrics": {"latency_ms": 0},
        }
        return build_envelope(
            msg_type="res",
            from_identity=request["to"],
            to_identity=request["from"],
            content_type="toolresult.v1",
            payload=result_payload,
            schema=get_builtin_descriptor("toolresult.v1"),
        )


class SwarmCoordinator:
    """Coordinates iterative buddy rounds over A2A envelopes."""

    def __init__(
        self,
        buddies: list[BuddyEndpoint],
        *,
        timeout_s: float = 60.0,
        retry_attempts: int = 1,
        retry_backoff_s: float = 0.1,
    ) -> None:
        if not buddies:
            raise SwarmError("at least one buddy endpoint is required")
        self.buddies = buddies
        self.timeout_s = timeout_s
        self.retry_attempts = retry_attempts
        self.retry_backoff_s = retry_backoff_s

    def run(
        self,
        *,
        goal: str,
        max_rounds: int = 8,
        near_final_rounds: int = 2,
    ) -> dict[str, Any]:
        message = goal
        rounds_run = 0
        near_final_streak = 0
        stable_working_streak = 0
        final_statuses: list[str] = []

        for round_index in range(1, max_rounds + 1):
            rounds_run = round_index
            statuses: list[str] = []

            for buddy in self.buddies:
                request_payload = {
                    "tool": "swarm.step",
                    "call_id": new_message_id(),
                    "args": {
                        "goal": goal,
                        "round": round_index,
                        "message": message,
                    },
                    "expect": {},
                }
                envelope = build_envelope(
                    msg_type="req",
                    from_identity={
                        "agent_id": "did:key:swarm-coordinator",
                        "name": "swarm-coordinator",
                        "instance": "main",
                        "role": "coordinator",
                    },
                    to_identity={
                        "agent_id": f"did:key:{buddy.name}",
                        "name": buddy.name,
                        "instance": "subagent",
                        "role": "buddy",
                    },
                    content_type="toolcall.v1",
                    payload=request_payload,
                    schema=get_builtin_descriptor("toolcall.v1"),
                )

                try:
                    response = send_http(
                        buddy.url,
                        envelope,
                        encoding="json",
                        timeout=self.timeout_s,
                        retry_attempts=self.retry_attempts,
                        retry_backoff_s=self.retry_backoff_s,
                    )
                    result = response.get("payload", {}).get("result", {})
                    reply = result.get("reply") if isinstance(result, dict) else None
                    normalized = _normalize_buddy_reply(reply)
                except Exception as exc:
                    normalized = {
                        "status": "working",
                        "summary": f"transport error: {type(exc).__name__}",
                        "handoff": "Continue and keep iterating feature completion.",
                    }
                statuses.append(normalized["status"])

                handoff = normalized.get("handoff")
                if isinstance(handoff, str) and handoff.strip():
                    message = handoff.strip()

            final_statuses = statuses
            near_final_votes = sum(1 for status in statuses if status == "near_final")
            majority_threshold = max(1, (len(statuses) // 2) + 1)
            if statuses and near_final_votes >= majority_threshold:
                near_final_streak += 1
            else:
                near_final_streak = 0

            if statuses and all(status == "working" for status in statuses):
                stable_working_streak += 1
            else:
                stable_working_streak = 0

            if near_final_streak >= max(1, near_final_rounds):
                break
            if stable_working_streak >= 3:
                break

        converged = near_final_streak >= max(1, near_final_rounds) or stable_working_streak >= 3
        mode = "near_final" if near_final_streak >= max(1, near_final_rounds) else "stabilized_working"
        return {
            "rounds_run": rounds_run,
            "converged": converged,
            "mode": mode if converged else "not_converged",
            "final_statuses": final_statuses,
            "goal": goal,
        }



def _build_buddy_prompt(
    *,
    name: str,
    goal: str,
    message: str,
    round_index: int,
    history: list[dict[str, Any]],
) -> str:
    history_json = json.dumps(history, ensure_ascii=False)
    return textwrap.dedent(
        f"""
        You are {name}, one of three collaborating protocol agents.
        Objective: refine the A2A protocol/framework toward near-final feature completeness.
        Reply with JSON only and no markdown using this schema exactly:
        {{"status":"working|near_final","summary":"short","handoff":"next instruction for the next buddy"}}

        Rules:
        - Keep responses concise.
        - Status should be "near_final" only when you think major feature work is complete.
        - If you see only minor polish or testing remains, set status to "near_final".
        - Provide a practical handoff for the next buddy.

        Context:
        goal={goal}
        round={round_index}
        incoming_message={message}
        recent_history={history_json}
        """
    ).strip()



def _parse_buddy_output(raw: str) -> dict[str, str]:
    text = raw.strip()
    if text.startswith("```"):
        lines = [line for line in text.splitlines() if not line.startswith("```")]
        text = "\n".join(lines).strip()

    try:
        decoded = json.loads(text)
    except Exception:
        extracted = _extract_json_object(text)
        if extracted is not None:
            try:
                decoded = json.loads(extracted)
                return _normalize_buddy_reply(decoded)
            except Exception:
                pass
        return {
            "status": _infer_status_from_text(text),
            "summary": _infer_summary_from_text(text),
            "handoff": _infer_handoff_from_text(text),
        }

    return _normalize_buddy_reply(decoded)



def _normalize_buddy_reply(reply: Any) -> dict[str, str]:
    if not isinstance(reply, dict):
        return {
            "status": "working",
            "summary": "invalid buddy payload",
            "handoff": "Continue and keep iterating feature completion.",
        }

    status_raw = reply.get("status")
    status = status_raw if isinstance(status_raw, str) and status_raw in {"working", "near_final"} else "working"

    summary_raw = reply.get("summary")
    summary = summary_raw if isinstance(summary_raw, str) and summary_raw.strip() else "no summary"

    handoff_raw = reply.get("handoff")
    handoff = handoff_raw if isinstance(handoff_raw, str) and handoff_raw.strip() else "Continue to reduce major feature gaps."

    return {
        "status": status,
        "summary": summary.strip(),
        "handoff": handoff.strip(),
    }


def _extract_json_object(text: str) -> str | None:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start : end + 1]


def _infer_status_from_text(text: str) -> str:
    lowered = text.lower()
    if "status=near_final" in lowered or "status: near_final" in lowered:
        return "near_final"
    if "near_final" in lowered:
        return "near_final"
    if "near final" in lowered and "not near final" not in lowered:
        return "near_final"
    near_final_signals = [
        "feature complete",
        "major features complete",
        "almost final",
        "protocol complete",
        "main features done",
        "core features done",
    ]
    if any(signal in lowered for signal in near_final_signals):
        return "near_final"
    return "working"


def _infer_summary_from_text(text: str) -> str:
    compact = " ".join(text.split())
    if not compact:
        return "non-json buddy output"
    return compact[:200]


def _infer_handoff_from_text(text: str) -> str:
    patterns = [
        r"handoff\s*[:=]\s*(.+)",
        r"next\s*[:=]\s*(.+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            if value:
                return value[:200]
    return "Continue and return strict JSON format."
