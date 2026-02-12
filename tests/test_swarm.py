from __future__ import annotations

import unittest
from unittest import mock

from a2a_sdl.swarm import (
    BuddyEndpoint,
    CodexBuddyServer,
    SwarmCoordinator,
    _normalize_buddy_reply,
    _parse_buddy_output,
)


class _FakeBackend:
    def __init__(self, statuses: list[str]) -> None:
        self._statuses = statuses
        self._idx = 0

    def run(self, prompt: str) -> str:
        status = self._statuses[min(self._idx, len(self._statuses) - 1)]
        self._idx += 1
        return (
            '{"status":"'
            + status
            + '","summary":"ok","handoff":"continue toward closure"}'
        )


class SwarmTests(unittest.TestCase):
    def test_normalize_buddy_reply_defaults(self) -> None:
        reply = _normalize_buddy_reply({"status": "bad", "summary": "", "handoff": ""})
        self.assertEqual(reply["status"], "working")
        self.assertTrue(bool(reply["summary"]))
        self.assertTrue(bool(reply["handoff"]))

    def test_swarm_converges_with_three_buddies(self) -> None:
        b1 = CodexBuddyServer(name="b1", host="127.0.0.1", port=0, backend=_FakeBackend(["working", "near_final", "near_final"]))
        b2 = CodexBuddyServer(name="b2", host="127.0.0.1", port=0, backend=_FakeBackend(["working", "near_final", "near_final"]))
        b3 = CodexBuddyServer(name="b3", host="127.0.0.1", port=0, backend=_FakeBackend(["working", "near_final", "near_final"]))

        buddies = [b1, b2, b3]
        for buddy in buddies:
            buddy.start()

        try:
            endpoints = [BuddyEndpoint(name=buddy.name, url=buddy.url) for buddy in buddies]
            coordinator = SwarmCoordinator(endpoints, timeout_s=10.0, retry_attempts=0)
            report = coordinator.run(
                goal="Reach near_final",
                max_rounds=5,
                near_final_rounds=2,
            )
            self.assertTrue(report["converged"])
            self.assertLessEqual(report["rounds_run"], 5)
            self.assertEqual(report["final_statuses"], ["near_final", "near_final", "near_final"])
        finally:
            for buddy in buddies:
                buddy.stop()

    def test_parse_buddy_output_infers_near_final_from_plain_text(self) -> None:
        parsed = _parse_buddy_output(
            "status: near_final\nsummary: major features complete\nhandoff: run verification pass"
        )
        self.assertEqual(parsed["status"], "near_final")
        self.assertIn("major features complete", parsed["summary"])
        self.assertIn("run verification pass", parsed["handoff"])

    def test_swarm_converges_by_majority_vote(self) -> None:
        b1 = CodexBuddyServer(name="b1", host="127.0.0.1", port=0, backend=_FakeBackend(["near_final"]))
        b2 = CodexBuddyServer(name="b2", host="127.0.0.1", port=0, backend=_FakeBackend(["near_final"]))
        b3 = CodexBuddyServer(name="b3", host="127.0.0.1", port=0, backend=_FakeBackend(["working"]))

        buddies = [b1, b2, b3]
        for buddy in buddies:
            buddy.start()

        try:
            endpoints = [BuddyEndpoint(name=buddy.name, url=buddy.url) for buddy in buddies]
            coordinator = SwarmCoordinator(endpoints, timeout_s=10.0, retry_attempts=0)
            report = coordinator.run(
                goal="Reach near_final",
                max_rounds=2,
                near_final_rounds=1,
            )
            self.assertTrue(report["converged"])
            self.assertEqual(report["final_statuses"].count("near_final"), 2)
        finally:
            for buddy in buddies:
                buddy.stop()

    def test_swarm_converges_with_two_buddies(self) -> None:
        b1 = CodexBuddyServer(name="b1", host="127.0.0.1", port=0, backend=_FakeBackend(["near_final"]))
        b2 = CodexBuddyServer(name="b2", host="127.0.0.1", port=0, backend=_FakeBackend(["near_final"]))

        buddies = [b1, b2]
        for buddy in buddies:
            buddy.start()

        try:
            endpoints = [BuddyEndpoint(name=buddy.name, url=buddy.url) for buddy in buddies]
            coordinator = SwarmCoordinator(endpoints, timeout_s=10.0, retry_attempts=0)
            report = coordinator.run(
                goal="Reach near_final",
                max_rounds=2,
                near_final_rounds=1,
            )
            self.assertTrue(report["converged"])
            self.assertEqual(report["final_statuses"], ["near_final", "near_final"])
        finally:
            for buddy in buddies:
                buddy.stop()

    @mock.patch("a2a_sdl.swarm.send_http", side_effect=TimeoutError("timeout"))
    def test_swarm_handles_transport_errors(self, _mock_send_http: mock.Mock) -> None:
        coordinator = SwarmCoordinator(
            [BuddyEndpoint(name="b1", url="http://127.0.0.1:1/a2a")],
            timeout_s=0.01,
            retry_attempts=0,
        )
        report = coordinator.run(goal="Reach near_final", max_rounds=1, near_final_rounds=1)
        self.assertFalse(report["converged"])
        self.assertEqual(report["final_statuses"], ["working"])

    def test_swarm_converges_when_working_state_stabilizes(self) -> None:
        b1 = CodexBuddyServer(name="b1", host="127.0.0.1", port=0, backend=_FakeBackend(["working"]))
        b2 = CodexBuddyServer(name="b2", host="127.0.0.1", port=0, backend=_FakeBackend(["working"]))
        b3 = CodexBuddyServer(name="b3", host="127.0.0.1", port=0, backend=_FakeBackend(["working"]))

        buddies = [b1, b2, b3]
        for buddy in buddies:
            buddy.start()

        try:
            endpoints = [BuddyEndpoint(name=buddy.name, url=buddy.url) for buddy in buddies]
            coordinator = SwarmCoordinator(endpoints, timeout_s=10.0, retry_attempts=0)
            report = coordinator.run(
                goal="Reach near_final",
                max_rounds=5,
                near_final_rounds=2,
            )
            self.assertTrue(report["converged"])
            self.assertEqual(report["mode"], "stabilized_working")
            self.assertEqual(report["rounds_run"], 3)
            self.assertEqual(report["final_statuses"], ["working", "working", "working"])
        finally:
            for buddy in buddies:
                buddy.stop()


if __name__ == "__main__":
    unittest.main()
