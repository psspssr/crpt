from __future__ import annotations

import copy
import random
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from a2a_sdl.envelope import EnvelopeValidationError, validate_envelope
from a2a_sdl.handlers import default_handler
from a2a_sdl.transport_http import A2AHTTPServer, send_http

from tests.test_helpers import make_task_envelope


class StressAndFuzzTests(unittest.TestCase):
    def test_envelope_mutation_fuzz_does_not_crash_validator(self) -> None:
        random.seed(1337)
        base = make_task_envelope()

        def mutate(env: dict[str, Any]) -> dict[str, Any]:
            mutated = copy.deepcopy(env)
            op = random.choice(
                [
                    "drop_field",
                    "bad_type",
                    "bad_ct",
                    "bad_timestamp",
                    "bad_trace",
                    "big_array",
                    "tamper_schema",
                ]
            )
            if op == "drop_field":
                mutated.pop(random.choice(["id", "ct", "schema", "payload", "from", "to"]), None)
            elif op == "bad_type":
                mutated["type"] = random.choice([123, None, "invalid"])
            elif op == "bad_ct":
                mutated["ct"] = f"unknown.v{random.randint(1, 9)}"
            elif op == "bad_timestamp":
                mutated["ts"] = "not-a-timestamp"
            elif op == "bad_trace":
                mutated["trace"] = {"root_id": "", "span_id": 123, "hops": -1}
            elif op == "big_array":
                payload = mutated.setdefault("payload", {})
                if isinstance(payload, dict):
                    payload["deliverables"] = [{}] * 20_000
            elif op == "tamper_schema":
                schema = mutated.get("schema")
                if isinstance(schema, dict):
                    schema["id"] = "sha256:deadbeef"
            return mutated

        for _ in range(250):
            env = mutate(base)
            try:
                validate_envelope(env)
            except (EnvelopeValidationError, ValueError, TypeError):
                pass

    def test_http_concurrent_load_roundtrip(self) -> None:
        server = A2AHTTPServer("127.0.0.1", 0, handler=default_handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)

        try:
            port = server._server.server_address[1]
            url = f"http://127.0.0.1:{port}/a2a"

            def send_one(i: int) -> str:
                req = make_task_envelope()
                req["id"] = f"load-{i}"
                response = send_http(url, req, encoding="json", timeout=10.0, retry_attempts=1, retry_backoff_s=0.01)
                return response["ct"]

            cts: list[str] = []
            with ThreadPoolExecutor(max_workers=24) as executor:
                futures = [executor.submit(send_one, i) for i in range(120)]
                for fut in as_completed(futures, timeout=30):
                    cts.append(fut.result())

            self.assertEqual(len(cts), 120)
            self.assertTrue(all(ct == "state.v1" for ct in cts))
        finally:
            server.shutdown()
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
