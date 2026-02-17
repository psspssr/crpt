from __future__ import annotations

import json
import tempfile
import unittest

from a2a_sdl.observability import JSONLMetricsExporter


class ObservabilityTests(unittest.TestCase):
    def test_jsonl_metrics_exporter_writes_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/metrics.jsonl"
            exporter = JSONLMetricsExporter(path)
            exporter.export({"requests_total": 1})
            exporter.export({"requests_total": 2, "inflight": 0})
            exporter.close()

            with open(path, "r", encoding="utf-8") as handle:
                lines = [line for line in handle.read().splitlines() if line.strip()]
            self.assertEqual(len(lines), 2)
            first = json.loads(lines[0])
            second = json.loads(lines[1])
            self.assertIn("ts", first)
            self.assertEqual(first["metrics"]["requests_total"], 1)
            self.assertEqual(second["metrics"]["requests_total"], 2)


if __name__ == "__main__":
    unittest.main()
