from __future__ import annotations

import unittest

from a2a_sdl.conformance import run_conformance_suite


class ConformanceTests(unittest.TestCase):
    def test_conformance_core_profile_passes(self) -> None:
        report = run_conformance_suite(
            transports={"core"},
            modes={"dev"},
            include_load=False,
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["failed"], 0)
        self.assertEqual(report["summary"]["transports"], ["core"])

    def test_conformance_http_dev_profile_passes(self) -> None:
        report = run_conformance_suite(
            transports={"http"},
            modes={"dev"},
            include_load=False,
            timeout_s=10.0,
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["failed"], 0)
        self.assertEqual(report["summary"]["transports"], ["http"])

    def test_conformance_ws_secure_profile_passes(self) -> None:
        report = run_conformance_suite(
            transports={"ws"},
            modes={"secure"},
            include_load=False,
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["failed"], 0)
        self.assertEqual(report["summary"]["modes"], ["secure"])

    def test_conformance_rejects_unknown_transport(self) -> None:
        with self.assertRaises(ValueError):
            run_conformance_suite(transports={"unknown"}, modes={"dev"}, include_load=False)


if __name__ == "__main__":
    unittest.main()

