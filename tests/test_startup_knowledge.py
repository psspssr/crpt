from __future__ import annotations

import unittest

from a2a_sdl.startup_knowledge import get_startup_knowledge, render_startup_knowledge_json, render_startup_knowledge_text


class StartupKnowledgeTests(unittest.TestCase):
    def test_get_startup_knowledge_has_expected_sections(self) -> None:
        data = get_startup_knowledge()
        self.assertIn("project", data)
        self.assertIn("install", data)
        self.assertIn("commands", data)
        self.assertIn("security_baseline", data)
        self.assertEqual(data["project"]["package"], "a2acrpt")

    def test_get_startup_knowledge_returns_copy(self) -> None:
        original = get_startup_knowledge()
        original["project"]["name"] = "mutated"
        fresh = get_startup_knowledge()
        self.assertEqual(fresh["project"]["name"], "A2A-SDL")

    def test_render_helpers_output_expected_content(self) -> None:
        text = render_startup_knowledge_text()
        payload = render_startup_knowledge_json()
        self.assertIn("a2a knowledge", text)
        self.assertIn('"default_profile": "full"', payload)


if __name__ == "__main__":
    unittest.main()
