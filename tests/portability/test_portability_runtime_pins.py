from __future__ import annotations

import re
import unittest
from pathlib import Path

from scripts.portability_runtime_pins import PYTHON_BASE_IMAGES

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class PortabilityRuntimePinTests(unittest.TestCase):
    def test_all_linux_base_images_use_unique_immutable_digests(self) -> None:
        self.assertEqual(set(PYTHON_BASE_IMAGES), {"3.11", "3.12", "3.13", "3.14"})
        self.assertEqual(len(set(PYTHON_BASE_IMAGES.values())), 4)
        for reference in PYTHON_BASE_IMAGES.values():
            self.assertRegex(reference, r"^python@sha256:[0-9a-f]{64}$")

    def test_every_workflow_action_uses_a_full_commit_sha(self) -> None:
        workflow = REPOSITORY_ROOT.joinpath(".github", "workflows", "installed-portability.yml").read_text(
            encoding="utf-8"
        )
        uses = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)
        self.assertEqual(len(uses), 7)
        for reference in uses:
            self.assertRegex(reference, r"^actions/[a-z-]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
