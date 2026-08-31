"""Static least-privilege checks for candidate GitHub Actions workflows."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
ACTION_REFERENCE = re.compile(r"^\s*-?\s*uses:\s*[^\s@]+@([^\s#]+)", re.MULTILINE)
FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


class GitHubWorkflowSecurityTests(unittest.TestCase):
    def workflow_sources(self) -> dict[str, str]:
        sources = {
            path.name: path.read_text(encoding="utf-8-sig")
            for path in sorted(WORKFLOW_ROOT.glob("*.yml"))
        }
        self.assertGreaterEqual(len(sources), 5)
        return sources

    def test_all_action_references_are_immutable_full_commit_shas(self) -> None:
        for name, source in self.workflow_sources().items():
            references = ACTION_REFERENCE.findall(source)
            self.assertTrue(references, name)
            for reference in references:
                with self.subTest(workflow=name, reference=reference):
                    self.assertRegex(reference, rf"^{FULL_COMMIT_SHA.pattern}$")

    def test_checkout_never_persists_credentials(self) -> None:
        for name, source in self.workflow_sources().items():
            lines = source.splitlines()
            checkout_lines = [
                index for index, line in enumerate(lines) if "uses: actions/checkout@" in line
            ]
            self.assertTrue(checkout_lines, name)
            for index in checkout_lines:
                step = "\n".join(lines[index : index + 5])
                with self.subTest(workflow=name, line=index + 1):
                    self.assertIn("persist-credentials: false", step)

    def test_workflows_have_explicit_permissions_and_job_timeouts(self) -> None:
        for name, source in self.workflow_sources().items():
            with self.subTest(workflow=name):
                self.assertIn("\npermissions:\n", source)
                self.assertEqual(source.count("runs-on:"), source.count("timeout-minutes:"))
                self.assertNotIn("permissions: write-all", source)
                self.assertNotIn("contents: write", source)
                self.assertNotIn("pull_request_target:", source)

    def test_publication_credentials_and_commands_are_absent(self) -> None:
        forbidden = (
            "secrets.PYPI",
            "secrets.GITHUB_TOKEN",
            "pypa/gh-action-pypi-publish",
            "gh release create",
            "FINPLANBR_RUN_WINDOWS_APPCONTAINER_DIAGNOSTIC",
        )
        for name, source in self.workflow_sources().items():
            for marker in forbidden:
                with self.subTest(workflow=name, marker=marker):
                    self.assertNotIn(marker, source)

    def test_portability_suites_are_bound_to_their_supported_operating_systems(self) -> None:
        source = self.workflow_sources()["technical-quality.yml"]
        self.assertNotIn(
            'discover -s tests/portability -p "test_*.py"',
            source,
        )
        for module in (
            "tests.portability.test_aggregate_portability_matrix",
            "tests.portability.test_bounded_runner_adoption",
            "tests.portability.test_installed_portability_probe",
            "tests.portability.test_portability_runtime_pins",
            "tests.portability.test_windows_portability_fail_closed",
        ):
            with self.subTest(module=module):
                self.assertIn(module, source)
        self.assertIn("Validate the supported Windows backend artifact profile", source)
        self.assertIn("tests.portability.test_portability_artifact_inventory", source)
        self.assertNotIn('discover -s tests/portability -p "test_windows_*.py"', source)
        for marker in (
            "Run host-independent Windows diagnostics without live opt-in",
            "WindowsAppContainerSpikeProtocolTests",
            "WindowsAppContainerSpikeExecutionTests",
            "test_watchdog_capture_enforces_output_budgets_during_execution",
            "WindowsAppContainerRealDiagnosticTests",
            "Classify and run protected-host PowerShell diagnostics",
            "WindowsAppContainerPowerShellResolutionTests",
            "unsupported:host_chain_mutable_by_current_token",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

    def test_gitleaks_exception_is_exactly_scoped_to_the_synthetic_fixture(self) -> None:
        ignore_path = REPOSITORY_ROOT / ".gitleaksignore"
        active_lines = [
            line.strip()
            for line in ignore_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(
            [
                "schemas/examples/invalid/input-adversarial-sensitive-and-decimal.json:"
                "stripe-access-token:40"
            ],
            active_lines,
        )

        fixture_path = (
            REPOSITORY_ROOT
            / "schemas/examples/invalid/input-adversarial-sensitive-and-decimal.json"
        )
        fixture_lines = fixture_path.read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(fixture_lines), 40)
        self.assertIn('"observable_ids"', fixture_lines[39])


if __name__ == "__main__":
    unittest.main()
