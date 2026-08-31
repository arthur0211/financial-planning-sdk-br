"""Regression tests for the decommissioned candidate-side authority stub."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_release_trust.py"
EXPECTED = (
    '{"authority_decision_attempted":false,'
    '"authority_integration":"absent",'
    '"external_material_read":false,'
    '"format":"financial-planning-sdk-br.external-authority-diagnostic.v1",'
    '"release_authorized":false,'
    '"status":"external_authority_not_implemented"}\n'
)


class DecommissionedReleaseAuthorityTests(unittest.TestCase):
    maxDiff = None

    def run_stub(
        self,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(SCRIPT), *arguments],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            env=environment,
        )

    def assert_closed(self, completed: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
        self.assertEqual(completed.stdout, EXPECTED)
        self.assertEqual(completed.stderr, "")
        self.assertNotIn('"passed"', completed.stdout)
        self.assertNotIn('"authenticated"', completed.stdout)

    def test_stub_has_one_closed_non_authorizing_result(self) -> None:
        self.assert_closed(self.run_stub())

    def test_arbitrary_arguments_cannot_change_result_or_create_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-decommissioned-authority-") as directory:
            base = Path(directory)
            private_key = base / "private.key"
            policy = base / "policy.json"
            result = base / "result.json"
            private_key.write_text("must-not-be-read", encoding="utf-8")
            policy.write_text("must-not-be-read", encoding="utf-8")
            completed = self.run_stub(
                "--result-signing-private-key",
                str(private_key),
                "--trust-policy",
                str(policy),
                "--result-output",
                str(result),
                "--python-runtime",
                str(base / "attacker-runtime.exe"),
                "--git-executable",
                str(base / "attacker-git.exe"),
                "--status",
                "passed",
            )
            self.assert_closed(completed)
            self.assertEqual(private_key.read_text(encoding="utf-8"), "must-not-be-read")
            self.assertEqual(policy.read_text(encoding="utf-8"), "must-not-be-read")
            self.assertFalse(result.exists())

    def test_environment_startup_markers_are_not_loaded_under_isolated_invocation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-stub-startup-") as directory:
            base = Path(directory)
            marker = base / "STARTUP_MARKER"
            attacker = base / "attacker"
            attacker.mkdir()
            payload = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
            )
            (attacker / "sitecustomize.py").write_text(payload, encoding="utf-8")
            (attacker / "usercustomize.py").write_text(payload, encoding="utf-8")
            environment = dict(os.environ)
            environment.update(PYTHONPATH=str(attacker), PYTHONUSERBASE=str(attacker))
            self.assert_closed(self.run_stub(environment=environment))
            self.assertFalse(marker.exists())

    def test_source_has_no_input_or_authority_implementation_surface(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        self.assertEqual(imports, [])
        forbidden = (
            "argparse",
            "base64",
            "cryptography",
            "ed25519",
            "hashlib",
            "open(",
            "pathlib",
            "private_key",
            "signature",
            "subprocess",
            "sys.argv",
            "verify",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token.casefold(), source.casefold())

    def test_repeated_invocations_are_byte_identical_and_always_nonzero(self) -> None:
        first = self.run_stub("--help")
        second = self.run_stub("--format", "json", "--unknown", "value")
        self.assert_closed(first)
        self.assert_closed(second)
        self.assertEqual(first.stdout.encode("ascii"), second.stdout.encode("ascii"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
