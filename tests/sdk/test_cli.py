from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import financial_planning_sdk_br.cli as cli_module
import financial_planning_sdk_br.reference as reference_module
from financial_planning_sdk_br import ValidationIssue, ValidationReport

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"
EXAMPLE = REPO_ROOT / "examples" / "deterministic-cashflow-ledger.json"


def run_cli(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.fspath(SOURCE_ROOT)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "PYTHONSTARTUP", "PYTHONINSPECT"):
        environment.pop(name, None)
    return subprocess.run(
        [sys.executable, "-m", "financial_planning_sdk_br", *arguments],
        cwd=REPO_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )


class CliTests(unittest.TestCase):
    def test_validate_and_compute_are_machine_readable(self) -> None:
        validation = run_cli("validate", os.fspath(EXAMPLE))
        self.assertEqual(validation.returncode, 0, validation.stderr.decode())
        report = json.loads(validation.stdout)
        self.assertTrue(report["valid"])
        self.assertEqual(report["authority"], "none")

        first = run_cli("compute", "deterministic", os.fspath(EXAMPLE))
        second = run_cli("compute", "deterministic", os.fspath(EXAMPLE))
        self.assertEqual(first.returncode, 0, first.stderr.decode())
        self.assertEqual(first.stdout, second.stdout)
        payload = json.loads(first.stdout)
        self.assertEqual(payload["valuation"]["present_value"], "-1.60")
        self.assertFalse(first.stderr)

    def test_invalid_input_is_redacted_and_returns_two(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-cli-") as directory:
            path = Path(directory) / "invalid.json"
            secret = "should-never-be-echoed"
            secret_key = "cpf_00000000000"
            path.write_text(json.dumps({secret_key: secret}), encoding="utf-8")
            result = run_cli("validate", os.fspath(path))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(secret.encode(), result.stderr)
        self.assertNotIn(secret_key.encode(), result.stdout)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["valid"])
        self.assertTrue(payload["issues"])

    def test_deep_valid_json_is_canonical_input_failure_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-deep-json-") as directory:
            path = Path(directory) / "deep.json"
            path.write_bytes(b"[" * 5_000 + b"null" + b"]" * 5_000)
            results = (
                run_cli("validate", os.fspath(path)),
                run_cli("compute", "deterministic", os.fspath(path)),
            )
        for result in results:
            self.assertEqual(result.returncode, 2)
            self.assertFalse(result.stdout)
            self.assertNotIn(b"Traceback", result.stderr)
            self.assertNotIn(b"RecursionError", result.stderr)
            payload = json.loads(result.stderr)
            self.assertEqual(payload["issues"][0]["code"], "DCL_JSON_INPUT")
            self.assertEqual(payload["issues"][0]["pointer"], "")
        self.assertEqual(results[0].stderr, results[1].stderr)

    def test_reference_run_help_documents_exit_and_remediation_contract(self) -> None:
        result = run_cli("reference", "run", "--help")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(result.stderr)
        for marker in (
            b"finplanbr.reference-acceptance-report.v2",
            b"Exit 0",
            b"Exit 1",
            b"diagnostics[].code",
            b"location",
            b"scope",
            b"remediation_id",
            b"reinstall_distribution",
            b"verify_installed_versions",
            b"inspect_bundled_pack_drift",
            b"inspect_case_output_mismatch",
        ):
            self.assertIn(marker, result.stdout)

    def test_reference_run_invalid_pack_returns_one_with_canonical_stdout(self) -> None:
        report = reference_module._evaluate_reference_acceptance_pack_bytes(
            b"[" * 5_000 + b"null" + b"]" * 5_000
        )
        stdout = Mock()
        stdout_bytes = io.BytesIO()
        stdout.buffer = Mock(wraps=stdout_bytes)
        stderr = Mock()
        stderr.buffer = io.BytesIO()
        with (
            patch.object(cli_module, "run_reference_acceptance_pack", return_value=report),
            patch.object(type(report), "to_dict", side_effect=AssertionError("CLI must not reparse stdout")),
            patch.object(cli_module.sys, "stdout", stdout),
            patch.object(cli_module.sys, "stderr", stderr),
        ):
            return_code = cli_module.main(["reference", "run"])
        self.assertEqual(return_code, 1)
        stdout.buffer.write.assert_called_once_with(report.to_json_bytes() + b"\n")
        self.assertEqual(stdout_bytes.getvalue(), report.to_json_bytes() + b"\n")
        self.assertFalse(stderr.buffer.getvalue())
        self.assertNotIn(b"Traceback", stdout_bytes.getvalue())

    def test_reference_internal_failure_is_redacted_before_stdout(self) -> None:
        stdout = Mock()
        stdout.buffer = io.BytesIO()
        stderr = Mock()
        stderr.buffer = io.BytesIO()
        with (
            patch.object(
                cli_module,
                "run_reference_acceptance_pack",
                side_effect=RuntimeError("bearer_should_never_be_echoed"),
            ),
            patch.object(cli_module.sys, "stdout", stdout),
            patch.object(cli_module.sys, "stderr", stderr),
        ):
            return_code = cli_module.main(["reference", "run"])
        self.assertEqual(return_code, 1)
        self.assertFalse(stdout.buffer.getvalue())
        self.assertEqual(stderr.buffer.getvalue(), b"reference report could not be produced safely\n")
        self.assertNotIn(b"bearer_should_never_be_echoed", stderr.buffer.getvalue())
        self.assertNotIn(b"Traceback", stderr.buffer.getvalue())

    def test_reference_short_stdout_write_returns_failure_without_retry(self) -> None:
        report = reference_module.run_reference_acceptance_pack()
        output = report.to_json_bytes() + b"\n"
        stdout = Mock()
        stdout.buffer.write.return_value = len(output) - 1
        stderr = Mock()
        stderr.buffer = io.BytesIO()
        with (
            patch.object(cli_module, "run_reference_acceptance_pack", return_value=report),
            patch.object(cli_module.sys, "stdout", stdout),
            patch.object(cli_module.sys, "stderr", stderr),
        ):
            return_code = cli_module.main(["reference", "run"])
        self.assertEqual(return_code, 1)
        stdout.buffer.write.assert_called_once_with(output)
        stdout.flush.assert_not_called()
        self.assertFalse(stderr.buffer.getvalue())

    def test_validation_report_serialization_failure_uses_fixed_redacted_v2_fallback(self) -> None:
        report = ValidationReport(
            valid=False,
            issues=(ValidationIssue("DCL_REQUIRED_FIELD", "/events", "required field is missing"),),
        )
        stdout = Mock()
        stdout_bytes = io.BytesIO()
        stdout.buffer = Mock(wraps=stdout_bytes)
        stderr = Mock()
        stderr.buffer = io.BytesIO()
        with (
            patch.object(cli_module, "validate_deterministic_request", return_value=report),
            patch.object(
                ValidationReport,
                "to_json_bytes",
                side_effect=RuntimeError("bearer_should_never_be_echoed"),
            ),
            patch.object(cli_module, "read_json_file", return_value={}),
            patch.object(cli_module.sys, "stdout", stdout),
            patch.object(cli_module.sys, "stderr", stderr),
        ):
            return_code = cli_module.main(["validate", os.fspath(EXAMPLE)])

        self.assertEqual(return_code, 1)
        self.assertFalse(stderr.buffer.getvalue())
        payload = json.loads(stdout_bytes.getvalue())
        self.assertEqual(payload["report_format"], "finplanbr.validation-report.v2")
        self.assertEqual(payload["issues"][0]["code"], "DCL_OUTPUT_WRITE")
        self.assertNotIn(b"bearer_should_never_be_echoed", stdout_bytes.getvalue())
        stdout.buffer.write.assert_called_once()

    def test_validation_report_short_write_returns_failure_without_retry(self) -> None:
        report = ValidationReport(valid=True, issues=())
        output = report.to_json_bytes() + b"\n"
        stdout = Mock()
        stdout.buffer.write.return_value = len(output) - 1
        stderr = Mock()
        stderr.buffer = io.BytesIO()
        with (
            patch.object(cli_module, "validate_deterministic_request", return_value=report),
            patch.object(cli_module, "read_json_file", return_value={}),
            patch.object(cli_module.sys, "stdout", stdout),
            patch.object(cli_module.sys, "stderr", stderr),
        ):
            return_code = cli_module.main(["validate", os.fspath(EXAMPLE)])

        self.assertEqual(return_code, 1)
        stdout.buffer.write.assert_called_once_with(output)
        stdout.flush.assert_not_called()
        self.assertFalse(stderr.buffer.getvalue())

    def test_hardlinked_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-hardlink-") as directory:
            primary = Path(directory) / "primary.json"
            linked = Path(directory) / "linked.json"
            primary.write_bytes(EXAMPLE.read_bytes())
            os.link(primary, linked)
            result = run_cli("validate", os.fspath(linked))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["issues"][0]["code"], "DCL_JSON_INPUT")

    @unittest.skipUnless(os.name == "nt", "NTFS alternate data stream policy is Windows-specific")
    def test_output_alternate_data_stream_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-output-ads-") as directory:
            output = Path(directory) / "result.json:shadow"
            result = run_cli("compute", "deterministic", os.fspath(EXAMPLE), "--output", os.fspath(output))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr)["issues"][0]["code"], "DCL_OUTPUT_WRITE")

    def test_atomic_output_refuses_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-output-") as directory:
            output = Path(directory) / "result.json"
            first = run_cli("compute", "deterministic", os.fspath(EXAMPLE), "--output", os.fspath(output))
            self.assertEqual(first.returncode, 0, first.stderr.decode())
            original = output.read_bytes()
            second = run_cli("compute", "deterministic", os.fspath(EXAMPLE), "--output", os.fspath(output))
            self.assertEqual(second.returncode, 1)
            self.assertEqual(output.read_bytes(), original)
            forced = run_cli(
                "compute",
                "deterministic",
                os.fspath(EXAMPLE),
                "--output",
                os.fspath(output),
                "--force",
            )
            self.assertEqual(forced.returncode, 0, forced.stderr.decode())

    def test_runtime_source_has_no_network_or_dynamic_execution_imports(self) -> None:
        forbidden = ("socket", "urllib", "requests", "httpx", "subprocess", "eval(", "exec(")
        for path in sorted((SOURCE_ROOT / "financial_planning_sdk_br").glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, text, f"{path.name} contains forbidden runtime marker {marker}")


if __name__ == "__main__":
    unittest.main()
