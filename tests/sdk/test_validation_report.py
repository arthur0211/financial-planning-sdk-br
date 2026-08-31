from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from financial_planning_sdk_br import (
    MAX_VALIDATION_ISSUES,
    InputValidationError,
    ValidationIssue,
    ValidationReport,
    compute_deterministic,
    validate_deterministic_request,
    validation_report_schema,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"


def invalid_event_budget_request() -> dict[str, object]:
    return {
        "contract_version": "0.1.0-draft.1",
        "calculation_id": "error_budget",
        "valuation_date": "2026-01-01",
        "base_currency": "BRL",
        "use_context": {
            "purpose": "software_testing",
            "client_specific": False,
            "recommendation_enabled": False,
            "execution_enabled": False,
        },
        "discount_factors": [],
        "cashflows": [],
        "accounts": [],
        "events": [{"event_type": "posting"} for _ in range(4096)],
    }


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


class ValidationReportContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = validation_report_schema()
        Draft202012Validator.check_schema(self.schema)
        self.validator = Draft202012Validator(self.schema)

    def assert_schema_valid(self, report: ValidationReport) -> None:
        self.assertEqual(list(self.validator.iter_errors(report.to_dict())), [])

    def test_v2_schema_closes_complete_and_truncated_reports(self) -> None:
        complete = ValidationReport(valid=True, issues=())
        self.assertEqual(complete.issue_count, 0)
        self.assertFalse(complete.issues_truncated)
        self.assertEqual(complete.omitted_issue_count, 0)
        self.assertNotIn("issue_count", complete.to_dict())
        self.assertEqual(complete.to_dict()["truncation"], {"status": "complete"})
        self.assert_schema_valid(complete)

        issue = ValidationIssue("DCL_REQUIRED_FIELD", "/events/0/event_id", "required field is missing")
        truncated = ValidationReport(
            valid=False,
            issues=(issue,) * MAX_VALIDATION_ISSUES,
            omitted_issue_count=2,
        )
        self.assertEqual(truncated.issue_count, MAX_VALIDATION_ISSUES + 2)
        self.assertTrue(truncated.issues_truncated)
        self.assertEqual(truncated.omitted_issue_count, 2)
        self.assertEqual(
            truncated.to_dict()["truncation"],
            {"status": "truncated", "omitted_issue_count": 2},
        )
        self.assert_schema_valid(truncated)
        self.assertLess(len(truncated.to_json_bytes()), 131_072)

        candidate = truncated.to_dict()
        candidate["issue_count"] = truncated.issue_count
        self.assertTrue(list(self.validator.iter_errors(candidate)))

        impossible_complete = truncated.to_dict()
        impossible_complete["truncation"] = {"status": "complete", "omitted_issue_count": 2}
        self.assertTrue(list(self.validator.iter_errors(impossible_complete)))

        impossible_truncated = ValidationReport(valid=False, issues=(issue,)).to_dict()
        impossible_truncated["truncation"] = {"status": "truncated", "omitted_issue_count": 1}
        self.assertTrue(list(self.validator.iter_errors(impossible_truncated)))

    def test_public_value_objects_are_deeply_immutable_and_always_serializable(self) -> None:
        issue = ValidationIssue("DCL_REQUIRED_FIELD", "/events", "required field is missing")
        report = ValidationReport(valid=False, issues=(issue,))
        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(issue, "message", "changed")
        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(report, "issues", ())
        self.assert_schema_valid(report)
        self.assertEqual(json.loads(report.to_json_bytes()), report.to_dict())

    def test_public_constructors_reject_schema_invalid_text_counts_and_shapes(self) -> None:
        for pointer in ("/bad\npath", "/bad\x00path", "/bad\ud800path", "/não_ascii", "/bad~2escape"):
            with self.subTest(pointer=ascii(pointer)):
                with self.assertRaises(ValueError):
                    ValidationIssue("DCL_REQUIRED_FIELD", pointer, "required field is missing")
        for message in ("bad\rmessage", "bad\x7fmessage", "bad\ud800message", "não ascii"):
            with self.subTest(message=ascii(message)):
                with self.assertRaises(ValueError):
                    ValidationIssue("DCL_REQUIRED_FIELD", "/events", message)

        issue = ValidationIssue("DCL_REQUIRED_FIELD", "/events", "required field is missing")
        with self.assertRaises(ValueError):
            ValidationReport(valid=False, issues=(issue,), omitted_issue_count=1)
        with self.assertRaises(ValueError):
            ValidationReport(
                valid=False,
                issues=(issue,) * MAX_VALIDATION_ISSUES,
                omitted_issue_count=999_873,
            )
        with self.assertRaises(ValueError):
            ValidationReport(valid=True, issues=(issue,))

        worst = ValidationIssue("DCL_NUMERIC_INVARIANT_FAILED", "/" + "x" * 127, "\\" * 128)
        largest = ValidationReport(
            valid=False,
            issues=(worst,) * MAX_VALIDATION_ISSUES,
            omitted_issue_count=999_872,
        )
        self.assert_schema_valid(largest)
        self.assertLess(len(largest.to_json_bytes()), 131_072)

    def test_extreme_exact_python_integers_are_totalized_and_int_subclasses_are_rejected(self) -> None:
        class IntSubclass(int):
            pass

        for value in (10**5000, -(10**5000), IntSubclass(1)):
            request = invalid_event_budget_request()
            request["events"] = []
            request["unexpected"] = value
            with self.subTest(kind=type(value).__name__, sign=value < 0):
                report = validate_deterministic_request(request)  # type: ignore[arg-type]
                self.assertFalse(report.valid)
                self.assertEqual(report.issues[0].code, "DCL_JSON_INPUT")
                with self.assertRaises(InputValidationError) as raised:
                    compute_deterministic(request)  # type: ignore[arg-type]
                self.assertEqual(raised.exception.report.issues[0].code, "DCL_JSON_INPUT")

    def test_extreme_json_integers_are_cli_rc2_without_traceback(self) -> None:
        request = invalid_event_budget_request()
        request["events"] = []
        request["unexpected"] = "integer_marker"
        template = json.dumps(request, separators=(",", ":")).encode("utf-8")
        for token in (b"1" * 5001, b"-" + b"1" * 5001):
            payload = template.replace(b'"integer_marker"', token)
            with tempfile.TemporaryDirectory(prefix="finplanbr-extreme-int-") as directory:
                path = Path(directory) / "request.json"
                path.write_bytes(payload)
                results = (
                    run_cli("validate", os.fspath(path)),
                    run_cli("compute", "deterministic", os.fspath(path)),
                )
            for index, result in enumerate(results):
                with self.subTest(sign=token.startswith(b"-"), route=index):
                    self.assertEqual(result.returncode, 2)
                    self.assertNotIn(b"Traceback", result.stdout + result.stderr)
                    payload_bytes = result.stdout or result.stderr
                    self.assertTrue(payload_bytes)
                    wire = json.loads(payload_bytes)
                    self.assertEqual(wire["issues"][0]["code"], "DCL_JSON_INPUT")
                    self.assertNotIn("issue_count", wire)
                    self.assertEqual(wire["truncation"], {"status": "complete"})

    def test_4096_invalid_events_have_exact_bounded_deterministic_prefix(self) -> None:
        request = invalid_event_budget_request()
        first = validate_deterministic_request(request)
        second = validate_deterministic_request(request)

        self.assertFalse(first.valid)
        self.assertEqual(first.issue_count, 81_918)
        self.assertEqual(len(first.issues), MAX_VALIDATION_ISSUES)
        self.assertEqual(first.omitted_issue_count, 81_918 - MAX_VALIDATION_ISSUES)
        self.assertTrue(first.issues_truncated)
        self.assertEqual(first.to_json_bytes(), second.to_json_bytes())
        self.assertEqual(first.issues, second.issues)
        self.assert_schema_valid(first)

    def test_4096_invalid_events_are_schema_valid_rc2_without_traceback_on_both_cli_routes(self) -> None:
        request = invalid_event_budget_request()
        with tempfile.TemporaryDirectory(prefix="finplanbr-error-budget-") as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(request, separators=(",", ":")), encoding="utf-8")
            results = (
                run_cli("validate", os.fspath(path)),
                run_cli("compute", "deterministic", os.fspath(path)),
            )

        for index, result in enumerate(results):
            with self.subTest(route=index):
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(b"Traceback", result.stderr)
                self.assertNotIn(b"Traceback", result.stdout)
                payload_bytes = result.stdout if index == 0 else result.stderr
                other_bytes = result.stderr if index == 0 else result.stdout
                self.assertFalse(other_bytes)
                payload = json.loads(payload_bytes)
                self.assertEqual(payload["report_format"], "finplanbr.validation-report.v2")
                self.assertEqual(len(payload["issues"]), MAX_VALIDATION_ISSUES)
                self.assertNotIn("issue_count", payload)
                self.assertEqual(
                    payload["truncation"],
                    {"status": "truncated", "omitted_issue_count": 81_918 - MAX_VALIDATION_ISSUES},
                )
                self.assertEqual(list(self.validator.iter_errors(payload)), [])


if __name__ == "__main__":
    unittest.main()
