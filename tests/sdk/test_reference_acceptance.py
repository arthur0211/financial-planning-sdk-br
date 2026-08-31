from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock, patch

from jsonschema import Draft202012Validator

import financial_planning_sdk_br.contracts as contracts_module
import financial_planning_sdk_br.reference as reference_module
from financial_planning_sdk_br import (
    reference_acceptance_report_schema,
    run_reference_acceptance_pack,
)
from financial_planning_sdk_br.jsonio import (
    MAX_INPUT_BYTES,
    MAX_NODES,
    JsonContractError,
    canonical_json_bytes,
    loads_strict,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"
PACK_PATH = SOURCE_ROOT / "financial_planning_sdk_br" / "reference-acceptance-pack.v2.json"
LEGACY_PACK_PATH = SOURCE_ROOT / "financial_planning_sdk_br" / "reference-acceptance-pack.v1.json"
LEGACY_PACK_RAW_SHA256 = "b3e5c8078a7258d8df521bb5c8843ef371feeaf681fb6710a6cd57a45918c18c"


def run_cli() -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.fspath(SOURCE_ROOT)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "PYTHONSTARTUP", "PYTHONINSPECT"):
        environment.pop(name, None)
    return subprocess.run(
        [sys.executable, "-m", "financial_planning_sdk_br", "reference", "run"],
        cwd=REPO_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )


def mutated_payload(document: dict[str, object]) -> tuple[bytes, str]:
    payload = canonical_json_bytes(document)
    return payload, hashlib.sha256(payload).hexdigest()


class TrackingBytesIO(io.BytesIO):
    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)


class FirstShortReadBytesIO(TrackingBytesIO):
    def __init__(self, payload: bytes, *, first_size: int) -> None:
        super().__init__(payload)
        self._first_size = first_size

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if len(self.read_sizes) == 1:
            size = min(size, self._first_size)
        return io.BytesIO.read(self, size)


class ReferenceAcceptanceTests(unittest.TestCase):
    def assert_report_schema_valid(self, payload: dict[str, object]) -> None:
        schema = reference_acceptance_report_schema()
        Draft202012Validator.check_schema(schema)
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(payload)), [])

    def pack_document(self) -> dict[str, Any]:
        return cast(dict[str, Any], loads_strict(PACK_PATH.read_bytes()))

    def evaluate_document(self, document: dict[str, Any]) -> dict[str, Any]:
        return reference_module._evaluate_reference_acceptance_pack_bytes(canonical_json_bytes(document)).to_dict()

    def evaluate_rehashed(self, document: dict[str, Any]) -> dict[str, Any]:
        payload, digest = mutated_payload(document)
        with patch.object(reference_module, "_EXPECTED_PACK_SHA256", digest):
            return reference_module._evaluate_reference_acceptance_pack_bytes(payload).to_dict()

    def assert_invalid_diagnostic(
        self,
        report: dict[str, Any],
        *,
        code: str,
        location: str,
        scope: str,
        remediation_id: str,
    ) -> None:
        self.assertEqual(report["status"], "local_technical_acceptance_invalid_pack")
        self.assertEqual(report["case_count"], 0)
        self.assertEqual(
            report["diagnostics"],
            [
                {
                    "code": code,
                    "location": location,
                    "scope": scope,
                    "remediation_id": remediation_id,
                }
            ],
        )
        self.assertFalse(report["release_authorized"])
        self.assert_report_schema_valid(report)

    def test_public_sdk_report_is_closed_machine_readable_and_schema_valid(self) -> None:
        report = run_reference_acceptance_pack()
        payload = report.to_dict()
        self.assertEqual(
            reference_acceptance_report_schema()["$id"],
            "urn:finplanbr:schema:reference-acceptance-report:2.0.0-draft.3",
        )
        self.assert_report_schema_valid(payload)
        self.assertEqual(payload["report_format"], "finplanbr.reference-acceptance-report.v2")
        self.assertNotEqual(payload["report_format"], "finplanbr.reference-acceptance-report.v1")
        self.assertEqual(payload["status"], "local_technical_acceptance_passed")
        self.assertEqual(payload["pack_id"], "deterministic_cashflow_ledger_reference_v2")
        self.assertEqual(payload["pack_version"], "2.0.0-draft.1")
        self.assertEqual(payload["case_count"], 3)
        self.assertEqual(payload["passed_count"], 3)
        self.assertEqual(payload["failed_count"], 0)
        self.assertEqual(payload["provenance"], "repository_local_untrusted")
        self.assertEqual(payload["reference_independence"], "not_claimed")
        self.assertEqual(payload["pack_sha256_basis"], "fpbr_c14n_1")
        self.assertEqual(payload["authority"], "none")
        self.assertEqual(payload["deployment_eligibility"], "not_authorized")
        self.assertFalse(payload["release_authorized"])
        self.assertEqual(
            [case["case_id"] for case in payload["cases"]],
            [
                "pv_final_rounding_half_even",
                "ledger_transfer_and_return",
                "total_return_double_count_rejection",
            ],
        )
        for case in payload["cases"]:
            self.assertTrue(case["exact_output_match"])
            self.assertEqual(case["expected_output_sha256"], case["observed_output_sha256"])
            self.assertTrue(case["assertions"])
            for assertion in case["assertions"]:
                self.assertEqual(assertion["status"], "passed")
                self.assertIs(type(assertion["expected"]), type(assertion["observed"]))
                self.assertEqual(assertion["expected"], assertion["observed"])

    def test_legacy_v1_pack_bytes_and_compute_expectations_are_preserved(self) -> None:
        self.assertEqual(hashlib.sha256(LEGACY_PACK_PATH.read_bytes()).hexdigest(), LEGACY_PACK_RAW_SHA256)
        legacy = cast(dict[str, Any], loads_strict(LEGACY_PACK_PATH.read_bytes()))
        current = self.pack_document()
        for index in (0, 1):
            self.assertEqual(
                canonical_json_bytes(legacy["cases"][index]["request"]),
                canonical_json_bytes(current["cases"][index]["request"]),
            )
            self.assertEqual(
                canonical_json_bytes(legacy["cases"][index]["expected_output"]),
                canonical_json_bytes(current["cases"][index]["expected_output"]),
            )

    def test_sdk_and_cli_emit_identical_reproducible_bytes(self) -> None:
        sdk_bytes = run_reference_acceptance_pack().to_json_bytes() + b"\n"
        first = run_cli()
        second = run_cli()
        self.assertEqual(first.returncode, 0, first.stderr.decode())
        self.assertEqual(second.returncode, 0, second.stderr.decode())
        self.assertFalse(first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stdout, sdk_bytes)

    def test_report_copy_cannot_mutate_canonical_sdk_result(self) -> None:
        report = run_reference_acceptance_pack()
        first = report.to_dict()
        first["limitations"].append("MUTATED")
        first["cases"][0]["assertions"][0]["observed"] = "MUTATED"
        second = report.to_dict()
        self.assertNotIn("MUTATED", second["limitations"])
        self.assertNotEqual(second["cases"][0]["assertions"][0]["observed"], "MUTATED")
        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(report, "_canonical_payload", b"{}")

    def test_report_status_and_serialized_line_are_output_bounded(self) -> None:
        report = run_reference_acceptance_pack()
        self.assertEqual(report.status, "local_technical_acceptance_passed")
        self.assertLessEqual(
            len(report.to_json_bytes()) + 1,
            reference_module.MAX_REFERENCE_REPORT_BYTES,
        )
        with self.assertRaisesRegex(TypeError, "only be created"):
            reference_module.ReferenceAcceptanceReport(
                b"x" * reference_module.MAX_REFERENCE_REPORT_BYTES,
                "local_technical_acceptance_failed",
            )
        with self.assertRaisesRegex(TypeError, "immutable bytes"):
            reference_module.ReferenceAcceptanceReport._from_canonical_payload(
                bytearray(b"{}"),  # type: ignore[arg-type]
                "local_technical_acceptance_failed",
            )
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            reference_module.ReferenceAcceptanceReport._from_canonical_payload(
                canonical_json_bytes(
                    {
                        "report_format": reference_module.REPORT_FORMAT,
                        "status": "local_technical_acceptance_failed",
                    }
                ),
                "local_technical_acceptance_passed",
            )
        with self.assertRaisesRegex(ValueError, "canonical"):
            reference_module.ReferenceAcceptanceReport._from_canonical_payload(
                b'{"status": "local_technical_acceptance_failed"}',
                "local_technical_acceptance_failed",
            )
        with self.assertRaisesRegex(ValueError, "output budget"):
            reference_module.ReferenceAcceptanceReport._from_canonical_payload(
                b"x" * reference_module.MAX_REFERENCE_REPORT_BYTES,
                "local_technical_acceptance_failed",
            )

    def test_strict_json_rejects_lone_surrogates_before_canonicalization(self) -> None:
        for payload in (b'{"value":"\\ud800"}', b'{"\\udfff":true}'):
            with self.subTest(payload=payload), self.assertRaises(JsonContractError):
                loads_strict(payload)
        for document in ({"value": "\ud800"}, {"\udfff": True}):
            with self.subTest(document=list(document)), self.assertRaises(JsonContractError):
                canonical_json_bytes(document)

        report = reference_module._evaluate_reference_acceptance_pack_bytes(
            b'{"credential_marker":"\\ud800"}'
        ).to_dict()
        self.assertNotIn("credential_marker", canonical_json_bytes(report).decode("utf-8"))
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_JSON_INVALID",
            location="",
            scope="document",
            remediation_id="reinstall_distribution",
        )

    def test_deterministic_route_budgets_do_not_expand_reference_pack_nodes(self) -> None:
        payload = json.dumps(
            {"padding": [None] * MAX_NODES},
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertLess(len(payload), MAX_INPUT_BYTES)
        report = reference_module._evaluate_reference_acceptance_pack_bytes(payload).to_dict()
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_JSON_INVALID",
            location="",
            scope="document",
            remediation_id="reinstall_distribution",
        )

    def test_oversized_resource_is_read_once_to_the_limit_and_not_hashed(self) -> None:
        stream = TrackingBytesIO(b"x" * (MAX_INPUT_BYTES + 1))
        resource = Mock()
        resource.open.return_value = stream
        package = Mock()
        package.joinpath.return_value = resource
        with (
            patch.object(reference_module, "files", return_value=package),
            patch.object(reference_module, "_sha256", wraps=reference_module._sha256) as digest,
        ):
            report = run_reference_acceptance_pack().to_dict()
        self.assertEqual(stream.read_sizes, [MAX_INPUT_BYTES + 1])
        digest.assert_not_called()
        self.assertIsNone(report["pack_sha256"])
        self.assertEqual(report["pack_sha256_basis"], "not_available")
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_INPUT_LIMIT",
            location="",
            scope="document",
            remediation_id="reinstall_distribution",
        )

    def test_short_read_is_followed_until_limit_before_hashing(self) -> None:
        stream = FirstShortReadBytesIO(
            b'{"pack":' + b"x" * (MAX_INPUT_BYTES + 1),
            first_size=8,
        )
        resource = Mock()
        resource.open.return_value = stream
        package = Mock()
        package.joinpath.return_value = resource
        with (
            patch.object(reference_module, "files", return_value=package),
            patch.object(reference_module, "_sha256", wraps=reference_module._sha256) as digest,
        ):
            report = run_reference_acceptance_pack().to_dict()
        self.assertGreaterEqual(len(stream.read_sizes), 2)
        self.assertEqual(stream.read_sizes[0], MAX_INPUT_BYTES + 1)
        digest.assert_not_called()
        self.assertIsNone(report["pack_sha256"])
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_INPUT_LIMIT",
            location="",
            scope="document",
            remediation_id="reinstall_distribution",
        )

    def test_contract_schema_loader_uses_bounded_strict_json(self) -> None:
        for payload in (
            b'{"type":"object","type":"array"}',
            b'{"description":"\\ud800"}',
            b"x" * (MAX_INPUT_BYTES + 1),
        ):
            with self.subTest(size=len(payload)):
                stream = TrackingBytesIO(payload)
                resource = Mock()
                resource.open.return_value = stream
                package = Mock()
                package.joinpath.return_value = resource
                with (
                    patch.object(contracts_module, "files", return_value=package),
                    self.assertRaises(JsonContractError),
                ):
                    contracts_module._load("candidate.schema.json")
                self.assertEqual(stream.read_sizes[0], MAX_INPUT_BYTES + 1)
                expected_calls = 1 if len(payload) > MAX_INPUT_BYTES else 2
                self.assertEqual(len(stream.read_sizes), expected_calls)

    def test_contract_schema_loader_follows_short_reads_before_accepting(self) -> None:
        stream = FirstShortReadBytesIO(
            b'{"type":"object"}' + b"x" * (MAX_INPUT_BYTES + 1),
            first_size=len(b'{"type":"object"}'),
        )
        resource = Mock()
        resource.open.return_value = stream
        package = Mock()
        package.joinpath.return_value = resource
        with (
            patch.object(contracts_module, "files", return_value=package),
            self.assertRaises(JsonContractError),
        ):
            contracts_module._load("candidate.schema.json")
        self.assertGreaterEqual(len(stream.read_sizes), 2)

    def test_resource_missing_and_unreadable_are_distinct_actionable_diagnostics(self) -> None:
        failures = (
            (FileNotFoundError("redacted"), "REFERENCE_PACK_RESOURCE_MISSING"),
            (PermissionError("redacted"), "REFERENCE_PACK_RESOURCE_UNREADABLE"),
            (RuntimeError("redacted"), "REFERENCE_PACK_RESOURCE_UNREADABLE"),
        )
        for failure, code in failures:
            with self.subTest(code=code), patch.object(reference_module, "files", side_effect=failure):
                report = run_reference_acceptance_pack().to_dict()
            self.assertIsNone(report["pack_sha256"])
            self.assertEqual(report["pack_sha256_basis"], "not_available")
            self.assertNotIn("redacted", canonical_json_bytes(report).decode("utf-8"))
            self.assert_invalid_diagnostic(
                report,
                code=code,
                location="reference-acceptance-pack.v2.json",
                scope="resource",
                remediation_id="reinstall_distribution",
            )

    def test_invalid_json_has_a_closed_document_diagnostic(self) -> None:
        report = reference_module._evaluate_reference_acceptance_pack_bytes(b'{"pack":').to_dict()
        self.assertEqual(report["pack_sha256_basis"], "raw_input")
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_JSON_INVALID",
            location="",
            scope="document",
            remediation_id="reinstall_distribution",
        )

    def test_deep_valid_json_has_a_depth_budget_diagnostic_without_recursion_escape(self) -> None:
        payload = b"[" * 5_000 + b"null" + b"]" * 5_000
        report = reference_module._evaluate_reference_acceptance_pack_bytes(payload).to_dict()
        self.assertEqual(report["pack_sha256_basis"], "raw_input")
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_DEPTH_BUDGET",
            location="",
            scope="document",
            remediation_id="reinstall_distribution",
        )

    def test_pack_digest_pin_corruption_has_a_canonical_digest_diagnostic(self) -> None:
        report = reference_module._report(
            pack_sha256="0" * 64,
            pack_sha256_basis="fpbr_c14n_1",
            status="local_technical_acceptance_invalid_pack",
            diagnostics=[
                reference_module._PackDiagnostic(
                    code="REFERENCE_PACK_DIGEST_MISMATCH",
                    location="",
                )
            ],
            cases=[],
        ).to_dict()
        self.assertEqual(report["pack_sha256_basis"], "fpbr_c14n_1")
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_DIGEST_MISMATCH",
            location="",
            scope="pack_integrity",
            remediation_id="reinstall_distribution",
        )

    def test_mutated_version_and_constant_corruption_are_distinct(self) -> None:
        mutations = (
            ("pack_version", "9.9.9", "REFERENCE_PACK_VERSION_MISMATCH", "compatibility", "verify_installed_versions"),
            (
                "authority",
                "invented",
                "REFERENCE_PACK_CONSTANT_MISMATCH",
                "pack_contract",
                "inspect_bundled_pack_drift",
            ),
        )
        for field, value, code, scope, remediation_id in mutations:
            with self.subTest(field=field):
                document = self.pack_document()
                document[field] = value
                report = self.evaluate_document(document)
            self.assert_invalid_diagnostic(
                report,
                code=code,
                location=f"/{field}",
                scope=scope,
                remediation_id=remediation_id,
            )

    def test_mutated_non_closed_structure_is_located_at_the_root(self) -> None:
        document = self.pack_document()
        document["unexpected"] = True
        report = self.evaluate_document(document)
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_STRUCTURE_INVALID",
            location="",
            scope="pack_contract",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_non_nominal_case_index_diagnostic_emitted_by_runtime_remains_schema_valid(self) -> None:
        document = self.pack_document()
        document["cases"].append(None)
        report = self.evaluate_document(document)
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_STRUCTURE_INVALID",
            location="/cases/3",
            scope="pack_contract",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_mutated_roster_route_and_derivation_corruption_are_distinct(self) -> None:
        mutations = (
            ("roster", "REFERENCE_PACK_ROSTER_MISMATCH", "/case_roster", "roster"),
            ("route", "REFERENCE_PACK_ROUTE_MISMATCH", "/cases/0/operation", "case_route"),
            (
                "derivation",
                "REFERENCE_PACK_DERIVATION_MISMATCH",
                "/cases/0/derivation_id",
                "case_derivation",
            ),
        )
        for mutation, code, location, scope in mutations:
            with self.subTest(mutation=mutation):
                document = self.pack_document()
                if mutation == "roster":
                    document["case_roster"] = list(reversed(document["case_roster"]))
                elif mutation == "route":
                    document["cases"][0]["operation"] = "validate"
                else:
                    document["cases"][0]["derivation_id"] = "invented_derivation_v1"
                report = self.evaluate_document(document)
            self.assert_invalid_diagnostic(
                report,
                code=code,
                location=location,
                scope=scope,
                remediation_id="inspect_bundled_pack_drift",
            )

    def test_mutated_request_context_corruption_is_actionable(self) -> None:
        document = self.pack_document()
        document["cases"][0]["request"]["use_context"]["client_specific"] = True
        report = self.evaluate_document(document)
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_REQUEST_INVALID",
            location="/cases/0/request/use_context",
            scope="case_request",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_incomplete_or_value_injected_request_is_rejected_before_execution_and_redacted(self) -> None:
        document = self.pack_document()
        secret_key = "credential_marker"
        secret_value = "bearer_should_never_be_echoed"
        del document["cases"][0]["request"]["cashflows"]
        document["cases"][0]["request"][secret_key] = secret_value
        report = self.evaluate_rehashed(document)
        serialized = canonical_json_bytes(report)
        self.assertNotIn(secret_key.encode(), serialized)
        self.assertNotIn(secret_value.encode(), serialized)
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_REQUEST_INVALID",
            location="/cases/0/request",
            scope="case_request",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_incomplete_request_is_structurally_rejected_even_with_coordinated_digest_pins(self) -> None:
        document = self.pack_document()
        case_id = cast(str, document["cases"][0]["case_id"])
        del document["cases"][0]["request"]["cashflows"]
        payload, pack_digest = mutated_payload(document)
        request_digest = hashlib.sha256(
            canonical_json_bytes(document["cases"][0]["request"])
        ).hexdigest()
        expected_case = reference_module._EXPECTED_CASES[case_id]
        coordinated_case = replace(expected_case, request_sha256=request_digest)
        with (
            patch.dict(reference_module._EXPECTED_CASES, {case_id: coordinated_case}),
            patch.object(reference_module, "_EXPECTED_PACK_SHA256", pack_digest),
            patch.object(reference_module, "_EXPECTED_MANIFEST_SHA256", "0" * 64),
            patch.object(reference_module, "compute_deterministic") as compute,
            patch.object(reference_module, "validate_deterministic_request") as validate,
        ):
            report = reference_module._evaluate_reference_acceptance_pack_bytes(payload).to_dict()
        compute.assert_not_called()
        validate.assert_not_called()
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_REQUEST_INVALID",
            location="/cases/0/request",
            scope="case_request",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_assertion_manifest_digest_prevents_pack_controlled_echo(self) -> None:
        document = self.pack_document()
        secret_token = "secret_bearer_should_never_be_echoed"
        document["cases"][0]["assertions"][0]["rule_id"] = secret_token
        report = self.evaluate_rehashed(document)
        self.assertNotIn(secret_token.encode(), canonical_json_bytes(report))
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
            location="/cases/0/assertions",
            scope="expected_output",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_assertion_cardinality_is_closed_to_one_through_sixteen(self) -> None:
        document = self.pack_document()
        template = document["cases"][0]["assertions"][0]
        document["cases"][0]["assertions"] = []
        for index in range(17):
            assertion = copy.deepcopy(template)
            assertion["assertion_id"] = f"a{index}"
            document["cases"][0]["assertions"].append(assertion)
        report = self.evaluate_rehashed(document)
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
            location="/cases/0/assertions",
            scope="expected_output",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_huge_json_pointer_index_never_reaches_python_integer_digit_limit(self) -> None:
        previous = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            with self.assertRaises(reference_module._PackConfigurationError):
                reference_module._pointer_get(
                    ["bounded"],
                    "/" + "9" * 1_000,
                    diagnostic_location="/cases/0/assertions/0/json_pointer",
                )
            document = self.pack_document()
            document["cases"][0]["assertions"][0]["json_pointer"] = "/" + "9" * 1_000
            report = self.evaluate_rehashed(document)
        finally:
            sys.set_int_max_str_digits(previous)
        self.assertNotIn(("9" * 1_000).encode(), canonical_json_bytes(report))
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
            location="/cases/0/assertions/0/json_pointer",
            scope="expected_output",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_consistently_rehashed_expected_output_corruption_still_fails_closed(self) -> None:
        document = self.pack_document()
        case = document["cases"][0]
        case["expected_output"]["valuation"]["present_value"] = "0.01"
        expected_bytes = canonical_json_bytes(case["expected_output"])
        case["expected_output_sha256"] = hashlib.sha256(expected_bytes).hexdigest()
        report = self.evaluate_document(document)
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
            location="/cases/0/expected_output",
            scope="expected_output",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_rehashed_request_math_corruption_is_rejected_by_fixed_request_digest(self) -> None:
        document = self.pack_document()
        document["cases"][0]["request"]["discount_factors"][0]["factor"] = "0.006"
        report = self.evaluate_rehashed(document)
        self.assert_invalid_diagnostic(
            report,
            code="REFERENCE_PACK_REQUEST_INVALID",
            location="/cases/0/request",
            scope="case_request",
            remediation_id="inspect_bundled_pack_drift",
        )

    def test_runtime_output_drift_is_a_schema_valid_failed_case_report(self) -> None:
        original_compute = reference_module.compute_deterministic
        secret = "bearer_runtime_value_should_never_be_echoed"

        def drift_first_case(request: dict[str, Any]) -> Any:
            result = original_compute(request)
            if request["calculation_id"] != "acceptance_pv_half_even":
                return result
            payload = result.to_dict()
            payload["valuation"]["present_value_exact"] = secret
            candidate = Mock()
            candidate.to_dict.return_value = payload
            return candidate

        with patch.object(reference_module, "compute_deterministic", side_effect=drift_first_case):
            report = run_reference_acceptance_pack().to_dict()
        self.assertEqual(report["status"], "local_technical_acceptance_failed")
        self.assertEqual(report["passed_count"], 2)
        self.assertEqual(report["failed_count"], 1)
        self.assertEqual(report["cases"][0]["diagnostic"], "REFERENCE_OUTPUT_MISMATCH")
        self.assertFalse(report["cases"][0]["exact_output_match"])
        self.assertEqual(report["cases"][0]["assertions"][0]["status"], "failed")
        self.assertIsNone(report["cases"][0]["assertions"][0]["observed"])
        self.assertNotIn(secret.encode(), canonical_json_bytes(report))
        self.assert_report_schema_valid(report)
        impossible = copy.deepcopy(report)
        impossible["cases"][0]["assertions"][0]["observed"] = secret
        self.assertTrue(
            list(Draft202012Validator(reference_acceptance_report_schema()).iter_errors(impossible))
        )

    def test_runtime_exception_is_redacted_into_a_schema_valid_failed_report(self) -> None:
        secret = "bearer_runtime_value_should_never_be_echoed"
        with patch.object(reference_module, "compute_deterministic", side_effect=RuntimeError(secret)):
            report = run_reference_acceptance_pack().to_dict()
        self.assertEqual(report["status"], "local_technical_acceptance_failed")
        self.assertEqual(report["passed_count"], 1)
        self.assertEqual(report["failed_count"], 2)
        for case in report["cases"][:2]:
            self.assertEqual(case["diagnostic"], "REFERENCE_CASE_EXECUTION_FAILED")
            self.assertEqual(
                case["observed_output_sha256"],
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            )
        self.assertNotIn(secret.encode(), canonical_json_bytes(report))
        self.assert_report_schema_valid(report)
        impossible = copy.deepcopy(report)
        for assertion in impossible["cases"][0]["assertions"]:
            assertion["status"] = "passed"
            assertion["observed"] = assertion["expected"]
        self.assertTrue(
            list(Draft202012Validator(reference_acceptance_report_schema()).iter_errors(impossible))
        )

    def test_validator_runtime_failure_is_case_execution_failure_not_invalid_pack(self) -> None:
        secret = "bearer_validator_runtime_value_should_never_be_echoed"
        with patch.object(
            reference_module,
            "validate_deterministic_request",
            side_effect=RuntimeError(secret),
        ):
            report = run_reference_acceptance_pack().to_dict()
        self.assertEqual(report["status"], "local_technical_acceptance_failed")
        self.assertEqual(report["passed_count"], 2)
        self.assertEqual(report["failed_count"], 1)
        self.assertEqual(report["cases"][2]["diagnostic"], "REFERENCE_CASE_EXECUTION_FAILED")
        self.assertNotIn(secret.encode(), canonical_json_bytes(report))
        self.assert_report_schema_valid(report)

    def test_closed_diagnostic_schema_rejects_strings_unknown_fields_and_invalid_combinations(self) -> None:
        baseline = reference_module._evaluate_reference_acceptance_pack_bytes(b'{"pack":').to_dict()
        candidates = []
        bare_string = copy.deepcopy(baseline)
        bare_string["diagnostics"] = ["REFERENCE_PACK_JSON_INVALID"]
        candidates.append(bare_string)
        unknown_field = copy.deepcopy(baseline)
        unknown_field["diagnostics"][0]["detail"] = "forbidden"
        candidates.append(unknown_field)
        unknown_code = copy.deepcopy(baseline)
        unknown_code["diagnostics"][0]["code"] = "REFERENCE_PACK_UNKNOWN"
        candidates.append(unknown_code)
        invalid_combination = copy.deepcopy(baseline)
        invalid_combination["diagnostics"][0]["scope"] = "compatibility"
        candidates.append(invalid_combination)
        invalid_digest_basis = copy.deepcopy(baseline)
        invalid_digest_basis["pack_sha256_basis"] = "fpbr_c14n_1"
        candidates.append(invalid_digest_basis)
        passed_with_raw_digest_basis = run_reference_acceptance_pack().to_dict()
        passed_with_raw_digest_basis["pack_sha256_basis"] = "raw_input"
        candidates.append(passed_with_raw_digest_basis)
        passed_with_failed_case = run_reference_acceptance_pack().to_dict()
        passed_with_failed_case["cases"][0]["status"] = "failed"
        passed_with_failed_case["cases"][0]["diagnostic"] = "REFERENCE_OUTPUT_MISMATCH"
        passed_with_failed_case["cases"][0]["exact_output_match"] = False
        candidates.append(passed_with_failed_case)
        passed_with_false_exact = run_reference_acceptance_pack().to_dict()
        passed_with_false_exact["cases"][0]["exact_output_match"] = False
        candidates.append(passed_with_false_exact)
        passed_with_wrong_observed_hash = run_reference_acceptance_pack().to_dict()
        passed_with_wrong_observed_hash["cases"][0]["observed_output_sha256"] = "0" * 64
        candidates.append(passed_with_wrong_observed_hash)
        passed_with_assertion_value_drift = run_reference_acceptance_pack().to_dict()
        passed_with_assertion_value_drift["cases"][0]["assertions"][0]["observed"] = "0.006"
        candidates.append(passed_with_assertion_value_drift)
        passed_with_assertion_roster_drift = run_reference_acceptance_pack().to_dict()
        passed_with_assertion_roster_drift["cases"][0]["assertions"].pop()
        candidates.append(passed_with_assertion_roster_drift)
        passed_with_counter_drift = run_reference_acceptance_pack().to_dict()
        passed_with_counter_drift["passed_count"] = 2
        passed_with_counter_drift["failed_count"] = 1
        candidates.append(passed_with_counter_drift)
        digest_mismatch_with_nominal_hash = run_reference_acceptance_pack().to_dict()
        digest_mismatch_with_nominal_hash.update(
            {
                "status": "local_technical_acceptance_invalid_pack",
                "case_count": 0,
                "passed_count": 0,
                "failed_count": 0,
                "diagnostics": [
                    reference_module._PackDiagnostic(
                        code="REFERENCE_PACK_DIGEST_MISMATCH",
                        location="",
                    ).to_dict()
                ],
                "cases": [],
            }
        )
        candidates.append(digest_mismatch_with_nominal_hash)

        schema = reference_acceptance_report_schema()
        validator = Draft202012Validator(schema)
        for index, candidate in enumerate(candidates):
            with self.subTest(index=index):
                self.assertTrue(list(validator.iter_errors(candidate)))

    def test_diagnostic_schema_closes_every_code_to_its_location_family(self) -> None:
        locations = {
            "REFERENCE_PACK_RESOURCE_MISSING": "reference-acceptance-pack.v2.json",
            "REFERENCE_PACK_RESOURCE_UNREADABLE": "reference-acceptance-pack.v2.json",
            "REFERENCE_PACK_JSON_INVALID": "",
            "REFERENCE_PACK_DEPTH_BUDGET": "",
            "REFERENCE_PACK_INPUT_LIMIT": "",
            "REFERENCE_PACK_DIGEST_MISMATCH": "",
            "REFERENCE_PACK_VERSION_MISMATCH": "/pack_version",
            "REFERENCE_PACK_CONSTANT_MISMATCH": "/authority",
            "REFERENCE_PACK_STRUCTURE_INVALID": "/cases/0",
            "REFERENCE_PACK_ROSTER_MISMATCH": "/cases/0/case_id",
            "REFERENCE_PACK_ROUTE_MISMATCH": "/cases/0/operation",
            "REFERENCE_PACK_DERIVATION_MISMATCH": "/cases/0/derivation_id",
            "REFERENCE_PACK_REQUEST_INVALID": "/cases/0/request/use_context",
            "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID": "/cases/0/assertions/0/json_pointer",
            "REFERENCE_CASE_FAILED": "/cases",
        }
        diagnostic_schema = reference_acceptance_report_schema()["$defs"]["diagnostic"]
        validator = Draft202012Validator(diagnostic_schema)
        self.assertEqual(set(locations), set(reference_module._PACK_DIAGNOSTIC_POLICY))
        for code, location in locations.items():
            scope, remediation_id = reference_module._PACK_DIAGNOSTIC_POLICY[code]
            candidate = {
                "code": code,
                "location": location,
                "scope": scope,
                "remediation_id": remediation_id,
            }
            with self.subTest(code=code, state="valid"):
                self.assertEqual(list(validator.iter_errors(candidate)), [])
            candidate["location"] = "/wrong"
            with self.subTest(code=code, state="wrong_location"):
                self.assertTrue(list(validator.iter_errors(candidate)))

        expected_scope, expected_remediation = reference_module._PACK_DIAGNOSTIC_POLICY[
            "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID"
        ]
        assertion_candidate = {
            "code": "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
            "location": "/cases/0/assertions/15/json_pointer",
            "scope": expected_scope,
            "remediation_id": expected_remediation,
        }
        self.assertEqual(list(validator.iter_errors(assertion_candidate)), [])
        for impossible_index in ("16", "999"):
            with self.subTest(assertion_index=impossible_index):
                assertion_candidate["location"] = (
                    f"/cases/0/assertions/{impossible_index}/json_pointer"
                )
                self.assertTrue(list(validator.iter_errors(assertion_candidate)))


if __name__ == "__main__":
    unittest.main()
