from __future__ import annotations

import copy
import json
import pickle
import unittest
from collections.abc import Callable
from pathlib import Path

from financial_planning_sdk_br import (
    DeterministicResult,
    ReferenceAcceptanceReport,
    ValidationIssue,
    ValidationReport,
    compute_deterministic,
    run_reference_acceptance_pack,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


class PublicValueObjectHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        request = json.loads((REPO_ROOT / "examples" / "deterministic-cashflow-ledger.json").read_bytes())
        cls.issue = ValidationIssue("DCL_REQUIRED_FIELD", "/events", "required field is missing")
        cls.validation = ValidationReport(valid=False, issues=(cls.issue,))
        cls.result = compute_deterministic(request)
        cls.reference = run_reference_acceptance_pack()
        cls.values = (cls.issue, cls.validation, cls.result, cls.reference)

    @staticmethod
    def _trust_accessors(
        value: object,
        *,
        public_type: type[object] | None = None,
    ) -> tuple[Callable[[], object], ...]:
        expected_type = type(value) if public_type is None else public_type
        common: list[Callable[[], object]] = [
            lambda: len(value),  # type: ignore[arg-type]
            lambda: tuple(value),  # type: ignore[arg-type]
            lambda: value[0],  # type: ignore[index]
            lambda: None in value,  # type: ignore[operator]
            lambda: value.count(None),  # type: ignore[attr-defined]
            lambda: value.index(None),  # type: ignore[attr-defined]
            lambda: repr(value),
            lambda: value == (),
            lambda: value < (),  # type: ignore[operator]
            lambda: hash(value),
            lambda: copy.copy(value),
            lambda: copy.deepcopy(value),
            lambda: pickle.dumps(value),
        ]
        if expected_type is ValidationIssue:
            issue = value
            common.extend(
                (
                    lambda: issue.code,
                    lambda: issue.pointer,
                    lambda: issue.message,
                    lambda: issue.to_dict(),
                )
            )
        elif expected_type is ValidationReport:
            report = value
            common.extend(
                (
                    lambda: report.valid,
                    lambda: report.issues,
                    lambda: report.omitted_issue_count,
                    lambda: report.contract_version,
                    lambda: report.authority,
                    lambda: report.issue_count,
                    lambda: report.issues_truncated,
                    lambda: report.to_dict(),
                    lambda: report.to_json_bytes(),
                )
            )
        elif expected_type is DeterministicResult:
            result = value
            common.extend(
                (
                    lambda: result._canonical_payload,
                    lambda: result.to_dict(),
                    lambda: result.to_json_bytes(),
                )
            )
        elif expected_type is ReferenceAcceptanceReport:
            reference = value
            common.extend(
                (
                    lambda: reference._canonical_payload,
                    lambda: reference._status,
                    lambda: reference.status,
                    lambda: reference.to_dict(),
                    lambda: reference.to_json_bytes(),
                )
            )
        return tuple(common)

    def test_classes_are_sealed_and_tuple_base_construction_is_impossible(self) -> None:
        for value in self.values:
            cls = type(value)
            with self.subTest(cls=cls.__name__), self.assertRaises(TypeError):
                type(f"Forged{cls.__name__}", (cls,), {})
            with self.subTest(cls=cls.__name__), self.assertRaises(TypeError):
                tuple.__new__(cls, tuple(value))

    def test_object_base_shells_fail_closed_for_every_trust_accessor(self) -> None:
        for valid in self.values:
            shell = object.__new__(type(valid))
            for accessor in self._trust_accessors(shell):
                with self.subTest(cls=type(valid).__name__, accessor=accessor), self.assertRaises(
                    (AttributeError, TypeError, ValueError)
                ):
                    accessor()

    def test_noncooperative_mro_subclasses_fail_before_private_virtual_dispatch(self) -> None:
        class SilentMixin:
            def __init_subclass__(cls, **_kwargs: object) -> None:
                pass

        class ReorderingMeta(type):
            def mro(cls) -> list[type[object]]:
                default = super().mro()
                return [
                    cls,
                    SilentMixin,
                    *(entry for entry in default[1:] if entry is not SilentMixin),
                ]

        for valid in self.values:
            public_type = type(valid)
            dispatches: list[str] = []

            def poisoned(
                *_args: object,
                dispatch_log: list[str] = dispatches,
                **_kwargs: object,
            ) -> object:
                dispatch_log.append("private virtual dispatch")
                return {}

            namespace: dict[str, object] = {
                "_validated_sequence": poisoned,
            }
            if public_type in {ValidationIssue, ValidationReport}:
                namespace["_document"] = poisoned
            if public_type is ValidationReport:
                namespace["_issues_from_document"] = staticmethod(poisoned)
                namespace["_omitted_from_document"] = staticmethod(poisoned)
            if public_type is DeterministicResult:
                namespace["_validated_document"] = poisoned
            if public_type is ReferenceAcceptanceReport:
                namespace["_validated_pair"] = poisoned

            forged_types = (
                type(
                    f"ForgedLeftMro{public_type.__name__}",
                    (SilentMixin, public_type),
                    namespace,
                ),
                ReorderingMeta(
                    f"ForgedCustomMeta{public_type.__name__}",
                    (public_type, SilentMixin),
                    namespace,
                ),
            )
            for forged_type in forged_types:
                forged = object.__new__(forged_type)
                for accessor in self._trust_accessors(forged, public_type=public_type):
                    with self.subTest(cls=public_type.__name__, accessor=accessor), self.assertRaises(
                        (AttributeError, TypeError, ValueError)
                    ):
                        accessor()
                    self.assertEqual(dispatches, [])

                if public_type is ValidationIssue:
                    with self.assertRaises(TypeError):
                        forged_type("DCL_REQUIRED_FIELD", "/events", "required field is missing")
                elif public_type is ValidationReport:
                    with self.assertRaises(TypeError):
                        forged_type(valid=False, issues=(self.issue,))
                elif public_type is DeterministicResult:
                    with self.assertRaises(TypeError):
                        forged_type._from_canonical_payload(self.result.to_json_bytes())
                else:
                    with self.assertRaises(TypeError):
                        forged_type._from_canonical_payload(
                            self.reference.to_json_bytes(),
                            "local_technical_acceptance_passed",
                        )
                self.assertEqual(dispatches, [])

    def test_object_setattr_cannot_change_or_initialize_state(self) -> None:
        for valid in self.values:
            baseline = tuple(valid)
            for target in (valid, object.__new__(type(valid))):
                for attribute, replacement in (
                    ("_canonical_payload", b"{}"),
                    ("_status", "local_technical_acceptance_passed"),
                    ("code", "DCL_REQUIRED_FIELD"),
                    ("__dict__", {}),
                    ("forged", b"{}"),
                ):
                    with self.subTest(
                        cls=type(valid).__name__,
                        shell=target is not valid,
                        attribute=attribute,
                    ), self.assertRaises((AttributeError, TypeError)):
                        object.__setattr__(target, attribute, replacement)
            self.assertEqual(tuple(valid), baseline)

    def test_compatible_class_reassignment_is_fail_inert_and_recoverable(self) -> None:
        issue = ValidationIssue("DCL_REQUIRED_FIELD", "/events", "required field is missing")
        baseline = issue.to_dict()

        object.__setattr__(issue, "__class__", ValidationReport)
        try:
            operations = (
                lambda: ValidationIssue.to_dict(issue),
                lambda: ValidationIssue.code.__get__(issue, ValidationIssue),
                lambda: ValidationReport.to_dict(issue),
                lambda: ValidationReport.valid.__get__(issue, ValidationReport),
                lambda: len(issue),
                lambda: copy.copy(issue),
                lambda: copy.deepcopy(issue),
                lambda: pickle.dumps(issue),
            )
            for operation in operations:
                with self.subTest(operation=operation), self.assertRaises(
                    (AttributeError, TypeError, ValueError)
                ):
                    operation()
        finally:
            object.__setattr__(issue, "__class__", ValidationIssue)

        self.assertEqual(issue.to_dict(), baseline)

    def test_valid_copy_is_identity_and_pickle_is_explicitly_rejected(self) -> None:
        for value in self.values:
            with self.subTest(cls=type(value).__name__):
                self.assertIs(copy.copy(value), value)
                self.assertIs(copy.deepcopy(value), value)
                with self.assertRaises(TypeError):
                    pickle.dumps(value)

    def test_internal_factories_reject_minimal_schema_invalid_and_status_unbound_wires(self) -> None:
        for terminator in ("\n", "\r", "\u0085", "\u2028", "\u2029"):
            with self.subTest(terminator=ascii(terminator)), self.assertRaises(ValueError):
                ValidationIssue("DCL_REQUIRED_FIELD", "/events" + terminator, "required field is missing")
            with self.subTest(terminator=ascii(terminator)), self.assertRaises(ValueError):
                ValidationIssue("DCL_REQUIRED_FIELD", "/events", "required field is missing" + terminator)

        minimal_result = (
            b'{"artifact_status":"draft","authority":"none","computational_status":"computed",'
            b'"contract_version":"0.1.0-draft.1","deployment_eligibility":"not_authorized",'
            b'"engine_version":"0.1.0.dev0",'
            b'"result_format":"finplanbr.deterministic-cashflow-ledger-result.v1"}'
        )
        with self.assertRaises(ValueError):
            DeterministicResult._from_canonical_payload(minimal_result)

        minimal_reference = (
            b'{"report_format":"finplanbr.reference-acceptance-report.v2",'
            b'"status":"local_technical_acceptance_passed"}'
        )
        with self.assertRaises(ValueError):
            ReferenceAcceptanceReport._from_canonical_payload(
                minimal_reference,
                "local_technical_acceptance_passed",
            )

        valid_payload = self.reference.to_json_bytes()
        with self.assertRaises(ValueError):
            ReferenceAcceptanceReport._from_canonical_payload(
                valid_payload,
                "local_technical_acceptance_failed",
            )

    def test_valid_accessors_revalidate_and_emit_canonical_schema_bound_wires(self) -> None:
        self.assertEqual(self.issue.code, "DCL_REQUIRED_FIELD")
        self.assertEqual(self.issue.pointer, "/events")
        self.assertEqual(self.issue.message, "required field is missing")
        self.assertEqual(tuple(self.issue), (self.issue.code, self.issue.pointer, self.issue.message))
        self.assertEqual(self.issue.to_dict()["code"], self.issue.code)

        self.assertFalse(self.validation.valid)
        self.assertEqual(self.validation.issues, (self.issue,))
        self.assertEqual(self.validation.omitted_issue_count, 0)
        self.assertEqual(self.validation.contract_version, "0.1.0-draft.1")
        self.assertEqual(self.validation.authority, "none")
        self.assertEqual(self.validation.issue_count, 1)
        self.assertFalse(self.validation.issues_truncated)

        self.assertEqual(self.result.to_dict()["authority"], "none")
        self.assertEqual(self.result._canonical_payload, self.result.to_json_bytes())
        self.assertEqual(self.reference.status, "local_technical_acceptance_passed")
        self.assertEqual(self.reference._status, self.reference.status)
        self.assertEqual(self.reference._canonical_payload, self.reference.to_json_bytes())

        for value in (self.validation, self.result, self.reference):
            payload = value.to_json_bytes()
            canonical = json.dumps(
                json.loads(payload),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self.assertEqual(payload, canonical)


if __name__ == "__main__":
    unittest.main()
