from __future__ import annotations

import copy
import io
import json
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock, patch

from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators

from financial_planning_sdk_br import (
    ValidationIssue,
    ValidationReport,
    compute_deterministic,
    deterministic_request_schema,
    deterministic_result_schema,
    reference_acceptance_report_schema,
    run_reference_acceptance_pack,
    validation_report_schema,
)
from financial_planning_sdk_br import _schema_validation as schema_validation_module
from financial_planning_sdk_br import contracts as contracts_module
from financial_planning_sdk_br._schema_validation import (
    SUPPORTED_PATTERNS,
    ClosedSchemaError,
    SchemaInstanceError,
    assert_schema_instance,
    assert_supported_schema,
)
from financial_planning_sdk_br.jsonio import JsonContractError

REPO_ROOT = Path(__file__).resolve().parents[2]
TERMINATORS = ("\n", "\r", "\u0085", "\u2028", "\u2029")


def _significant_digits(value: str) -> int:
    digits = value.lstrip("-").replace(".", "").lstrip("0")
    return len(digits) or 1


def _validate_significant_digits(
    _validator: Draft202012Validator,
    budget: int,
    instance: object,
    _schema: dict[str, object],
) -> Any:
    if type(instance) is str and _significant_digits(instance) > budget:
        yield ValidationError("value exceeds x-significant-digit-budget")


DifferentialValidator = validators.extend(
    Draft202012Validator,
    {"x-significant-digit-budget": _validate_significant_digits},
)


def _collect_patterns(value: object) -> set[str]:
    patterns: set[str] = set()
    if type(value) is dict:
        for key, child in cast(dict[str, object], value).items():
            if key == "pattern":
                patterns.add(cast(str, child))
            else:
                patterns.update(_collect_patterns(child))
    elif type(value) is list:
        for child in cast(list[object], value):
            patterns.update(_collect_patterns(child))
    return patterns


class ClosedSchemaValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.request = json.loads((REPO_ROOT / "examples" / "deterministic-cashflow-ledger.json").read_bytes())
        cls.result = compute_deterministic(copy.deepcopy(cls.request)).to_dict()
        cls.reference = run_reference_acceptance_pack().to_dict()
        cls.validation = ValidationReport(
            valid=False,
            issues=(ValidationIssue("DCL_REQUIRED_FIELD", "/events", "required field is missing"),),
        ).to_dict()
        cls.schemas = {
            "request": deterministic_request_schema(),
            "result": deterministic_result_schema(),
            "validation": validation_report_schema(),
            "reference": reference_acceptance_report_schema(),
        }

    def assert_differential(self, schema: dict[str, object], instance: object) -> None:
        validator = DifferentialValidator(schema, format_checker=FormatChecker())
        expected = validator.is_valid(instance)
        try:
            assert_schema_instance(cast(dict[str, Any], schema), instance)
        except SchemaInstanceError:
            observed = False
        else:
            observed = True
        self.assertEqual(observed, expected)

    def test_pattern_inventory_is_exactly_the_four_packaged_schemas(self) -> None:
        observed: set[str] = set()
        for schema in self.schemas.values():
            Draft202012Validator.check_schema(schema)
            observed.update(_collect_patterns(schema))
        self.assertEqual(observed, set(SUPPORTED_PATTERNS))
        self.assertEqual(len(observed), 17)

    def test_each_packaged_schema_is_digest_bound_before_use(self) -> None:
        names = (
            "deterministic-request.schema.json",
            "deterministic-result.schema.json",
            "reference-acceptance-report.schema.json",
            "validation-report.schema.json",
        )
        self.assertEqual(set(names), set(contracts_module._SCHEMA_SHA256))
        for name in names:
            payload = (REPO_ROOT / "src" / "financial_planning_sdk_br" / name).read_bytes() + b" "
            resource = Mock()
            resource.open.return_value = io.BytesIO(payload)
            package = Mock()
            package.joinpath.return_value = resource
            with self.subTest(name=name), patch.object(contracts_module, "files", return_value=package):
                with self.assertRaisesRegex(JsonContractError, "digest mismatch"):
                    contracts_module._load(name)

    def test_every_pattern_preserves_search_and_absolute_end_semantics(self) -> None:
        samples = {
            r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?$(?![\s\S])": "1.0",
            r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,20})?$(?![\s\S])": "1.0",
            r"^-?(?:0|[1-9][0-9]*)\.[0-9]{2}$(?![\s\S])": "1.00",
            r"^(?:|/(?:[ -}]|~[01])*)$(?![\s\S])": "/ok",
            r"^(?:|/(?:[A-Za-z0-9_.~-]+)(?:/[A-Za-z0-9_.~-]+)*)$(?![\s\S])": "/cases/0",
            r"^(?:|/cases(?:/[0-9]+)?)$(?![\s\S])": "/cases/0",
            r"^[ -~]+$(?![\s\S])": "message",
            r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$(?![\s\S])": "2026-01-01",
            r"^[0-9a-f]{64}$(?![\s\S])": "0" * 64,
            r"^[a-z][a-z0-9_-]{0,63}$(?![\s\S])": "identifier",
            r"^[a-z][a-z0-9_.-]{0,127}$(?![\s\S])": "identifier.rule",
            r"^/": "/open-prefix",
            r"^/(?:case_roster(?:/[0-9]+)?|cases(?:/[0-2]/case_id)?)$(?![\s\S])": "/case_roster/0",
            (
                r"^/cases/[0-2]/(?:expected_output(?:_sha256)?|"
                r"assertions(?:/(?:[0-9]|1[0-5])(?:/(?:assertion_id|rule_id|json_pointer|expected))?)?)"
                r"$(?![\s\S])"
            ): "/cases/0/expected_output",
            r"^/cases/[0-2]/derivation_id$(?![\s\S])": "/cases/0/derivation_id",
            r"^/cases/[0-2]/operation$(?![\s\S])": "/cases/0/operation",
            r"^/cases/[0-2]/request(?:/use_context)?$(?![\s\S])": "/cases/0/request/use_context",
        }
        self.assertEqual(set(samples), set(SUPPORTED_PATTERNS))
        for pattern, sample in samples.items():
            schema: dict[str, object] = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "urn:finplanbr:test:pattern",
                "type": "string",
                "pattern": pattern,
            }
            assert_supported_schema(cast(dict[str, Any], schema), expected_id="urn:finplanbr:test:pattern")
            self.assert_differential(schema, sample)
            for terminator in TERMINATORS:
                with self.subTest(pattern=pattern, terminator=ascii(terminator)):
                    candidate = sample + terminator
                    self.assert_differential(schema, candidate)
                    expected = pattern == r"^/"
                    self.assertEqual(DifferentialValidator(schema).is_valid(candidate), expected)

    def test_runtime_and_jsonschema_agree_on_valid_wires_and_closed_mutations(self) -> None:
        cases: list[tuple[str, dict[str, object], object]] = []
        for name, baseline in (
            ("request", self.request),
            ("result", self.result),
            ("validation", self.validation),
            ("reference", self.reference),
        ):
            cases.append((f"{name}-valid", self.schemas[name], baseline))
            missing = copy.deepcopy(baseline)
            missing.pop(next(iter(cast(dict[str, object], missing))))
            cases.append((f"{name}-missing", self.schemas[name], missing))
            extra = copy.deepcopy(baseline)
            extra["unexpected"] = None
            cases.append((f"{name}-extra", self.schemas[name], extra))

        for terminator in TERMINATORS:
            request = copy.deepcopy(self.request)
            request["calculation_id"] += terminator
            cases.append((f"request-terminator-{ord(terminator):x}", self.schemas["request"], request))

            result = copy.deepcopy(self.result)
            result["calculation_id"] += terminator
            cases.append((f"result-terminator-{ord(terminator):x}", self.schemas["result"], result))

            validation = copy.deepcopy(self.validation)
            validation["issues"][0]["pointer"] += terminator
            cases.append((f"validation-pointer-{ord(terminator):x}", self.schemas["validation"], validation))
            validation_message = copy.deepcopy(self.validation)
            validation_message["issues"][0]["message"] += terminator
            cases.append(
                (f"validation-message-{ord(terminator):x}", self.schemas["validation"], validation_message)
            )

            reference = copy.deepcopy(self.reference)
            reference["cases"][0]["case_id"] += terminator
            cases.append((f"reference-terminator-{ord(terminator):x}", self.schemas["reference"], reference))

        result_warnings = copy.deepcopy(self.result)
        result_warnings["warnings"].pop()
        cases.append(("result-prefix-items", self.schemas["result"], result_warnings))
        result_digits = copy.deepcopy(self.result)
        result_digits["valuation"]["present_value"] = "1" * 39 + ".00"
        cases.append(("result-significant-digits", self.schemas["result"], result_digits))
        invalid_counter = copy.deepcopy(self.reference)
        invalid_counter["passed_count"] = 2
        cases.append(("reference-condition", self.schemas["reference"], invalid_counter))
        wrong_authority = copy.deepcopy(self.reference)
        wrong_authority["authority"] = "external"
        cases.append(("reference-authority", self.schemas["reference"], wrong_authority))

        for label, schema, candidate in cases:
            with self.subTest(label=label):
                self.assert_differential(schema, candidate)

    def test_ref_siblings_apply_and_profile_fails_closed_on_schema_drift(self) -> None:
        schema: dict[str, object] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:finplanbr:test:ref-sibling",
            "$defs": {"text": {"type": "string"}},
            "$ref": "#/$defs/text",
            "const": "bound",
        }
        assert_supported_schema(cast(dict[str, Any], schema), expected_id="urn:finplanbr:test:ref-sibling")
        assert_schema_instance(cast(dict[str, Any], schema), "bound")
        with self.assertRaises(SchemaInstanceError):
            assert_schema_instance(cast(dict[str, Any], schema), "unbound")

        corruptions: tuple[Callable[[dict[str, object]], None], ...] = (
            lambda value: value.update({"unknownKeyword": True}),
            lambda value: value.update({"format": "uri"}),
            lambda value: value.update({"$ref": "https://example.invalid/schema"}),
            lambda value: value.update({"pattern": ".*"}),
        )
        for mutate in corruptions:
            candidate = copy.deepcopy(schema)
            mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(ClosedSchemaError):
                assert_supported_schema(
                    cast(dict[str, Any], candidate),
                    expected_id="urn:finplanbr:test:ref-sibling",
                )

    def test_root_only_identifiers_and_acyclic_ref_topology_are_admission_requirements(self) -> None:
        expected_id = "urn:finplanbr:test:root-only"
        for keyword, value in (
            ("$schema", "https://json-schema.org/draft/2020-12/schema"),
            ("$id", "urn:finplanbr:test:nested-resource"),
        ):
            schema: dict[str, object] = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": expected_id,
                "$defs": {"target": {"type": "string", keyword: value}},
                "$ref": "#/$defs/target",
            }
            with self.subTest(keyword=keyword), self.assertRaises(ClosedSchemaError):
                assert_supported_schema(cast(dict[str, Any], schema), expected_id=expected_id)

        for token in (
            "a%2Fb",
            "a%2fb",
            "a%7Eb",
            "a%25b",
            "a#b",
            "a b",
            "a\\b",
            "a\tb",
        ):
            escaped_schema: dict[str, object] = {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": expected_id,
                "$defs": {token: {"type": "string"}},
                "$ref": f"#/$defs/{token}",
            }
            with self.subTest(ref_token=token), self.assertRaises(ClosedSchemaError):
                assert_supported_schema(cast(dict[str, Any], escaped_schema), expected_id=expected_id)

        cycles: tuple[dict[str, object], ...] = (
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": expected_id,
                "$defs": {"loop": {"$ref": "#/$defs/loop"}},
                "$ref": "#/$defs/loop",
            },
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": expected_id,
                "$defs": {
                    "left": {"allOf": [{"$ref": "#/$defs/right"}]},
                    "right": {"properties": {"value": {"$ref": "#/$defs/left"}}},
                },
                "$ref": "#/$defs/left",
            },
        )
        for schema in cycles:
            with (
                self.subTest(schema=schema),
                patch.object(
                    schema_validation_module,
                    "_matches",
                    side_effect=AssertionError("matching must not start for cyclic schemas"),
                ) as matcher,
                self.assertRaises(ClosedSchemaError),
            ):
                assert_schema_instance(cast(dict[str, Any], schema), None)
            matcher.assert_not_called()

    def test_recursion_never_escapes_the_closed_schema_boundaries(self) -> None:
        expected_id = "urn:finplanbr:test:recursion"
        recursive_node: dict[str, object] = {}
        recursive_node["not"] = recursive_node
        recursive_schema: dict[str, object] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": expected_id,
            "$defs": {"loop": recursive_node},
            "$ref": "#/$defs/loop",
        }
        with self.assertRaises(ClosedSchemaError):
            assert_supported_schema(cast(dict[str, Any], recursive_schema), expected_id=expected_id)

        deeply_nested: object = None
        for _index in range(2_000):
            deeply_nested = [deeply_nested]
        instance_schema: dict[str, object] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": expected_id,
            "const": deeply_nested,
        }
        with self.assertRaises(SchemaInstanceError):
            assert_schema_instance(cast(dict[str, Any], instance_schema), deeply_nested)


if __name__ == "__main__":
    unittest.main()
