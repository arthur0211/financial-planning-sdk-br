from __future__ import annotations

import copy
import dataclasses
import importlib
import inspect
import json
import unittest
from collections.abc import Iterator, Mapping
from datetime import date
from decimal import (
    ROUND_05UP,
    ROUND_CEILING,
    ROUND_DOWN,
    ROUND_FLOOR,
    ROUND_HALF_DOWN,
    ROUND_HALF_EVEN,
    ROUND_HALF_UP,
    ROUND_UP,
    Context,
    DecimalException,
    localcontext,
)
from typing import Any
from unittest.mock import patch

import financial_planning_sdk_br as public_sdk
import financial_planning_sdk_br.numeric as numeric_module
from financial_planning_sdk_br import InputValidationError, compute_deterministic, validate_deterministic_request
from financial_planning_sdk_br.jsonio import (
    MAX_DETERMINISTIC_REQUEST_NODES,
    MAX_INPUT_BYTES,
    JsonContractError,
    canonical_json_bytes,
    loads_strict,
)
from tests.sdk.independent_deterministic_challenger import challenge_numeric_result, exact_present_value_text

_ROUNDINGS = (
    ROUND_05UP,
    ROUND_CEILING,
    ROUND_DOWN,
    ROUND_FLOOR,
    ROUND_HALF_DOWN,
    ROUND_HALF_EVEN,
    ROUND_HALF_UP,
    ROUND_UP,
)


def _money(value: str) -> dict[str, str]:
    return {"currency": "BRL", "value": value}


def _base_request() -> dict[str, Any]:
    return {
        "contract_version": "0.1.0-draft.1",
        "calculation_id": "decimal_boundary",
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
        "events": [],
    }


def _cent_loss_request() -> dict[str, Any]:
    request = _base_request()
    request["accounts"] = [
        {
            "account_id": "cash",
            "opening_balance": _money("100000000000000000000000000000.00"),
            "return_basis": "none",
        }
    ]
    request["events"] = [
        {
            "event_type": "posting",
            "event_id": "cent",
            "effective_date": "2026-01-02",
            "sequence": 1,
            "account_id": "cash",
            "category": "adjustment",
            "claim_id": "cent_claim",
            "amount": _money("0.01"),
        }
    ]
    return request


def _context_snapshot(context: Context) -> tuple[object, ...]:
    signals = tuple(sorted(context.flags, key=lambda signal: signal.__name__))
    return (
        context.prec,
        context.rounding,
        context.Emin,
        context.Emax,
        context.capitals,
        context.clamp,
        tuple((signal.__name__, context.flags[signal], context.traps[signal]) for signal in signals),
    )


def _hostile_context(index: int, rounding: str) -> Context:
    precision = (1, 2, 7, 28)[index % 4]
    context = Context(
        prec=precision,
        rounding=rounding,
        Emin=-1,
        Emax=1,
        capitals=index % 2,
        clamp=index % 2,
    )
    for signal_index, signal in enumerate(sorted(context.flags, key=lambda item: item.__name__)):
        context.flags[signal] = (signal_index + index) % 2 == 0
        context.traps[signal] = (signal_index + index) % 3 != 0
    return context


class DecimalContextIsolationTests(unittest.TestCase):
    def test_cent_is_preserved_and_caller_context_is_untouched_across_hostile_matrix(self) -> None:
        request = _cent_loss_request()
        baseline = compute_deterministic(copy.deepcopy(request)).to_json_bytes()
        baseline_validation = validate_deterministic_request(copy.deepcopy(request)).to_dict()
        self.assertEqual(
            json.loads(baseline)["ledger"]["closing_consolidated_wealth"],
            "100000000000000000000000000000.01",
        )

        for index, rounding in enumerate(_ROUNDINGS):
            with self.subTest(rounding=rounding):
                with localcontext(_hostile_context(index, rounding)) as caller:
                    before = _context_snapshot(caller)
                    try:
                        observed_validation = validate_deterministic_request(copy.deepcopy(request)).to_dict()
                        observed = compute_deterministic(copy.deepcopy(request)).to_json_bytes()
                    except DecimalException as exc:  # pragma: no cover - explicit regression guard
                        self.fail(f"public API leaked {type(exc).__name__}")
                    after = _context_snapshot(caller)
                self.assertEqual(observed, baseline)
                self.assertEqual(observed_validation, baseline_validation)
                self.assertEqual(after, before)

    def test_exact_dict_root_matches_json_and_custom_mapping_is_rejected_without_iteration(self) -> None:
        request = _cent_loss_request()
        from_json = json.loads(json.dumps(request))
        self.assertEqual(
            compute_deterministic(from_json).to_json_bytes(),
            compute_deterministic(request).to_json_bytes(),
        )

        class ObservableMapping(Mapping[str, Any]):
            calls = 0

            def __getitem__(self, key: str) -> Any:
                del key
                type(self).calls += 1
                raise AssertionError("custom Mapping code is outside the public boundary")

            def __iter__(self) -> Iterator[str]:
                type(self).calls += 1
                raise AssertionError("custom Mapping code is outside the public boundary")

            def __len__(self) -> int:
                type(self).calls += 1
                raise AssertionError("custom Mapping code is outside the public boundary")

        report = validate_deterministic_request(ObservableMapping())  # type: ignore[arg-type]
        self.assertFalse(report.valid)
        self.assertEqual({issue.code for issue in report.issues}, {"DCL_TYPE_MISMATCH"})
        self.assertEqual(ObservableMapping.calls, 0)
        with self.assertRaises(InputValidationError):
            compute_deterministic(ObservableMapping())  # type: ignore[arg-type]
        self.assertEqual(ObservableMapping.calls, 0)


class IndependentChallengerTests(unittest.TestCase):
    def test_isolated_positive_and_negative_money_ties_cover_pv_and_return_boundaries(self) -> None:
        expected = {
            "0.005": "0.00",
            "0.015": "0.02",
            "-0.005": "0.00",
            "-0.015": "-0.02",
        }
        for tie, rounded in expected.items():
            with self.subTest(surface="pv", tie=tie):
                pv = _base_request()
                pv["calculation_id"] = "isolated_pv_tie"
                pv["discount_factors"] = [{"date": "2026-01-02", "factor": tie.lstrip("-")}]
                pv["cashflows"] = [
                    {
                        "cashflow_id": "tie",
                        "claim_id": "tie_claim",
                        "event_date": "2026-01-02",
                        "amount": _money("-1.00" if tie.startswith("-") else "1.00"),
                    }
                ]
                valuation = compute_deterministic(pv).to_dict()["valuation"]
                self.assertEqual(valuation["present_value_exact"], tie)
                self.assertEqual(valuation["present_value"], rounded)

            with self.subTest(surface="return", tie=tie):
                returned = _base_request()
                returned["calculation_id"] = "isolated_return_tie"
                returned["accounts"] = [
                    {"account_id": "portfolio", "opening_balance": _money("1.00"), "return_basis": "price_return"}
                ]
                returned["events"] = [
                    {
                        "event_type": "return",
                        "event_id": "tie",
                        "effective_date": "2026-01-02",
                        "sequence": 1,
                        "account_id": "portfolio",
                        "return_basis": "price_return",
                        "rate": tie,
                        "cash_distribution": _money("0.00"),
                    }
                ]
                event = compute_deterministic(returned).to_dict()["ledger"]["events"][0]
                self.assertEqual(event["gain"], rounded)

    def test_sequential_returns_use_each_current_balance(self) -> None:
        request = _base_request()
        request["accounts"] = [
            {"account_id": "portfolio", "opening_balance": _money("100.00"), "return_basis": "price_return"}
        ]
        request["events"] = [
            {
                "event_type": "return",
                "event_id": f"return_{index}",
                "effective_date": f"2026-01-0{index + 1}",
                "sequence": index,
                "account_id": "portfolio",
                "return_basis": "price_return",
                "rate": "0.10",
                "cash_distribution": _money("0.00"),
            }
            for index in (1, 2)
        ]
        ledger = compute_deterministic(request).to_dict()["ledger"]
        self.assertEqual([event["gain"] for event in ledger["events"]], ["10.00", "11.00"])
        self.assertEqual(ledger["closing_consolidated_wealth"], "121.00")
        challenge_numeric_result(
            request,
            {
                "valuation": {"present_value_exact": "0", "present_value": "0.00", "cashflows": []},
                "ledger": ledger,
            },
        )

    def test_minimum_product_and_large_cancellation_remain_exact(self) -> None:
        minimum = _base_request()
        minimum["discount_factors"] = [{"date": "2026-01-02", "factor": "0.000000000000000001"}]
        minimum["cashflows"] = [
            {
                "cashflow_id": "minimum",
                "claim_id": "minimum_claim",
                "event_date": "2026-01-02",
                "amount": _money("0.01"),
            }
        ]
        minimum_result = compute_deterministic(minimum).to_dict()
        challenge_numeric_result(minimum, minimum_result)
        self.assertEqual(minimum_result["valuation"]["present_value_exact"], "0.00000000000000000001")

        cancellation = _base_request()
        cancellation["discount_factors"] = [{"date": "2026-01-02", "factor": "1"}]
        cancellation["cashflows"] = [
            {
                "cashflow_id": "a_large_positive",
                "claim_id": "positive_claim",
                "event_date": "2026-01-02",
                "amount": _money("999999999999999999999999999999999999.99"),
            },
            {
                "cashflow_id": "b_cent",
                "claim_id": "cent_claim",
                "event_date": "2026-01-02",
                "amount": _money("0.01"),
            },
            {
                "cashflow_id": "c_large_negative",
                "claim_id": "negative_claim",
                "event_date": "2026-01-02",
                "amount": _money("-999999999999999999999999999999999999.99"),
            },
        ]
        cancellation_result = compute_deterministic(cancellation).to_dict()
        challenge_numeric_result(cancellation, cancellation_result)
        self.assertEqual(cancellation_result["valuation"]["present_value_exact"], "0.01")

    def test_challenger_replays_mixed_ledger_in_cents_and_fraction(self) -> None:
        request = _base_request()
        request["discount_factors"] = [
            {"date": "2026-01-02", "factor": "0.005"},
            {"date": "2026-01-03", "factor": "1.234567890123456789"},
        ]
        request["cashflows"] = [
            {
                "cashflow_id": "negative_tie",
                "claim_id": "negative_tie_claim",
                "event_date": "2026-01-02",
                "amount": _money("-1.00"),
            },
            {
                "cashflow_id": "scaled",
                "claim_id": "scaled_claim",
                "event_date": "2026-01-03",
                "amount": _money("1234567890123456.78"),
            },
        ]
        request["accounts"] = [
            {"account_id": "a", "opening_balance": _money("99999999999999999999.99"), "return_basis": "none"},
            {"account_id": "b", "opening_balance": _money("100.00"), "return_basis": "price_return"},
        ]
        request["events"] = [
            {
                "event_type": "posting",
                "event_id": "post_cent",
                "effective_date": "2026-01-02",
                "sequence": 1,
                "account_id": "a",
                "category": "adjustment",
                "claim_id": "post_cent_claim",
                "amount": _money("0.01"),
            },
            {
                "event_type": "transfer",
                "event_id": "move",
                "effective_date": "2026-01-03",
                "sequence": 2,
                "from_account_id": "b",
                "to_account_id": "a",
                "economic_source_id": "move_source",
                "amount": _money("10.00"),
            },
            {
                "event_type": "return",
                "event_id": "return_tie",
                "effective_date": "2026-01-04",
                "sequence": 3,
                "account_id": "b",
                "return_basis": "price_return",
                "rate": "0.000055555555555556",
                "cash_distribution": _money("0.01"),
            },
        ]
        result = compute_deterministic(request).to_dict()
        challenge_numeric_result(request, result)

    def test_challenger_covers_4096_term_98_digit_precision_bound(self) -> None:
        request = _base_request()
        request["discount_factors"] = [
            {"date": "2026-01-02", "factor": "0.000000000000000001"},
            {"date": "2026-01-03", "factor": "99999999999999999999999999999999999999"},
            {"date": "2026-01-04", "factor": "99999999999999999999999999999999999999"},
        ]
        request["cashflows"] = [
            {
                "cashflow_id": f"a_tiny_{index:04d}",
                "claim_id": f"a_tiny_claim_{index:04d}",
                "event_date": "2026-01-02",
                "amount": _money("0.01"),
            }
            for index in range(2)
        ] + [
            {
                "cashflow_id": f"b_positive_{index:04d}",
                "claim_id": f"b_positive_claim_{index:04d}",
                "event_date": "2026-01-03",
                "amount": _money("999999999999999999999999999999999999.99"),
            }
            for index in range(2047)
        ] + [
            {
                "cashflow_id": f"c_negative_{index:04d}",
                "claim_id": f"c_negative_claim_{index:04d}",
                "event_date": "2026-01-04",
                "amount": _money("-999999999999999999999999999999999999.99"),
            }
            for index in range(2047)
        ]
        expected_exact = "0.00000000000000000002"
        self.assertEqual(exact_present_value_text(request), expected_exact)
        report = validate_deterministic_request(request)
        self.assertTrue(report.valid, report.issues)

        request_payload = json.dumps(
            request,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        with self.assertRaises(JsonContractError):
            loads_strict(request_payload)
        from_json = loads_strict(request_payload, max_nodes=MAX_DETERMINISTIC_REQUEST_NODES)

        baseline = compute_deterministic(request).to_json_bytes()
        self.assertEqual(compute_deterministic(from_json).to_json_bytes(), baseline)
        baseline_result = json.loads(baseline)
        challenge_numeric_result(request, baseline_result)
        self.assertEqual(baseline_result["valuation"]["present_value_exact"], expected_exact)

        with patch.object(numeric_module, "ARITHMETIC_PRECISION", 98):
            self.assertEqual(compute_deterministic(from_json).to_json_bytes(), baseline)
        with patch.object(numeric_module, "ARITHMETIC_PRECISION", 97):
            rejected = validate_deterministic_request(from_json)
            self.assertFalse(rejected.valid)
            self.assertEqual({issue.code for issue in rejected.issues}, {"DCL_NUMERIC_INVARIANT_FAILED"})
            with self.assertRaises(InputValidationError) as raised:
                compute_deterministic(from_json)
        self.assertEqual({issue.code for issue in raised.exception.issues}, {"DCL_NUMERIC_INVARIANT_FAILED"})

        for index, rounding in enumerate(_ROUNDINGS):
            with self.subTest(rounding=rounding):
                with localcontext(_hostile_context(index, rounding)) as caller:
                    before = _context_snapshot(caller)
                    try:
                        observed = compute_deterministic(request).to_json_bytes()
                    except DecimalException as exc:  # pragma: no cover - explicit regression guard
                        self.fail(f"public API leaked {type(exc).__name__}")
                    after = _context_snapshot(caller)
                self.assertEqual(observed, baseline)
                self.assertEqual(after, before)

    def test_38_and_39_digit_boundaries_are_separate_for_money_factor_and_rate(self) -> None:
        money_38 = _base_request()
        money_38["accounts"] = [
            {
                "account_id": "cash",
                "opening_balance": _money("999999999999999999999999999999999999.99"),
                "return_basis": "none",
            }
        ]
        result = compute_deterministic(money_38).to_dict()
        challenge_numeric_result(money_38, result)

        money_39 = copy.deepcopy(money_38)
        money_39["accounts"][0]["opening_balance"] = _money("9999999999999999999999999999999999999.99")

        factor_38 = _base_request()
        factor_38["discount_factors"] = [{"date": "2026-01-02", "factor": "9" * 38}]
        self.assertTrue(validate_deterministic_request(factor_38).valid)
        factor_39 = copy.deepcopy(factor_38)
        factor_39["discount_factors"][0]["factor"] = "9" * 39

        rate_38 = _base_request()
        rate_38["accounts"] = [
            {"account_id": "portfolio", "opening_balance": _money("0.00"), "return_basis": "price_return"}
        ]
        rate_38["events"] = [
            {
                "event_type": "return",
                "event_id": "rate_limit",
                "effective_date": "2026-01-02",
                "sequence": 1,
                "account_id": "portfolio",
                "return_basis": "price_return",
                "rate": "9" * 38,
                "cash_distribution": _money("0.00"),
            }
        ]
        self.assertTrue(validate_deterministic_request(rate_38).valid)
        rate_39 = copy.deepcopy(rate_38)
        rate_39["events"][0]["rate"] = "9" * 39

        for label, request, code, pointer in (
            ("money", money_39, "DCL_INVALID_MONEY", "/accounts/0/opening_balance/value"),
            ("discount_factor", factor_39, "DCL_INVALID_DECIMAL", "/discount_factors/0/factor"),
            ("return_rate", rate_39, "DCL_INVALID_DECIMAL", "/events/0/rate"),
        ):
            with self.subTest(domain=label):
                report = validate_deterministic_request(request)
                self.assertFalse(report.valid)
                self.assertIn((code, pointer), {(issue.code, issue.pointer) for issue in report.issues})

    def test_unexpected_exact_signal_is_a_closed_invariant_diagnostic(self) -> None:
        request = _base_request()
        request["discount_factors"] = [{"date": "2026-01-02", "factor": "1.234567890123456789"}]
        request["cashflows"] = [
            {
                "cashflow_id": "signal",
                "claim_id": "signal_claim",
                "event_date": "2026-01-02",
                "amount": _money("9999999999999999.99"),
            }
        ]
        with patch.object(numeric_module, "ARITHMETIC_PRECISION", 1):
            report = validate_deterministic_request(request)
            self.assertFalse(report.valid)
            self.assertEqual({issue.code for issue in report.issues}, {"DCL_NUMERIC_INVARIANT_FAILED"})
            with self.assertRaises(InputValidationError) as raised:
                compute_deterministic(request)
        self.assertEqual({issue.code for issue in raised.exception.issues}, {"DCL_NUMERIC_INVARIANT_FAILED"})


class PublicApiInvariantTests(unittest.TestCase):
    def test_sdk_applies_canonical_one_mib_and_recursive_exact_json_type_boundary(self) -> None:
        oversized = _base_request()
        oversized["discount_factors"] = [{"date": "2026-01-02", "factor": "1"}]
        oversized["cashflows"] = [
            {
                "cashflow_id": f"c{index:04d}" + "x" * 59,
                "claim_id": f"q{index:04d}" + "y" * 59,
                "event_date": "2026-01-02",
                "amount": _money(
                    ("-" if index % 2 else "") + "999999999999999999999999999999999999.99"
                ),
            }
            for index in range(4096)
        ]
        payload = canonical_json_bytes(
            oversized,
            max_bytes=2 * MAX_INPUT_BYTES,
            max_nodes=MAX_DETERMINISTIC_REQUEST_NODES,
        )
        self.assertGreater(len(payload), MAX_INPUT_BYTES)
        report = validate_deterministic_request(oversized)
        self.assertFalse(report.valid)
        self.assertEqual({issue.code for issue in report.issues}, {"DCL_JSON_INPUT"})
        with self.assertRaises(InputValidationError) as raised:
            compute_deterministic(oversized)
        self.assertEqual({issue.code for issue in raised.exception.issues}, {"DCL_JSON_INPUT"})

        class ObservableList(list[object]):
            calls = 0

            def __iter__(self) -> Iterator[object]:
                type(self).calls += 1
                raise AssertionError("custom container code must not execute")

        custom_nested = _base_request()
        custom_nested["events"] = ObservableList()
        nested_report = validate_deterministic_request(custom_nested)  # type: ignore[arg-type]
        self.assertFalse(nested_report.valid)
        self.assertEqual({issue.code for issue in nested_report.issues}, {"DCL_JSON_INPUT"})
        self.assertEqual(ObservableList.calls, 0)

    def test_public_input_annotations_name_recursive_json_object_not_any_or_mapping(self) -> None:
        self.assertIn("JsonObject", public_sdk.__all__)
        for function in (compute_deterministic, validate_deterministic_request):
            annotation = inspect.signature(function).parameters["data"].annotation
            rendered = str(annotation)
            self.assertIn("JsonObject", rendered)
            self.assertNotIn("Any", rendered)
            self.assertNotIn("Mapping", rendered)

    def test_public_functions_have_discoverable_docstrings(self) -> None:
        functions = (
            public_sdk.compute_deterministic,
            public_sdk.deterministic_request_schema,
            public_sdk.deterministic_result_schema,
            public_sdk.reference_acceptance_report_schema,
            public_sdk.run_reference_acceptance_pack,
            public_sdk.validate_deterministic_request,
            public_sdk.validation_report_schema,
        )
        for function in functions:
            with self.subTest(function=function.__name__):
                self.assertTrue(inspect.getdoc(function))

    def test_non_json_python_values_and_broken_mapping_fail_without_user_code_execution_escape(self) -> None:
        class ExplosiveValue:
            def __eq__(self, other: object) -> bool:
                del other
                raise RuntimeError("user equality must not run")

            def __hash__(self) -> int:
                raise RuntimeError("user hash must not run")

        malformed = _base_request()
        malformed["contract_version"] = ExplosiveValue()
        malformed["base_currency"] = ExplosiveValue()
        malformed["use_context"]["purpose"] = ExplosiveValue()
        report = validate_deterministic_request(malformed)
        self.assertFalse(report.valid)
        with self.assertRaises(InputValidationError):
            compute_deterministic(malformed)

        class BrokenMapping(Mapping[str, Any]):
            def __getitem__(self, key: str) -> Any:
                del key
                raise RuntimeError("mapping acquisition failed")

            def __iter__(self) -> Iterator[str]:
                raise RuntimeError("mapping acquisition failed")

            def __len__(self) -> int:
                return 1

        broken_report = validate_deterministic_request(BrokenMapping())
        self.assertFalse(broken_report.valid)
        self.assertEqual({issue.code for issue in broken_report.issues}, {"DCL_TYPE_MISMATCH"})
        with self.assertRaises(InputValidationError) as raised:
            compute_deterministic(BrokenMapping())
        self.assertEqual({issue.code for issue in raised.exception.issues}, {"DCL_TYPE_MISMATCH"})

    def test_internal_manual_replace_and_forged_objects_cannot_compute(self) -> None:
        deterministic_module = importlib.import_module("financial_planning_sdk_br.deterministic")
        parsed = deterministic_module._parse_deterministic_request(_base_request())
        request_type = type(parsed)
        manual = request_type(
            calculation_id="UPPERCASE_INVALID",
            valuation_date=date(2026, 1, 1),
            base_currency="USD",
            purpose="personal_recommendation",
            client_specific=True,
            recommendation_enabled=True,
            execution_enabled=True,
            discount_factors=(),
            cashflows=(),
            accounts=(),
            events=(),
            contract_version="forged-version",
        )
        replaced = dataclasses.replace(parsed, base_currency="USD", execution_enabled=True)

        class ForgedRequest:
            contract_version = "0.1.0-draft.1"
            calculation_id = "looks_valid"
            valuation_date = date(2026, 1, 1)
            base_currency = "BRL"

        for label, value in (
            ("parsed", parsed),
            ("manual", manual),
            ("replace", replaced),
            ("forged", ForgedRequest()),
            ("uninitialized", object.__new__(request_type)),
        ):
            with self.subTest(route=label):
                report = validate_deterministic_request(value)
                self.assertFalse(report.valid)
                self.assertEqual({issue.code for issue in report.issues}, {"DCL_TYPE_MISMATCH"})
                with self.assertRaises(InputValidationError) as raised:
                    compute_deterministic(value)
                self.assertEqual({issue.code for issue in raised.exception.issues}, {"DCL_TYPE_MISMATCH"})

    def test_internal_request_types_and_parser_are_not_public_sdk_exports(self) -> None:
        self.assertNotIn("DeterministicRequest", public_sdk.__all__)
        self.assertNotIn("parse_deterministic_request", public_sdk.__all__)
        self.assertFalse(hasattr(public_sdk, "DeterministicRequest"))
        self.assertFalse(hasattr(public_sdk, "parse_deterministic_request"))


if __name__ == "__main__":
    unittest.main()
