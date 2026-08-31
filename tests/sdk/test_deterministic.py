from __future__ import annotations

import copy
import json
import random
import re
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from financial_planning_sdk_br import (
    DETERMINISTIC_REASON_CODES,
    DeterministicResult,
    compute_deterministic,
    deterministic_request_schema,
    deterministic_result_schema,
    validate_deterministic_request,
)
from financial_planning_sdk_br.jsonio import (
    MAX_DETERMINISTIC_REQUEST_NODES,
    MAX_DETERMINISTIC_RESULT_BYTES,
    MAX_DETERMINISTIC_RESULT_NODES,
    MAX_NODES,
    JsonContractError,
    canonical_json_bytes,
    loads_strict,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def money(value: str) -> dict[str, str]:
    return {"currency": "BRL", "value": value}


def base_request() -> dict[str, object]:
    return {
        "contract_version": "0.1.0-draft.1",
        "calculation_id": "test_case_001",
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


class DeterministicEngineTests(unittest.TestCase):
    def test_public_request_and_result_schemas_match_runtime(self) -> None:
        request_schema = deterministic_request_schema()
        result_schema = deterministic_result_schema()
        Draft202012Validator.check_schema(request_schema)
        Draft202012Validator.check_schema(result_schema)
        document = json.loads((REPO_ROOT / "examples/deterministic-cashflow-ledger.json").read_text(encoding="utf-8"))
        request_errors = list(
            Draft202012Validator(request_schema, format_checker=FormatChecker()).iter_errors(document)
        )
        self.assertEqual(request_errors, [])
        result = compute_deterministic(document).to_dict()
        result_errors = list(Draft202012Validator(result_schema, format_checker=FormatChecker()).iter_errors(result))
        self.assertEqual(result_errors, [])

        mutated = copy.deepcopy(document)
        mutated["unmodeled"] = True
        self.assertTrue(list(Draft202012Validator(request_schema).iter_errors(mutated)))

    def test_repository_example_is_valid_and_computes(self) -> None:
        document = json.loads((REPO_ROOT / "examples/deterministic-cashflow-ledger.json").read_text(encoding="utf-8"))
        report = validate_deterministic_request(document)
        self.assertTrue(report.valid, report.issues)
        result = compute_deterministic(document).to_dict()
        self.assertEqual(result["valuation"]["present_value"], "-1.60")
        self.assertEqual(result["valuation"]["present_value_exact"], "-1.6")
        self.assertEqual(result["ledger"]["opening_consolidated_wealth"], "110.00")
        self.assertEqual(result["ledger"]["closing_consolidated_wealth"], "118.15")
        self.assertEqual(result["ledger"]["consolidated_transfer_contribution"], "0.00")
        self.assertEqual(result["authority"], "none")
        self.assertEqual(result["deployment_eligibility"], "not_authorized")

    def test_pv_vectors_and_final_half_even_rounding(self) -> None:
        request = base_request()
        request["discount_factors"] = [
            {"date": "2027-01-01", "factor": "0.9"},
            {"date": "2028-01-01", "factor": "0.81"},
            {"date": "2029-01-01", "factor": "0.729"},
        ]
        request["cashflows"] = [
            {
                "cashflow_id": f"payment_{index}",
                "claim_id": f"claim_{index}",
                "event_date": f"{2026 + index}-01-01",
                "amount": money("100.00"),
            }
            for index in range(1, 4)
        ]
        result = compute_deterministic(request).to_dict()
        self.assertEqual(result["valuation"]["present_value"], "243.90")
        self.assertEqual(result["valuation"]["present_value_exact"], "243.9")

        tie = base_request()
        tie["discount_factors"] = [{"date": "2027-01-01", "factor": "0.005"}]
        tie["cashflows"] = [
            {
                "cashflow_id": "tie",
                "claim_id": "tie_claim",
                "event_date": "2027-01-01",
                "amount": money("1.00"),
            }
        ]
        tie_result = compute_deterministic(tie).to_dict()
        self.assertEqual(tie_result["valuation"]["present_value_exact"], "0.005")
        self.assertEqual(tie_result["valuation"]["present_value"], "0.00")

    def test_cent_exact_balance_reconciliation(self) -> None:
        request = base_request()
        request["accounts"] = [{"account_id": "cash", "opening_balance": money("100.00"), "return_basis": "none"}]
        request["events"] = [
            {
                "event_type": "posting",
                "event_id": f"event_{index}",
                "effective_date": f"2026-01-0{index + 1}",
                "sequence": index,
                "account_id": "cash",
                "category": "adjustment",
                "claim_id": f"claim_{index}",
                "amount": money(amount),
            }
            for index, amount in enumerate(("20.00", "-3.33", "-7.67"), start=1)
        ]
        ledger = compute_deterministic(request).to_dict()["ledger"]
        self.assertEqual(ledger["posting_net_change"], "9.00")
        self.assertEqual(ledger["return_net_change"], "0.00")
        self.assertEqual(ledger["closing_consolidated_wealth"], "109.00")
        self.assertTrue(ledger["reconciled"])

    def test_internal_transfer_conserves_consolidated_wealth(self) -> None:
        request = base_request()
        request["accounts"] = [
            {"account_id": "account_a", "opening_balance": money("100.00"), "return_basis": "none"},
            {"account_id": "account_b", "opening_balance": money("10.00"), "return_basis": "none"},
        ]
        request["events"] = [
            {
                "event_type": "transfer",
                "event_id": "transfer_001",
                "effective_date": "2026-01-02",
                "sequence": 1,
                "from_account_id": "account_b",
                "to_account_id": "account_a",
                "economic_source_id": "synthetic_transfer_001",
                "amount": money("3.00"),
            }
        ]
        ledger = compute_deterministic(request).to_dict()["ledger"]
        balances = {item["account_id"]: item["closing_balance"] for item in ledger["accounts"]}
        self.assertEqual(balances, {"account_a": "103.00", "account_b": "7.00"})
        self.assertEqual(ledger["opening_consolidated_wealth"], "110.00")
        self.assertEqual(ledger["closing_consolidated_wealth"], "110.00")
        self.assertEqual(ledger["consolidated_transfer_contribution"], "0.00")

    def test_price_return_and_total_return_do_not_double_count_income(self) -> None:
        price = base_request()
        price["accounts"] = [
            {"account_id": "portfolio", "opening_balance": money("100.00"), "return_basis": "price_return"}
        ]
        price["events"] = [
            {
                "event_type": "return",
                "event_id": "return_001",
                "effective_date": "2026-12-31",
                "sequence": 1,
                "account_id": "portfolio",
                "return_basis": "price_return",
                "rate": "0.05",
                "cash_distribution": money("3.00"),
            }
        ]
        event = compute_deterministic(price).to_dict()["ledger"]["events"][0]
        self.assertEqual(event["asset_value_after_return"], "105.00")
        self.assertEqual(event["cash_distribution"], "3.00")
        self.assertEqual(event["postings"][0]["after_balance"], "108.00")

        total = copy.deepcopy(price)
        total["accounts"][0]["return_basis"] = "total_return"
        total["events"][0]["return_basis"] = "total_return"
        total["events"][0]["rate"] = "0.08"
        total["events"][0]["cash_distribution"] = money("0.00")
        total_event = compute_deterministic(total).to_dict()["ledger"]["events"][0]
        self.assertEqual(total_event["postings"][0]["after_balance"], "108.00")

        total["events"][0]["cash_distribution"] = money("3.00")
        report = validate_deterministic_request(total)
        self.assertFalse(report.valid)
        self.assertIn("DCL_RETURN_BASIS_DOUBLE_COUNT", {issue.code for issue in report.issues})

    def test_validation_rejects_missing_factor_order_and_negative_balance(self) -> None:
        missing = base_request()
        missing["cashflows"] = [
            {
                "cashflow_id": "future",
                "claim_id": "future_claim",
                "event_date": "2027-01-01",
                "amount": money("1.00"),
            }
        ]
        self.assertIn(
            "DCL_DISCOUNT_FACTOR_MISSING",
            {issue.code for issue in validate_deterministic_request(missing).issues},
        )

        ordered = base_request()
        ordered["accounts"] = [{"account_id": "cash", "opening_balance": money("1.00"), "return_basis": "none"}]
        ordered["events"] = [
            {
                "event_type": "posting",
                "event_id": "second",
                "effective_date": "2026-01-03",
                "sequence": 2,
                "account_id": "cash",
                "category": "withdrawal",
                "claim_id": "claim_second",
                "amount": money("-2.00"),
            },
            {
                "event_type": "posting",
                "event_id": "first",
                "effective_date": "2026-01-02",
                "sequence": 1,
                "account_id": "cash",
                "category": "contribution",
                "claim_id": "claim_first",
                "amount": money("1.00"),
            },
        ]
        self.assertIn(
            "DCL_NONCANONICAL_ORDER",
            {issue.code for issue in validate_deterministic_request(ordered).issues},
        )
        ordered["events"].reverse()
        ordered["events"][1]["amount"] = money("-3.00")
        self.assertIn(
            "DCL_NEGATIVE_BALANCE",
            {issue.code for issue in validate_deterministic_request(ordered).issues},
        )

    def test_seeded_transfer_property_is_cent_exact(self) -> None:
        generator = random.Random(20260809)
        for index in range(100):
            left = generator.randint(1, 1_000_000)
            right = generator.randint(1, 1_000_000)
            amount = generator.randint(0, right)
            request = base_request()
            request["calculation_id"] = f"property_{index}"
            request["accounts"] = [
                {"account_id": "a", "opening_balance": money(f"{left / 100:.2f}"), "return_basis": "none"},
                {"account_id": "b", "opening_balance": money(f"{right / 100:.2f}"), "return_basis": "none"},
            ]
            request["events"] = [
                {
                    "event_type": "transfer",
                    "event_id": f"transfer_{index}",
                    "effective_date": "2026-01-02",
                    "sequence": index,
                    "from_account_id": "b",
                    "to_account_id": "a",
                    "economic_source_id": f"source_{index}",
                    "amount": money(f"{amount / 100:.2f}"),
                }
            ]
            if amount == 0:
                request["events"][0]["amount"] = money("0.01")
            result = compute_deterministic(request).to_dict()["ledger"]
            self.assertEqual(result["opening_consolidated_wealth"], result["closing_consolidated_wealth"])
            self.assertEqual(result["consolidated_transfer_contribution"], "0.00")

    def test_strict_json_and_canonical_output(self) -> None:
        with self.assertRaises(JsonContractError):
            loads_strict(b'{"a":1,"a":2}')
        with self.assertRaises(JsonContractError):
            loads_strict(b'{"rate":0.1}')
        document = {"z": "á", "a": [1, True, None]}
        self.assertEqual(canonical_json_bytes(document), b'{"a":[1,true,null],"z":"\xc3\xa1"}')

    def test_deep_valid_json_fails_under_the_closed_depth_budget(self) -> None:
        payload = b"[" * 5_000 + b"null" + b"]" * 5_000
        with self.assertRaises(JsonContractError) as raised:
            loads_strict(payload)
        self.assertEqual(raised.exception.reason, "depth_budget")
        self.assertEqual(str(raised.exception), "JSON document exceeds the depth budget")

    def test_route_specific_json_budgets_reject_one_node_or_byte_over(self) -> None:
        for label, max_nodes in (
            ("generic", MAX_NODES),
            ("deterministic_request", MAX_DETERMINISTIC_REQUEST_NODES),
            ("deterministic_result", MAX_DETERMINISTIC_RESULT_NODES),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(JsonContractError, "node budget"):
                canonical_json_bytes(
                    [None] * max_nodes,
                    max_bytes=MAX_DETERMINISTIC_RESULT_BYTES,
                    max_nodes=max_nodes,
                )
        with self.assertRaisesRegex(JsonContractError, "byte budget"):
            canonical_json_bytes({"a": "b"}, max_bytes=8, max_nodes=MAX_NODES)

    def test_result_copy_cannot_mutate_engine_result(self) -> None:
        result = compute_deterministic(base_request())
        first = result.to_dict()
        first["warnings"].append("MUTATED")
        self.assertNotIn("MUTATED", result.to_dict()["warnings"])
        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(result, "_canonical_payload", b"{}")
        with self.assertRaisesRegex(TypeError, "only be created"):
            DeterministicResult(b"{}")

    def test_reason_code_roster_is_closed_and_source_complete(self) -> None:
        package_root = REPO_ROOT / "src" / "financial_planning_sdk_br"
        observed: set[str] = set()
        for source in package_root.glob("*.py"):
            observed.update(re.findall(r'"(DCL_[A-Z0-9_]+)"', source.read_text(encoding="utf-8")))
        self.assertEqual(observed, set(DETERMINISTIC_REASON_CODES))
        self.assertEqual(len(observed), 36)

    def test_numeric_overflow_is_a_closed_validation_failure(self) -> None:
        request = base_request()
        request["discount_factors"] = [{"date": "2027-01-01", "factor": "99999999999999999999999999999999999999"}]
        request["cashflows"] = [
            {
                "cashflow_id": "bounded_overflow",
                "claim_id": "bounded_overflow_claim",
                "event_date": "2027-01-01",
                "amount": money("999999999999999999999999999999999999.99"),
            }
        ]
        report = validate_deterministic_request(request)
        self.assertFalse(report.valid)
        self.assertIn("DCL_NUMERIC_OVERFLOW", {issue.code for issue in report.issues})


if __name__ == "__main__":
    unittest.main()
