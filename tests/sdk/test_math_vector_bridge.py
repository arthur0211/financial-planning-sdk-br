from __future__ import annotations

import json
import random
import unittest
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path

from financial_planning_sdk_br import compute_deterministic, validate_deterministic_request

REPO_ROOT = Path(__file__).resolve().parents[2]
VECTOR_ROOT = REPO_ROOT / "tests" / "vectors" / "math" / "v1"


def load_vector(name: str) -> dict[str, object]:
    return json.loads((VECTOR_ROOT / f"{name}.json").read_text(encoding="utf-8"))


def money(value: str) -> dict[str, str]:
    return {"currency": "BRL", "value": value}


def request() -> dict[str, object]:
    return {
        "contract_version": "0.1.0-draft.1",
        "calculation_id": "vector_bridge",
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


class MathVectorBridgeTests(unittest.TestCase):
    def test_pv_and_annuity_vectors_use_the_real_sdk(self) -> None:
        pv = load_vector("pv-unit-cashflow")
        pv_input = pv["input"]
        self.assertIsInstance(pv_input, dict)
        case = request()
        case["valuation_date"] = pv_input["valuation_date"]
        case["discount_factors"] = [{"date": pv_input["payment_date"], "factor": pv_input["discount_factor"]}]
        case["cashflows"] = [
            {
                "cashflow_id": "pv_cashflow",
                "claim_id": "pv_claim",
                "event_date": pv_input["payment_date"],
                "amount": money(pv_input["cash_flow_amount"]),
            }
        ]
        self.assertEqual(
            compute_deterministic(case).to_dict()["valuation"]["present_value"],
            pv["expected_output"]["present_value"],
        )

        annuity = load_vector("finite-annuity-certain")
        annuity_input = annuity["input"]
        self.assertIsInstance(annuity_input, dict)
        case = request()
        dates = ["2027-01-01", "2028-01-01", "2029-01-01"]
        case["discount_factors"] = [
            {"date": event_date, "factor": factor}
            for event_date, factor in zip(dates, annuity_input["discount_factors"], strict=True)
        ]
        case["cashflows"] = [
            {
                "cashflow_id": f"annuity_{index}",
                "claim_id": f"annuity_claim_{index}",
                "event_date": event_date,
                "amount": money(annuity_input["payment_amount"]),
            }
            for index, event_date in enumerate(dates, start=1)
        ]
        self.assertEqual(
            compute_deterministic(case).to_dict()["valuation"]["present_value"],
            annuity["expected_output"]["present_value"],
        )

    def test_balance_and_transfer_vectors_use_the_real_sdk(self) -> None:
        balance = load_vector("balance-reconciliation")
        balance_input = balance["input"]
        self.assertIsInstance(balance_input, dict)
        case = request()
        case["accounts"] = [
            {"account_id": "cash", "opening_balance": money(balance_input["opening_balance"]), "return_basis": "none"}
        ]
        case["events"] = [
            {
                "event_type": "posting",
                "event_id": f"posting_{index}",
                "effective_date": event["date"],
                "sequence": index,
                "account_id": "cash",
                "category": "adjustment",
                "claim_id": f"balance_claim_{index}",
                "amount": money(event["amount"]),
            }
            for index, event in enumerate(balance_input["events"], start=1)
        ]
        ledger = compute_deterministic(case).to_dict()["ledger"]
        self.assertEqual(ledger["posting_net_change"], balance["expected_output"]["net_change"])
        self.assertEqual(ledger["return_net_change"], "0.00")
        self.assertEqual(ledger["closing_consolidated_wealth"], balance["expected_output"]["closing_balance"])

        transfer = load_vector("internal-transfer-conservation")
        transfer_input = transfer["input"]
        self.assertIsInstance(transfer_input, dict)
        case = request()
        case["accounts"] = [
            {"account_id": account_id, "opening_balance": money(value), "return_basis": "none"}
            for account_id, value in sorted(transfer_input["opening_balances"].items())
        ]
        transfer_event = transfer_input["transfer"]
        case["events"] = [
            {
                "event_type": "transfer",
                "event_id": "transfer_vector",
                "effective_date": "2026-01-02",
                "sequence": 1,
                "from_account_id": transfer_event["from_account"],
                "to_account_id": transfer_event["to_account"],
                "economic_source_id": transfer_input["economic_source_id"],
                "amount": money(transfer_event["amount"]),
            }
        ]
        ledger = compute_deterministic(case).to_dict()["ledger"]
        closing = {item["account_id"]: item["closing_balance"] for item in ledger["accounts"]}
        self.assertEqual(closing, transfer["expected_output"]["closing_balances"])
        self.assertEqual(
            ledger["consolidated_transfer_contribution"],
            transfer["expected_output"]["consolidated_transfer_contribution"],
        )

    def test_return_basis_vectors_use_the_real_sdk(self) -> None:
        for vector_name, rate_key, distribution_key, basis in (
            ("return-basis-distribution", "price_return", "cash_distribution", "price_return"),
            ("total-return-positive", "total_return", "separate_distribution_event", "total_return"),
        ):
            with self.subTest(vector=vector_name):
                vector = load_vector(vector_name)
                vector_input = vector["input"]
                case = request()
                case["accounts"] = [
                    {
                        "account_id": "portfolio",
                        "opening_balance": money(vector_input["opening_consolidated_wealth"]),
                        "return_basis": basis,
                    }
                ]
                case["events"] = [
                    {
                        "event_type": "return",
                        "event_id": "return_vector",
                        "effective_date": "2026-12-31",
                        "sequence": 1,
                        "account_id": "portfolio",
                        "return_basis": basis,
                        "rate": vector_input[rate_key],
                        "cash_distribution": money(vector_input[distribution_key]),
                    }
                ]
                ledger = compute_deterministic(case).to_dict()["ledger"]
                self.assertEqual(
                    ledger["closing_consolidated_wealth"],
                    vector["expected_output"]["closing_consolidated_wealth"],
                )

        invalid = load_vector("return-basis-invalid-combination")
        invalid_input = invalid["input"]
        self.assertIsInstance(invalid_input, dict)
        case = request()
        case["accounts"] = [
            {
                "account_id": "portfolio",
                "opening_balance": money(invalid_input["opening_consolidated_wealth"]),
                "return_basis": "total_return",
            }
        ]
        case["events"] = [
            {
                "event_type": "return",
                "event_id": "invalid_return_vector",
                "effective_date": "2026-12-31",
                "sequence": 1,
                "account_id": "portfolio",
                "return_basis": "total_return",
                "rate": invalid_input["period_return"],
                "cash_distribution": money(invalid_input["separate_distribution_event"]),
            }
        ]
        report = validate_deterministic_request(case)
        self.assertFalse(report.valid)
        self.assertIn("DCL_RETURN_BASIS_DOUBLE_COUNT", {issue.code for issue in report.issues})

    def test_seeded_pv_differential_uses_fraction_oracle(self) -> None:
        generator = random.Random(20260809)
        for run in range(50):
            case = request()
            factors: list[dict[str, str]] = []
            cashflows: list[dict[str, object]] = []
            expected = Fraction(0)
            for index in range(1, 9):
                amount_cents = generator.randint(-100_000, 100_000)
                factor_millis = generator.randint(1, 2_000)
                amount = f"{Decimal(amount_cents) / Decimal(100):.2f}"
                factor = format(Decimal(factor_millis) / Decimal(1000), "f")
                event_date = f"{2026 + index}-01-01"
                factors.append({"date": event_date, "factor": factor})
                cashflows.append(
                    {
                        "cashflow_id": f"cashflow_{index}",
                        "claim_id": f"claim_{index}",
                        "event_date": event_date,
                        "amount": money(amount),
                    }
                )
                expected += Fraction(amount_cents, 100) * Fraction(factor_millis, 1000)
            case["calculation_id"] = f"differential_{run}"
            case["discount_factors"] = factors
            case["cashflows"] = cashflows
            observed = compute_deterministic(case).to_dict()["valuation"]["present_value_exact"]
            with localcontext() as context:
                context.prec = 60
                expected_decimal = Decimal(expected.numerator) / Decimal(expected.denominator)
            expected_text = format(expected_decimal, "f")
            if "." in expected_text:
                expected_text = expected_text.rstrip("0").rstrip(".")
            if expected_text in {"", "-0"}:
                expected_text = "0"
            self.assertEqual(observed, expected_text)


if __name__ == "__main__":
    unittest.main()
