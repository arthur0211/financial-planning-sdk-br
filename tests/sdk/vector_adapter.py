"""Closed adapter from selected math vectors to the public SDK surface.

This module is test tooling.  It translates only the seven corpus vectors that
the deterministic 0.1 slice actually implements.  It is neither a second
calculation engine nor a compatibility promise for the remaining corpus.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from financial_planning_sdk_br import compute_deterministic, validate_deterministic_request

MATH_SUT_PROTOCOL = "financial-planning-sdk-br.math-sut.v1"
SDK_CONTRACT_VERSION = "0.1.0-draft.1"


def _money(value: object) -> dict[str, str]:
    if not isinstance(value, str):
        raise ValueError("vector money input must be decimal text")
    return {"currency": "BRL", "value": value}


def _base_request(calculation_id: str) -> dict[str, Any]:
    return {
        "contract_version": SDK_CONTRACT_VERSION,
        "calculation_id": calculation_id,
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


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _pv(vector_input: Mapping[str, Any]) -> dict[str, Any]:
    request = _base_request("vector_pv_unit")
    request["valuation_date"] = vector_input["valuation_date"]
    request["discount_factors"] = [
        {"date": vector_input["payment_date"], "factor": vector_input["discount_factor"]}
    ]
    request["cashflows"] = [
        {
            "cashflow_id": "vector_cashflow",
            "claim_id": "vector_claim",
            "event_date": vector_input["payment_date"],
            "amount": _money(vector_input["cash_flow_amount"]),
        }
    ]
    result = compute_deterministic(request).to_dict()
    return {"present_value": result["valuation"]["present_value"]}


def _annuity(vector_input: Mapping[str, Any]) -> dict[str, Any]:
    factors = vector_input.get("discount_factors")
    if not isinstance(factors, list) or len(factors) != 3:
        raise ValueError("finite-annuity bridge requires exactly three discount factors")
    dates = ("2027-01-01", "2028-01-01", "2029-01-01")
    request = _base_request("vector_finite_annuity")
    request["valuation_date"] = vector_input["valuation_date"]
    request["discount_factors"] = [
        {"date": event_date, "factor": factor}
        for event_date, factor in zip(dates, factors, strict=True)
    ]
    request["cashflows"] = [
        {
            "cashflow_id": f"vector_payment_{index}",
            "claim_id": f"vector_claim_{index}",
            "event_date": event_date,
            "amount": _money(vector_input["payment_amount"]),
        }
        for index, event_date in enumerate(dates, start=1)
    ]
    result = compute_deterministic(request).to_dict()
    return {"present_value": result["valuation"]["present_value"]}


def _balance(vector_input: Mapping[str, Any]) -> dict[str, Any]:
    raw_events = vector_input.get("events")
    if not isinstance(raw_events, list):
        raise ValueError("balance vector events must be an array")
    request = _base_request("vector_balance")
    request["accounts"] = [
        {
            "account_id": "cash",
            "opening_balance": _money(vector_input["opening_balance"]),
            "return_basis": "none",
        }
    ]
    request["events"] = [
        {
            "event_type": "posting",
            "event_id": f"vector_posting_{index}",
            "effective_date": _mapping(event, "balance event")["date"],
            "sequence": index,
            "account_id": "cash",
            "category": "adjustment",
            "claim_id": f"vector_balance_claim_{index}",
            "amount": _money(_mapping(event, "balance event")["amount"]),
        }
        for index, event in enumerate(raw_events, start=1)
    ]
    ledger = compute_deterministic(request).to_dict()["ledger"]
    return {
        "net_change": ledger["posting_net_change"],
        "closing_balance": ledger["closing_consolidated_wealth"],
    }


def _transfer(vector_input: Mapping[str, Any]) -> dict[str, Any]:
    opening_balances = _mapping(vector_input.get("opening_balances"), "opening_balances")
    transfer = _mapping(vector_input.get("transfer"), "transfer")
    request = _base_request("vector_transfer")
    request["accounts"] = [
        {"account_id": account_id, "opening_balance": _money(value), "return_basis": "none"}
        for account_id, value in sorted(opening_balances.items())
    ]
    request["events"] = [
        {
            "event_type": "transfer",
            "event_id": "vector_transfer_event",
            "effective_date": "2026-01-02",
            "sequence": 1,
            "from_account_id": transfer["from_account"],
            "to_account_id": transfer["to_account"],
            "economic_source_id": vector_input["economic_source_id"],
            "amount": _money(transfer["amount"]),
        }
    ]
    ledger = compute_deterministic(request).to_dict()["ledger"]
    event = ledger["events"][0]
    return {
        "ledger_deltas": {posting["account_id"]: posting["delta"] for posting in event["postings"]},
        "closing_balances": {
            account["account_id"]: account["closing_balance"] for account in ledger["accounts"]
        },
        "opening_consolidated_wealth": ledger["opening_consolidated_wealth"],
        "closing_consolidated_wealth": ledger["closing_consolidated_wealth"],
        "consolidated_transfer_contribution": ledger["consolidated_transfer_contribution"],
    }


def _return_request(
    vector_input: Mapping[str, Any],
    *,
    basis: str,
    rate_key: str,
    distribution_key: str,
) -> dict[str, Any]:
    request = _base_request(f"vector_{basis}")
    request["accounts"] = [
        {
            "account_id": "portfolio",
            "opening_balance": _money(vector_input["opening_consolidated_wealth"]),
            "return_basis": basis,
        }
    ]
    request["events"] = [
        {
            "event_type": "return",
            "event_id": "vector_return_event",
            "effective_date": "2026-12-31",
            "sequence": 1,
            "account_id": "portfolio",
            "return_basis": basis,
            "rate": vector_input[rate_key],
            "cash_distribution": _money(vector_input[distribution_key]),
        }
    ]
    return request


def _price_return(vector_input: Mapping[str, Any]) -> dict[str, Any]:
    request = _return_request(
        vector_input,
        basis="price_return",
        rate_key="price_return",
        distribution_key="cash_distribution",
    )
    ledger = compute_deterministic(request).to_dict()["ledger"]
    event = ledger["events"][0]
    return {
        "closing_asset_value": event["asset_value_after_return"],
        "closing_cash_from_distribution": event["cash_distribution"],
        "closing_consolidated_wealth": ledger["closing_consolidated_wealth"],
    }


def _total_return(vector_input: Mapping[str, Any]) -> dict[str, Any]:
    request = _return_request(
        vector_input,
        basis="total_return",
        rate_key="total_return",
        distribution_key="separate_distribution_event",
    )
    ledger = compute_deterministic(request).to_dict()["ledger"]
    event = ledger["events"][0]
    return {
        "closing_account_value": ledger["accounts"][0]["closing_balance"],
        "separate_distribution_event": event["cash_distribution"],
        "closing_consolidated_wealth": ledger["closing_consolidated_wealth"],
    }


def _invalid_total_return(vector_input: Mapping[str, Any]) -> dict[str, Any]:
    request = _return_request(
        vector_input,
        basis="total_return",
        rate_key="period_return",
        distribution_key="separate_distribution_event",
    )
    report = validate_deterministic_request(request)
    codes = {issue.code for issue in report.issues}
    if report.valid or "DCL_RETURN_BASIS_DOUBLE_COUNT" not in codes:
        return {"reason_code": "not_rejected_as_distribution_double_count"}
    return {"reason_code": "distribution_double_count"}


_ROUTES: dict[str, tuple[str, Callable[[Mapping[str, Any]], dict[str, Any]]]] = {
    "pv-unit-cashflow": ("deterministic_present_value", _pv),
    "finite-annuity-certain": ("finite_annuity_closed_form", _annuity),
    "balance-reconciliation": ("cent_exact_balance_reconciliation", _balance),
    "internal-transfer-conservation": ("economic_claim_conservation", _transfer),
    "return-basis-distribution": ("price_return_vs_total_return", _price_return),
    "total-return-positive": ("total_return_without_separate_distribution", _total_return),
    "return-basis-invalid-combination": (
        "total_return_distribution_double_count_rejection",
        _invalid_total_return,
    ),
}

SUPPORTED_VECTOR_IDS = frozenset(_ROUTES)


def compute(request: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one supported math-vector request through the public SDK."""

    if set(request) != {"protocol", "id", "topic", "input"}:
        raise ValueError("vector request must use the closed math-SUT envelope")
    if request.get("protocol") != MATH_SUT_PROTOCOL:
        raise ValueError("unsupported vector protocol")
    vector_id = request.get("id")
    if not isinstance(vector_id, str) or vector_id not in _ROUTES:
        raise ValueError("vector is outside the deterministic SDK bridge")
    expected_topic, route = _ROUTES[vector_id]
    if request.get("topic") != expected_topic:
        raise ValueError("vector topic does not match the closed bridge route")
    return route(_mapping(request.get("input"), "vector input"))
