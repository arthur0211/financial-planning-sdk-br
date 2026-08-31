"""Independent integer/Fraction challenger for the deterministic SDK tests.

This module deliberately does not import the package under test or any binary/
decimal floating-point representation.  It reconstructs every public financial
number from the request's canonical ASCII text.
"""

from __future__ import annotations

import re
from fractions import Fraction
from typing import Any

_DECIMAL_TEXT = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$", re.ASCII)


def _fraction(text: object) -> Fraction:
    if type(text) is not str or _DECIMAL_TEXT.fullmatch(text) is None:
        raise AssertionError("challenger received non-canonical decimal text")
    negative = text.startswith("-")
    unsigned = text[1:] if negative else text
    whole, separator, fractional = unsigned.partition(".")
    scale = 10 ** len(fractional) if separator else 1
    numerator = int(whole) * scale + (int(fractional) if fractional else 0)
    return Fraction(-numerator if negative else numerator, scale)


def _money_cents(value: object) -> int:
    if type(value) is not dict or set(value) != {"currency", "value"}:
        raise AssertionError("challenger received malformed money")
    if value["currency"] != "BRL":
        raise AssertionError("challenger only covers the closed BRL slice")
    text = value["value"]
    if type(text) is not str or re.fullmatch(r"-?(?:0|[1-9][0-9]*)\.[0-9]{2}", text, re.ASCII) is None:
        raise AssertionError("challenger received malformed money text")
    amount = _fraction(text) * 100
    if amount.denominator != 1:
        raise AssertionError("money is not an integral number of cents")
    return amount.numerator


def _round_half_even_cents(value: Fraction) -> int:
    scaled = value * 100
    negative = scaled.numerator < 0
    quotient, remainder = divmod(abs(scaled.numerator), scaled.denominator)
    twice_remainder = remainder * 2
    if twice_remainder > scaled.denominator or (
        twice_remainder == scaled.denominator and quotient % 2 == 1
    ):
        quotient += 1
    return -quotient if negative else quotient


def _format_cents(value: int) -> str:
    sign = "-" if value < 0 else ""
    whole, cents = divmod(abs(value), 100)
    return f"{sign}{whole}.{cents:02d}"


def _format_fraction(value: Fraction) -> str:
    if value == 0:
        return "0"
    denominator = value.denominator
    twos = 0
    fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        raise AssertionError("challenger result is not a finite decimal")
    scale = max(twos, fives)
    scaled = abs(value.numerator) * (2 ** (scale - twos)) * (5 ** (scale - fives))
    digits = str(scaled).rjust(scale + 1, "0")
    if scale:
        whole = digits[:-scale]
        fractional = digits[-scale:].rstrip("0")
        rendered = whole if not fractional else f"{whole}.{fractional}"
    else:
        rendered = digits
    return f"-{rendered}" if value < 0 else rendered


def _require_equal(observed: object, expected: object, label: str) -> None:
    if observed != expected:
        raise AssertionError(f"{label}: observed {observed!r}, expected {expected!r}")


def exact_present_value_text(request: dict[str, Any]) -> str:
    """Return the request PV as independently reconstructed finite text."""

    factor_by_date = {item["date"]: _fraction(item["factor"]) for item in request["discount_factors"]}
    total = sum(
        (
            _fraction(cashflow["amount"]["value"]) * factor_by_date[cashflow["event_date"]]
            for cashflow in request["cashflows"]
        ),
        Fraction(0),
    )
    return _format_fraction(total)


def challenge_numeric_result(request: dict[str, Any], result: dict[str, Any]) -> None:
    """Challenge all financial-number fields without sharing SDK arithmetic."""

    factor_by_date = {item["date"]: _fraction(item["factor"]) for item in request["discount_factors"]}
    present_value = Fraction(0)
    observed_cashflows = result["valuation"]["cashflows"]
    _require_equal(len(observed_cashflows), len(request["cashflows"]), "cashflow cardinality")
    for index, cashflow in enumerate(request["cashflows"]):
        factor = factor_by_date[cashflow["event_date"]]
        exact = _fraction(cashflow["amount"]["value"]) * factor
        present_value += exact
        observed = observed_cashflows[index]
        _require_equal(observed["cashflow_id"], cashflow["cashflow_id"], f"cashflow {index} id")
        _require_equal(observed["claim_id"], cashflow["claim_id"], f"cashflow {index} claim")
        _require_equal(observed["event_date"], cashflow["event_date"], f"cashflow {index} date")
        _require_equal(observed["amount"]["value"], cashflow["amount"]["value"], f"cashflow {index} amount")
        _require_equal(observed["discount_factor"], _format_fraction(factor), f"cashflow {index} factor")
        _require_equal(observed["present_value_exact"], _format_fraction(exact), f"cashflow {index} exact PV")
    _require_equal(
        result["valuation"]["present_value_exact"],
        _format_fraction(present_value),
        "aggregate exact PV",
    )
    _require_equal(
        result["valuation"]["present_value"],
        _format_cents(_round_half_even_cents(present_value)),
        "aggregate rounded PV",
    )

    opening_by_account = {
        account["account_id"]: _money_cents(account["opening_balance"]) for account in request["accounts"]
    }
    states = dict(opening_by_account)
    opening_total = sum(states.values())
    posting_change = 0
    return_change = 0
    transfer_change = 0
    expected_events: list[dict[str, Any]] = []
    for index, event in enumerate(request["events"]):
        event_type = event["event_type"]
        if event_type == "posting":
            account_id = event["account_id"]
            before = states[account_id]
            delta = _money_cents(event["amount"])
            after = before + delta
            states[account_id] = after
            posting_change += delta
            expected_events.append(
                {
                    "event_id": event["event_id"],
                    "postings": [
                        {
                            "account_id": account_id,
                            "before_balance": _format_cents(before),
                            "delta": _format_cents(delta),
                            "after_balance": _format_cents(after),
                        }
                    ],
                }
            )
        elif event_type == "transfer":
            from_id = event["from_account_id"]
            to_id = event["to_account_id"]
            amount = _money_cents(event["amount"])
            before_from = states[from_id]
            before_to = states[to_id]
            after_from = before_from - amount
            after_to = before_to + amount
            states[from_id] = after_from
            states[to_id] = after_to
            transfer_change += -amount + amount
            expected_events.append(
                {
                    "event_id": event["event_id"],
                    "postings": [
                        {
                            "account_id": from_id,
                            "before_balance": _format_cents(before_from),
                            "delta": _format_cents(-amount),
                            "after_balance": _format_cents(after_from),
                        },
                        {
                            "account_id": to_id,
                            "before_balance": _format_cents(before_to),
                            "delta": _format_cents(amount),
                            "after_balance": _format_cents(after_to),
                        },
                    ],
                }
            )
        elif event_type == "return":
            account_id = event["account_id"]
            before = states[account_id]
            gain = _round_half_even_cents(Fraction(before, 100) * _fraction(event["rate"]))
            distribution = _money_cents(event["cash_distribution"])
            asset_after_return = before + gain
            after = asset_after_return + distribution
            delta = gain + distribution
            states[account_id] = after
            return_change += delta
            expected_events.append(
                {
                    "event_id": event["event_id"],
                    "gain": _format_cents(gain),
                    "asset_value_after_return": _format_cents(asset_after_return),
                    "cash_distribution": _format_cents(distribution),
                    "postings": [
                        {
                            "account_id": account_id,
                            "before_balance": _format_cents(before),
                            "delta": _format_cents(delta),
                            "after_balance": _format_cents(after),
                        }
                    ],
                }
            )
        else:  # pragma: no cover - the SDK parser closes the event roster first
            raise AssertionError(f"unsupported challenger event type at index {index}")

    closing_total = sum(states.values())
    expected_total = opening_total + posting_change + return_change + transfer_change
    if transfer_change != 0 or closing_total != expected_total:
        raise AssertionError("independent integer ledger identity did not reconcile")

    ledger = result["ledger"]
    _require_equal(ledger["opening_consolidated_wealth"], _format_cents(opening_total), "ledger opening")
    _require_equal(ledger["closing_consolidated_wealth"], _format_cents(closing_total), "ledger closing")
    _require_equal(ledger["posting_net_change"], _format_cents(posting_change), "ledger postings")
    _require_equal(ledger["return_net_change"], _format_cents(return_change), "ledger returns")
    _require_equal(
        ledger["consolidated_transfer_contribution"],
        _format_cents(transfer_change),
        "ledger transfers",
    )
    _require_equal(ledger["reconciled"], True, "ledger reconciled flag")

    _require_equal(len(ledger["accounts"]), len(request["accounts"]), "account cardinality")
    for index, account in enumerate(request["accounts"]):
        account_id = account["account_id"]
        observed = ledger["accounts"][index]
        _require_equal(observed["account_id"], account_id, f"account {index} id")
        _require_equal(
            observed["opening_balance"],
            _format_cents(opening_by_account[account_id]),
            f"account {index} opening",
        )
        _require_equal(observed["closing_balance"], _format_cents(states[account_id]), f"account {index} closing")
        _require_equal(
            observed["net_change"],
            _format_cents(states[account_id] - opening_by_account[account_id]),
            f"account {index} net change",
        )

    _require_equal(len(ledger["events"]), len(expected_events), "event cardinality")
    for index, expected in enumerate(expected_events):
        observed = ledger["events"][index]
        for field, expected_value in expected.items():
            _require_equal(observed[field], expected_value, f"event {index} {field}")
