"""Accounting oracles by ordered event/double-entry replay."""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .common import q, result, s


def balance(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    opening = q(data["opening_balance"])
    running = opening
    for event in sorted(data["events"], key=lambda row: row["date"]):
        running += q(event["amount"])
    return result(request, {"net_change": s(running - opening), "closing_balance": s(running)})


def transfer(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    opening = {key: q(value) for key, value in data["opening_balances"].items()}
    closing = dict(opening)
    deltas = {key: Fraction() for key in opening}
    amount = q(data["transfer"]["amount"])
    journal = ((data["transfer"]["from_account"], -amount), (data["transfer"]["to_account"], amount))
    for account, posting in journal:
        closing[account] += posting
        deltas[account] += posting
    return result(request, {
        "ledger_deltas": {key: s(value) for key, value in deltas.items()},
        "closing_balances": {key: s(value) for key, value in closing.items()},
        "opening_consolidated_wealth": s(sum(opening.values(), Fraction())),
        "closing_consolidated_wealth": s(sum(closing.values(), Fraction())),
        "consolidated_transfer_contribution": "0",
    })
