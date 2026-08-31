"""Single-lot tax oracle as an event/state transition machine."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .common import q, result, s


@dataclass
class LotState:
    quantity: Fraction
    cost_basis: Fraction
    cash: Fraction = Fraction()
    realized_gain: Fraction = Fraction()
    tax_due: Fraction = Fraction()


def compute(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    held = q(data["lot"]["quantity"])
    state = LotState(held, held * q(data["lot"]["unit_cost"]))
    sold = q(data["sale"]["quantity"])
    fraction_sold = sold / state.quantity
    allocated_basis = state.cost_basis * fraction_sold
    proceeds = sold * q(data["sale"]["unit_price"])
    state.quantity -= sold
    state.cost_basis -= allocated_basis
    state.cash += proceeds
    state.realized_gain += proceeds - allocated_basis
    if state.realized_gain > 0:
        state.tax_due += state.realized_gain * q(data["tax_rate_on_positive_gain"])
        state.cash -= state.tax_due
    return result(request, {
        "sold_quantity": s(sold), "remaining_quantity": s(state.quantity),
        "gross_proceeds": s(proceeds), "allocated_cost_basis": s(allocated_basis),
        "taxable_gain": s(state.realized_gain), "tax_due": s(state.tax_due),
        "net_proceeds": s(state.cash), "remaining_cost_basis": s(state.cost_basis),
    })
