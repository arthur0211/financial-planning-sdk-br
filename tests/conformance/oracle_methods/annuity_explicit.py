"""Annuity oracles by explicit cash-flow/state enumeration.

The reference adapter aggregates a constant payment and a factor sum.  These
methods instead construct and add every discounted payment ticket.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .common import q, result, s


def finite(request: dict[str, Any]) -> dict[str, Any]:
    payment = q(request["input"]["payment_amount"])
    tickets = [payment * q(factor) for factor in request["input"]["discount_factors"]]
    return result(request, {"present_value": s(sum(tickets, Fraction()))})


def survival(request: dict[str, Any]) -> dict[str, Any]:
    tickets: list[Fraction] = []
    for row in request["input"]["payments"]:
        tickets.append(q(row["amount_if_alive"]) * q(row["discount_factor"]) * q(row["survival_probability"]))
    return result(request, {"present_value": s(sum(tickets, Fraction()))})
