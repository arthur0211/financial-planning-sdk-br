"""Contribution oracles solved as balance roots, not rearranged formulas."""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .common import q, result, s


def future_value(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    assets = q(data["initial_assets"]) * q(data["accumulation_factor_initial_to_horizon"])
    flows = [q(data["constant_contribution"]) * q(row["accumulation_factor_to_horizon"]) for row in data["contribution_schedule"]]
    contributions = sum(flows, Fraction())
    return result(request, {"accumulated_initial_assets": s(assets), "accumulated_contributions": s(contributions), "future_value": s(assets + contributions)})


def _balance(data: dict[str, Any], contribution: Fraction) -> Fraction:
    assets = q(data["financial_assets_at_t0"]) * q(data["accumulation_factor_t0_to_r"])
    terminal = q(data["planned_terminal_reserve_at_omega"]) * q(data["discount_factor_r_to_omega"])
    accumulated = sum((contribution * q(row["accumulation_factor_to_r"]) for row in data["constant_contribution_schedule"]), Fraction())
    return assets + accumulated - q(data["planned_reserve_at_r"]) - terminal


def retirement_balance_root(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    # The balance is affine.  A secant root uses only independently evaluated
    # balances at two trial contributions; it never copies the adapter's
    # rearranged contribution equation.
    x0, x1 = Fraction(0), Fraction(1)
    f0, f1 = _balance(data, x0), _balance(data, x1)
    if f1 == f0:
        raise ArithmeticError("contribution balance has no identifiable root")
    contribution = x1 - f1 * (x1 - x0) / (f1 - f0)
    residual = _balance(data, contribution)
    if residual != 0:
        raise ArithmeticError("secant contribution root did not reconcile")
    assets = q(data["financial_assets_at_t0"]) * q(data["accumulation_factor_t0_to_r"])
    terminal = q(data["planned_terminal_reserve_at_omega"]) * q(data["discount_factor_r_to_omega"])
    factors = sum((q(row["accumulation_factor_to_r"]) for row in data["constant_contribution_schedule"]), Fraction())
    accumulated = sum((contribution * q(row["accumulation_factor_to_r"]) for row in data["constant_contribution_schedule"]), Fraction())
    return result(request, {
        "accumulated_initial_assets_at_r": s(assets),
        "discounted_terminal_reserve_at_r": s(terminal),
        "sum_contribution_accumulation_factors": s(factors),
        "constant_contribution_at_each_schedule_date": s(contribution),
        "accumulated_contributions_at_r": s(accumulated),
        "planned_surplus_at_r": s(residual),
    })
