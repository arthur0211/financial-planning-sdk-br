"""Independent oracle registry for the deterministic conformance corpus.

Material derivation families live in separate ``oracle_methods`` modules.  The
registry records stable method IDs so the corpus can reject branch swaps.  No
handler imports or calls the reference adapter.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any, Callable

from oracle_methods import (
    annuity_explicit,
    contribution_root,
    cvar_eta,
    household_sample_space,
    ledger_replay,
    nonanticipative_candidates,
    portfolio_symbolic,
    tax_state_machine,
)
from oracle_methods.common import q, result, s


Handler = Callable[[dict[str, Any]], dict[str, Any]]
HANDLERS: dict[str, Handler] = {}
DERIVATION_METHOD_IDS: dict[str, str] = {}


def derived(vector_id: str, method_id: str) -> Callable[[Handler], Handler]:
    def register(function: Handler) -> Handler:
        HANDLERS[vector_id] = function
        DERIVATION_METHOD_IDS[vector_id] = method_id
        return function
    return register


def register(vector_id: str, method_id: str, function: Handler) -> None:
    HANDLERS[vector_id] = function
    DERIVATION_METHOD_IDS[vector_id] = method_id


@derived("pv-unit-cashflow", "discounted_cashflow_defining_identity")
def pv(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    return result(request, {"present_value": s(q(data["cash_flow_amount"]) * q(data["discount_factor"]))})


register("finite-annuity-certain", "cashflow_by_cashflow_explicit_sum", annuity_explicit.finite)
register("survival-annuity-small", "alive_payment_state_explicit_sum", annuity_explicit.survival)


@derived("perpetuity-closed-form", "perpetuity_fixed_point_identity")
def perpetuity(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    payment, rate = q(data["payment_amount"]), q(data["effective_rate_per_period"])
    candidate = payment / rate
    if candidate * rate != payment:
        raise ArithmeticError("perpetuity fixed-point identity failed")
    return result(request, {"present_value": s(candidate)})


@derived("reserve-plan-vs-replan", "information_set_state_enumeration")
def reserve(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    plan, replan = data["plan_information_at_t0"], data["replan_information_at_r"]
    state_values = [q(probability) * q(plan["gap_at_payment_by_state"][state]) for state, probability in plan["state_probabilities"].items()]
    planned = q(plan["discount_factor_r_to_payment"]) * sum(state_values, Fraction())
    replanned = q(replan["discount_factor_r_to_payment"]) * q(replan["gap_at_payment"])
    return result(request, {"planned_reserve_at_r_using_I_t0": s(planned), "replanned_reserve_at_r_using_I_r": s(replanned), "replanning_difference": s(replanned - planned), "planned_decision_must_use": "planned_reserve_at_r_using_I_t0"})


@derived("survival-half-single-weight", "pathwise_vs_analytic_identity")
def survival_modes(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    pathwise = sum((q(row["probability"]) * q(row["indicator_adjusted_gap"]) for row in data["pathwise_scenarios"]), Fraction())
    analytic = q(data["analytic_survival_probability"]) * q(data["gap_conditional_on_alive"])
    return result(request, {"pathwise_expected_deficit": s(pathwise), "analytic_survival_weighted_deficit": s(analytic), "equivalence_holds": pathwise == analytic})


@derived("couple-dependence-indeterminate", "partial_identification_check")
def couple_indeterminate(request: dict[str, Any]) -> dict[str, Any]:
    return result(request, {"reason_code": "dependence_model_required"}, "indeterminate")


register("couple-four-states", "bernoulli_sample_space_enumeration", household_sample_space.independent_states)
register("couple-deterministic-mortality", "civil_date_sample_space_classifier", household_sample_space.deterministic_state)


@derived("return-basis-distribution", "stock_cash_ledger_reconciliation")
def price_return(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    asset = q(data["opening_consolidated_wealth"]) + q(data["opening_consolidated_wealth"]) * q(data["price_return"])
    cash = q(data["cash_distribution"])
    return result(request, {"closing_asset_value": s(asset), "closing_cash_from_distribution": s(cash), "closing_consolidated_wealth": s(asset + cash)})


@derived("total-return-positive", "total_return_terminal_identity")
def total_return(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    closing = q(data["opening_consolidated_wealth"]) + q(data["opening_consolidated_wealth"]) * q(data["total_return"])
    return result(request, {"closing_account_value": s(closing), "separate_distribution_event": "0", "closing_consolidated_wealth": s(closing)})


@derived("return-basis-invalid-combination", "return_basis_exclusivity_predicate")
def invalid_return(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    reason = "distribution_double_count" if data["return_basis"] == "total_return" and q(data["separate_distribution_event"]) != 0 else "fixture_did_not_exercise_invalid_combination"
    return result(request, {"reason_code": reason}, "rejected")


register("internal-transfer-conservation", "double_entry_event_replay", ledger_replay.transfer)
register("balance-reconciliation", "ordered_balance_event_replay", ledger_replay.balance)
register("tax-lot-simple", "tax_lot_state_machine_replay", tax_state_machine.compute)
register("tax-lot-no-tax", "zero_tax_state_machine_counterfactual", tax_state_machine.compute)
register("portfolio-two-asset-convex", "symbolic_objective_candidate_enumeration", portfolio_symbolic.compute)
register("cvar-discrete-enumerable", "eta_lp_vertex_enumeration", cvar_eta.compute)
register("two-stage-nonanticipativity", "exhaustive_critical_candidate_minimization", nonanticipative_candidates.compute)
register("constant-contribution-closed-form", "future_value_explicit_cashflow_sum", contribution_root.future_value)
register("contribution-all-at-r", "numerical_secant_balance_root", contribution_root.retirement_balance_root)


def compute(request: dict[str, Any]) -> dict[str, Any]:
    return HANDLERS[request["id"]](request)
