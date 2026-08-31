"""Test-only Decimal implementation of the math SUT protocol."""

from __future__ import annotations

import json
import sys
from decimal import Decimal, localcontext
from typing import Any

def _d(value: Any) -> Decimal: return Decimal(value)
def _s(value: Decimal) -> str:
    with localcontext() as context:
        context.prec = 60
        return format(+value, "f")
def _response(vector_id: str, status: str, output: dict[str, Any]) -> dict[str, Any]: return {"vector_id": vector_id, "computational_status": status, "output": output}
def _computed(vector_id: str, output: dict[str, Any]) -> dict[str, Any]: return _response(vector_id, "computed", output)
def _rejected(vector_id: str, reason: str) -> dict[str, Any]: return _response(vector_id, "rejected", {"reason_code": reason})
def _indeterminate(vector_id: str, reason: str) -> dict[str, Any]: return _response(vector_id, "indeterminate", {"reason_code": reason})


def _compute(request: dict[str, Any], mutant: str | None = None) -> dict[str, Any]:
    vector_id, data = request["id"], request["input"]
    if vector_id == "pv-unit-cashflow":
        response = _computed(vector_id, {"present_value": _s(_d(data["cash_flow_amount"]) * _d(data["discount_factor"]))})
    elif vector_id == "finite-annuity-certain":
        response = _computed(vector_id, {"present_value": _s(_d(data["payment_amount"]) * sum(map(_d, data["discount_factors"]), Decimal(0)))})
    elif vector_id == "perpetuity-closed-form":
        response = _computed(vector_id, {"present_value": _s(_d(data["payment_amount"]) / _d(data["effective_rate_per_period"]))})
    elif vector_id == "survival-annuity-small":
        value = sum((_d(row["survival_probability"]) * _d(row["discount_factor"]) * _d(row["amount_if_alive"]) for row in data["payments"]), Decimal(0))
        response = _computed(vector_id, {"present_value": _s(value)})
    elif vector_id == "reserve-plan-vs-replan":
        plan, replan = data["plan_information_at_t0"], data["replan_information_at_r"]
        expected_gap = sum((_d(plan["state_probabilities"][state]) * _d(plan["gap_at_payment_by_state"][state]) for state in plan["state_probabilities"]), Decimal(0))
        planned = _d(plan["discount_factor_r_to_payment"]) * expected_gap
        replanned = _d(replan["discount_factor_r_to_payment"]) * _d(replan["gap_at_payment"])
        response = _computed(vector_id, {"planned_reserve_at_r_using_I_t0": _s(planned), "replanned_reserve_at_r_using_I_r": _s(replanned), "replanning_difference": _s(replanned-planned), "planned_decision_must_use": "planned_reserve_at_r_using_I_t0"})
    elif vector_id == "survival-half-single-weight":
        pathwise = sum((_d(row["probability"]) * _d(row["indicator_adjusted_gap"]) for row in data["pathwise_scenarios"]), Decimal(0))
        analytic = _d(data["analytic_survival_probability"]) * _d(data["gap_conditional_on_alive"])
        response = _computed(vector_id, {"pathwise_expected_deficit": _s(pathwise), "analytic_survival_weighted_deficit": _s(analytic), "equivalence_holds": pathwise == analytic})
    elif vector_id == "couple-dependence-indeterminate":
        response = _indeterminate(vector_id, "dependence_model_required")
    elif vector_id == "couple-deterministic-mortality":
        horizon = data["horizon_date"]
        alive_a, alive_b = data["death_date_a"] > horizon, data["death_date_b"] > horizon
        state = "both_alive" if alive_a and alive_b else "only_a_alive" if alive_a else "only_b_alive" if alive_b else "none_alive"
        response = _computed(vector_id, {"household_state": state, "active_person_count": str(int(alive_a)+int(alive_b))})
    elif vector_id == "couple-four-states":
        pa, pb = _d(data["survival_probability_a"]), _d(data["survival_probability_b"])
        probabilities = {"both_alive": pa*pb, "only_a_alive": pa*(1-pb), "only_b_alive": (1-pa)*pb, "none_alive": (1-pa)*(1-pb)}
        gaps, floor, income, gap = {}, Decimal(0), Decimal(0), Decimal(0)
        for state, probability in probabilities.items():
            row = data["floor_and_secure_income_by_state"][state]; state_gap = max(Decimal(0), _d(row["essential_floor"])-_d(row["secure_income"])); gaps[state] = state_gap
            floor += probability*_d(row["essential_floor"]); income += probability*_d(row["secure_income"]); gap += probability*state_gap
        response = _computed(vector_id, {"state_probabilities": {key:_s(value) for key,value in probabilities.items()}, "probability_at_least_one_alive": _s(1-probabilities["none_alive"]), "gap_by_state": {key:_s(value) for key,value in gaps.items()}, "probability_weighted_essential_floor": _s(floor), "probability_weighted_secure_income": _s(income), "probability_weighted_gap": _s(gap)})
    elif vector_id == "return-basis-distribution":
        opening, distribution = _d(data["opening_consolidated_wealth"]), _d(data["cash_distribution"]); asset = opening*(1+_d(data["price_return"]))
        response = _computed(vector_id, {"closing_asset_value": _s(asset), "closing_cash_from_distribution": _s(distribution), "closing_consolidated_wealth": _s(asset+distribution)})
    elif vector_id == "total-return-positive":
        closing = _d(data["opening_consolidated_wealth"])*(1+_d(data["total_return"]))
        response = _computed(vector_id, {"closing_account_value": _s(closing), "separate_distribution_event": "0", "closing_consolidated_wealth": _s(closing)})
    elif vector_id == "return-basis-invalid-combination":
        response = _rejected(vector_id, "distribution_double_count" if data["return_basis"] == "total_return" and _d(data["separate_distribution_event"]) != 0 else "fixture_did_not_exercise_invalid_combination")
    elif vector_id == "internal-transfer-conservation":
        source, destination, amount = data["transfer"]["from_account"], data["transfer"]["to_account"], _d(data["transfer"]["amount"])
        closing = {key:_d(value) for key,value in data["opening_balances"].items()}; closing[source] -= amount; closing[destination] += amount
        deltas = {key:Decimal(0) for key in closing}; deltas[source] -= amount; deltas[destination] += amount
        response = _computed(vector_id, {"ledger_deltas": {key:_s(value) for key,value in deltas.items()}, "closing_balances": {key:_s(value) for key,value in closing.items()}, "opening_consolidated_wealth": _s(sum(map(_d, data["opening_balances"].values()), Decimal(0))), "closing_consolidated_wealth": _s(sum(closing.values(), Decimal(0))), "consolidated_transfer_contribution": "0"})
    elif vector_id == "balance-reconciliation":
        opening = _d(data["opening_balance"]); change = sum((_d(row["amount"]) for row in data["events"]), Decimal(0))
        response = _computed(vector_id, {"net_change": _s(change), "closing_balance": _s(opening+change)})
    elif vector_id in {"tax-lot-simple", "tax-lot-no-tax"}:
        sold, held = _d(data["sale"]["quantity"]), _d(data["lot"]["quantity"]); gross = sold*_d(data["sale"]["unit_price"]); basis = sold*_d(data["lot"]["unit_cost"]); gain = gross-basis; tax = max(Decimal(0), gain)*_d(data["tax_rate_on_positive_gain"])
        response = _computed(vector_id, {"sold_quantity":_s(sold), "remaining_quantity":_s(held-sold), "gross_proceeds":_s(gross), "allocated_cost_basis":_s(basis), "taxable_gain":_s(gain), "tax_due":_s(tax), "net_proceeds":_s(gross-tax), "remaining_cost_basis":_s((held-sold)*_d(data["lot"]["unit_cost"]))})
    elif vector_id == "portfolio-two-asset-convex":
        va,vb,cov = _d(data["variance_a"]),_d(data["variance_b"]),_d(data["covariance_ab"]); wa=(vb-cov)/(va+vb-2*cov); wb=1-wa; variance=wa*wa*va+wb*wb*vb+2*wa*wb*cov
        response = _computed(vector_id, {"weight_a":_s(wa), "weight_b":_s(wb), "portfolio_variance":_s(variance)})
    elif vector_id == "cvar-discrete-enumerable":
        alpha=_d(data["alpha"]); ascending=sorted((_d(row["loss"]),_d(row["probability"])) for row in data["scenarios"]); cumulative=Decimal(0); var=ascending[-1][0]
        for loss, probability in ascending:
            cumulative += probability
            if cumulative >= alpha: var=loss; break
        remaining=1-alpha; tail_total=Decimal(0)
        for loss, probability in reversed(ascending):
            used=min(remaining,probability); tail_total += used*loss; remaining -= used
            if remaining == 0: break
        response = _computed(vector_id, {"var":_s(var), "tail_expected_shortfall":_s(tail_total/(1-alpha))})
    elif vector_id == "two-stage-nonanticipativity":
        low,high=data["stage_1_scenarios"]["low"],data["stage_1_scenarios"]["high"]; pl,ph=_d(low["probability"]),_d(high["probability"]); tl,th=_d(low["target_revealed_at_stage_1"]),_d(high["target_revealed_at_stage_1"]); action=pl*tl+ph*th; ll=(action-tl)**2; lh=(action-th)**2
        response = _computed(vector_id, {"implementable_policy":{"stage_0_action_low_path":_s(action),"stage_0_action_high_path":_s(action),"scenario_loss_low":_s(ll),"scenario_loss_high":_s(lh),"expected_loss":_s(pl*ll+ph*lh),"nonanticipativity_satisfied":True},"perfect_information_diagnostic":{"stage_0_action_low_path":_s(tl),"stage_0_action_high_path":_s(th),"expected_loss":"0","implementable_at_stage_0":False,"bound_for_minimization":"lower"}})
    elif vector_id == "constant-contribution-closed-form":
        assets = _d(data["initial_assets"])*_d(data["accumulation_factor_initial_to_horizon"])
        contributions = _d(data["constant_contribution"])*sum((_d(row["accumulation_factor_to_horizon"]) for row in data["contribution_schedule"]),Decimal(0))
        response = _computed(vector_id,{"accumulated_initial_assets":_s(assets),"accumulated_contributions":_s(contributions),"future_value":_s(assets+contributions)})
    elif vector_id == "contribution-all-at-r":
        assets=_d(data["financial_assets_at_t0"])*_d(data["accumulation_factor_t0_to_r"]); terminal=_d(data["planned_terminal_reserve_at_omega"])*_d(data["discount_factor_r_to_omega"]); factor=sum((_d(row["accumulation_factor_to_r"]) for row in data["constant_contribution_schedule"]),Decimal(0)); contribution=(_d(data["planned_reserve_at_r"])+terminal-assets)/factor; accumulated=contribution*factor
        response = _computed(vector_id,{"accumulated_initial_assets_at_r":_s(assets),"discounted_terminal_reserve_at_r":_s(terminal),"sum_contribution_accumulation_factors":_s(factor),"constant_contribution_at_each_schedule_date":_s(contribution),"accumulated_contributions_at_r":_s(accumulated),"planned_surplus_at_r":_s(assets+accumulated-_d(data["planned_reserve_at_r"])-terminal)})
    else: raise ValueError(f"unsupported vector id: {vector_id}")
    if mutant:
        from math_mutants import MUTANTS
        response = MUTANTS[mutant](request, response)
    return response


def compute(request: dict[str, Any], mutant: str | None = None) -> dict[str, Any]:
    with localcontext() as context:
        context.prec = 60
        return _compute(request, mutant)


def main() -> int:
    from math_mutants import MUTANTS
    import argparse
    parser=argparse.ArgumentParser(); parser.add_argument("--mutant",choices=sorted(MUTANTS)); args=parser.parse_args()
    request=json.loads(sys.stdin.read()); json.dump(compute(request,args.mutant),sys.stdout,ensure_ascii=False,separators=(",",":")); sys.stdout.write("\n"); return 0


if __name__ == "__main__": raise SystemExit(main())
