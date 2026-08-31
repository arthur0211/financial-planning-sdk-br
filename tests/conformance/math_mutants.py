"""Persistent defects used only to measure reference fixture sensitivity."""

from __future__ import annotations
from copy import deepcopy
from decimal import Decimal
from typing import Any, Callable

Response=dict[str,Any]; Mutation=Callable[[dict[str,Any],Response],Response]
def d(value:Any)->Decimal:return Decimal(value)
def s(value:Decimal)->str:return format(value,"f")

def pv_ignores_amount(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="pv-unit-cashflow":response["output"]["present_value"]=request["input"]["discount_factor"]
    return response
def pv_absolute_cashflow(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="pv-unit-cashflow":response["output"]["present_value"]=s(abs(d(request["input"]["cash_flow_amount"]))*d(request["input"]["discount_factor"]))
    return response
def reserve_equal_probabilities(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="reserve-plan-vs-replan":
        plan=request["input"]["plan_information_at_t0"]; gaps=plan["gap_at_payment_by_state"]; planned=d(plan["discount_factor_r_to_payment"])*(d(gaps["low_need"])+d(gaps["high_need"]))/2; response["output"]["planned_reserve_at_r_using_I_t0"]=s(planned)
    return response
def survival_double_weight(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="survival-half-single-weight":response["output"]["pathwise_expected_deficit"]=s(d(response["output"]["pathwise_expected_deficit"])*d(request["input"]["analytic_survival_probability"]))
    return response
def couple_reuses_probability_a(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="couple-four-states":
        changed=deepcopy(request);changed["input"]["survival_probability_b"]=changed["input"]["survival_probability_a"]
        from reference_adapter import compute
        return compute(changed)
    return response
def transfer_ignores_account_ids(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="internal-transfer-conservation":
        opening=request["input"]["opening_balances"];amount=d(request["input"]["transfer"]["amount"]);response["output"]["closing_balances"]={"account_a":s(d(opening["account_a"])-amount),"account_b":s(d(opening["account_b"])+amount)}
    return response
def return_double_counts_distribution(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="total-return-positive":response["output"]["closing_consolidated_wealth"]=s(d(response["output"]["closing_consolidated_wealth"])+Decimal("3"))
    return response
def nonanticipativity_equal_probabilities(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="two-stage-nonanticipativity":
        scenarios=request["input"]["stage_1_scenarios"];wrong=(d(scenarios["low"]["target_revealed_at_stage_1"])+d(scenarios["high"]["target_revealed_at_stage_1"]))/2;response["output"]["implementable_policy"]["stage_0_action_low_path"]=s(wrong);response["output"]["implementable_policy"]["stage_0_action_high_path"]=s(wrong)
    return response

def annuity_ignores_payments_after_two(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="finite-annuity-certain":
        data=request["input"];response["output"]["present_value"]=s(d(data["payment_amount"])*sum((d(item) for item in data["discount_factors"][:2]),Decimal()))
    return response
def death_at_horizon_is_alive(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="couple-deterministic-mortality":
        data=request["input"];alive_a=data["death_date_a"]>=data["horizon_date"];alive_b=data["death_date_b"]>=data["horizon_date"]
        state="both_alive" if alive_a and alive_b else "only_a_alive" if alive_a else "only_b_alive" if alive_b else "none_alive"
        response["output"].update({"household_state":state,"active_person_count":str(int(alive_a)+int(alive_b))})
    return response
def tax_loss_creates_credit(request:dict[str,Any],response:Response)->Response:
    if request["id"] in {"tax-lot-simple","tax-lot-no-tax"}:
        gain=d(response["output"]["taxable_gain"]);tax=gain*d(request["input"]["tax_rate_on_positive_gain"]);gross=d(response["output"]["gross_proceeds"])
        response["output"]["tax_due"]=s(tax);response["output"]["net_proceeds"]=s(gross-tax)
    return response
def portfolio_clips_weights(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="portfolio-two-asset-convex":
        wa=min(Decimal(1),max(Decimal(),d(response["output"]["weight_a"])));wb=Decimal(1)-wa;data=request["input"];va,vb,cov=d(data["variance_a"]),d(data["variance_b"]),d(data["covariance_ab"])
        response["output"].update({"weight_a":s(wa),"weight_b":s(wb),"portfolio_variance":s(wa*wa*va+wb*wb*vb+2*wa*wb*cov)})
    return response
def cvar_ignores_scenarios(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="cvar-discrete-enumerable":response["output"].update({"var":"10","tail_expected_shortfall":"60"})
    return response
def contribution_uses_frozen_factors(request:dict[str,Any],response:Response)->Response:
    if request["id"]=="contribution-all-at-r":
        data=request["input"];assets=d(data["financial_assets_at_t0"])*d(data["accumulation_factor_t0_to_r"]);terminal=d(data["planned_terminal_reserve_at_omega"])*d(data["discount_factor_r_to_omega"]);factor=Decimal("2.10");contribution=(d(data["planned_reserve_at_r"])+terminal-assets)/factor;accumulated=contribution*factor
        response["output"].update({"sum_contribution_accumulation_factors":s(factor),"constant_contribution_at_each_schedule_date":s(contribution),"accumulated_contributions_at_r":s(accumulated),"planned_surplus_at_r":s(assets+accumulated-d(data["planned_reserve_at_r"])-terminal)})
    return response

MUTANTS={
 "couple_reuses_probability_a":couple_reuses_probability_a,
 "nonanticipativity_equal_probabilities":nonanticipativity_equal_probabilities,
 "pv_absolute_cashflow":pv_absolute_cashflow,
 "pv_ignores_amount":pv_ignores_amount,
 "reserve_equal_probabilities":reserve_equal_probabilities,
 "return_double_counts_distribution":return_double_counts_distribution,
 "survival_double_weight":survival_double_weight,
 "transfer_ignores_account_ids":transfer_ignores_account_ids,
 "annuity_ignores_payments_after_two":annuity_ignores_payments_after_two,
 "death_at_horizon_is_alive":death_at_horizon_is_alive,
 "tax_loss_creates_credit":tax_loss_creates_credit,
 "portfolio_clips_weights":portfolio_clips_weights,
 "cvar_ignores_scenarios":cvar_ignores_scenarios,
 "contribution_uses_frozen_factors":contribution_uses_frozen_factors,
}
