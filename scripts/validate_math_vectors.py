#!/usr/bin/env python3
"""Fail-closed, cross-platform conformance runner for mathematical JSON vectors."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import importlib
import importlib.util
import json
import math
import os
import re
import shlex
import stat
import sys
import tempfile
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation, getcontext, setcontext
from pathlib import Path
from typing import Any

_BOUNDARY_PATH = Path(__file__).resolve().with_name("bounded_subprocess.py")
_BOUNDARY_SPEC = importlib.util.spec_from_file_location("_finplanbr_math_bounded_subprocess", _BOUNDARY_PATH)
if _BOUNDARY_SPEC is None or _BOUNDARY_SPEC.loader is None:
    raise RuntimeError("bounded subprocess helper could not be loaded")
_BOUNDARY = importlib.util.module_from_spec(_BOUNDARY_SPEC)
_BOUNDARY_SPEC.loader.exec_module(_BOUNDARY)
BoundedProcessCleanupError = _BOUNDARY.BoundedProcessCleanupError
BoundedProcessOutputLimit = _BOUNDARY.BoundedProcessOutputLimit
BoundedProcessStartError = _BOUNDARY.BoundedProcessStartError
BoundedProcessTimeout = _BOUNDARY.BoundedProcessTimeout
run_bounded = _BOUNDARY.run_bounded


VECTOR_FORMAT = "financial-planning-sdk-br.math-vector.v1"
PROTOCOL = "financial-planning-sdk-br.math-sut.v1"
CANONICALIZATION = "sorted-key-json-utf8-excluding-fingerprint"
MANIFEST_FORMAT = "financial-planning-sdk-br.math-vector-manifest.v1"
SUT_MUTANTS_FORMAT = "financial-planning-sdk-br.math-sut-mutants.v1"
ORACLE_BUNDLE_FORMAT = "financial-planning-sdk-br.math-validation-route-bundle.v1"
ORACLE_BUNDLE_CLAIM = "validation_route_static_boundary_not_proof_of_independence"
MANIFEST_CATEGORIES = {"accounting_identity", "closed_form", "negative_contract"}
MUTATION_FAILURE_POLICIES = {"strict"}
DECIMAL_TEXT = re.compile(r"^-?(?:0|[1-9]\d*)(?:\.\d+)?$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
STATUSES = {"computed", "computed_with_warnings", "indeterminate", "rejected"}
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_STDOUT_LIMIT = 1_048_576
DEFAULT_STDERR_LIMIT = 65_536
EXPECTED_ORACLE_SOURCE_SETS = {
    "reference": {"reference_adapter.py", "math_mutants.py"},
    "validation": {
        "independent_oracle.py",
        "oracle_methods/__init__.py",
        "oracle_methods/annuity_explicit.py",
        "oracle_methods/common.py",
        "oracle_methods/contribution_root.py",
        "oracle_methods/cvar_eta.py",
        "oracle_methods/household_sample_space.py",
        "oracle_methods/ledger_replay.py",
        "oracle_methods/nonanticipative_candidates.py",
        "oracle_methods/portfolio_symbolic.py",
        "oracle_methods/tax_state_machine.py",
    },
    "harness": {"module_worker.py", "property_suite.py"},
}
VALIDATION_IMPORT_ROOTS = {
    "__future__",
    "dataclasses",
    "datetime",
    "decimal",
    "fractions",
    "itertools",
    "oracle_methods",
    "typing",
}
PROPERTY_SUITE_IMPORT_ROOTS = {"__future__", "copy", "decimal", "hashlib", "random", "re", "typing"}
REQUIRED_IDS = {
    "balance-reconciliation",
    "constant-contribution-closed-form",
    "contribution-all-at-r",
    "couple-dependence-indeterminate",
    "couple-deterministic-mortality",
    "couple-four-states",
    "cvar-discrete-enumerable",
    "finite-annuity-certain",
    "internal-transfer-conservation",
    "perpetuity-closed-form",
    "portfolio-two-asset-convex",
    "pv-unit-cashflow",
    "reserve-plan-vs-replan",
    "return-basis-distribution",
    "return-basis-invalid-combination",
    "survival-annuity-small",
    "survival-half-single-weight",
    "tax-lot-simple",
    "tax-lot-no-tax",
    "total-return-positive",
    "two-stage-nonanticipativity",
}
SUPPLEMENTAL_IDS = {
    "couple-dependence-indeterminate",
    "couple-four-states",
    "reserve-plan-vs-replan",
}

SPEC_CASE_IDS = {str(index) for index in range(1, 16)}
ORACLE_DERIVATION_METHODS = {
    "balance-reconciliation":"ordered_balance_event_replay", "constant-contribution-closed-form":"future_value_explicit_cashflow_sum",
    "contribution-all-at-r":"numerical_secant_balance_root", "couple-dependence-indeterminate":"partial_identification_check",
    "couple-deterministic-mortality":"civil_date_sample_space_classifier", "couple-four-states":"bernoulli_sample_space_enumeration",
    "cvar-discrete-enumerable":"eta_lp_vertex_enumeration", "finite-annuity-certain":"cashflow_by_cashflow_explicit_sum",
    "internal-transfer-conservation":"double_entry_event_replay", "perpetuity-closed-form":"perpetuity_fixed_point_identity",
    "portfolio-two-asset-convex":"symbolic_objective_candidate_enumeration", "pv-unit-cashflow":"discounted_cashflow_defining_identity",
    "reserve-plan-vs-replan":"information_set_state_enumeration", "return-basis-distribution":"stock_cash_ledger_reconciliation",
    "return-basis-invalid-combination":"return_basis_exclusivity_predicate", "survival-annuity-small":"alive_payment_state_explicit_sum",
    "survival-half-single-weight":"pathwise_vs_analytic_identity", "tax-lot-no-tax":"zero_tax_state_machine_counterfactual",
    "tax-lot-simple":"tax_lot_state_machine_replay", "total-return-positive":"total_return_terminal_identity",
    "two-stage-nonanticipativity":"exhaustive_critical_candidate_minimization",
}

VALIDATION_TYPES = {
    "independent_algorithm",
    "independent_enumeration",
    "exact_identity_reconciliation",
    "independent_numeric_representation",
}
ORACLE_VALIDATION_TYPES = {
    "balance-reconciliation": "exact_identity_reconciliation",
    "constant-contribution-closed-form": "independent_enumeration",
    "contribution-all-at-r": "independent_algorithm",
    "couple-dependence-indeterminate": "exact_identity_reconciliation",
    "couple-deterministic-mortality": "independent_enumeration",
    "couple-four-states": "independent_enumeration",
    "cvar-discrete-enumerable": "independent_enumeration",
    "finite-annuity-certain": "independent_enumeration",
    "internal-transfer-conservation": "exact_identity_reconciliation",
    "perpetuity-closed-form": "exact_identity_reconciliation",
    "portfolio-two-asset-convex": "independent_algorithm",
    "pv-unit-cashflow": "independent_numeric_representation",
    "reserve-plan-vs-replan": "independent_enumeration",
    "return-basis-distribution": "exact_identity_reconciliation",
    "return-basis-invalid-combination": "exact_identity_reconciliation",
    "survival-annuity-small": "independent_enumeration",
    "survival-half-single-weight": "exact_identity_reconciliation",
    "tax-lot-no-tax": "independent_algorithm",
    "tax-lot-simple": "independent_algorithm",
    "total-return-positive": "exact_identity_reconciliation",
    "two-stage-nonanticipativity": "independent_enumeration",
}
VALIDATION_METHODS_BY_VECTOR = {
    vector_id: (
        {
            "method_id": "reference_decimal_test_only",
            "validation_type": "independent_numeric_representation",
        },
        {
            "method_id": ORACLE_DERIVATION_METHODS[vector_id],
            "validation_type": ORACLE_VALIDATION_TYPES[vector_id],
        },
    )
    for vector_id in REQUIRED_IDS
}

VECTOR_TOPICS = {
    "balance-reconciliation":"cent_exact_balance_reconciliation",
    "constant-contribution-closed-form":"constant_contribution_future_value_closed_form",
    "contribution-all-at-r":"dimensional_reconciliation_at_retirement",
    "couple-dependence-indeterminate":"household_survival_states_without_dependence_model",
    "couple-deterministic-mortality":"deterministic_household_mortality_state",
    "couple-four-states":"household_survival_states",
    "cvar-discrete-enumerable":"enumerable_tail_expected_shortfall",
    "finite-annuity-certain":"finite_annuity_closed_form",
    "internal-transfer-conservation":"economic_claim_conservation",
    "perpetuity-closed-form":"perpetuity_mathematical_test_only",
    "portfolio-two-asset-convex":"two_asset_minimum_variance_closed_form",
    "pv-unit-cashflow":"deterministic_present_value",
    "reserve-plan-vs-replan":"information_sets_and_reserve_replanning",
    "return-basis-distribution":"price_return_vs_total_return",
    "return-basis-invalid-combination":"total_return_distribution_double_count_rejection",
    "survival-annuity-small":"survival_weighted_annuity_closed_form",
    "survival-half-single-weight":"survival_treatment_exclusivity",
    "tax-lot-no-tax":"synthetic_single_lot_zero_tax_counterfactual",
    "tax-lot-simple":"synthetic_single_tax_lot_identity",
    "total-return-positive":"total_return_without_separate_distribution",
    "two-stage-nonanticipativity":"scenario_tree_information_filtration",
}

SPEC_CASE_VECTOR_IDS = {
    "1": ("pv-unit-cashflow",), "2": ("finite-annuity-certain",), "3": ("perpetuity-closed-form",),
    "4": ("survival-annuity-small",), "5": ("constant-contribution-closed-form",),
    "6": ("portfolio-two-asset-convex",), "7": ("cvar-discrete-enumerable",),
    "8": ("couple-deterministic-mortality",), "9": ("tax-lot-no-tax", "tax-lot-simple"),
    "10": ("balance-reconciliation",),
    "11": ("return-basis-distribution", "total-return-positive", "return-basis-invalid-combination"),
    "12": ("internal-transfer-conservation",), "13": ("two-stage-nonanticipativity",),
    "14": ("survival-half-single-weight",), "15": ("contribution-all-at-r",),
}

# Exact unit vocabulary.  A value is accepted only when both this enum and the
# field-specific contract below agree; dimension-prefix guessing is forbidden.
UNIT_DIMENSIONS = {
    "probability": "probability",
    "dimensionless": "dimensionless",
    "dimensionless_BRL_at_r_per_BRL_at_contribution_date": "dimensionless",
    "dimensionless_BRL_at_r_per_BRL_at_omega": "dimensionless",
    "dimensionless_BRL_at_r_per_BRL_at_payment_date": "dimensionless",
    "dimensionless_BRL_at_r_per_BRL_at_t0": "dimensionless",
    "dimensionless_BRL_at_valuation_date_per_BRL_at_payment_date": "dimensionless",
    "dimensionless_period_rate": "dimensionless",
    "dimensionless_period_return": "dimensionless",
    "dimensionless_portfolio_weight": "dimensionless",
    "dimensionless_rate": "dimensionless",
    "BRL_at_close": "currency",
    "BRL_at_event_time": "currency",
    "BRL_at_open": "currency",
    "BRL_at_payment_date": "currency",
    "BRL_at_payment_date_conditional_on_alive": "currency",
    "BRL_at_period_end": "currency",
    "BRL_at_period_start": "currency",
    "BRL_at_sale_date": "currency",
    "BRL_in_common_stage_0_valuation_units_committed_at_stage_0": "currency",
    "BRL_in_common_stage_0_valuation_units_revealed_at_stage_1": "currency",
    "BRL_loss_at_horizon": "currency",
    "BRL_nominal_at_each_contribution_date": "currency",
    "BRL_nominal_at_each_payment_date": "currency",
    "BRL_nominal_at_omega": "currency",
    "BRL_nominal_at_payment_date": "currency",
    "BRL_nominal_at_r": "currency",
    "BRL_nominal_at_t0": "currency",
    "BRL_nominal_at_valuation_date": "currency",
    "BRL_per_unit": "currency_per_unit",
    "BRL_squared": "currency_squared",
    "quantity_units": "quantity",
    "return_squared": "variance",
    "years_exact": "time_years",
    "persons_count": "count",
}

# Normative dimensions are bound to fields, independently of fixture-supplied labels.
# This prevents a fixture from relabelling currency as probability while retaining coverage.
FIELD_DIMENSIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "pv-unit-cashflow": (("input.cash_flow_amount", "currency"), ("input.discount_factor", "dimensionless"), ("expected_output.present_value", "currency")),
    "finite-annuity-certain": (("input.payment_amount", "currency"), ("input.discount_factors.*", "dimensionless"), ("expected_output.present_value", "currency")),
    "perpetuity-closed-form": (("input.payment_amount", "currency"), ("input.effective_rate_per_period", "dimensionless"), ("expected_output.present_value", "currency")),
    "survival-annuity-small": (("input.payments.*.survival_probability", "probability"), ("input.payments.*.discount_factor", "dimensionless"), ("input.payments.*.amount_if_alive", "currency"), ("expected_output.present_value", "currency")),
    "reserve-plan-vs-replan": (("input.plan_information_at_t0.discount_factor_r_to_payment", "dimensionless"), ("input.plan_information_at_t0.state_probabilities.*", "probability"), ("input.plan_information_at_t0.gap_at_payment_by_state.*", "currency"), ("input.replan_information_at_r.discount_factor_r_to_payment", "dimensionless"), ("input.replan_information_at_r.gap_at_payment", "currency"), ("expected_output.planned_reserve_at_r_using_I_t0", "currency"), ("expected_output.replanned_reserve_at_r_using_I_r", "currency"), ("expected_output.replanning_difference", "currency"), ("anti_oracles.planned_reserve_with_look_ahead", "currency")),
    "survival-half-single-weight": (("input.pathwise_scenarios.*.probability", "probability"), ("input.pathwise_scenarios.*.indicator_adjusted_gap", "currency"), ("input.analytic_survival_probability", "probability"), ("input.gap_conditional_on_alive", "currency"), ("expected_output.pathwise_expected_deficit", "currency"), ("expected_output.analytic_survival_weighted_deficit", "currency"), ("anti_oracles.double_weighted_deficit", "currency")),
    "couple-four-states": (("input.survival_probability_*", "probability"), ("input.floor_and_secure_income_by_state.*.*", "currency"), ("expected_output.state_probabilities.*", "probability"), ("expected_output.probability_at_least_one_alive", "probability"), ("expected_output.gap_by_state.*", "currency"), ("expected_output.probability_weighted_*", "currency")),
    "couple-dependence-indeterminate": (("input.survival_probability_*", "probability"), ("input.floor_and_secure_income_by_state.*.*", "currency")),
    "couple-deterministic-mortality": (("input.age_a_at_valuation", "time_years"), ("input.age_b_at_valuation", "time_years"), ("expected_output.active_person_count", "count")),
    "return-basis-distribution": (("input.opening_consolidated_wealth", "currency"), ("input.price_return", "dimensionless"), ("input.cash_distribution", "currency"), ("expected_output.*", "currency"), ("anti_oracles.total_return_plus_distribution", "currency")),
    "total-return-positive": (("input.opening_consolidated_wealth", "currency"), ("input.total_return", "dimensionless"), ("input.separate_distribution_event", "currency"), ("expected_output.*", "currency"), ("anti_oracles.double_counted_closing_wealth", "currency")),
    "return-basis-invalid-combination": (("input.opening_consolidated_wealth", "currency"), ("input.period_return", "dimensionless"), ("input.separate_distribution_event", "currency")),
    "internal-transfer-conservation": (("input.opening_balances.*", "currency"), ("input.transfer.amount", "currency"), ("expected_output.*", "currency"), ("expected_output.*.*", "currency")),
    "balance-reconciliation": (("input.opening_balance", "currency"), ("input.events.*.amount", "currency"), ("expected_output.closing_balance", "currency"), ("expected_output.net_change", "currency")),
    "tax-lot-simple": (("input.lot.quantity", "quantity"), ("input.lot.unit_cost", "currency_per_unit"), ("input.sale.quantity", "quantity"), ("input.sale.unit_price", "currency_per_unit"), ("input.tax_rate_on_positive_gain", "dimensionless"), ("expected_output.sold_quantity", "quantity"), ("expected_output.remaining_quantity", "quantity"), ("expected_output.gross_proceeds", "currency"), ("expected_output.allocated_cost_basis", "currency"), ("expected_output.taxable_gain", "currency"), ("expected_output.tax_due", "currency"), ("expected_output.net_proceeds", "currency"), ("expected_output.remaining_cost_basis", "currency")),
    "tax-lot-no-tax": (("input.lot.quantity", "quantity"), ("input.lot.unit_cost", "currency_per_unit"), ("input.sale.quantity", "quantity"), ("input.sale.unit_price", "currency_per_unit"), ("input.tax_rate_on_positive_gain", "dimensionless"), ("expected_output.sold_quantity", "quantity"), ("expected_output.remaining_quantity", "quantity"), ("expected_output.gross_proceeds", "currency"), ("expected_output.allocated_cost_basis", "currency"), ("expected_output.taxable_gain", "currency"), ("expected_output.tax_due", "currency"), ("expected_output.net_proceeds", "currency"), ("expected_output.remaining_cost_basis", "currency")),
    "portfolio-two-asset-convex": (("input.variance_a", "variance"), ("input.variance_b", "variance"), ("input.covariance_ab", "variance"), ("expected_output.weight_a", "dimensionless"), ("expected_output.weight_b", "dimensionless"), ("expected_output.portfolio_variance", "variance")),
    "cvar-discrete-enumerable": (("input.alpha", "probability"), ("input.scenarios.*.probability", "probability"), ("input.scenarios.*.loss", "currency"), ("expected_output.var", "currency"), ("expected_output.tail_expected_shortfall", "currency")),
    "two-stage-nonanticipativity": (("input.stage_1_scenarios.*.probability", "probability"), ("input.stage_1_scenarios.*.target_revealed_at_stage_1", "currency"), ("expected_output.*.stage_0_action_*", "currency"), ("expected_output.*.*loss*", "currency_squared")),
    "constant-contribution-closed-form": (("input.initial_assets", "currency"), ("input.accumulation_factor_initial_to_horizon", "dimensionless"), ("input.constant_contribution", "currency"), ("input.contribution_schedule.*.accumulation_factor_to_horizon", "dimensionless"), ("expected_output.accumulated_initial_assets", "currency"), ("expected_output.accumulated_contributions", "currency"), ("expected_output.future_value", "currency")),
    "contribution-all-at-r": (("input.financial_assets_at_t0", "currency"), ("input.accumulation_factor_t0_to_r", "dimensionless"), ("input.constant_contribution_schedule.*.accumulation_factor_to_r", "dimensionless"), ("input.planned_reserve_at_r", "currency"), ("input.planned_terminal_reserve_at_omega", "currency"), ("input.discount_factor_r_to_omega", "dimensionless"), ("expected_output.accumulated_initial_assets_at_r", "currency"), ("expected_output.discounted_terminal_reserve_at_r", "currency"), ("expected_output.sum_contribution_accumulation_factors", "dimensionless"), ("expected_output.constant_contribution_at_each_schedule_date", "currency"), ("expected_output.accumulated_contributions_at_r", "currency"), ("expected_output.planned_surplus_at_r", "currency"), ("anti_oracles.mixed_date_surplus", "currency")),
}

# Allowed units are exact per normative field.  Wildcards describe structural
# repetition, not a permission to substitute a same-dimension unit.
FIELD_UNITS: dict[str, dict[str, str]] = {
    "pv-unit-cashflow": {"input.cash_flow_amount":"BRL_nominal_at_payment_date","input.discount_factor":"dimensionless_BRL_at_valuation_date_per_BRL_at_payment_date","expected_output.present_value":"BRL_nominal_at_valuation_date"},
    "finite-annuity-certain": {"input.payment_amount":"BRL_nominal_at_each_payment_date","input.discount_factors.*":"dimensionless_BRL_at_valuation_date_per_BRL_at_payment_date","expected_output.present_value":"BRL_nominal_at_valuation_date"},
    "perpetuity-closed-form": {"input.payment_amount":"BRL_nominal_at_each_payment_date","input.effective_rate_per_period":"dimensionless_period_rate","expected_output.present_value":"BRL_nominal_at_valuation_date"},
    "survival-annuity-small": {"input.payments.*.survival_probability":"probability","input.payments.*.discount_factor":"dimensionless_BRL_at_valuation_date_per_BRL_at_payment_date","input.payments.*.amount_if_alive":"BRL_nominal_at_payment_date","expected_output.present_value":"BRL_nominal_at_valuation_date"},
    "reserve-plan-vs-replan": {"input.plan_information_at_t0.discount_factor_r_to_payment":"dimensionless_BRL_at_r_per_BRL_at_payment_date","input.plan_information_at_t0.state_probabilities.*":"probability","input.plan_information_at_t0.gap_at_payment_by_state.*":"BRL_nominal_at_payment_date","input.replan_information_at_r.discount_factor_r_to_payment":"dimensionless_BRL_at_r_per_BRL_at_payment_date","input.replan_information_at_r.gap_at_payment":"BRL_nominal_at_payment_date","expected_output.planned_reserve_at_r_using_I_t0":"BRL_nominal_at_r","expected_output.replanned_reserve_at_r_using_I_r":"BRL_nominal_at_r","expected_output.replanning_difference":"BRL_nominal_at_r","anti_oracles.planned_reserve_with_look_ahead":"BRL_nominal_at_r"},
    "survival-half-single-weight": {"input.pathwise_scenarios.*.probability":"probability","input.pathwise_scenarios.*.indicator_adjusted_gap":"BRL_at_payment_date","input.analytic_survival_probability":"probability","input.gap_conditional_on_alive":"BRL_at_payment_date_conditional_on_alive","expected_output.pathwise_expected_deficit":"BRL_at_payment_date","expected_output.analytic_survival_weighted_deficit":"BRL_at_payment_date","anti_oracles.double_weighted_deficit":"BRL_at_payment_date"},
    "couple-four-states": {"input.survival_probability_*":"probability","input.floor_and_secure_income_by_state.*.*":"BRL_at_payment_date","expected_output.state_probabilities.*":"probability","expected_output.probability_at_least_one_alive":"probability","expected_output.gap_by_state.*":"BRL_at_payment_date","expected_output.probability_weighted_*":"BRL_at_payment_date"},
    "couple-dependence-indeterminate": {"input.survival_probability_*":"probability","input.floor_and_secure_income_by_state.*.*":"BRL_at_payment_date"},
    "couple-deterministic-mortality": {"input.age_a_at_valuation":"years_exact","input.age_b_at_valuation":"years_exact","expected_output.active_person_count":"persons_count"},
    "return-basis-distribution": {"input.opening_consolidated_wealth":"BRL_at_period_start","input.price_return":"dimensionless_period_return","input.cash_distribution":"BRL_at_period_end","expected_output.*":"BRL_at_period_end","anti_oracles.total_return_plus_distribution":"BRL_at_period_end"},
    "total-return-positive": {"input.opening_consolidated_wealth":"BRL_at_period_start","input.total_return":"dimensionless_period_return","input.separate_distribution_event":"BRL_at_period_end","expected_output.*":"BRL_at_period_end","anti_oracles.double_counted_closing_wealth":"BRL_at_period_end"},
    "return-basis-invalid-combination": {"input.opening_consolidated_wealth":"BRL_at_period_start","input.period_return":"dimensionless_period_return","input.separate_distribution_event":"BRL_at_period_end"},
    "internal-transfer-conservation": {"input.opening_balances.*":"BRL_at_event_time","input.transfer.amount":"BRL_at_event_time","expected_output.*":"BRL_at_event_time","expected_output.*.*":"BRL_at_event_time"},
    "balance-reconciliation": {"input.opening_balance":"BRL_at_open","input.events.*.amount":"BRL_at_event_time","expected_output.closing_balance":"BRL_at_close","expected_output.net_change":"BRL_at_close"},
    "tax-lot-simple": {}, "tax-lot-no-tax": {},
    "portfolio-two-asset-convex": {"input.variance_a":"return_squared","input.variance_b":"return_squared","input.covariance_ab":"return_squared","expected_output.weight_a":"dimensionless_portfolio_weight","expected_output.weight_b":"dimensionless_portfolio_weight","expected_output.portfolio_variance":"return_squared"},
    "cvar-discrete-enumerable": {"input.alpha":"probability","input.scenarios.*.probability":"probability","input.scenarios.*.loss":"BRL_loss_at_horizon","expected_output.var":"BRL_loss_at_horizon","expected_output.tail_expected_shortfall":"BRL_loss_at_horizon"},
    "two-stage-nonanticipativity": {"input.stage_1_scenarios.*.probability":"probability","input.stage_1_scenarios.*.target_revealed_at_stage_1":"BRL_in_common_stage_0_valuation_units_revealed_at_stage_1","expected_output.*.stage_0_action_*":"BRL_in_common_stage_0_valuation_units_committed_at_stage_0","expected_output.*.*loss*":"BRL_squared"},
    "constant-contribution-closed-form": {"input.initial_assets":"BRL_nominal_at_t0","input.accumulation_factor_initial_to_horizon":"dimensionless_BRL_at_r_per_BRL_at_t0","input.constant_contribution":"BRL_nominal_at_each_contribution_date","input.contribution_schedule.*.accumulation_factor_to_horizon":"dimensionless_BRL_at_r_per_BRL_at_contribution_date","expected_output.accumulated_initial_assets":"BRL_nominal_at_r","expected_output.accumulated_contributions":"BRL_nominal_at_r","expected_output.future_value":"BRL_nominal_at_r"},
    "contribution-all-at-r": {"input.financial_assets_at_t0":"BRL_nominal_at_t0","input.accumulation_factor_t0_to_r":"dimensionless_BRL_at_r_per_BRL_at_t0","input.constant_contribution_schedule.*.accumulation_factor_to_r":"dimensionless_BRL_at_r_per_BRL_at_contribution_date","input.planned_reserve_at_r":"BRL_nominal_at_r","input.planned_terminal_reserve_at_omega":"BRL_nominal_at_omega","input.discount_factor_r_to_omega":"dimensionless_BRL_at_r_per_BRL_at_omega","expected_output.accumulated_initial_assets_at_r":"BRL_nominal_at_r","expected_output.discounted_terminal_reserve_at_r":"BRL_nominal_at_r","expected_output.sum_contribution_accumulation_factors":"dimensionless","expected_output.constant_contribution_at_each_schedule_date":"BRL_nominal_at_each_contribution_date","expected_output.accumulated_contributions_at_r":"BRL_nominal_at_r","expected_output.planned_surplus_at_r":"BRL_nominal_at_r","anti_oracles.mixed_date_surplus":"BRL_nominal_at_r"},
}

_lot_units = {"input.lot.quantity":"quantity_units","input.lot.unit_cost":"BRL_per_unit","input.sale.quantity":"quantity_units","input.sale.unit_price":"BRL_per_unit","input.tax_rate_on_positive_gain":"dimensionless_rate","expected_output.sold_quantity":"quantity_units","expected_output.remaining_quantity":"quantity_units","expected_output.gross_proceeds":"BRL_at_sale_date","expected_output.allocated_cost_basis":"BRL_at_sale_date","expected_output.taxable_gain":"BRL_at_sale_date","expected_output.tax_due":"BRL_at_sale_date","expected_output.net_proceeds":"BRL_at_sale_date","expected_output.remaining_cost_basis":"BRL_at_sale_date"}
FIELD_UNITS["tax-lot-simple"] = dict(_lot_units)
FIELD_UNITS["tax-lot-no-tax"] = dict(_lot_units)


class ConformanceError(Exception):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConformanceError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json_strict(text: str, source: str = "JSON") -> Any:
    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_keys, parse_constant=lambda value: (_ for _ in ()).throw(ConformanceError(f"non-finite JSON number: {value}")))
    except (json.JSONDecodeError, ConformanceError) as exc:
        raise ConformanceError(f"{source}: invalid JSON ({exc})") from exc


def canonical_bytes(vector: dict[str, Any]) -> bytes:
    return json.dumps({key: value for key, value in vector.items() if key != "fingerprint"}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def fingerprint(vector: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(vector)).hexdigest()


def is_reparse_point(path: Path) -> bool:
    try: attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError: return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)) or path.is_symlink()


def ensure_regular_file(path: Path, label: str) -> Path:
    try: info = os.lstat(path)
    except OSError as exc: raise ConformanceError(f"{label}: cannot inspect {path}: {exc}") from exc
    if is_reparse_point(path): raise ConformanceError(f"{label}: symlink/junction/reparse point is forbidden: {path}")
    if not stat.S_ISREG(info.st_mode): raise ConformanceError(f"{label}: regular file required: {path}")
    return path.resolve(strict=True)


def ensure_no_reparse_ancestors(path: Path, label: str) -> None:
    absolute = path.absolute()
    for ancestor in (absolute, *absolute.parents):
        if ancestor == Path(ancestor.anchor):
            continue
        if is_reparse_point(ancestor):
            raise ConformanceError(f"{label}: junction/symlink/reparse ancestor is forbidden: {ancestor}")


def ensure_single_link_regular_file(path: Path, label: str) -> Path:
    ensure_no_reparse_ancestors(path, label)
    resolved = ensure_regular_file(path, label)
    info = os.stat(resolved, follow_symlinks=False)
    if info.st_nlink != 1:
        raise ConformanceError(f"{label}: hardlinked artifact is forbidden (nlink={info.st_nlink})")
    return resolved


def stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def path_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Fields comparable between Windows fstat handles and path stat calls."""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)


def read_single_handle_snapshot(path: Path, label: str) -> tuple[Path, bytes, tuple[int, int, int, int, int, int]]:
    """Read one immutable byte snapshot and bind it to one opened file identity."""
    ensure_no_reparse_ancestors(path, label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.absolute(), flags)
    except OSError as exc:
        raise ConformanceError(f"{label}: cannot open a single-handle snapshot: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ConformanceError(f"{label}: regular file required: {path}")
        if before.st_nlink != 1:
            raise ConformanceError(f"{label}: hardlinked artifact is forbidden (nlink={before.st_nlink})")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            snapshot = stream.read()
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_identity, after_identity = stat_identity(before), stat_identity(after)
    if before_identity != after_identity:
        raise ConformanceError(f"{label}: file identity changed while its byte snapshot was read")
    try:
        path_info = os.lstat(path)
    except OSError as exc:
        raise ConformanceError(f"{label}: path disappeared after snapshot: {exc}") from exc
    if is_reparse_point(path) or path_identity(path_info) != path_identity(after):
        raise ConformanceError(f"{label}: path identity differs from the opened snapshot")
    ensure_no_reparse_ancestors(path, f"{label} post-read")
    return path.resolve(strict=True), snapshot, after_identity


def decode_json_snapshot(snapshot: bytes, source: str) -> Any:
    try:
        text = snapshot.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise ConformanceError(f"{source}: invalid UTF-8 ({exc})") from exc
    return load_json_strict(text, source)


def resolve_confined_file(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ConformanceError(f"{label}: path must be a confined relative path")
    root_resolved = root.resolve(strict=True)
    candidate = root / relative
    current = root
    for part in Path(relative).parts:
        current = current / part
        if is_reparse_point(current): raise ConformanceError(f"{label}: reparse path component is forbidden: {relative}")
    resolved = ensure_regular_file(candidate, label)
    try: resolved.relative_to(root_resolved)
    except ValueError as exc: raise ConformanceError(f"{label}: path escapes confinement root") from exc
    return resolved


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024): digest.update(chunk)
    return digest.hexdigest()


def inspect_corpus_tree(root: Path) -> tuple[set[str], list[str]]:
    errors: list[str] = []; json_files: set[str] = set()
    try:
        ensure_no_reparse_ancestors(root, "[corpus] vector root")
        root_info = os.lstat(root)
        if is_reparse_point(root): return set(), [f"[corpus] vector root must not be a symlink/junction/reparse point: {root}"]
        if not stat.S_ISDIR(root_info.st_mode): return set(), [f"[corpus] vector root must be a directory: {root}"]
    except ConformanceError as exc: return set(), [str(exc)]
    except OSError as exc: return set(), [f"[corpus] vector root cannot be inspected: {exc}"]
    def visit(directory: Path) -> None:
        try: entries = list(os.scandir(directory))
        except OSError as exc:
            errors.append(f"[corpus] cannot scan {directory}: {exc}"); return
        for entry in entries:
            path = Path(entry.path); relative = path.relative_to(root).as_posix()
            if is_reparse_point(path): errors.append(f"[corpus] symlink/junction/reparse point is forbidden: {relative}"); continue
            try: info = os.lstat(path)
            except OSError as exc: errors.append(f"[corpus] cannot inspect {relative}: {exc}"); continue
            if stat.S_ISDIR(info.st_mode): visit(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    errors.append(f"[corpus] hardlinked file is forbidden: {relative} (nlink={info.st_nlink})")
                    continue
                if path.suffix == ".json" and path.name != "manifest.json": json_files.add(relative)
            else: errors.append(f"[corpus] non-regular entry is forbidden: {relative}")
    visit(root)
    return json_files, errors


def decimal(value: Any, context: str) -> Decimal:
    if not isinstance(value, str) or not DECIMAL_TEXT.fullmatch(value):
        raise ConformanceError(f"{context}: expected canonical decimal string without exponent")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise ConformanceError(f"{context}: invalid decimal {value!r}") from exc
    if not result.is_finite() or (result == 0 and value.startswith("-")):
        raise ConformanceError(f"{context}: decimal must be finite and must not use negative zero")
    return result


def is_decimal_text(value: Any) -> bool:
    return isinstance(value, str) and bool(DECIMAL_TEXT.fullmatch(value))


def leaf_paths(value: Any, prefix: str) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaf_paths(item, f"{prefix}.{key}" if prefix else key)
    elif isinstance(value, list):
        for item in value:
            yield from leaf_paths(item, f"{prefix}.*")
    else:
        yield prefix, value


def numeric_leaf_paths(value: Any, prefix: str) -> Iterable[str]:
    for path, item in leaf_paths(value, prefix):
        if (isinstance(item, (int, float)) and not isinstance(item, bool)) or is_decimal_text(item):
            yield path


def pattern_matches(pattern: str, path: str) -> bool:
    expected = pattern.split(".")
    actual = path.split(".")
    return len(expected) == len(actual) and all(fnmatch.fnmatchcase(part, wanted) for wanted, part in zip(expected, actual))


def unit_dimension(unit: str) -> str | None:
    return UNIT_DIMENSIONS.get(unit)


def validate_unit_semantics(vector: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    vector_id = vector.get("id")
    contract = FIELD_DIMENSIONS.get(vector_id, ())
    units = vector.get("units")
    if not isinstance(units, dict) or not units:
        return ["units must be a non-empty object"]
    unit_contract = FIELD_UNITS.get(vector_id, {})
    numeric: dict[str, Any] = {}
    all_leaves: dict[str, Any] = {}
    for section in ("input", "expected_output", "anti_oracles"):
        for path, value in leaf_paths(vector.get(section, {}), section):
            all_leaves[path] = value
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                errors.append(f"numeric field {path!r} must be a canonical decimal string, not a JSON number")
                numeric[path] = value
            elif is_decimal_text(value):
                numeric[path] = value
                try: decimal(value, path)
                except ConformanceError as exc: errors.append(str(exc))
    for pattern, dimension in contract:
        matches = [(path, value) for path, value in all_leaves.items() if pattern_matches(pattern, path)]
        if not matches:
            errors.append(f"required numeric field pattern {pattern!r} is missing")
        for path, value in matches:
            try: decimal(value, path)
            except ConformanceError as exc: errors.append(str(exc))
    for path in sorted(numeric):
        dimensions = [dimension for pattern, dimension in contract if pattern_matches(pattern, path)]
        if len(dimensions) != 1:
            errors.append(f"numeric field {path!r} has no unique normative field dimension")
            continue
        declarations = [unit for pattern, unit in units.items() if isinstance(pattern, str) and pattern_matches(pattern, path)]
        if len(declarations) != 1:
            errors.append(f"numeric field {path!r} must have exactly one unit declaration")
        else:
            expected_units = {unit for pattern, unit in unit_contract.items() if pattern_matches(pattern, path)}
            if len(expected_units) != 1 or declarations[0] not in expected_units:
                errors.append(f"numeric field {path!r} requires exact unit {sorted(expected_units)!r}, got {declarations[0]!r}")
            elif unit_dimension(declarations[0]) != dimensions[0]:
                errors.append(f"numeric field {path!r} requires dimension {dimensions[0]!r}, got unit {declarations[0]!r}")
    for pattern, unit in units.items():
        if not isinstance(pattern, str) or not pattern:
            errors.append("unit path patterns must be non-empty strings")
        elif not any(pattern_matches(pattern, path) for path in numeric):
            errors.append(f"unit pattern {pattern!r} covers no numeric field")
        if not isinstance(unit, str) or unit not in UNIT_DIMENSIONS:
            errors.append(f"unit declaration {pattern!r} is not a recognized semantic unit")
    return errors


# Compatibility name retained for callers; validation is now semantic, not coverage-only.
validate_unit_coverage = validate_unit_semantics


def parse_date(value: Any, context: str) -> date:
    if not isinstance(value, str) or not ISO_DATE.fullmatch(value):
        raise ConformanceError(f"{context}: date must use exact YYYY-MM-DD format")
    try: return date.fromisoformat(value)
    except ValueError as exc: raise ConformanceError(f"{context}: invalid civil date") from exc


def get_path(value: dict[str, Any], dotted: str) -> Any:
    current: Any = value
    for part in dotted.split("."): current = current[part]
    return current


DATE_ORDERS = {
    "pv-unit-cashflow": ("input.valuation_date", "input.payment_date"),
    "reserve-plan-vs-replan": ("input.valuation_date_t0", "input.retirement_date_r", "input.payment_date"),
    "contribution-all-at-r": ("input.valuation_date_t0", "input.retirement_date_r", "input.terminal_date_omega"),
    "finite-annuity-certain": ("input.valuation_date", "input.first_payment_date", "input.last_payment_date"),
    "constant-contribution-closed-form": ("input.valuation_date", "input.horizon_date"),
    "couple-deterministic-mortality": ("input.valuation_date", "input.horizon_date"),
}


def require_mapping(parent: Any, key: str, context: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(parent, dict):
        errors.append(f"{context}: parent must be an object")
        return None
    if key not in parent:
        errors.append(f"{context}.{key}: required field is missing")
        return None
    value = parent[key]
    if not isinstance(value, dict):
        errors.append(f"{context}.{key}: must be an object")
        return None
    return value


def require_list(parent: Any, key: str, context: str, errors: list[str]) -> list[Any] | None:
    if not isinstance(parent, dict) or key not in parent:
        errors.append(f"{context}.{key}: required field is missing")
        return None
    value = parent[key]
    if not isinstance(value, list) or not value:
        errors.append(f"{context}.{key}: must be a non-empty array")
        return None
    return value


def require_keys(value: Any, keys: set[str], context: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{context}: must be an object")
        return False
    missing = keys - value.keys()
    for key in sorted(missing): errors.append(f"{context}.{key}: required field is missing")
    unexpected = value.keys() - keys
    for key in sorted(unexpected): errors.append(f"{context}.{key}: unexpected field")
    return not missing


BOOLEAN_PATHS = {
    "expected_output.equivalence_holds",
    "input.conditional_independence_assumed",
    "expected_output.implementable_policy.nonanticipativity_satisfied",
    "expected_output.perfect_information_diagnostic.implementable_at_stage_0",
}


def validate_total_json_types(vector: Any) -> list[str]:
    """Reject every untyped JSON leaf/container without indexing through it.

    The vector protocol has no JSON-number or null fields: numeric quantities
    are canonical decimal strings and the four declared flags are booleans.
    Structural object/array shapes are checked by ``validate_required_structure``.
    """
    if not isinstance(vector, dict):
        return ["top-level JSON value must be an object"]
    errors: list[str] = []
    for field in ("vector_format", "id", "topic", "expected_status", "derivation"):
        if field in vector and not isinstance(vector[field], str):
            errors.append(f"{field}: must be a string")
    for field in ("input", "expected_output", "units", "tolerance", "fingerprint"):
        if field in vector and not isinstance(vector[field], dict):
            errors.append(f"{field}: must be an object")
    if "anti_oracles" in vector and not isinstance(vector["anti_oracles"], dict):
        errors.append("anti_oracles: must be an object")
    for container in ("input", "expected_output", "anti_oracles"):
        value = vector.get(container)
        if not isinstance(value, dict):
            continue
        for path, leaf in leaf_paths(value, container):
            if path in BOOLEAN_PATHS:
                if type(leaf) is not bool:
                    errors.append(f"{path}: must be a boolean")
            elif isinstance(leaf, bool) or not isinstance(leaf, str):
                errors.append(f"{path}: must be a string")
    units = vector.get("units")
    if isinstance(units, dict):
        for key, value in units.items():
            if not isinstance(key, str) or not isinstance(value, str):
                errors.append("units: every field name and unit must be a string")
    for block_name, keys in (("tolerance", {"absolute", "relative"}), ("fingerprint", {"algorithm", "canonicalization", "value"})):
        block = vector.get(block_name)
        if isinstance(block, dict):
            if set(block) != keys:
                errors.append(f"{block_name}: fields must be exactly {sorted(keys)}")
            for key, value in block.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    errors.append(f"{block_name}.{key}: must be a string")
    return errors


def validate_required_structure(vector: dict[str, Any]) -> list[str]:
    """Emit field-level diagnostics without assuming any nested value exists."""
    errors: list[str] = []
    vector_id, data, output = vector.get("id"), vector.get("input"), vector.get("expected_output")
    if not isinstance(data, dict) or not isinstance(output, dict): return errors
    direct: dict[str, tuple[set[str], set[str]]] = {
        "pv-unit-cashflow": ({"valuation_date","payment_date","cash_flow_amount","discount_factor"},{"present_value"}),
        "finite-annuity-certain": ({"valuation_date","first_payment_date","last_payment_date","payment_amount","discount_factors"},{"present_value"}),
        "perpetuity-closed-form": ({"payment_amount","effective_rate_per_period"},{"present_value"}),
        "survival-annuity-small": ({"payments"},{"present_value"}),
        "reserve-plan-vs-replan": ({"valuation_date_t0","retirement_date_r","payment_date","plan_information_at_t0","replan_information_at_r"},{"planned_reserve_at_r_using_I_t0","replanned_reserve_at_r_using_I_r","replanning_difference","planned_decision_must_use"}),
        "survival-half-single-weight": ({"pathwise_scenarios","analytic_survival_probability","gap_conditional_on_alive"},{"pathwise_expected_deficit","analytic_survival_weighted_deficit","equivalence_holds"}),
        "couple-four-states": ({"survival_probability_a","survival_probability_b","conditional_independence_assumed","floor_and_secure_income_by_state"},{"state_probabilities","probability_at_least_one_alive","gap_by_state","probability_weighted_essential_floor","probability_weighted_secure_income","probability_weighted_gap"}),
        "couple-dependence-indeterminate": ({"survival_probability_a","survival_probability_b","conditional_independence_assumed","floor_and_secure_income_by_state"},{"reason_code"}),
        "couple-deterministic-mortality": ({"valuation_date","horizon_date","age_a_at_valuation","age_b_at_valuation","death_date_a","death_date_b"},{"household_state","active_person_count"}),
        "return-basis-distribution": ({"opening_consolidated_wealth","return_basis","price_return","cash_distribution"},{"closing_asset_value","closing_cash_from_distribution","closing_consolidated_wealth"}),
        "total-return-positive": ({"opening_consolidated_wealth","return_basis","total_return","separate_distribution_event"},{"closing_account_value","separate_distribution_event","closing_consolidated_wealth"}),
        "return-basis-invalid-combination": ({"opening_consolidated_wealth","return_basis","period_return","separate_distribution_event"},{"reason_code"}),
        "internal-transfer-conservation": ({"economic_source_id","opening_balances","transfer"},{"ledger_deltas","closing_balances","opening_consolidated_wealth","closing_consolidated_wealth","consolidated_transfer_contribution"}),
        "balance-reconciliation": ({"opening_balance","events"},{"net_change","closing_balance"}),
        "tax-lot-simple": ({"account_id","lot","sale","tax_rate_on_positive_gain"},{"sold_quantity","remaining_quantity","gross_proceeds","allocated_cost_basis","taxable_gain","tax_due","net_proceeds","remaining_cost_basis"}),
        "tax-lot-no-tax": ({"account_id","lot","sale","tax_rate_on_positive_gain"},{"sold_quantity","remaining_quantity","gross_proceeds","allocated_cost_basis","taxable_gain","tax_due","net_proceeds","remaining_cost_basis"}),
        "portfolio-two-asset-convex": ({"variance_a","variance_b","covariance_ab"},{"weight_a","weight_b","portfolio_variance"}),
        "cvar-discrete-enumerable": ({"alpha","scenarios"},{"var","tail_expected_shortfall"}),
        "two-stage-nonanticipativity": ({"objective","stage_0_information_set","stage_1_scenarios","stage_0_action_domain"},{"implementable_policy","perfect_information_diagnostic"}),
        "constant-contribution-closed-form": ({"valuation_date","horizon_date","initial_assets","accumulation_factor_initial_to_horizon","constant_contribution","contribution_schedule"},{"accumulated_initial_assets","accumulated_contributions","future_value"}),
        "contribution-all-at-r": ({"valuation_date_t0","retirement_date_r","terminal_date_omega","financial_assets_at_t0","accumulation_factor_t0_to_r","constant_contribution_schedule","planned_reserve_at_r","planned_terminal_reserve_at_omega","discount_factor_r_to_omega"},{"accumulated_initial_assets_at_r","discounted_terminal_reserve_at_r","sum_contribution_accumulation_factors","constant_contribution_at_each_schedule_date","accumulated_contributions_at_r","planned_surplus_at_r"}),
    }
    if vector_id in direct:
        require_keys(data, direct[vector_id][0], "input", errors)
        require_keys(output, direct[vector_id][1], "expected_output", errors)
    state_keys = {"both_alive","only_a_alive","only_b_alive","none_alive"}
    if vector_id in {"couple-four-states","couple-dependence-indeterminate"}:
        floors = data.get("floor_and_secure_income_by_state")
        if require_keys(floors, state_keys, "input.floor_and_secure_income_by_state", errors):
            for state in state_keys: require_keys(floors[state], {"essential_floor","secure_income"}, f"input.floor_and_secure_income_by_state.{state}", errors)
    if vector_id == "couple-four-states":
        require_keys(output.get("state_probabilities"), state_keys, "expected_output.state_probabilities", errors)
        require_keys(output.get("gap_by_state"), state_keys, "expected_output.gap_by_state", errors)
    list_contracts = {
        "survival-annuity-small": ("payments", {"payment_date","survival_probability","discount_factor","amount_if_alive"}),
        "balance-reconciliation": ("events", {"date","amount"}),
        "cvar-discrete-enumerable": ("scenarios", {"probability","loss"}),
        "constant-contribution-closed-form": ("contribution_schedule", {"date","accumulation_factor_to_horizon"}),
        "contribution-all-at-r": ("constant_contribution_schedule", {"date","accumulation_factor_to_r"}),
        "survival-half-single-weight": ("pathwise_scenarios", {"state","probability","indicator_adjusted_gap"}),
    }
    if vector_id in list_contracts:
        key, keys = list_contracts[vector_id]
        rows = require_list(data, key, "input", errors)
        if rows is not None:
            for index, row in enumerate(rows): require_keys(row, keys, f"input.{key}[{index}]", errors)
    if vector_id == "reserve-plan-vs-replan":
        plan = require_mapping(data, "plan_information_at_t0", "input", errors)
        replan = require_mapping(data, "replan_information_at_r", "input", errors)
        if plan is not None:
            require_keys(plan, {"discount_factor_r_to_payment","state_probabilities","gap_at_payment_by_state"}, "input.plan_information_at_t0", errors)
            states = plan.get("state_probabilities")
            gaps = plan.get("gap_at_payment_by_state")
            if isinstance(states, dict) and isinstance(gaps, dict):
                if not states: errors.append("input.plan_information_at_t0.state_probabilities: must be non-empty")
                if set(states) != set(gaps): errors.append("reserve state probability and gap keys must match exactly")
        if replan is not None: require_keys(replan, {"observed_state","discount_factor_r_to_payment","gap_at_payment"}, "input.replan_information_at_r", errors)
    if vector_id in {"tax-lot-simple","tax-lot-no-tax"}:
        lot, sale = data.get("lot"), data.get("sale")
        require_keys(lot, {"quantity","unit_cost"}, "input.lot", errors)
        require_keys(sale, {"quantity","unit_price"}, "input.sale", errors)
    if vector_id == "internal-transfer-conservation": require_keys(data.get("transfer"), {"from_account","to_account","amount"}, "input.transfer", errors)
    if vector_id == "two-stage-nonanticipativity":
        scenarios = data.get("stage_1_scenarios")
        if require_keys(scenarios, {"low","high"}, "input.stage_1_scenarios", errors):
            for name in ("low","high"): require_keys(scenarios[name], {"probability","target_revealed_at_stage_1"}, f"input.stage_1_scenarios.{name}", errors)
    return errors


def validate_domain_semantics(vector: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    vector_id = vector.get("id")
    data = vector.get("input", {})
    if not isinstance(data, dict): return ["input: must be an object"]
    probability_patterns = [pattern for pattern, dimension in FIELD_DIMENSIONS.get(vector_id, ()) if dimension == "probability"]
    for path, value in leaf_paths(vector.get("input", {}), "input"):
        leaf_name = path.split(".")[-1]
        if leaf_name == "date" or leaf_name.endswith("_date") or "_date_" in leaf_name:
            try: parse_date(value, path)
            except ConformanceError as exc: errors.append(str(exc))
        if any(pattern_matches(pattern, path) for pattern in probability_patterns):
            try:
                p = decimal(value, path)
                if not Decimal(0) <= p <= Decimal(1): errors.append(f"{path}: probability must be in [0,1]")
            except ConformanceError as exc: errors.append(str(exc))
    for path, value in leaf_paths(vector.get("expected_output", {}), "expected_output"):
        if any(pattern_matches(pattern, path) for pattern in probability_patterns):
            try:
                p = decimal(value, path)
                if not Decimal(0) <= p <= Decimal(1): errors.append(f"{path}: probability must be in [0,1]")
            except ConformanceError as exc: errors.append(str(exc))
    if vector_id in DATE_ORDERS:
        try:
            dates = [parse_date(get_path(vector, path), path) for path in DATE_ORDERS[vector_id]]
            if any(left >= right for left, right in zip(dates, dates[1:])): errors.append(f"{vector_id}: normative dates must be strictly increasing")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"date order cannot be evaluated: {exc}")
    if vector_id == "contribution-all-at-r":
        try:
            t0 = parse_date(vector["input"]["valuation_date_t0"], "valuation_date_t0")
            retirement = parse_date(vector["input"]["retirement_date_r"], "retirement_date_r")
            schedule = [parse_date(row["date"], "contribution date") for row in vector["input"]["constant_contribution_schedule"]]
            if schedule != sorted(schedule) or len(schedule) != len(set(schedule)) or any(not t0 < item <= retirement for item in schedule): errors.append("contribution schedule dates must be unique, increasing, and in (t0,r]")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"contribution schedule cannot be evaluated: {exc}")
    if vector_id == "balance-reconciliation":
        try:
            event_dates = [parse_date(row["date"], "event date") for row in vector["input"]["events"]]
            if event_dates != sorted(event_dates) or len(event_dates) != len(set(event_dates)): errors.append("balance event dates must be unique and increasing")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"balance dates cannot be evaluated: {exc}")
    if vector_id == "survival-annuity-small":
        try:
            payment_dates = [parse_date(row["payment_date"], "payment date") for row in vector["input"]["payments"]]
            if payment_dates != sorted(payment_dates) or len(payment_dates) != len(set(payment_dates)): errors.append("survival-annuity payment dates must be unique and increasing")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"annuity dates cannot be evaluated: {exc}")
    if vector_id == "constant-contribution-closed-form":
        try:
            t0, horizon = parse_date(data["valuation_date"], "input.valuation_date"), parse_date(data["horizon_date"], "input.horizon_date")
            schedule = [parse_date(row["date"], "contribution date") for row in data["contribution_schedule"]]
            if schedule != sorted(schedule) or len(schedule) != len(set(schedule)) or any(not t0 < item <= horizon for item in schedule): errors.append("closed-form contribution dates must be unique, increasing, and in (valuation,horizon]")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"closed-form contribution dates cannot be evaluated: {exc}")
    groups: list[tuple[str, list[Any]]] = []
    try:
        if vector_id == "reserve-plan-vs-replan": groups.append(("reserve states", list(data["plan_information_at_t0"]["state_probabilities"].values())))
        elif vector_id == "survival-half-single-weight": groups.append(("pathwise scenarios", [row["probability"] for row in data["pathwise_scenarios"]]))
        elif vector_id == "two-stage-nonanticipativity": groups.append(("stage-1 scenarios", [row["probability"] for row in data["stage_1_scenarios"].values()]))
        elif vector_id == "cvar-discrete-enumerable": groups.append(("CVaR scenarios", [row["probability"] for row in data["scenarios"]]))
    except (KeyError, TypeError) as exc: errors.append(f"probability group cannot be evaluated: {exc}")
    for label, group in groups:
        try:
            if sum((decimal(value, label) for value in group), Decimal(0)) != Decimal(1): errors.append(f"{label} probabilities must sum to one exactly")
        except ConformanceError as exc: errors.append(str(exc))
    if vector_id == "couple-four-states":
        try:
            if sum((decimal(value, "expected state probability") for value in vector["expected_output"]["state_probabilities"].values()), Decimal(0)) != 1: errors.append("expected household state probabilities must sum to one exactly")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"household state probabilities cannot be evaluated: {exc}")
    if vector_id == "portfolio-two-asset-convex":
        try:
            if decimal(vector["expected_output"]["weight_a"], "weight_a") + decimal(vector["expected_output"]["weight_b"], "weight_b") != 1: errors.append("portfolio weights must sum to one exactly")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"portfolio weights cannot be evaluated: {exc}")
    if vector_id == "internal-transfer-conservation":
        try:
            transfer = vector["input"]["transfer"]
            accounts = vector["input"]["opening_balances"]
            if transfer["from_account"] == transfer["to_account"]: errors.append("transfer.from_account must differ from transfer.to_account")
            if transfer["from_account"] not in accounts or transfer["to_account"] not in accounts: errors.append("transfer account ids must exist in opening_balances")
        except (KeyError, TypeError) as exc: errors.append(f"transfer field missing: {exc}")
    for path, value in leaf_paths(data, "input"):
        leaf = path.split(".")[-1]
        if "discount_factor" in leaf or "accumulation_factor" in leaf:
            try:
                if decimal(value, path) <= 0: errors.append(f"{path}: factor must be greater than zero")
            except ConformanceError as exc: errors.append(str(exc))
        if re.search(r"(?:^|_)age(?:_|$)", leaf):
            try:
                age = decimal(value, path)
                if not Decimal(0) <= age <= Decimal(130): errors.append(f"{path}: age must be in [0,130]")
            except ConformanceError as exc: errors.append(str(exc))
    if vector_id == "cvar-discrete-enumerable":
        try:
            alpha = decimal(data["alpha"], "input.alpha")
            if not Decimal(0) < alpha < Decimal(1): errors.append("input.alpha: must satisfy 0 < alpha < 1")
        except (KeyError, ConformanceError) as exc: errors.append(f"input.alpha: cannot be evaluated ({exc})")
    if vector_id == "perpetuity-closed-form":
        try:
            if decimal(data["effective_rate_per_period"], "input.effective_rate_per_period") <= 0: errors.append("input.effective_rate_per_period: must be greater than zero")
        except (KeyError, ConformanceError) as exc: errors.append(f"perpetuity rate cannot be evaluated: {exc}")
    if vector_id == "portfolio-two-asset-convex":
        try:
            va, vb, covariance = decimal(data["variance_a"], "input.variance_a"), decimal(data["variance_b"], "input.variance_b"), decimal(data["covariance_ab"], "input.covariance_ab")
            if va <= 0 or vb <= 0: errors.append("portfolio variances must be greater than zero")
            if covariance * covariance > va * vb: errors.append("portfolio covariance matrix must be positive semidefinite")
            if va + vb - 2 * covariance <= 0: errors.append("portfolio minimum-variance denominator must be greater than zero")
        except (KeyError, ConformanceError) as exc: errors.append(f"portfolio domain cannot be evaluated: {exc}")
    if vector_id in {"tax-lot-simple", "tax-lot-no-tax"}:
        try:
            held, sold = decimal(data["lot"]["quantity"], "input.lot.quantity"), decimal(data["sale"]["quantity"], "input.sale.quantity")
            if held <= 0: errors.append("input.lot.quantity: must be greater than zero")
            if sold <= 0 or sold > held: errors.append("input.sale.quantity: must satisfy 0 < sold <= lot quantity")
            rate = decimal(data["tax_rate_on_positive_gain"], "input.tax_rate_on_positive_gain")
            if not Decimal(0) <= rate <= Decimal(1): errors.append("input.tax_rate_on_positive_gain: must be in [0,1]")
            if decimal(data["lot"]["unit_cost"], "input.lot.unit_cost") < 0 or decimal(data["sale"]["unit_price"], "input.sale.unit_price") < 0: errors.append("lot unit cost and sale unit price must be non-negative")
            account = data["account_id"]
            if not isinstance(account, str) or not SAFE_IDENTIFIER.fullmatch(account): errors.append("input.account_id: invalid account identifier")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"tax lot domain cannot be evaluated: {exc}")
    if vector_id == "internal-transfer-conservation":
        try:
            accounts = data["opening_balances"]
            if not isinstance(accounts, dict) or len(accounts) < 2: errors.append("input.opening_balances: at least two accounts are required")
            elif any(not isinstance(key, str) or not SAFE_IDENTIFIER.fullmatch(key) for key in accounts): errors.append("input.opening_balances: invalid account identifier")
            amount = decimal(data["transfer"]["amount"], "input.transfer.amount")
            if amount <= 0: errors.append("input.transfer.amount: must be greater than zero")
            source = data["transfer"]["from_account"]
            if source in accounts and amount > decimal(accounts[source], f"input.opening_balances.{source}"): errors.append("input.transfer.amount: exceeds source account balance")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"transfer domain cannot be evaluated: {exc}")
    if vector_id == "couple-deterministic-mortality":
        try:
            valuation, horizon = parse_date(data["valuation_date"], "input.valuation_date"), parse_date(data["horizon_date"], "input.horizon_date")
            deaths = [parse_date(data[name], f"input.{name}") for name in ("death_date_a","death_date_b")]
            if any(death <= valuation for death in deaths): errors.append("deterministic death dates must be after valuation_date")
            if horizon <= valuation: errors.append("horizon_date must be after valuation_date")
        except (KeyError, TypeError, ConformanceError) as exc: errors.append(f"deterministic mortality dates cannot be evaluated: {exc}")
    return errors


def validate_vector(vector: Any, source: Path, update_fingerprints: bool) -> list[str]:
    if not isinstance(vector, dict): return ["top-level JSON value must be an object"]
    errors: list[str] = []
    required = {"vector_format", "id", "topic", "input", "expected_status", "expected_output", "units", "tolerance", "derivation", "fingerprint"}
    allowed = required | {"anti_oracles"}
    if set(vector) - allowed: errors.append(f"unexpected top-level fields: {sorted(set(vector) - allowed)}")
    for field in sorted(required - vector.keys()): errors.append(f"missing required field {field!r}")
    if vector.get("vector_format") != VECTOR_FORMAT: errors.append(f"vector_format must be {VECTOR_FORMAT!r}")
    vector_id = vector.get("id")
    if not isinstance(vector_id, str) or vector_id not in REQUIRED_IDS: errors.append("id is not in the required analytical corpus")
    expected_status = vector.get("expected_status")
    if not isinstance(expected_status, str) or expected_status not in STATUSES: errors.append("expected_status is invalid")
    if isinstance(vector_id, str) and vector.get("topic") != VECTOR_TOPICS.get(vector_id): errors.append("topic does not match the registered vector semantics")
    if not isinstance(vector.get("input"), dict): errors.append("input must be an object")
    if not isinstance(vector.get("expected_output"), dict): errors.append("expected_output must be an object")
    if any(str(key).startswith("forbidden_") for key in _walk_keys(vector.get("expected_output", {}))): errors.append("forbidden_* diagnostics belong in anti_oracles, never expected_output")
    if not isinstance(vector.get("derivation"), str) or not vector.get("derivation", "").strip(): errors.append("derivation must be non-empty")
    errors.extend(validate_total_json_types(vector))
    for validator in (validate_required_structure, validate_unit_semantics, validate_domain_semantics):
        try:
            errors.extend(validator(vector))
        except (KeyError, TypeError, ValueError, AttributeError, ConformanceError) as exc:
            errors.append(f"{validator.__name__}: cannot evaluate malformed field ({type(exc).__name__}: {exc})")
    tolerance = vector.get("tolerance")
    if not isinstance(tolerance, dict) or set(tolerance) != {"absolute", "relative"}: errors.append("tolerance must contain exactly absolute and relative")
    else:
        for name in ("absolute", "relative"):
            try:
                if decimal(tolerance[name], f"tolerance.{name}") < 0: errors.append(f"tolerance.{name} must be non-negative")
            except ConformanceError as exc: errors.append(str(exc))
    try: expected = fingerprint(vector)
    except (TypeError, ValueError) as exc:
        errors.append(f"fingerprint input cannot be canonicalized: {exc}")
        expected = ""
    block = vector.get("fingerprint")
    if update_fingerprints and isinstance(block, dict) and not errors:
        block.update({"algorithm": "sha256", "canonicalization": CANONICALIZATION, "value": expected})
        source.write_text(json.dumps(vector, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    elif not isinstance(block, dict): errors.append("fingerprint must be an object")
    else:
        if block.get("algorithm") != "sha256": errors.append("fingerprint.algorithm must be 'sha256'")
        if block.get("canonicalization") != CANONICALIZATION: errors.append(f"fingerprint.canonicalization must be {CANONICALIZATION!r}")
        if block.get("value") != expected: errors.append(f"fingerprint mismatch: expected {expected}")
    return errors


def _walk_keys(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key; yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value: yield from _walk_keys(item)


def close_enough(actual: Any, expected: Any, absolute: Decimal, relative: Decimal, path: str) -> bool:
    actual_decimal = decimal(actual, path); expected_decimal = decimal(expected, path)
    return abs(actual_decimal - expected_decimal) <= absolute + relative * abs(expected_decimal)


def compare_values(actual: Any, expected: Any, absolute: Decimal, relative: Decimal, path: str = "output") -> list[str]:
    errors: list[str] = []
    if isinstance(expected, dict):
        if not isinstance(actual, dict): return [f"{path}: expected object, got {type(actual).__name__}"]
        if set(actual) != set(expected):
            if set(expected) - set(actual): errors.append(f"{path}: missing keys {sorted(set(expected) - set(actual))}")
            if set(actual) - set(expected): errors.append(f"{path}: unexpected keys {sorted(set(actual) - set(expected))}")
        for key in sorted(set(actual) & set(expected)): errors.extend(compare_values(actual[key], expected[key], absolute, relative, f"{path}.{key}"))
    elif isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected): return [f"{path}: list shape differs"]
        for index, (left, right) in enumerate(zip(actual, expected)): errors.extend(compare_values(left, right, absolute, relative, f"{path}[{index}]"))
    elif is_decimal_text(expected):
        try:
            if not close_enough(actual, expected, absolute, relative, path): errors.append(f"{path}: expected {expected!r}, got {actual!r} (abs={absolute}, rel={relative})")
        except ConformanceError as exc: errors.append(str(exc))
    elif actual != expected: errors.append(f"{path}: expected {expected!r}, got {actual!r}")
    return errors


def make_request(vector: dict[str, Any]) -> dict[str, Any]:
    return {"protocol": PROTOCOL, "id": vector["id"], "topic": vector["topic"], "input": deepcopy(vector["input"])}


class Sut:
    def compute(self, request: dict[str, Any]) -> dict[str, Any]: raise NotImplementedError


def canonical_request_key(request: dict[str, Any]) -> bytes:
    return json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class FrozenValidationSut(Sut):
    """Read-only response map populated by a separately rooted subprocess route."""

    def __init__(
        self,
        validation_subprocess: Sut,
        requests: Iterable[dict[str, Any]],
        repeatability_requests: Iterable[dict[str, Any]],
    ) -> None:
        unique = {canonical_request_key(request): deepcopy(request) for request in requests}
        repeatability_keys = {canonical_request_key(request) for request in repeatability_requests}
        if not repeatability_keys or not repeatability_keys <= set(unique):
            raise ConformanceError("validation cache repeatability sample must be a non-empty subset of the closed request set")
        self._responses: dict[bytes, dict[str, Any]] = {}
        self.repeatability_checks = 0
        for key in sorted(unique):
            request = unique[key]
            first = validation_subprocess.compute(deepcopy(request))
            if key in repeatability_keys:
                second = validation_subprocess.compute(deepcopy(request))
                self.repeatability_checks += 1
                if canonical_request_key(first) != canonical_request_key(second):
                    raise ConformanceError("validation route is nondeterministic on the repeatability sample")
            self._responses[key] = deepcopy(first)
        self.cache_entries = len(self._responses)

    def compute(self, request: dict[str, Any]) -> dict[str, Any]:
        key = canonical_request_key(request)
        if key not in self._responses:
            raise ConformanceError("validation request is outside the precomputed closed request set")
        return deepcopy(self._responses[key])


class SutTimeoutError(ConformanceError): pass
class SutCrashError(ConformanceError): pass
class SutNonviableError(ConformanceError): pass


def isolated_environment(temp_root: str) -> dict[str, str]:
    allowed = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update({"HOME": temp_root, "USERPROFILE": temp_root, "TMP": temp_root, "TEMP": temp_root, "PYTHONHASHSEED": "0", "PYTHONIOENCODING": "utf-8", "PYTHONNOUSERSITE": "1", "NO_PROXY": "*", "no_proxy": "*"})
    return environment


class CommandSut(Sut):
    def __init__(self, command: str | list[str], timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS, stdout_limit: int = DEFAULT_STDOUT_LIMIT, stderr_limit: int = DEFAULT_STDERR_LIMIT, stderr_policy: str = "forbid") -> None:
        self.command = command if isinstance(command, list) else (json.loads(command) if command.lstrip().startswith("[") else shlex.split(command))
        if not isinstance(self.command, list) or not self.command or not all(isinstance(item, str) and item for item in self.command): raise ConformanceError("SUT command must be a non-empty argv string array")
        try:
            timeout_value = float(timeout_seconds) if type(timeout_seconds) in (int, float) else float("nan")
        except OverflowError as exc:
            raise ConformanceError("SUT timeout must be a positive finite number") from exc
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_value) or timeout_value <= 0: raise ConformanceError("SUT timeout must be a positive finite number")
        if type(stdout_limit) is not int or type(stderr_limit) is not int or stdout_limit <= 0 or stderr_limit <= 0: raise ConformanceError("SUT output limits must be positive exact integers")
        if stderr_policy not in {"forbid", "allow"}: raise ConformanceError("stderr policy must be forbid or allow")
        self.timeout_seconds, self.stdout_limit, self.stderr_limit, self.stderr_policy = timeout_value, stdout_limit, stderr_limit, stderr_policy

    def compute(self, request: dict[str, Any]) -> dict[str, Any]:
        request_bytes = (json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        with tempfile.TemporaryDirectory(prefix="math-sut-") as isolated_cwd:
            try:
                completed = run_bounded(
                    self.command,
                    cwd=isolated_cwd,
                    env=isolated_environment(isolated_cwd),
                    input_bytes=request_bytes,
                    timeout_seconds=self.timeout_seconds,
                    stdout_limit=self.stdout_limit,
                    stderr_limit=self.stderr_limit,
                )
            except BoundedProcessTimeout as exc:
                raise SutTimeoutError(f"SUT command timed out after {self.timeout_seconds:g}s") from exc
            except BoundedProcessOutputLimit as exc:
                raise SutNonviableError(f"SUT {exc.stream} exceeds {exc.limit} byte limit") from exc
            except (BoundedProcessStartError, BoundedProcessCleanupError, OSError) as exc:
                raise SutNonviableError(f"SUT command could not start: {exc}") from exc
            try:
                stdout = completed.stdout.decode("utf-8", errors="strict")
                stderr = completed.stderr.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc: raise SutNonviableError(f"SUT output is not UTF-8: {exc}") from exc
        if completed.returncode != 0:
            stderr_bytes = completed.stderr
            stderr_digest = hashlib.sha256(stderr_bytes).hexdigest()
            raise SutCrashError(
                f"SUT command exited {completed.returncode}; "
                f"stderr_bytes={len(stderr_bytes)}; stderr_sha256={stderr_digest}"
            )
        if self.stderr_policy == "forbid" and stderr: raise SutNonviableError("SUT command wrote to stderr under forbid policy")
        try: response = load_json_strict(stdout, "SUT stdout")
        except ConformanceError as exc: raise SutNonviableError(str(exc)) from exc
        if not isinstance(response, dict): raise SutNonviableError("SUT response must be one JSON object")
        return response


class ModuleSut(CommandSut):
    def __init__(self, specification: str, module_root: Path, worker_path: Path, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS, stdout_limit: int = DEFAULT_STDOUT_LIMIT, stderr_limit: int = DEFAULT_STDERR_LIMIT, stderr_policy: str = "forbid") -> None:
        module_name, separator, callable_name = specification.partition(":")
        callable_name = callable_name if separator else "compute"
        dotted = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
        if not dotted.fullmatch(module_name) or not re.fullmatch(r"^[A-Za-z_]\w*$", callable_name): raise ConformanceError("SUT module specification must be dotted.module[:callable]")
        if not module_root.is_dir() or is_reparse_point(module_root): raise ConformanceError("SUT module root must be a regular, non-reparse directory")
        ensure_regular_file(worker_path, "module worker")
        self.specification, self.module_root = specification, module_root.resolve()
        # -P prevents implicit unsafe path prepending and -s disables the user
        # site.  Unlike -I, these flags do not discard PYTHONHASHSEED=0.
        super().__init__([sys.executable, "-P", "-s", str(worker_path.resolve()), "--module", specification, "--module-root", str(self.module_root)], timeout_seconds, stdout_limit, stderr_limit, stderr_policy)


class PinnedReferenceRuntime:
    """Bounded in-process runtime for trusted fixture sensitivity only.

    This never evaluates a candidate SUT.  It imports the already snapshotted
    test-only reference source, restores colliding modules, and guards the
    caller's Decimal context around every computation.
    """

    MODULE_NAMES = ("reference_adapter", "math_mutants")

    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        self._saved_modules = {name: sys.modules.get(name) for name in self.MODULE_NAMES}
        self._path_text = str(self.root)
        self._closed = False
        self._initial_decimal_context = getcontext().copy()
        for name in self.MODULE_NAMES:
            sys.modules.pop(name, None)
        sys.path.insert(0, self._path_text)
        try:
            importlib.invalidate_caches()
            self.reference = importlib.import_module("reference_adapter")
            self.mutants = importlib.import_module("math_mutants").MUTANTS
            expected = {
                "reference_adapter": self.root / "reference_adapter.py",
                "math_mutants": self.root / "math_mutants.py",
            }
            for name, path in expected.items():
                module_path = Path(getattr(sys.modules[name], "__file__", "")).resolve(strict=True)
                if module_path != path.resolve(strict=True):
                    raise ConformanceError(f"pinned reference module {name} loaded from unexpected path {module_path}")
        except Exception:
            self.close()
            raise

    def compute(self, request: dict[str, Any], mutant: str) -> dict[str, Any]:
        context = getcontext().copy()
        try:
            return deepcopy(self.reference.compute(deepcopy(request), mutant=mutant))
        finally:
            setcontext(context)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for name in self.MODULE_NAMES:
            sys.modules.pop(name, None)
            saved = self._saved_modules.get(name)
            if saved is not None:
                sys.modules[name] = saved
        try:
            sys.path.remove(self._path_text)
        except ValueError:
            pass
        setcontext(self._initial_decimal_context)


class PinnedReferenceMutantSut(Sut):
    def __init__(self, runtime: PinnedReferenceRuntime, mutant: str) -> None:
        if mutant not in runtime.mutants:
            raise ConformanceError(f"unknown pinned reference mutant {mutant!r}")
        self.runtime = runtime
        self.mutant = mutant

    def compute(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.runtime.compute(request, self.mutant)


def validate_response(vector: dict[str, Any], response: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_keys = {"vector_id", "computational_status", "output"}
    if set(response) != expected_keys: errors.append(f"response keys must be exactly {sorted(expected_keys)}")
    if response.get("vector_id") != vector["id"]: errors.append(f"vector_id expected {vector['id']!r}, got {response.get('vector_id')!r}")
    if response.get("computational_status") != vector["expected_status"]: errors.append(f"computational_status expected {vector['expected_status']!r}, got {response.get('computational_status')!r}")
    errors.extend(compare_values(response.get("output"), vector["expected_output"], decimal(vector["tolerance"]["absolute"], "tolerance.absolute"), decimal(vector["tolerance"]["relative"], "tolerance.relative")))
    return errors


@dataclass
class EvaluationResult:
    property_counts: dict[str, int] = field(default_factory=dict)
    semantic_errors: list[str] = field(default_factory=list)
    assertion_errors: list[str] = field(default_factory=list)
    crashes: list[str] = field(default_factory=list)
    nonviable: list[str] = field(default_factory=list)
    timeouts: list[str] = field(default_factory=list)

    def all_errors(self) -> list[str]:
        return self.semantic_errors + self.assertion_errors + self.crashes + self.nonviable + self.timeouts

    def mutation_category(self) -> str:
        if self.timeouts: return "timeout"
        if self.nonviable: return "nonviable"
        if self.crashes: return "crash"
        if self.semantic_errors: return "semantic_kill"
        if self.assertion_errors: return "assertion_kill"
        return "survived"


def evaluate_sut(
    sut: Sut,
    vectors: list[dict[str, Any]],
    include_properties: bool = True,
    stop_on_execution_failure: bool = False,
    validation_sut: Sut | None = None,
    property_suite_path: Path | None = None,
) -> EvaluationResult:
    evaluation = EvaluationResult()
    for vector in vectors:
        try: evaluation.semantic_errors.extend(f"[{vector['id']}] {message}" for message in validate_response(vector, sut.compute(make_request(vector))))
        except SutTimeoutError as exc: evaluation.timeouts.append(f"[{vector['id']}] timeout: {exc}")
        except SutNonviableError as exc: evaluation.nonviable.append(f"[{vector['id']}] nonviable: {exc}")
        except SutCrashError as exc: evaluation.crashes.append(f"[{vector['id']}] crash: {exc}")
        except Exception as exc: evaluation.crashes.append(f"[{vector['id']}] crash: {type(exc).__name__}: {exc}")
        if stop_on_execution_failure and (evaluation.timeouts or evaluation.nonviable or evaluation.crashes): break
    if include_properties and not evaluation.all_errors():
        try:
            evaluation.property_counts, property_errors = run_properties(
                sut,
                {vector["id"]: vector for vector in vectors},
                validation_sut,
                property_suite_path,
            )
            evaluation.assertion_errors.extend(f"[properties] {message}" for message in property_errors)
        except SutTimeoutError as exc: evaluation.timeouts.append(f"[properties] timeout: {exc}")
        except SutNonviableError as exc: evaluation.nonviable.append(f"[properties] nonviable: {exc}")
        except SutCrashError as exc: evaluation.crashes.append(f"[properties] crash: {exc}")
        except Exception as exc: evaluation.crashes.append(f"[properties] crash: {type(exc).__name__}: {exc}")
    return evaluation


def load_pinned_property_suite(property_suite_path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(
        f"_pinned_math_property_suite_{hashlib.sha256(str(property_suite_path).encode()).hexdigest()[:12]}",
        property_suite_path,
    )
    if spec is None or spec.loader is None:
        raise ConformanceError("pinned property suite cannot be loaded")
    suite = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(suite)
    return suite


def closed_validation_requests(
    vectors: list[dict[str, Any]],
    property_suite_path: Path,
    include_properties: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    suite = load_pinned_property_suite(property_suite_path)
    fixtures = {vector["id"]: vector for vector in vectors}
    generated = [request for _, _, request in suite.generated_requests(fixtures)] if include_properties else []
    requests = [make_request(vector) for vector in vectors] + generated
    if include_properties:
        annuity_sample = next(request for request in generated if request["id"] == "finite-annuity-certain" and len(request["input"]["discount_factors"]) == 4)
        cvar_sample = next(request for request in generated if request["id"] == "cvar-discrete-enumerable" and request["input"]["alpha"] != fixtures["cvar-discrete-enumerable"]["input"]["alpha"])
    else:
        annuity_sample = make_request(fixtures["finite-annuity-certain"])
        cvar_sample = make_request(fixtures["cvar-discrete-enumerable"])
    repeatability = [make_request(fixtures["pv-unit-cashflow"]), annuity_sample, cvar_sample]
    return requests, repeatability


def run_properties(
    sut: Sut,
    fixtures: dict[str, dict[str, Any]],
    validation_sut: Sut | None = None,
    property_suite_path: Path | None = None,
) -> tuple[dict[str, int], list[str]]:
    conformance_dir = Path(__file__).resolve().parents[1] / "tests" / "conformance"
    if property_suite_path is None:
        sys.path.insert(0, str(conformance_dir))
        try:
            suite = importlib.import_module("property_suite")
            validation = importlib.import_module("independent_oracle").compute
            counts, errors = suite.run(sut.compute, validation, fixtures)
        finally:
            sys.path.pop(0)
    else:
        suite = load_pinned_property_suite(property_suite_path)
        if validation_sut is None:
            raise ConformanceError("pinned property suite requires the separate validation subprocess")
        counts, errors = suite.run(sut.compute, validation_sut.compute, fixtures)
    date_checks = 0
    reversed_pv = deepcopy(fixtures["pv-unit-cashflow"]); reversed_pv["input"]["payment_date"] = "2025-01-01"; date_checks += 1
    if not any("strictly increasing" in error for error in validate_domain_semantics(reversed_pv)): errors.append("property civil-date-domain:reversed-pv failed")
    duplicated = deepcopy(fixtures["contribution-all-at-r"]); duplicated["input"]["constant_contribution_schedule"][1]["date"] = duplicated["input"]["constant_contribution_schedule"][0]["date"]; date_checks += 1
    if not any("unique, increasing" in error for error in validate_domain_semantics(duplicated)): errors.append("property civil-date-domain:duplicate-contribution-date failed")
    counts["civil-date-domain"] = date_checks
    return counts, errors


def empty_mutation_categories() -> dict[str, list[str]]:
    return {name: [] for name in ("semantic_kill", "assertion_kill", "crash", "timeout", "nonviable", "survived")}


def run_reference_fixture_sensitivity(
    vectors: list[dict[str, Any]],
    conformance_dir: Path,
    validation_sut: Sut | None = None,
    property_suite_path: Path | None = None,
    reference_script: Path | None = None,
    mutant_ids: tuple[str, ...] | None = None,
    command_limits: tuple[float, int, int, str] | None = None,
) -> dict[str, list[str]]:
    """Classify every internal mutant without treating execution failure as a kill."""
    pinned_runtime: PinnedReferenceRuntime | None = None
    if reference_script is None:
        sys.path.insert(0, str(conformance_dir))
    try:
        categories = empty_mutation_categories()
        if reference_script is None:
            reference = importlib.import_module("reference_adapter")
            mutants = importlib.import_module("math_mutants").MUTANTS
            names = tuple(sorted(mutants))
        else:
            if mutant_ids is None:
                raise ConformanceError("pinned reference sensitivity requires statically extracted mutant IDs")
            reference = None
            pinned_runtime = PinnedReferenceRuntime(reference_script.parent)
            if set(mutant_ids) != set(pinned_runtime.mutants):
                raise ConformanceError("statically extracted mutant IDs differ from the pinned runtime registry")
            names = tuple(sorted(mutant_ids))
        for name in names:
            if reference_script is None:
                mutant_sut = type(
                    "InternalMutantSut",
                    (Sut,),
                    {"compute": lambda self, request, mutant=name: reference.compute(request, mutant=mutant)},  # type: ignore[union-attr]
                )()
            else:
                mutant_sut = PinnedReferenceMutantSut(pinned_runtime, name)
            outcome = evaluate_sut(
                mutant_sut,
                vectors,
                include_properties=True,
                stop_on_execution_failure=True,
                validation_sut=validation_sut,
                property_suite_path=property_suite_path,
            )
            categories[outcome.mutation_category()].append(name)
        return categories
    finally:
        if pinned_runtime is not None:
            pinned_runtime.close()
        if reference_script is None:
            sys.path.pop(0)


# Backward-compatible API name; callers must not label this a SUT mutation score.
run_mutations = run_reference_fixture_sensitivity


def cross_check_independent_oracle(vectors: list[dict[str, Any]], conformance_dir: Path) -> list[str]:
    sys.path.insert(0, str(conformance_dir))
    try:
        reference = importlib.import_module("reference_adapter"); independent = importlib.import_module("independent_oracle")
        errors: list[str] = []
        if getattr(independent, "DERIVATION_METHOD_IDS", None) != ORACLE_DERIVATION_METHODS:
            errors.append("[oracle] independent derivation_method_id registry does not match the manifest contract")
        for vector in vectors:
            first, second = reference.compute(make_request(vector)), independent.compute(make_request(vector))
            errors.extend(f"[{vector['id']}] independent oracle disagreement: {message}" for message in validate_response(vector, first))
            errors.extend(f"[{vector['id']}] independent oracle disagreement: {message}" for message in validate_response(vector, second))
            errors.extend(f"[{vector['id']}] oracle-to-oracle disagreement: {message}" for message in compare_values(first, second, decimal(vector["tolerance"]["absolute"], "absolute"), decimal(vector["tolerance"]["relative"], "relative"), "response"))
        return errors
    finally: sys.path.pop(0)


def cross_check_validation_routes(vectors: list[dict[str, Any]], reference: Sut, validation: Sut) -> list[str]:
    """Reconcile two separately rooted subprocess routes without claiming proof of independence."""
    errors: list[str] = []
    for vector in vectors:
        try:
            first = reference.compute(make_request(vector))
            second = validation.compute(make_request(vector))
        except (SutTimeoutError, SutCrashError, SutNonviableError) as exc:
            errors.append(f"[{vector['id']}] validation route execution failed: {exc}")
            continue
        errors.extend(f"[{vector['id']}] reference route disagreement: {message}" for message in validate_response(vector, first))
        errors.extend(f"[{vector['id']}] validation route disagreement: {message}" for message in validate_response(vector, second))
        errors.extend(f"[{vector['id']}] route-to-route disagreement: {message}" for message in compare_values(first, second, decimal(vector["tolerance"]["absolute"], "absolute"), decimal(vector["tolerance"]["relative"], "relative"), "response"))
    return errors


def load_vectors(root: Path, update_fingerprints: bool) -> tuple[list[dict[str, Any]], list[str]]:
    vectors, errors = [], []
    actual, tree_errors = inspect_corpus_tree(root)
    if tree_errors: return [], tree_errors
    manifest_path = root / "manifest.json"
    try:
        manifest_path, manifest_snapshot, _ = read_single_handle_snapshot(manifest_path, "[manifest]")
        manifest = decode_json_snapshot(manifest_snapshot, str(manifest_path))
    except (OSError, ConformanceError) as exc: return [], [str(exc)]
    if not isinstance(manifest, dict): return [], ["[manifest] top-level JSON must be an object"]
    if set(manifest) != {"manifest_format", "corpus_version", "artifact_status", "spec_case_mapping", "vectors"}: errors.append("[manifest] fields must include exact spec_case_mapping and vectors")
    if not isinstance(manifest.get("manifest_format"), str) or manifest.get("manifest_format") != MANIFEST_FORMAT: errors.append(f"[manifest] manifest_format must be {MANIFEST_FORMAT!r}")
    if not isinstance(manifest.get("corpus_version"), str) or manifest.get("corpus_version") != "1": errors.append("[manifest] corpus_version must be '1'")
    if not isinstance(manifest.get("artifact_status"), str) or manifest.get("artifact_status") != "draft": errors.append("[manifest] artifact_status must remain 'draft'")
    entries = manifest.get("vectors")
    if not isinstance(entries, list) or not entries: return [], errors + ["[manifest] vectors must be a non-empty array"]
    registered_paths, registered_ids, valid_entries = set(), set(), []
    fields = {"id", "path", "fingerprint", "category", "expected_status", "spec_case_id", "derivation_method_id", "validation_methods"}
    for index, entry in enumerate(entries):
        label = f"[manifest.vectors[{index}]]"
        if not isinstance(entry, dict) or set(entry) != fields: errors.append(f"{label} fields must be exactly {sorted(fields)}"); continue
        entry_id, entry_path = entry.get("id"), entry.get("path")
        if not isinstance(entry_id, str) or not entry_id: errors.append(f"{label} id must be non-empty"); continue
        if entry_id in registered_ids: errors.append(f"{label} duplicate manifest id {entry_id!r}")
        registered_ids.add(entry_id)
        if not isinstance(entry_path, str) or not entry_path.endswith(".json") or entry_path == "manifest.json" or Path(entry_path).name != entry_path or Path(entry_path).is_absolute(): errors.append(f"{label} path traversal/nesting is forbidden; path must be a direct child JSON filename"); continue
        if entry_path in registered_paths: errors.append(f"{label} duplicate manifest path {entry_path!r}")
        registered_paths.add(entry_path)
        category = entry.get("category")
        if not isinstance(category, str) or category not in MANIFEST_CATEGORIES: errors.append(f"{label} category is invalid")
        status_value = entry.get("expected_status")
        if not isinstance(status_value, str) or status_value not in STATUSES: errors.append(f"{label} expected_status is invalid")
        spec_case_value = entry.get("spec_case_id")
        if spec_case_value is not None and (not isinstance(spec_case_value, str) or spec_case_value not in SPEC_CASE_IDS): errors.append(f"{label} spec_case_id must be null or one of the 15 normative cases")
        if not isinstance(entry.get("derivation_method_id"), str) or not SAFE_IDENTIFIER.fullmatch(entry["derivation_method_id"]): errors.append(f"{label} derivation_method_id is invalid")
        elif ORACLE_DERIVATION_METHODS.get(entry_id) != entry["derivation_method_id"]: errors.append(f"{label} derivation_method_id does not match the registered independent derivation")
        validation_methods = entry.get("validation_methods")
        expected_methods = VALIDATION_METHODS_BY_VECTOR.get(entry_id)
        if not isinstance(validation_methods, list) or len(validation_methods) != 2:
            errors.append(f"{label} validation_methods must declare exactly two methods")
        else:
            for method_index, method in enumerate(validation_methods):
                method_label = f"{label}.validation_methods[{method_index}]"
                if not isinstance(method, dict) or set(method) != {"method_id", "validation_type"}:
                    errors.append(f"{method_label} fields must be exactly method_id and validation_type")
                    continue
                if not isinstance(method.get("method_id"), str) or not SAFE_IDENTIFIER.fullmatch(method["method_id"]):
                    errors.append(f"{method_label} method_id is invalid")
                if method.get("validation_type") not in VALIDATION_TYPES:
                    errors.append(f"{method_label} validation_type must be one of {sorted(VALIDATION_TYPES)}")
            if expected_methods is None or validation_methods != list(expected_methods):
                errors.append(f"{label} validation_methods do not match the registered two-method contract")
            method_ids = [method.get("method_id") for method in validation_methods if isinstance(method, dict)]
            if len(method_ids) != len(set(method_ids)):
                errors.append(f"{label} validation_methods must use two distinct method_id values")
        if not isinstance(entry.get("fingerprint"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["fingerprint"]): errors.append(f"{label} fingerprint must be lowercase SHA-256")
        valid_entries.append(entry)
    mappings = manifest.get("spec_case_mapping")
    mapped_cases: dict[str, list[str]] = {}
    mapped_bindings: dict[str, dict[str, str]] = {}
    if not isinstance(mappings, list): errors.append("[manifest] spec_case_mapping must be an array")
    else:
        for index, mapping in enumerate(mappings):
            label = f"[manifest.spec_case_mapping[{index}]]"
            if not isinstance(mapping, dict) or set(mapping) != {"case_id","vector_bindings"}: errors.append(f"{label} fields must be exactly case_id and vector_bindings"); continue
            case_id, bindings = mapping.get("case_id"), mapping.get("vector_bindings")
            if not isinstance(case_id, str) or case_id not in SPEC_CASE_IDS or case_id in mapped_cases: errors.append(f"{label} case_id is invalid or duplicate"); continue
            if not isinstance(bindings, list) or not bindings: errors.append(f"{label} vector_bindings must be a non-empty array"); continue
            vector_ids: list[str] = []
            for binding_index, binding in enumerate(bindings):
                binding_label = f"{label}.vector_bindings[{binding_index}]"
                fields = {"vector_id", "topic", "property_family_id", "derivation_method_id"}
                if not isinstance(binding, dict) or set(binding) != fields:
                    errors.append(f"{binding_label} fields must be exactly {sorted(fields)}")
                    continue
                if any(not isinstance(binding.get(field), str) or not binding[field] for field in fields):
                    errors.append(f"{binding_label} all fields must be non-empty strings")
                    continue
                vector_id = binding["vector_id"]
                vector_ids.append(vector_id)
                if vector_id in mapped_bindings:
                    errors.append(f"{binding_label} vector_id is duplicated across normative cases")
                mapped_bindings[vector_id] = binding
                if binding["property_family_id"] != vector_id:
                    errors.append(f"{binding_label} property_family_id must bind the vector's exact property family")
                if binding["topic"] != VECTOR_TOPICS.get(vector_id):
                    errors.append(f"{binding_label} topic is not allowed for vector {vector_id!r}")
                if binding["derivation_method_id"] != ORACLE_DERIVATION_METHODS.get(vector_id):
                    errors.append(f"{binding_label} derivation method is not allowed for vector {vector_id!r}")
            if len(vector_ids) != len(set(vector_ids)):
                errors.append(f"{label} contains duplicate vector bindings")
            expected_ids = SPEC_CASE_VECTOR_IDS.get(case_id, ())
            if tuple(vector_ids) != expected_ids:
                errors.append(f"{label} semantic binding must be exactly {list(expected_ids)!r} in normative order")
            mapped_cases[case_id] = vector_ids
        for missing_case in sorted(SPEC_CASE_IDS - mapped_cases.keys(), key=int): errors.append(f"[manifest] normative spec case {missing_case} is not mapped")
        mapped_ids = {item for values in mapped_cases.values() for item in values}
        for unknown in sorted(mapped_ids - registered_ids): errors.append(f"[manifest] spec mapping references unknown vector {unknown!r}")
        expected_mapped_ids = REQUIRED_IDS - SUPPLEMENTAL_IDS
        if mapped_ids != expected_mapped_ids:
            errors.append(f"[manifest] normative mapping must contain exactly 18 vectors; missing={sorted(expected_mapped_ids - mapped_ids)}, extra={sorted(mapped_ids - expected_mapped_ids)}")
        for entry in valid_entries:
            if entry["spec_case_id"] is not None and entry["id"] not in mapped_cases.get(entry["spec_case_id"], []): errors.append(f"[manifest] vector {entry['id']!r} is not listed under its spec_case_id {entry['spec_case_id']}")
            if entry["id"] in SUPPLEMENTAL_IDS and entry["spec_case_id"] is not None:
                errors.append(f"[manifest] supplemental vector {entry['id']!r} must have null spec_case_id")
            if entry["id"] not in SUPPLEMENTAL_IDS and entry["spec_case_id"] is None:
                errors.append(f"[manifest] normative vector {entry['id']!r} must declare a spec_case_id")
    for orphan in sorted(actual - registered_paths): errors.append(f"[manifest] unregistered JSON file {orphan!r}")
    for missing in sorted(registered_paths - actual): errors.append(f"[manifest] registered vector file is missing: {missing!r}")
    seen: set[str] = set()
    for entry in valid_entries:
        path = root / entry["path"]
        try:
            path, vector_snapshot, _ = read_single_handle_snapshot(path, f"[{entry['id']}]")
            vector = decode_json_snapshot(vector_snapshot, str(path)); vector_errors = validate_vector(vector, path, update_fingerprints)
            raw_vector_id = vector.get("id", path.name) if isinstance(vector, dict) else path.name
            vector_id = raw_vector_id if isinstance(raw_vector_id, str) else path.name
            errors.extend(f"[{vector_id}] {message}" for message in vector_errors)
            if isinstance(vector, dict):
                if raw_vector_id != entry["id"]: errors.append(f"[{vector_id}] manifest id is {entry['id']!r}")
                binding = mapped_bindings.get(vector_id)
                if entry.get("spec_case_id") is not None and binding is not None:
                    if vector.get("topic") != binding["topic"]: errors.append(f"[{vector_id}] topic differs from its normative case binding")
                    if entry.get("derivation_method_id") != binding["derivation_method_id"]: errors.append(f"[{vector_id}] derivation differs from its normative case binding")
                if vector.get("expected_status") != entry["expected_status"]: errors.append(f"[{vector_id}] expected_status does not match manifest")
                embedded = vector.get("fingerprint", {}).get("value") if isinstance(vector.get("fingerprint"), dict) else None
                if update_fingerprints: entry["fingerprint"] = embedded
                elif embedded != entry["fingerprint"]: errors.append(f"[{vector_id}] fingerprint does not match manifest")
                if isinstance(raw_vector_id, str):
                    if vector_id in seen: errors.append(f"[{vector_id}] duplicate vector id")
                    seen.add(vector_id); vectors.append(vector)
        except (OSError, ConformanceError) as exc: errors.append(str(exc))
    for missing in sorted(REQUIRED_IDS - seen): errors.append(f"[corpus] missing required vector {missing!r}")
    for extra in sorted(seen - REQUIRED_IDS): errors.append(f"[corpus] unexpected vector {extra!r}")
    if update_fingerprints and not errors: manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return vectors, errors


@dataclass(frozen=True)
class ArtifactPin:
    path: Path
    sha256: str
    label: str
    stat_identity: tuple[int, int, int, int, int, int]
    snapshot_bytes: bytes = field(repr=False, compare=False)

    def recheck(self) -> None:
        _, snapshot, identity = read_single_handle_snapshot(self.path, f"{self.label} recheck")
        if identity != self.stat_identity or snapshot != self.snapshot_bytes or hashlib.sha256(snapshot).hexdigest() != self.sha256:
            raise ConformanceError(f"{self.label}: artifact identity/hash changed during mutation run")


@dataclass(frozen=True)
class LauncherDefinition:
    python_executable: ArtifactPin
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class MutantDefinition:
    mutant_id: str
    operator_id: str
    mutant_artifact: ArtifactPin
    operator_artifact: ArtifactPin
    launcher: LauncherDefinition


@dataclass(frozen=True)
class PinnedMutationManifest:
    path: Path
    external_sha256: str
    manifest_snapshot: bytes = field(repr=False, compare=False)
    manifest_stat_identity: tuple[int, int, int, int, int, int]
    base_artifact: ArtifactPin
    base_launcher: LauncherDefinition
    mutants: tuple[MutantDefinition, ...]
    execution_failure_policy: str
    pins: tuple[ArtifactPin, ...] = field(default_factory=tuple)

    def recheck(self) -> None:
        _, snapshot, identity = read_single_handle_snapshot(self.path, "mutation manifest recheck")
        if identity != self.manifest_stat_identity or snapshot != self.manifest_snapshot or hashlib.sha256(snapshot).hexdigest() != self.external_sha256:
            raise ConformanceError("mutation manifest identity/hash changed after initial single-handle verification")
        for pin in self.pins:
            pin.recheck()


def _load_artifact_pin(root: Path, block: Any, label: str) -> ArtifactPin:
    if not isinstance(block, dict) or set(block) != {"path","sha256"}: raise ConformanceError(f"{label}: must contain exactly path and sha256")
    digest = block.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest): raise ConformanceError(f"{label}: sha256 must be lowercase hex")
    path = resolve_confined_file(root, block.get("path"), label)
    path, snapshot, identity = read_single_handle_snapshot(path, label)
    if hashlib.sha256(snapshot).hexdigest() != digest: raise ConformanceError(f"{label}: SHA-256 mismatch")
    return ArtifactPin(path, digest, label, identity, snapshot)


@dataclass(frozen=True)
class RouteFilePin:
    relative_path: str
    artifact: ArtifactPin


@dataclass(frozen=True)
class PinnedValidationRouteBundle:
    path: Path
    manifest_sha256: str
    externally_pinned: bool
    manifest_snapshot: bytes = field(repr=False, compare=False)
    manifest_stat_identity: tuple[int, int, int, int, int, int]
    reference_entrypoint: str
    validation_entrypoint: str
    source_sets: dict[str, tuple[RouteFilePin, ...]]
    mutant_ids: tuple[str, ...]

    def recheck(self) -> None:
        _, snapshot, identity = read_single_handle_snapshot(self.path, "validation route manifest recheck")
        if identity != self.manifest_stat_identity or snapshot != self.manifest_snapshot or hashlib.sha256(snapshot).hexdigest() != self.manifest_sha256:
            raise ConformanceError("validation route manifest identity/hash changed after initial verification")
        for files in self.source_sets.values():
            for pin in files:
                pin.artifact.recheck()


def _validation_import_errors(
    files: tuple[RouteFilePin, ...],
    allowed_import_roots: set[str] = VALIDATION_IMPORT_ROOTS,
) -> list[str]:
    errors: list[str] = []
    forbidden_names = {"__import__", "compile", "eval", "exec", "importlib", "reference_adapter"}
    for route_file in files:
        if not route_file.relative_path.endswith(".py"):
            errors.append(f"{route_file.relative_path}: validation source must be Python")
            continue
        try:
            source = route_file.artifact.snapshot_bytes.decode("utf-8-sig", errors="strict")
            tree = ast.parse(source, filename=route_file.relative_path)
        except (UnicodeDecodeError, SyntaxError) as exc:
            errors.append(f"{route_file.relative_path}: cannot parse pinned validation source: {exc}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.partition(".")[0]
                    if root not in allowed_import_roots:
                        errors.append(f"{route_file.relative_path}:{node.lineno}: import root {root!r} is outside the validation whitelist")
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                root = (node.module or "").partition(".")[0]
                if root not in allowed_import_roots:
                    errors.append(f"{route_file.relative_path}:{node.lineno}: import root {root!r} is outside the validation whitelist")
            elif isinstance(node, ast.Name) and node.id in forbidden_names:
                errors.append(f"{route_file.relative_path}:{node.lineno}: forbidden dynamic/reuse name {node.id!r}")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value == "reference_adapter":
                errors.append(f"{route_file.relative_path}:{node.lineno}: forbidden reference route module literal")
    return errors


def _mutant_ids_from_snapshot(snapshot: bytes) -> tuple[str, ...]:
    try:
        tree = ast.parse(snapshot.decode("utf-8-sig", errors="strict"), filename="math_mutants.py")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ConformanceError(f"math_mutants.py cannot be parsed without execution: {exc}") from exc
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not any(isinstance(target, ast.Name) and target.id == "MUTANTS" for target in node.targets):
            continue
        if not isinstance(node.value, ast.Dict):
            break
        keys = tuple(key.value for key in node.value.keys if isinstance(key, ast.Constant) and isinstance(key.value, str))
        if len(keys) != len(node.value.keys) or not keys or len(set(keys)) != len(keys):
            break
        return tuple(sorted(keys))
    raise ConformanceError("math_mutants.py must expose one literal, non-empty MUTANTS string-key registry")


def load_validation_route_bundle(
    path: Path,
    external_sha256: str | None,
    require_external_pin: bool,
) -> PinnedValidationRouteBundle:
    manifest_path, manifest_snapshot, manifest_identity = read_single_handle_snapshot(path, "validation route manifest")
    observed_sha256 = hashlib.sha256(manifest_snapshot).hexdigest()
    if external_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", external_sha256):
        raise ConformanceError("--oracle-bundle-manifest-sha256 must be a lowercase SHA-256")
    if require_external_pin and external_sha256 is None:
        raise ConformanceError("SUT conformance requires an external --oracle-bundle-manifest-sha256 pin")
    if external_sha256 is not None and observed_sha256 != external_sha256:
        raise ConformanceError("validation route manifest does not match the external SHA-256 pin")
    manifest = decode_json_snapshot(manifest_snapshot, str(manifest_path))
    required = {
        "manifest_format",
        "claim",
        "reference_entrypoint",
        "validation_entrypoint",
        "validation_import_roots",
        "source_sets",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ConformanceError(f"validation route manifest fields must be exactly {sorted(required)}")
    if manifest.get("manifest_format") != ORACLE_BUNDLE_FORMAT:
        raise ConformanceError("validation route manifest format is invalid")
    if manifest.get("claim") != ORACLE_BUNDLE_CLAIM:
        raise ConformanceError("validation route manifest must use the bounded non-independence claim")
    if manifest.get("reference_entrypoint") != "reference_adapter:compute" or manifest.get("validation_entrypoint") != "independent_oracle:compute":
        raise ConformanceError("validation route entrypoints are not the closed expected pair")
    if manifest.get("validation_import_roots") != sorted(VALIDATION_IMPORT_ROOTS):
        raise ConformanceError("validation import whitelist does not match the runner policy")
    raw_sets = manifest.get("source_sets")
    if not isinstance(raw_sets, dict) or set(raw_sets) != set(EXPECTED_ORACLE_SOURCE_SETS):
        raise ConformanceError("validation route source_sets must be exactly reference, validation, and harness")
    root = manifest_path.parent
    source_sets: dict[str, tuple[RouteFilePin, ...]] = {}
    all_paths: set[str] = set()
    for set_name, expected_paths in EXPECTED_ORACLE_SOURCE_SETS.items():
        entries = raw_sets.get(set_name)
        if not isinstance(entries, list):
            raise ConformanceError(f"validation route source_sets.{set_name} must be an array")
        parsed: list[RouteFilePin] = []
        declared_paths: set[str] = set()
        for index, entry in enumerate(entries):
            label = f"validation route source_sets.{set_name}[{index}]"
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                raise ConformanceError(f"{label}: fields must be exactly path and sha256")
            relative = entry.get("path")
            if not isinstance(relative, str) or "\\" in relative or relative != Path(relative).as_posix():
                raise ConformanceError(f"{label}: path must be normalized repo-relative POSIX text")
            if relative in declared_paths or relative in all_paths:
                raise ConformanceError(f"{label}: duplicate or cross-set source path {relative!r}")
            declared_paths.add(relative); all_paths.add(relative)
            parsed.append(RouteFilePin(relative, _load_artifact_pin(root, entry, label)))
        if declared_paths != expected_paths:
            raise ConformanceError(f"validation route {set_name} source set differs: expected={sorted(expected_paths)}, got={sorted(declared_paths)}")
        source_sets[set_name] = tuple(parsed)
    reference_digests = {pin.artifact.sha256 for pin in source_sets["reference"]}
    validation_digests = {pin.artifact.sha256 for pin in source_sets["validation"]}
    if reference_digests & validation_digests:
        raise ConformanceError("reference and validation source sets reuse identical source bytes")
    import_errors = _validation_import_errors(source_sets["validation"])
    property_pin = next(pin for pin in source_sets["harness"] if pin.relative_path == "property_suite.py")
    import_errors.extend(_validation_import_errors((property_pin,), PROPERTY_SUITE_IMPORT_ROOTS))
    if import_errors:
        raise ConformanceError("validation route static boundary rejected: " + "; ".join(import_errors))
    mutant_pin = next(pin for pin in source_sets["reference"] if pin.relative_path == "math_mutants.py")
    bundle = PinnedValidationRouteBundle(
        manifest_path,
        observed_sha256,
        external_sha256 is not None,
        manifest_snapshot,
        manifest_identity,
        manifest["reference_entrypoint"],
        manifest["validation_entrypoint"],
        source_sets,
        _mutant_ids_from_snapshot(mutant_pin.artifact.snapshot_bytes),
    )
    bundle.recheck()
    return bundle


def _load_executable_pin(block: Any, label: str) -> ArtifactPin:
    if not isinstance(block, dict) or set(block) != {"path", "sha256"}: raise ConformanceError(f"{label}: must contain exactly path and sha256")
    raw_path, digest = block.get("path"), block.get("sha256")
    if not isinstance(raw_path, str) or not Path(raw_path).is_absolute(): raise ConformanceError(f"{label}: path must be an absolute executable path")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest): raise ConformanceError(f"{label}: sha256 must be lowercase hex")
    path, snapshot, identity = read_single_handle_snapshot(Path(raw_path), label)
    if hashlib.sha256(snapshot).hexdigest() != digest: raise ConformanceError(f"{label}: SHA-256 mismatch")
    return ArtifactPin(path, digest, label, identity, snapshot)


def _load_launcher(block: Any, label: str) -> LauncherDefinition:
    fields = {"kind", "python_executable", "arguments"}
    if not isinstance(block, dict) or set(block) != fields: raise ConformanceError(f"{label}: launcher fields must be exactly {sorted(fields)}")
    if block.get("kind") != "python_script": raise ConformanceError(f"{label}: only runner-controlled python_script launchers are supported")
    arguments = block.get("arguments")
    if not isinstance(arguments, list) or any(not isinstance(item, str) or "\x00" in item for item in arguments): raise ConformanceError(f"{label}: arguments must be a JSON string array")
    return LauncherDefinition(_load_executable_pin(block.get("python_executable"), f"{label}.python_executable"), tuple(arguments))


def load_sut_mutation_manifest(path: Path, external_sha256: str | None) -> PinnedMutationManifest:
    if not isinstance(external_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", external_sha256): raise ConformanceError("--sut-mutants-manifest-sha256 is required as an external lowercase SHA-256 pin")
    manifest_path, manifest_snapshot, manifest_identity = read_single_handle_snapshot(path, "mutation manifest")
    if hashlib.sha256(manifest_snapshot).hexdigest() != external_sha256: raise ConformanceError("mutation manifest does not match the external SHA-256 pin")
    manifest = decode_json_snapshot(manifest_snapshot, str(manifest_path))
    required = {"manifest_format","association_statement","execution_failure_policy","base_artifact","base_launcher","mutants"}
    if not isinstance(manifest, dict) or set(manifest) != required: raise ConformanceError(f"mutation manifest fields must be exactly {sorted(required)}")
    if manifest.get("manifest_format") != SUT_MUTANTS_FORMAT: raise ConformanceError("mutation manifest format is invalid")
    if manifest.get("association_statement") != "declared_by_manifest_not_verified_ownership": raise ConformanceError("mutation manifest must disclaim verified ownership")
    policy = manifest.get("execution_failure_policy")
    if not isinstance(policy, str) or policy not in MUTATION_FAILURE_POLICIES: raise ConformanceError(f"execution_failure_policy must be one of {sorted(MUTATION_FAILURE_POLICIES)}")
    root = manifest_path.parent
    base = _load_artifact_pin(root, manifest.get("base_artifact"), "base artifact")
    base_launcher = _load_launcher(manifest.get("base_launcher"), "base launcher")
    raw_mutants = manifest.get("mutants")
    if not isinstance(raw_mutants, list) or not raw_mutants: raise ConformanceError("mutation manifest must declare at least one mutant")
    mutants: list[MutantDefinition] = []; ids: set[str] = set(); pins = [base]
    for index, entry in enumerate(raw_mutants):
        label = f"mutants[{index}]"; fields = {"id","operator_id","operator_artifact","mutant_artifact","launcher"}
        if not isinstance(entry, dict) or set(entry) != fields: raise ConformanceError(f"{label}: fields must be exactly {sorted(fields)}")
        mutant_id, operator_id = entry.get("id"), entry.get("operator_id")
        if not isinstance(mutant_id, str) or not SAFE_IDENTIFIER.fullmatch(mutant_id) or mutant_id in ids: raise ConformanceError(f"{label}: mutant id is invalid or duplicate")
        if not isinstance(operator_id, str) or not SAFE_IDENTIFIER.fullmatch(operator_id): raise ConformanceError(f"{label}: operator_id is invalid")
        mutant_pin = _load_artifact_pin(root, entry.get("mutant_artifact"), f"{label}.mutant_artifact")
        operator_pin = _load_artifact_pin(root, entry.get("operator_artifact"), f"{label}.operator_artifact")
        launcher = _load_launcher(entry.get("launcher"), f"{label}.launcher")
        ids.add(mutant_id); pins.extend((mutant_pin, operator_pin, launcher.python_executable)); mutants.append(MutantDefinition(mutant_id, operator_id, mutant_pin, operator_pin, launcher))
    pins.append(base_launcher.python_executable)
    result = PinnedMutationManifest(manifest_path, external_sha256, manifest_snapshot, manifest_identity, base, base_launcher, tuple(mutants), policy, tuple(pins))
    result.recheck()
    return result


@dataclass
class PreparedMutationRun:
    temporary: tempfile.TemporaryDirectory[str]
    base_sut: Sut
    mutant_suts: list[tuple[str, Sut]]
    manifest: PinnedMutationManifest
    snapshot_pins: list[ArtifactPin]

    def recheck(self) -> None:
        self.manifest.recheck()
        for pin in self.snapshot_pins: pin.recheck()

    def close(self) -> None:
        # Restore write permission so TemporaryDirectory can clean up on POSIX.
        for pin in self.snapshot_pins:
            try: os.chmod(pin.path, stat.S_IWRITE | stat.S_IREAD)
            except OSError: pass
        self.temporary.cleanup()


def _snapshot_pin(source: ArtifactPin, destination: Path, label: str) -> ArtifactPin:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source.snapshot_bytes)
    copied, snapshot, identity = read_single_handle_snapshot(destination, label)
    if hashlib.sha256(snapshot).hexdigest() != source.sha256: raise ConformanceError(f"{label}: private snapshot copy hash mismatch")
    os.chmod(copied, stat.S_IREAD)
    # chmod changes ctime, so bind the immutable pin after permissions settle.
    copied, snapshot, identity = read_single_handle_snapshot(copied, label)
    return ArtifactPin(copied, source.sha256, label, identity, snapshot)


@dataclass
class PreparedValidationRoutes:
    temporary: tempfile.TemporaryDirectory[str]
    bundle: PinnedValidationRouteBundle
    reference_sut: ModuleSut
    validation_sut: ModuleSut
    reference_script: Path
    property_suite_path: Path
    worker_path: Path
    snapshot_pins: tuple[ArtifactPin, ...]

    def recheck(self) -> None:
        self.bundle.recheck()
        for pin in self.snapshot_pins:
            pin.recheck()

    def close(self) -> None:
        for pin in self.snapshot_pins:
            try:
                os.chmod(pin.path, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
        self.temporary.cleanup()


def prepare_validation_routes(
    bundle: PinnedValidationRouteBundle,
    command_limits: tuple[float, int, int, str],
) -> PreparedValidationRoutes:
    """Copy the two source sets into disjoint private roots before any route executes."""
    bundle.recheck()
    temporary = tempfile.TemporaryDirectory(prefix="math-validation-routes-")
    root = Path(temporary.name)
    destinations = {name: root / name for name in EXPECTED_ORACLE_SOURCE_SETS}
    snapshot_pins: list[ArtifactPin] = []
    try:
        for set_name, route_files in bundle.source_sets.items():
            for route_file in route_files:
                destination = destinations[set_name] / Path(route_file.relative_path)
                snapshot_pins.append(
                    _snapshot_pin(route_file.artifact, destination, f"{set_name} route snapshot {route_file.relative_path}")
                )
        worker_path = destinations["harness"] / "module_worker.py"
        property_suite_path = destinations["harness"] / "property_suite.py"
        reference_script = destinations["reference"] / "reference_adapter.py"
        prepared = PreparedValidationRoutes(
            temporary,
            bundle,
            ModuleSut(bundle.reference_entrypoint, destinations["reference"], worker_path, *command_limits),
            ModuleSut(bundle.validation_entrypoint, destinations["validation"], worker_path, *command_limits),
            reference_script,
            property_suite_path,
            worker_path,
            tuple(snapshot_pins),
        )
        prepared.recheck()
        return prepared
    except Exception:
        for pin in snapshot_pins:
            try:
                os.chmod(pin.path, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
        temporary.cleanup()
        raise


def prepare_mutation_run(manifest: PinnedMutationManifest, command_limits: tuple[float, int, int, str]) -> PreparedMutationRun:
    """Freeze every launcher/artifact before the main SUT can start."""
    manifest.recheck()
    temporary = tempfile.TemporaryDirectory(prefix="math-mutants-private-")
    root = Path(temporary.name)
    try: os.chmod(root, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    except OSError: pass
    snapshot_pins: list[ArtifactPin] = []

    base_dir = root / "base"
    base_snapshot = _snapshot_pin(manifest.base_artifact, base_dir / manifest.base_artifact.path.name, "base snapshot")
    snapshot_pins.append(base_snapshot)
    # Operators are copied into the base directory as import dependencies, but
    # the runner-selected base script remains the exact executable target.
    for index, mutant in enumerate(manifest.mutants):
        dependency = base_dir / mutant.operator_artifact.path.name
        if not dependency.exists(): snapshot_pins.append(_snapshot_pin(mutant.operator_artifact, dependency, f"base operator snapshot[{index}]"))
    base_command = [str(manifest.base_launcher.python_executable.path), str(base_snapshot.path), *manifest.base_launcher.arguments]
    base_sut = CommandSut(base_command, *command_limits)

    mutant_suts: list[tuple[str, Sut]] = []
    for index, mutant in enumerate(manifest.mutants):
        mutant_dir = root / "mutants" / f"{index:04d}-{mutant.mutant_id}"
        mutant_snapshot = _snapshot_pin(mutant.mutant_artifact, mutant_dir / mutant.mutant_artifact.path.name, f"mutant snapshot[{mutant.mutant_id}]")
        operator_snapshot = _snapshot_pin(mutant.operator_artifact, mutant_dir / mutant.operator_artifact.path.name, f"operator snapshot[{mutant.mutant_id}]")
        snapshot_pins.extend((mutant_snapshot, operator_snapshot))
        command = [str(mutant.launcher.python_executable.path), str(mutant_snapshot.path), *mutant.launcher.arguments]
        mutant_suts.append((mutant.mutant_id, CommandSut(command, *command_limits)))
    prepared = PreparedMutationRun(temporary, base_sut, mutant_suts, manifest, snapshot_pins)
    prepared.recheck()
    return prepared


def mutation_score_text(results: dict[str, list[str]], policy: str, externally_pinned: bool) -> str:
    if not externally_pinned: return "sut_mutation_score not_evaluated (no externally pinned mutation manifest)"
    semantic, assertion = len(results["semantic_kill"]), len(results["assertion_kill"])
    crash, timeout = len(results["crash"]), len(results["timeout"])
    nonviable, survived = len(results["nonviable"]), len(results["survived"])
    killed, denominator = semantic + assertion, semantic + assertion + crash + timeout + nonviable + survived
    return f"sut_mutation_score {killed}/{denominator} killed policy=strict" if denominator else "sut_mutation_score not_evaluated (no declared mutants)"


def mutation_category_text(prefix: str, results: dict[str, list[str]]) -> str:
    return (
        f"{prefix} semantic_kill={len(results['semantic_kill'])} "
        f"assertion_kill={len(results['assertion_kill'])} "
        f"crash={len(results['crash'])} timeout={len(results['timeout'])} "
        f"nonviable={len(results['nonviable'])} survived={len(results['survived'])}"
    )


REPORT_FORMAT = "financial-planning-sdk-br.math-conformance-report.v1"


def isolation_report() -> dict[str, str]:
    return {
        "filesystem": "not_enforced",
        "network": "not_enforced",
        "process_tree_windows": "job_object_kill_on_close",
        "process_tree_posix": "best_effort_same_process_group_daemon_escape_possible",
        "strict_untrusted_requires": "external_sandbox_cgroup_or_namespace",
    }


def category_count_report(results: dict[str, list[str]], evaluated: bool) -> dict[str, Any]:
    counts = {name: len(results[name]) for name in ("semantic_kill", "assertion_kill", "crash", "timeout", "nonviable", "survived")}
    counts["evaluated"] = evaluated
    counts["killed"] = counts["semantic_kill"] + counts["assertion_kill"]
    counts["total"] = sum(counts[name] for name in ("semantic_kill", "assertion_kill", "crash", "timeout", "nonviable", "survived"))
    return counts


def emit_failure_report(
    args: argparse.Namespace,
    sut_mode: bool,
    stage: str,
    errors: list[str],
    exit_code: int,
) -> int:
    mode = "sut_conformance" if sut_mode else "corpus_reference_self_check"
    if args.output_format == "json":
        empty = empty_mutation_categories()
        payload = {
            "report_format": REPORT_FORMAT,
            "status": "failed",
            "execution_mode": mode,
            "sut_conformance_status": "failed" if sut_mode else "not_evaluated",
            "authority": "technical_validation_only_not_release_authority",
            "failure": {"stage": stage, "errors": errors},
            "counts": {
                "vectors": None,
                "normative_bindings": 18,
                "supplemental_vectors": 3,
                "property_families": None,
                "property_checks": None,
                "reference_fixture_sensitivity": category_count_report(empty, False),
                "reference_adapter_mutation": category_count_report(empty, False),
                "sut_mutation": category_count_report(empty, False),
            },
            "oracle_boundary": {
                "status": "not_evaluated",
                "evidence": "static_boundary_not_proof",
                "digest_provenance": None,
                "digest_authentication": "not_provided",
                "manifest_sha256": None,
                "source_set_counts": None,
                "validation_cache": {"entries": None, "repeatability_checks": None},
                "execution": "validation_precomputed_by_separate_subprocess_disjoint_private_roots",
            },
            "isolation": isolation_report(),
            "validation_subject": None,
            "declared_validation_types": sorted(VALIDATION_TYPES),
        }
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")), file=sys.stderr)
    else:
        prefix = "Math SUT conformance FAILED" if sut_mode else "Math corpus/reference self-check FAILED"
        print(f"{prefix}: {stage}: {len(errors)} error(s).", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    repository_root = Path(__file__).resolve().parents[1]
    conformance_dir = repository_root / "tests" / "conformance"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vector-root", type=Path, default=repository_root / "tests" / "vectors" / "math" / "v1")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sut-command")
    group.add_argument("--sut-module")
    group.add_argument(
        "--self-check",
        "--reference",
        action="store_true",
        dest="self_check",
        help="verify the corpus and bundled test-only reference routes; this is not SUT conformance",
    )
    parser.add_argument("--sut-module-root", type=Path, default=repository_root)
    parser.add_argument("--sut-mutants-manifest", type=Path, help="manifest declaring mutation artifacts; association is not proof of ownership")
    parser.add_argument("--sut-mutants-manifest-sha256", help="external SHA-256 pin required with --sut-mutants-manifest")
    parser.add_argument("--oracle-bundle-manifest", type=Path, default=conformance_dir / "oracle_bundle_manifest.json")
    parser.add_argument("--oracle-bundle-manifest-sha256", help="external SHA-256 pin required for a SUT conformance claim")
    parser.add_argument("--output-format", choices=("text", "json"), default="text")
    parser.add_argument("--sut-timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--sut-stdout-limit", type=int, default=DEFAULT_STDOUT_LIMIT)
    parser.add_argument("--sut-stderr-limit", type=int, default=DEFAULT_STDERR_LIMIT)
    parser.add_argument("--sut-stderr-policy", choices=("forbid", "allow"), default="forbid")
    parser.add_argument("--update-fingerprints", action="store_true")
    parser.add_argument("--skip-properties", action="store_true")
    parser.add_argument("--skip-reference-sensitivity", "--skip-mutations", action="store_true", dest="skip_reference_sensitivity")
    args = parser.parse_args(argv)
    sut_mode = bool(args.sut_command or args.sut_module)
    if bool(args.sut_mutants_manifest) != bool(args.sut_mutants_manifest_sha256):
        return emit_failure_report(args, sut_mode, "configuration", ["mutation manifest and external SHA-256 pin must be supplied together"], 2)
    if sut_mode and not args.sut_mutants_manifest:
        return emit_failure_report(args, sut_mode, "configuration", ["SUT mode requires an externally pinned mutation manifest; mutation status cannot be not_evaluated"], 2)
    if sut_mode and not args.oracle_bundle_manifest_sha256:
        return emit_failure_report(args, sut_mode, "configuration", ["SUT mode requires an externally pinned validation route manifest"], 2)
    try:
        mutation_manifest = load_sut_mutation_manifest(args.sut_mutants_manifest, args.sut_mutants_manifest_sha256) if args.sut_mutants_manifest else None
        route_bundle = load_validation_route_bundle(args.oracle_bundle_manifest, args.oracle_bundle_manifest_sha256, sut_mode)
    except (OSError, ConformanceError) as exc:
        return emit_failure_report(args, sut_mode, "pin_validation", [str(exc)], 2)
    if not args.vector_root.is_dir():
        return emit_failure_report(args, sut_mode, "corpus", [f"vector root not found: {args.vector_root}"], 2)
    vectors, fixture_errors = load_vectors(args.vector_root, args.update_fingerprints)
    if fixture_errors:
        return emit_failure_report(args, sut_mode, "corpus", fixture_errors, 1)

    limits = (args.sut_timeout_seconds, args.sut_stdout_limit, args.sut_stderr_limit, args.sut_stderr_policy)
    mutation_results = empty_mutation_categories()
    sensitivity_results = empty_mutation_categories()
    evaluation = EvaluationResult()
    base_mutation_evaluation = EvaluationResult()
    prepared_mutations: PreparedMutationRun | None = None
    prepared_routes: PreparedValidationRoutes | None = None
    validation_cache: FrozenValidationSut | None = None
    route_errors: list[str] = []
    execution_error: str | None = None
    recheck_errors: list[str] = []
    sut_label: str | None = None
    try:
        prepared_routes = prepare_validation_routes(route_bundle, limits)
        if mutation_manifest:
            prepared_mutations = prepare_mutation_run(mutation_manifest, limits)
        validation_requests, repeatability_requests = closed_validation_requests(vectors, prepared_routes.property_suite_path, not args.skip_properties)
        validation_cache = FrozenValidationSut(prepared_routes.validation_sut, validation_requests, repeatability_requests)
        route_errors = cross_check_validation_routes(vectors, prepared_routes.reference_sut, validation_cache)
        if not route_errors:
            if args.sut_command:
                sut, sut_label = CommandSut(args.sut_command, *limits), "command"
            elif args.sut_module:
                sut, sut_label = ModuleSut(args.sut_module, args.sut_module_root, prepared_routes.worker_path, *limits), f"module subprocess {args.sut_module}"
            else:
                sut, sut_label = prepared_routes.reference_sut, "test_only_reference_route_subprocess"
            property_arguments = {
                "validation_sut": validation_cache,
                "property_suite_path": prepared_routes.property_suite_path,
            }
            if prepared_mutations:
                base_mutation_evaluation = evaluate_sut(
                    prepared_mutations.base_sut,
                    vectors,
                    not args.skip_properties,
                    stop_on_execution_failure=True,
                    **property_arguments,
                )
                prepared_mutations.recheck()
            evaluation = evaluate_sut(sut, vectors, not args.skip_properties, **property_arguments)
            if not args.skip_reference_sensitivity:
                sensitivity_results = run_reference_fixture_sensitivity(
                    vectors,
                    conformance_dir,
                    validation_sut=validation_cache,
                    property_suite_path=prepared_routes.property_suite_path,
                    reference_script=prepared_routes.reference_script,
                    mutant_ids=route_bundle.mutant_ids,
                    command_limits=limits,
                )
            if prepared_mutations:
                for mutant_id, mutant_sut in prepared_mutations.mutant_suts:
                    outcome = evaluate_sut(
                        mutant_sut,
                        vectors,
                        not args.skip_properties,
                        stop_on_execution_failure=True,
                        **property_arguments,
                    )
                    mutation_results[outcome.mutation_category()].append(mutant_id)
                    prepared_mutations.recheck()
            prepared_routes.recheck()
    except (OSError, ImportError, AttributeError, ConformanceError, json.JSONDecodeError) as exc:
        execution_error = str(exc)
    finally:
        if prepared_mutations:
            try:
                prepared_mutations.recheck()
            except ConformanceError as exc:
                recheck_errors.append(str(exc))
            prepared_mutations.close()
        elif mutation_manifest:
            try:
                mutation_manifest.recheck()
            except ConformanceError as exc:
                recheck_errors.append(str(exc))
        if prepared_routes:
            try:
                prepared_routes.recheck()
            except ConformanceError as exc:
                recheck_errors.append(str(exc))
            prepared_routes.close()
        else:
            try:
                route_bundle.recheck()
            except ConformanceError as exc:
                recheck_errors.append(str(exc))
    if recheck_errors:
        return emit_failure_report(args, sut_mode, "post_execution_pin_recheck", recheck_errors, 2)
    if execution_error:
        return emit_failure_report(args, sut_mode, "execution", [execution_error], 2)
    if route_errors:
        return emit_failure_report(args, sut_mode, "validation_route", route_errors, 1)

    sut_errors = evaluation.all_errors()
    sut_errors.extend(f"[sut_mutation_base] {message}" for message in base_mutation_evaluation.all_errors())
    for category in ("crash", "timeout", "nonviable", "survived"):
        sut_errors.extend(f"[reference_fixture_sensitivity] {category} cannot satisfy sensitivity gate: {name}" for name in sensitivity_results[category])
    sut_errors.extend(f"[sut_mutation] survivor: {name}" for name in mutation_results["survived"])
    if mutation_manifest:
        sut_errors.extend(f"[sut_mutation] crash cannot satisfy strict score: {name}" for name in mutation_results["crash"])
        sut_errors.extend(f"[sut_mutation] timeout cannot satisfy strict score: {name}" for name in mutation_results["timeout"])
        sut_errors.extend(f"[sut_mutation] nonviable cannot satisfy strict score: {name}" for name in mutation_results["nonviable"])
    if sut_errors:
        category_summary = (
            f"{mutation_category_text('reference_fixture_sensitivity_categories', sensitivity_results)}; "
            f"{mutation_category_text('sut_mutation_categories', mutation_results)}"
        )
        return emit_failure_report(args, sut_mode, "evaluation", [category_summary, *sut_errors], 1)

    property_checks = sum(evaluation.property_counts.values())
    property_text = "properties not_evaluated" if args.skip_properties else f"property_families={len(evaluation.property_counts)} property_checks={property_checks}; full_response_validation_route=pinned_subprocess"
    sensitivity_killed = len(sensitivity_results["semantic_kill"]) + len(sensitivity_results["assertion_kill"])
    sensitivity_total = sum(len(items) for items in sensitivity_results.values())
    sensitivity_text = "reference_fixture_sensitivity not_evaluated" if args.skip_reference_sensitivity else f"reference_fixture_sensitivity {sensitivity_killed}/{sensitivity_total} killed"
    mutation_evaluated = mutation_manifest is not None
    mutation_text = "reference_adapter_mutation_score not_evaluated"
    mutation_detail = ""
    if mutation_manifest:
        score = mutation_score_text(mutation_results, mutation_manifest.execution_failure_policy, True)
        mutation_text = score if sut_mode else score.replace("sut_mutation_score", "reference_adapter_mutation_score", 1)
        mutation_detail = f"; {mutation_category_text('mutation_categories', mutation_results)}; association=declared_not_verified"
    mode = "sut_conformance" if sut_mode else "corpus_reference_self_check"
    status = "sut_conformance_passed" if sut_mode else "self_check_passed"
    sut_status = "passed" if sut_mode else "not_evaluated"
    oracle_boundary = {
        "status": "static_checks_passed",
        "evidence": "static_boundary_not_proof",
        "digest_provenance": "caller_supplied_sha256" if route_bundle.externally_pinned else "repository_local_untrusted",
        "digest_authentication": "not_provided",
        "manifest_sha256": route_bundle.manifest_sha256,
        "source_set_counts": {name: len(files) for name, files in sorted(route_bundle.source_sets.items())},
        "validation_cache": {
            "entries": validation_cache.cache_entries if validation_cache is not None else None,
            "repeatability_checks": validation_cache.repeatability_checks if validation_cache is not None else None,
        },
        "execution": "validation_precomputed_by_separate_subprocess_disjoint_private_roots",
    }
    if args.output_format == "json":
        payload = {
            "report_format": REPORT_FORMAT,
            "status": status,
            "execution_mode": mode,
            "sut_conformance_status": sut_status,
            "authority": "technical_validation_only_not_release_authority",
            "failure": None,
            "counts": {
                "vectors": len(vectors),
                "normative_bindings": 18,
                "supplemental_vectors": 3,
                "property_families": None if args.skip_properties else len(evaluation.property_counts),
                "property_checks": None if args.skip_properties else property_checks,
                "reference_fixture_sensitivity": category_count_report(sensitivity_results, not args.skip_reference_sensitivity),
                "reference_adapter_mutation": category_count_report(mutation_results, mutation_evaluated and not sut_mode),
                "sut_mutation": category_count_report(mutation_results, mutation_evaluated and sut_mode),
            },
            "oracle_boundary": oracle_boundary,
            "isolation": isolation_report(),
            "validation_subject": sut_label,
            "declared_validation_types": sorted(VALIDATION_TYPES),
        }
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        prefix = "Math SUT conformance PASSED" if sut_mode else "Math corpus/reference self-check PASSED"
        print(
            f"{prefix}: {len(vectors)} vectors (18 normative mappings + 3 supplemental); "
            f"execution_mode={mode}; sut_conformance_status={sut_status}; "
            f"fingerprints {'updated' if args.update_fingerprints else 'verified'}; semantic units verified; domains verified; "
            f"validation_methods_per_vector=2 declared_validation_types={','.join(sorted(VALIDATION_TYPES))}; validation_subject={sut_label}; "
            f"{property_text}; {sensitivity_text}; {mutation_category_text('reference_fixture_sensitivity_categories', sensitivity_results)}; "
            f"oracle_boundary=static_checks_passed digest_provenance={oracle_boundary['digest_provenance']} digest_authentication=not_provided "
            f"independence_evidence=static_boundary_not_proof authority=technical_validation_only_not_release_authority "
            f"validation_cache_entries={oracle_boundary['validation_cache']['entries']} repeatability_checks={oracle_boundary['validation_cache']['repeatability_checks']} "
            f"route_execution=validation_precomputed_by_separate_subprocess_disjoint_private_roots; filesystem_isolation=not_enforced; network_isolation=not_enforced; "
            f"process_tree_windows=job_object_kill_on_close; process_tree_posix=best_effort_same_process_group daemon_escape=possible "
            f"strict_untrusted_requires=external_sandbox_cgroup_or_namespace; {mutation_text}{mutation_detail}."
        )
    return 0


if __name__ == "__main__": raise SystemExit(main())
