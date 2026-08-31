"""Deterministic, full-response differential grids for every vector family.

Each generated request is evaluated by the candidate SUT and by a caller-
supplied, pinned validation route.  The comparison is deliberately over
the complete response tree: keys, container shapes, status, reason codes,
booleans, strings, and every numeric leaf.  Selected invariants are not a
substitute for that comparison.  A small set of exact-identity sentinels is
also evaluated without either route so a shared defect cannot make the
differential comparison green by itself.
"""

from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, InvalidOperation
import hashlib
import random
import re
from typing import Any, Callable


PROPERTY_FAMILIES = {
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
    "tax-lot-no-tax",
    "tax-lot-simple",
    "total-return-positive",
    "two-stage-nonanticipativity",
}
PROPERTY_GRID_SEED = 20260809
DECIMAL_TEXT = re.compile(r"^-?(?:0|[1-9]\d*)(?:\.\d+)?$")
COMMON_MODE_SENTINEL_FAMILIES = {"finite-annuity-certain"}


def seeded_grid(family: str, cases: tuple[Any, ...]) -> list[Any]:
    """Return a reproducibly shuffled, family-specific perturbation grid."""
    seed_material = f"{PROPERTY_GRID_SEED}:{family}".encode("ascii")
    seed = int.from_bytes(hashlib.sha256(seed_material).digest()[:8], "big")
    result = list(cases)
    random.Random(seed).shuffle(result)
    return result


def d(value: Any) -> Decimal:
    return Decimal(value)


def request(fixtures: dict[str, dict[str, Any]], vector_id: str) -> dict[str, Any]:
    vector = fixtures[vector_id]
    return {
        "protocol": "financial-planning-sdk-br.math-sut.v1",
        "id": vector_id,
        "topic": vector["topic"],
        "input": deepcopy(vector["input"]),
    }


def generated_requests(fixtures: dict[str, dict[str, Any]]) -> list[tuple[str, str, dict[str, Any]]]:
    """Build the closed deterministic perturbation grid for all 21 families."""
    generated: list[tuple[str, str, dict[str, Any]]] = []

    def add(family: str, label: str, value: dict[str, Any]) -> None:
        generated.append((family, label, value))

    for amount, factor in seeded_grid("pv-unit-cashflow", (("-7", "0.4"), ("13", "0.75"))):
        req = request(fixtures, "pv-unit-cashflow")
        req["input"].update({"cash_flow_amount": amount, "discount_factor": factor})
        add("pv-unit-cashflow", f"{amount}@{factor}", req)

    for payment, factors in seeded_grid("finite-annuity-certain", (("11", ["1", "0.5"]), ("3", ["0.9", "0.8", "0.7", "0.6"]))):
        req = request(fixtures, "finite-annuity-certain")
        req["input"].update({"payment_amount": payment, "discount_factors": factors})
        add("finite-annuity-certain", payment, req)

    for payment, rate in seeded_grid("perpetuity-closed-form", (("12", "0.03"), ("7.5", "0.15"))):
        req = request(fixtures, "perpetuity-closed-form")
        req["input"].update({"payment_amount": payment, "effective_rate_per_period": rate})
        add("perpetuity-closed-form", rate, req)

    survival_cases = (
        (["0.2", "0.7"], ["1", "0.5"], ["10", "20"]),
        (["1", "0"], ["0.8", "0.4"], ["5", "99"]),
    )
    for probabilities, factors, amounts in seeded_grid("survival-annuity-small", survival_cases):
        req = request(fixtures, "survival-annuity-small")
        req["input"]["payments"] = [
            {
                "payment_date": f"202{7 + index}-01-01",
                "survival_probability": probability,
                "discount_factor": factor,
                "amount_if_alive": amount,
            }
            for index, (probability, factor, amount) in enumerate(zip(probabilities, factors, amounts))
        ]
        add("survival-annuity-small", str(probabilities), req)

    reserve_cases = (
        (["0.2", "0.8"], ["10", "40"], "40"),
        (["0.75", "0.25"], ["8", "80"], "8"),
    )
    for probabilities, gaps, observed in seeded_grid("reserve-plan-vs-replan", reserve_cases):
        req = request(fixtures, "reserve-plan-vs-replan")
        plan = req["input"]["plan_information_at_t0"]
        plan["state_probabilities"] = {"low_need": probabilities[0], "high_need": probabilities[1]}
        plan["gap_at_payment_by_state"] = {"low_need": gaps[0], "high_need": gaps[1]}
        req["input"]["replan_information_at_r"]["gap_at_payment"] = observed
        add("reserve-plan-vs-replan", str(probabilities), req)

    for probability, gap in seeded_grid("survival-half-single-weight", (("0.2", "70"), ("0.85", "12"))):
        req = request(fixtures, "survival-half-single-weight")
        req["input"].update({"analytic_survival_probability": probability, "gap_conditional_on_alive": gap})
        req["input"]["pathwise_scenarios"] = [
            {"probability": probability, "indicator_adjusted_gap": gap},
            {"probability": str(Decimal(1) - d(probability)), "indicator_adjusted_gap": "0"},
        ]
        add("survival-half-single-weight", probability, req)

    for probability_a, probability_b in seeded_grid("couple-dependence-indeterminate", (("0.1", "0.9"), ("0.7", "0.3"))):
        req = request(fixtures, "couple-dependence-indeterminate")
        req["input"].update({"survival_probability_a": probability_a, "survival_probability_b": probability_b})
        add("couple-dependence-indeterminate", probability_a + probability_b, req)

    for probability_a, probability_b in seeded_grid("couple-four-states", (("0.2", "0.7"), ("1", "0.4"))):
        req = request(fixtures, "couple-four-states")
        req["input"].update({"survival_probability_a": probability_a, "survival_probability_b": probability_b})
        add("couple-four-states", probability_a + probability_b, req)

    mortality_cases = (
        "2028-01-01",
        "2029-01-01",
        "2031-01-01",
        "2032-01-01",
        "2033-01-01",
    )
    for horizon in seeded_grid("couple-deterministic-mortality", mortality_cases):
        req = request(fixtures, "couple-deterministic-mortality")
        req["input"]["horizon_date"] = horizon
        add("couple-deterministic-mortality", horizon, req)

    for opening, rate, cash in seeded_grid("return-basis-distribution", (("80", "0.25", "4"), ("120", "-0.1", "7"))):
        req = request(fixtures, "return-basis-distribution")
        req["input"].update({"opening_consolidated_wealth": opening, "price_return": rate, "cash_distribution": cash})
        add("return-basis-distribution", opening, req)

    for opening, rate in seeded_grid("total-return-positive", (("80", "0.25"), ("120", "-0.1"))):
        req = request(fixtures, "total-return-positive")
        req["input"].update({"opening_consolidated_wealth": opening, "total_return": rate, "separate_distribution_event": "0"})
        add("total-return-positive", opening, req)

    for distribution in seeded_grid("return-basis-invalid-combination", ("0.01", "17")):
        req = request(fixtures, "return-basis-invalid-combination")
        req["input"]["separate_distribution_event"] = distribution
        add("return-basis-invalid-combination", distribution, req)

    transfer_cases = (
        ({"cash": "101", "reserve": "17"}, "cash", "reserve", "23"),
        ({"alpha": "9", "beta": "50", "gamma": "1"}, "beta", "gamma", "4"),
    )
    for accounts, source, destination, amount in seeded_grid("internal-transfer-conservation", transfer_cases):
        req = request(fixtures, "internal-transfer-conservation")
        req["input"]["opening_balances"] = accounts
        req["input"]["transfer"].update({"from_account": source, "to_account": destination, "amount": amount})
        add("internal-transfer-conservation", source, req)

    for opening, amounts in seeded_grid("balance-reconciliation", (("10", ["1", "2", "-0.5"]), ("200", ["-50", "3.25"]))):
        req = request(fixtures, "balance-reconciliation")
        req["input"]["opening_balance"] = opening
        req["input"]["events"] = [
            {"date": f"2026-0{index + 1}-01", "amount": amount}
            for index, amount in enumerate(amounts)
        ]
        add("balance-reconciliation", opening, req)

    tax_cases = {
        "tax-lot-no-tax": (("0", "15"), ("0", "6")),
        "tax-lot-simple": (("0.1", "15"), ("0.35", "20"), ("0.25", "6")),
    }
    for family in ("tax-lot-no-tax", "tax-lot-simple"):
        for rate, price in seeded_grid(family, tax_cases[family]):
            req = request(fixtures, family)
            req["input"]["tax_rate_on_positive_gain"] = rate
            req["input"]["sale"].update({"quantity": "3", "unit_price": price})
            add(family, rate + price, req)

    # The grid includes both variance orderings and an admissible short position.
    portfolio_cases = (("0.04", "0.09", "0"), ("0.09", "0.04", "0.01"), ("0.04", "0.09", "0.05"))
    for variance_a, variance_b, covariance in seeded_grid("portfolio-two-asset-convex", portfolio_cases):
        req = request(fixtures, "portfolio-two-asset-convex")
        req["input"].update({"variance_a": variance_a, "variance_b": variance_b, "covariance_ab": covariance})
        add("portfolio-two-asset-convex", variance_a + variance_b + covariance, req)

    scenarios = [
        {"probability": "0.50", "loss": "0"},
        {"probability": "0.30", "loss": "10"},
        {"probability": "0.10", "loss": "20"},
        {"probability": "0.10", "loss": "100"},
    ]
    cvar_cases = (
        ("0.80", scenarios),
        ("0.90", scenarios),
        ("0.75", [{"probability": "0.25", "loss": "-5"}, {"probability": "0.50", "loss": "5"}, {"probability": "0.25", "loss": "65"}]),
    )
    for alpha, case_scenarios in seeded_grid("cvar-discrete-enumerable", cvar_cases):
        req = request(fixtures, "cvar-discrete-enumerable")
        req["input"].update({"alpha": alpha, "scenarios": deepcopy(case_scenarios)})
        add("cvar-discrete-enumerable", alpha, req)

    for probability, low, high in seeded_grid("two-stage-nonanticipativity", (("0.25", "10", "90"), ("0.6", "-10", "40"))):
        req = request(fixtures, "two-stage-nonanticipativity")
        req["input"]["stage_1_scenarios"] = {
            "low": {"probability": probability, "target_revealed_at_stage_1": low},
            "high": {"probability": str(Decimal(1) - d(probability)), "target_revealed_at_stage_1": high},
        }
        add("two-stage-nonanticipativity", probability, req)

    for assets, contribution in seeded_grid("constant-contribution-closed-form", (("0", "7"), ("40", "3.5"))):
        req = request(fixtures, "constant-contribution-closed-form")
        req["input"].update({"initial_assets": assets, "constant_contribution": contribution})
        add("constant-contribution-closed-form", assets, req)

    contribution_cases = (
        ("50", "120", "10", "0.8", ["1.4", "1.1", "1"]),
        ("200", "100", "30", "0.5", ["0.9", "1.3"]),
        ("0", "75", "0", "1", ["2", "0.5", "1.25", "0.75"]),
    )
    for assets, reserve, terminal, discount, factors in seeded_grid("contribution-all-at-r", contribution_cases):
        req = request(fixtures, "contribution-all-at-r")
        req["input"].update({
            "financial_assets_at_t0": assets,
            "planned_reserve_at_r": reserve,
            "planned_terminal_reserve_at_omega": terminal,
            "discount_factor_r_to_omega": discount,
        })
        req["input"]["constant_contribution_schedule"] = [
            {"date": f"2027-{index + 1:02d}-01", "accumulation_factor_to_r": factor}
            for index, factor in enumerate(factors)
        ]
        add("contribution-all-at-r", assets, req)

    generated_families = {family for family, _, _ in generated}
    if generated_families != PROPERTY_FAMILIES:
        missing = sorted(PROPERTY_FAMILIES - generated_families)
        extra = sorted(generated_families - PROPERTY_FAMILIES)
        raise AssertionError(f"property grid family mismatch: missing={missing}, extra={extra}")
    return generated


def compare_full_response(
    actual: Any,
    expected: Any,
    absolute: Decimal,
    relative: Decimal,
    path: str = "response",
) -> list[str]:
    """Compare the complete response tree, using tolerance only for decimals."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{path}: expected object, got {type(actual).__name__}"]
        errors: list[str] = []
        if set(actual) != set(expected):
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            if missing:
                errors.append(f"{path}: missing keys {missing}")
            if extra:
                errors.append(f"{path}: unexpected keys {extra}")
        for key in sorted(set(actual) & set(expected)):
            errors.extend(compare_full_response(actual[key], expected[key], absolute, relative, f"{path}.{key}"))
        return errors
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return [f"{path}: list shape differs"]
        errors: list[str] = []
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            errors.extend(compare_full_response(actual_item, expected_item, absolute, relative, f"{path}[{index}]"))
        return errors
    if isinstance(expected, str) and DECIMAL_TEXT.fullmatch(expected):
        if not isinstance(actual, str) or not DECIMAL_TEXT.fullmatch(actual):
            return [f"{path}: expected canonical decimal string, got {actual!r}"]
        try:
            actual_decimal, expected_decimal = Decimal(actual), Decimal(expected)
        except InvalidOperation:
            return [f"{path}: invalid decimal output"]
        difference = abs(actual_decimal - expected_decimal)
        if difference > absolute + relative * abs(expected_decimal):
            return [f"{path}: expected {expected!r}, got {actual!r} (abs={absolute}, rel={relative})"]
        return []
    if type(actual) is not type(expected) or actual != expected:
        return [f"{path}: expected {expected!r}, got {actual!r}"]
    return []


def exact_identity_sentinel(response: Any, req: dict[str, Any]) -> list[str]:
    """Check narrow defining identities without calling either compute route."""
    if req["id"] != "finite-annuity-certain":
        return []
    data = req["input"]
    expected = d(data["payment_amount"]) * sum((d(value) for value in data["discount_factors"]), Decimal(0))
    try:
        actual = response["output"]["present_value"]
    except (KeyError, TypeError):
        return ["finite-annuity exact-identity sentinel: response path output.present_value is absent"]
    if not isinstance(actual, str) or not DECIMAL_TEXT.fullmatch(actual):
        return [f"finite-annuity exact-identity sentinel: non-decimal present_value {actual!r}"]
    if d(actual) != expected:
        return [f"finite-annuity exact-identity sentinel: expected {expected}, got {actual}"]
    return []


def run(
    compute: Callable[[dict[str, Any]], dict[str, Any]],
    validation_compute: Callable[[dict[str, Any]], dict[str, Any]],
    fixtures: dict[str, dict[str, Any]],
) -> tuple[dict[str, int], list[str]]:
    counts = {name: 0 for name in PROPERTY_FAMILIES}
    errors: list[str] = []
    for family, label, req in generated_requests(fixtures):
        actual = compute(deepcopy(req))
        expected = validation_compute(deepcopy(req))
        tolerance = fixtures[family]["tolerance"]
        comparison_errors = compare_full_response(
            actual,
            expected,
            Decimal(tolerance["absolute"]),
            Decimal(tolerance["relative"]),
        )
        counts[family] += 1
        errors.extend(f"property {family}:{label} full-response {message}" for message in comparison_errors)
        if family in COMMON_MODE_SENTINEL_FAMILIES:
            errors.extend(f"property {family}:{label} candidate {message}" for message in exact_identity_sentinel(actual, req))
            errors.extend(f"property {family}:{label} validation-route {message}" for message in exact_identity_sentinel(expected, req))
    return counts, errors
