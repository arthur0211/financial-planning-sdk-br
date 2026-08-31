"""Household states from an explicit Bernoulli sample space."""

from __future__ import annotations

from datetime import date
from fractions import Fraction
from itertools import product
from typing import Any

from .common import q, result, s


STATE_BY_TICKET = {(True, True): "both_alive", (True, False): "only_a_alive", (False, True): "only_b_alive", (False, False): "none_alive"}


def independent_states(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    alive_probabilities = (q(data["survival_probability_a"]), q(data["survival_probability_b"]))
    probabilities: dict[str, Fraction] = {}
    for ticket in product((False, True), repeat=2):
        probability = Fraction(1)
        for alive, alive_probability in zip(ticket, alive_probabilities):
            probability *= alive_probability if alive else 1 - alive_probability
        probabilities[STATE_BY_TICKET[ticket]] = probability
    rows = data["floor_and_secure_income_by_state"]
    gaps = {state: max(Fraction(), q(rows[state]["essential_floor"]) - q(rows[state]["secure_income"])) for state in probabilities}
    weighted = lambda field: sum((probabilities[state] * q(rows[state][field]) for state in probabilities), Fraction())
    return result(request, {
        "state_probabilities": {state: s(value) for state, value in probabilities.items()},
        "probability_at_least_one_alive": s(sum((value for state, value in probabilities.items() if state != "none_alive"), Fraction())),
        "gap_by_state": {state: s(value) for state, value in gaps.items()},
        "probability_weighted_essential_floor": s(weighted("essential_floor")),
        "probability_weighted_secure_income": s(weighted("secure_income")),
        "probability_weighted_gap": s(sum((probabilities[state] * gaps[state] for state in probabilities), Fraction())),
    })


def deterministic_state(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    horizon = date.fromisoformat(data["horizon_date"])
    ticket = tuple(date.fromisoformat(data[key]) > horizon for key in ("death_date_a", "death_date_b"))
    return result(request, {"household_state": STATE_BY_TICKET[ticket], "active_person_count": str(sum(ticket))})
