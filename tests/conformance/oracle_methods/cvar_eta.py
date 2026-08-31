"""Discrete CVaR by enumeration of the Rockafellar-Uryasev eta LP."""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .common import q, result, s


def compute(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    alpha = q(data["alpha"])
    rows = [(q(row["loss"]), q(row["probability"])) for row in data["scenarios"]]
    candidates = sorted({loss for loss, _ in rows})
    objectives = {
        eta: eta + sum((probability * max(Fraction(), loss - eta) for loss, probability in rows), Fraction()) / (1 - alpha)
        for eta in candidates
    }
    best = min(candidates, key=lambda eta: (objectives[eta], eta))
    return result(request, {"var": s(best), "tail_expected_shortfall": s(objectives[best])})
