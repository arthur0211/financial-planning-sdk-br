"""Two-stage oracle by exhaustive evaluation of all critical candidates."""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .common import q, result, s


def compute(request: dict[str, Any]) -> dict[str, Any]:
    rows = list(request["input"]["stage_1_scenarios"].values())
    probabilities = [q(row["probability"]) for row in rows]
    targets = [q(row["target_revealed_at_stage_1"]) for row in rows]

    def loss(candidate: Fraction) -> Fraction:
        return sum((probability * (candidate - target) ** 2 for probability, target in zip(probabilities, targets)), Fraction())

    # A convex piecewise-polynomial objective can minimize only at a boundary
    # or a derivative root.  Enumerating that complete finite candidate set is
    # an independent minimization check against the adapter's analytic action.
    derivative_root = sum((probability * target for probability, target in zip(probabilities, targets)), Fraction()) / sum(probabilities, Fraction())
    candidates = sorted(set(targets + [derivative_root]))
    action = min(candidates, key=lambda candidate: (loss(candidate), candidate))
    losses = [(action - target) ** 2 for target in targets]
    return result(request, {
        "implementable_policy": {
            "stage_0_action_low_path": s(action), "stage_0_action_high_path": s(action),
            "scenario_loss_low": s(losses[0]), "scenario_loss_high": s(losses[1]),
            "expected_loss": s(loss(action)), "nonanticipativity_satisfied": True,
        },
        "perfect_information_diagnostic": {
            "stage_0_action_low_path": s(targets[0]), "stage_0_action_high_path": s(targets[1]),
            "expected_loss": "0", "implementable_at_stage_0": False, "bound_for_minimization": "lower",
        },
    })
