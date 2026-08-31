"""Two-asset portfolio oracle by symbolic objective candidate evaluation."""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .common import q, result, s


def _objective(weight_a: Fraction, va: Fraction, vb: Fraction, covariance: Fraction) -> Fraction:
    weight_b = 1 - weight_a
    return weight_a * weight_a * va + weight_b * weight_b * vb + 2 * weight_a * weight_b * covariance


def compute(request: dict[str, Any]) -> dict[str, Any]:
    data = request["input"]
    va, vb, covariance = q(data["variance_a"]), q(data["variance_b"]), q(data["covariance_ab"])
    # Expanding V(w,1-w)=a*w^2+b*w+c gives the only stationary candidate.
    # Evaluate it alongside the feasible boundary candidates instead of using
    # the adapter's simultaneous KKT weight equations.
    a = va + vb - 2 * covariance
    b = 2 * (covariance - vb)
    stationary = -b / (2 * a)
    # The corpus declares only the full-investment equality; it does not impose
    # long-only bounds.  Enumerate the stationary point and symmetric symbolic
    # perturbations to check the convex objective without clipping the weight.
    candidates = [stationary - 1, stationary, stationary + 1]
    weight_a = min(candidates, key=lambda item: _objective(item, va, vb, covariance))
    weight_b = 1 - weight_a
    return result(request, {"weight_a": s(weight_a), "weight_b": s(weight_b), "portfolio_variance": s(_objective(weight_a, va, vb, covariance))})
