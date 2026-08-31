from __future__ import annotations

from decimal import Decimal, localcontext
from fractions import Fraction
from typing import Any


def q(value: str) -> Fraction:
    return Fraction(value)


def s(value: Fraction) -> str:
    with localcontext() as context:
        context.prec = 60
        return format(Decimal(value.numerator) / Decimal(value.denominator), "f")


def result(request: dict[str, Any], output: dict[str, Any], status: str = "computed") -> dict[str, Any]:
    return {"vector_id": request["id"], "computational_status": status, "output": output}
