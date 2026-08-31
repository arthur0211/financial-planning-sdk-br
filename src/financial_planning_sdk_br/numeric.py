"""Exact decimal and BRL money primitives for the deterministic slice."""

from __future__ import annotations

import re
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DecimalException,
    Inexact,
    Rounded,
    localcontext,
)
from typing import Literal

MONEY_QUANTUM = Decimal("0.01")
ARITHMETIC_PRECISION = 128
ARITHMETIC_EMIN = -127
ARITHMETIC_EMAX = 127
MAX_MONEY_SIGNIFICANT_DIGITS = 38
MAX_DISCOUNT_FACTOR_SIGNIFICANT_DIGITS = 38
MAX_RETURN_RATE_SIGNIFICANT_DIGITS = 38
_MONEY_PATTERN = re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]{2}$")
_DECIMAL_PATTERN = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?$")

NumericFailure = Literal["invalid", "overflow", "invariant"]
DecimalDomain = Literal["discount_factor", "return_rate"]


class NumericContractError(ValueError):
    def __init__(self, message: str, *, failure: NumericFailure = "invalid") -> None:
        self.failure = failure
        super().__init__(message)


def _context(*, allow_money_rounding: bool) -> Context:
    """Return one fresh, fully explicit arithmetic context.

    Context flags are mutable and sticky.  A fresh instance per boundary avoids
    history dependence and cross-thread sharing, while ``localcontext`` restores
    every caller setting and flag when the operation finishes.
    """

    context = Context(
        prec=ARITHMETIC_PRECISION,
        rounding=ROUND_HALF_EVEN,
        Emin=ARITHMETIC_EMIN,
        Emax=ARITHMETIC_EMAX,
        capitals=1,
        clamp=0,
    )
    for signal in context.traps:
        context.traps[signal] = True
    if allow_money_rounding:
        context.traps[Inexact] = False
        context.traps[Rounded] = False
    context.clear_flags()
    return context


def _significant_digits(text: str) -> int:
    digits = text.lstrip("-").replace(".", "").lstrip("0")
    return len(digits) or 1


def parse_money(text: object) -> Decimal:
    if type(text) is not str or not _MONEY_PATTERN.fullmatch(text):
        raise NumericContractError("money must be an ASCII decimal string with exactly two fractional digits")
    if text == "-0.00" or _significant_digits(text) > MAX_MONEY_SIGNIFICANT_DIGITS:
        raise NumericContractError("money is non-canonical or exceeds the 38-digit budget")
    try:
        value = Decimal(text)
    except DecimalException as exc:  # pragma: no cover - regex already narrows input
        raise NumericContractError("money cannot be parsed as Decimal") from exc
    if not value.is_finite():
        raise NumericContractError("money must be finite")
    return value


def parse_decimal(
    text: object,
    *,
    domain: DecimalDomain,
    positive: bool = False,
    minimum: Decimal | None = None,
) -> Decimal:
    if type(text) is not str or not _DECIMAL_PATTERN.fullmatch(text):
        raise NumericContractError("value must be a bounded ASCII decimal string without exponent notation")
    max_significant_digits = (
        MAX_DISCOUNT_FACTOR_SIGNIFICANT_DIGITS
        if domain == "discount_factor"
        else MAX_RETURN_RATE_SIGNIFICANT_DIGITS
    )
    if _significant_digits(text) > max_significant_digits:
        raise NumericContractError("value exceeds the 38-digit budget")
    try:
        value = Decimal(text)
    except DecimalException as exc:  # pragma: no cover - regex already narrows input
        raise NumericContractError("value cannot be parsed as Decimal") from exc
    if text.startswith("-") and value == 0:
        raise NumericContractError("negative zero is forbidden")
    if not value.is_finite():
        raise NumericContractError("value must be finite")
    if positive and value <= 0:
        raise NumericContractError("value must be strictly positive")
    if minimum is not None and value < minimum:
        raise NumericContractError("value is below the permitted lower bound")
    return value


def money(value: Decimal) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise NumericContractError("monetary result is not a finite Decimal", failure="invariant")
    try:
        with localcontext(_context(allow_money_rounding=True)) as context:
            rounded = context.quantize(value, MONEY_QUANTUM)
            unexpected_flags = any(
                enabled for signal, enabled in context.flags.items() if signal not in {Inexact, Rounded}
            )
    except DecimalException as exc:
        raise NumericContractError(
            "monetary quantization violated the arithmetic context", failure="invariant"
        ) from exc
    if unexpected_flags or not rounded.is_finite():
        raise NumericContractError("monetary quantization violated the arithmetic context", failure="invariant")
    if _significant_digits(format(rounded, "f")) > MAX_MONEY_SIGNIFICANT_DIGITS:
        raise NumericContractError("monetary result exceeds the 38-digit output budget", failure="overflow")
    return Decimal("0.00") if rounded == 0 else rounded


def multiply(left: Decimal, right: Decimal) -> Decimal:
    if type(left) is not Decimal or type(right) is not Decimal or not left.is_finite() or not right.is_finite():
        raise NumericContractError("multiplication operands violate the Decimal invariant", failure="invariant")
    try:
        with localcontext(_context(allow_money_rounding=False)) as context:
            result = context.multiply(left, right)
            signaled = any(context.flags.values())
    except DecimalException as exc:
        raise NumericContractError("exact multiplication violated the arithmetic context", failure="invariant") from exc
    if signaled or not result.is_finite():
        raise NumericContractError("exact multiplication violated the arithmetic context", failure="invariant")
    return result


def add(*values: Decimal) -> Decimal:
    if any(type(value) is not Decimal or not value.is_finite() for value in values):
        raise NumericContractError("addition operands violate the Decimal invariant", failure="invariant")
    try:
        with localcontext(_context(allow_money_rounding=False)) as context:
            total = Decimal(0)
            for value in values:
                total = context.add(total, value)
            signaled = any(context.flags.values())
    except DecimalException as exc:
        raise NumericContractError("exact addition violated the arithmetic context", failure="invariant") from exc
    if signaled or not total.is_finite():
        raise NumericContractError("exact addition violated the arithmetic context", failure="invariant")
    return total


def money_to_minor_units(value: Decimal) -> int:
    rounded = money(value)
    parts = rounded.as_tuple()
    if parts.exponent != -2 or not isinstance(parts.exponent, int):  # pragma: no cover - quantize fixes the exponent
        raise NumericContractError("money exponent violated the minor-unit invariant", failure="invariant")
    units = 0
    for digit in parts.digits:
        units = units * 10 + digit
    return -units if parts.sign else units


def bounded_minor_units(value: int) -> int:
    if type(value) is not int:
        raise NumericContractError("minor units must be an integer", failure="invariant")
    if len(str(abs(value))) > MAX_MONEY_SIGNIFICANT_DIGITS:
        raise NumericContractError("monetary result exceeds the 38-digit output budget", failure="overflow")
    return value


def format_minor_units(value: int) -> str:
    bounded = bounded_minor_units(value)
    sign = "-" if bounded < 0 else ""
    whole, cents = divmod(abs(bounded), 100)
    return f"{sign}{whole}.{cents:02d}"


def minor_units_decimal(value: int) -> Decimal:
    return Decimal(format_minor_units(value))


def format_money(value: Decimal) -> str:
    return format(money(value), ".2f")


def format_decimal(value: Decimal) -> str:
    if type(value) is not Decimal or not value.is_finite():
        raise NumericContractError("formatted value violates the Decimal invariant", failure="invariant")
    if value == 0:
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered
