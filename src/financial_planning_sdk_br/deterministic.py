"""Deterministic present-value and cash-flow ledger vertical.

This module performs arithmetic only. It does not fetch data, infer Brazilian
rules, rank alternatives, recommend products, or authorize deployment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, DecimalException
from typing import Any, cast

from ._value_object import _opaque_state, _OpaqueValueObject, _register_opaque_state
from .contracts import _assert_public_schema
from .errors import MAX_VALIDATION_ISSUES, InputValidationError, ValidationIssue, ValidationReport
from .jsonio import (
    MAX_DETERMINISTIC_REQUEST_NODES,
    MAX_DETERMINISTIC_RESULT_BYTES,
    MAX_DETERMINISTIC_RESULT_NODES,
    MAX_INPUT_BYTES,
    JsonContractError,
    JsonObject,
    canonical_json_bytes,
    loads_strict,
)
from .numeric import (
    DecimalDomain,
    NumericContractError,
    add,
    bounded_minor_units,
    format_decimal,
    format_minor_units,
    format_money,
    minor_units_decimal,
    money,
    money_to_minor_units,
    multiply,
    parse_decimal,
    parse_money,
)

CONTRACT_VERSION = "0.1.0-draft.1"
ENGINE_VERSION = "0.1.0.dev0"
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_POSTING_CATEGORIES = {"contribution", "withdrawal", "income", "gain", "fee", "tax", "adjustment"}
_RETURN_BASES = {"none", "price_return", "total_return"}


@dataclass(frozen=True, slots=True)
class MoneyValue:
    value: Decimal
    currency: str = "BRL"

    def to_dict(self) -> dict[str, str]:
        return {"currency": self.currency, "value": format_money(self.value)}


@dataclass(frozen=True, slots=True)
class DiscountFactor:
    event_date: date
    factor: Decimal


@dataclass(frozen=True, slots=True)
class CashFlow:
    cashflow_id: str
    claim_id: str
    event_date: date
    amount: MoneyValue


@dataclass(frozen=True, slots=True)
class Account:
    account_id: str
    opening_balance: MoneyValue
    return_basis: str


@dataclass(frozen=True, slots=True)
class PostingEvent:
    event_id: str
    effective_date: date
    sequence: int
    account_id: str
    category: str
    claim_id: str
    amount: MoneyValue
    event_type: str = "posting"


@dataclass(frozen=True, slots=True)
class TransferEvent:
    event_id: str
    effective_date: date
    sequence: int
    from_account_id: str
    to_account_id: str
    economic_source_id: str
    amount: MoneyValue
    event_type: str = "transfer"


@dataclass(frozen=True, slots=True)
class ReturnEvent:
    event_id: str
    effective_date: date
    sequence: int
    account_id: str
    return_basis: str
    rate: Decimal
    cash_distribution: MoneyValue
    event_type: str = "return"


LedgerEvent = PostingEvent | TransferEvent | ReturnEvent


@dataclass(frozen=True, slots=True)
class _DeterministicRequest:
    calculation_id: str
    valuation_date: date
    base_currency: str
    purpose: str
    client_specific: bool
    recommendation_enabled: bool
    execution_enabled: bool
    discount_factors: tuple[DiscountFactor, ...]
    cashflows: tuple[CashFlow, ...]
    accounts: tuple[Account, ...]
    events: tuple[LedgerEvent, ...]
    contract_version: str = CONTRACT_VERSION


class DeterministicResult(_OpaqueValueObject):
    """Canonical immutable result; construction is reserved to the engine."""

    __slots__ = ()

    def __new__(cls, *_args: object, **_kwargs: object) -> DeterministicResult:
        raise TypeError("deterministic results can only be created by the engine")

    @classmethod
    def _from_canonical_payload(cls, payload: bytes) -> DeterministicResult:
        if cls is not DeterministicResult:
            raise TypeError("DeterministicResult is an exact sealed public type")
        if type(payload) is not bytes:
            raise TypeError("deterministic result payload must be immutable bytes")
        try:
            document = loads_strict(
                payload,
                max_bytes=MAX_DETERMINISTIC_RESULT_BYTES,
                max_nodes=MAX_DETERMINISTIC_RESULT_NODES,
            )
            canonical = canonical_json_bytes(
                document,
                max_bytes=MAX_DETERMINISTIC_RESULT_BYTES,
                max_nodes=MAX_DETERMINISTIC_RESULT_NODES,
            )
        except JsonContractError as exc:
            raise ValueError("deterministic result payload is outside the canonical contract") from exc
        if (
            type(document) is not dict
            or canonical != payload
            or document.get("result_format") != "finplanbr.deterministic-cashflow-ledger-result.v1"
            or document.get("contract_version") != CONTRACT_VERSION
            or document.get("engine_version") != ENGINE_VERSION
            or document.get("artifact_status") != "draft"
            or document.get("computational_status") != "computed"
            or document.get("authority") != "none"
            or document.get("deployment_eligibility") != "not_authorized"
        ):
            raise ValueError("deterministic result payload is inconsistent with the public result contract")
        _assert_public_schema("deterministic-result.schema.json", document)
        instance = object.__new__(cls)
        _register_opaque_state(instance, payload, exact_type=DeterministicResult)
        return instance

    def _validated_document(self) -> JsonObject:
        state = _opaque_state(self, exact_type=DeterministicResult)
        if type(state) is not bytes:
            raise ValueError("deterministic result state is not immutable canonical bytes")
        payload = state
        try:
            document = loads_strict(
                payload,
                max_bytes=MAX_DETERMINISTIC_RESULT_BYTES,
                max_nodes=MAX_DETERMINISTIC_RESULT_NODES,
            )
            canonical = canonical_json_bytes(
                document,
                max_bytes=MAX_DETERMINISTIC_RESULT_BYTES,
                max_nodes=MAX_DETERMINISTIC_RESULT_NODES,
            )
        except JsonContractError as exc:
            raise ValueError("deterministic result state is outside the canonical contract") from exc
        if (
            type(document) is not dict
            or canonical != payload
            or document.get("result_format") != "finplanbr.deterministic-cashflow-ledger-result.v1"
            or document.get("contract_version") != CONTRACT_VERSION
            or document.get("engine_version") != ENGINE_VERSION
            or document.get("artifact_status") != "draft"
            or document.get("computational_status") != "computed"
            or document.get("authority") != "none"
            or document.get("deployment_eligibility") != "not_authorized"
        ):
            raise ValueError("deterministic result state is inconsistent with the public result contract")
        _assert_public_schema("deterministic-result.schema.json", document)
        return document

    def _validated_sequence(self) -> tuple[object, ...]:
        DeterministicResult._validated_document(self)
        return (cast(bytes, _opaque_state(self, exact_type=DeterministicResult)),)

    @property
    def _canonical_payload(self) -> bytes:
        DeterministicResult._validated_document(self)
        return cast(bytes, _opaque_state(self, exact_type=DeterministicResult))

    def to_dict(self) -> JsonObject:
        return DeterministicResult._validated_document(self)

    def to_json_bytes(self) -> bytes:
        DeterministicResult._validated_document(self)
        return cast(bytes, _opaque_state(self, exact_type=DeterministicResult))


class _BoundedIssues:
    """Count every issue while retaining only a deterministic discovery prefix."""

    __slots__ = ("items", "total_count")

    def __init__(self) -> None:
        self.items: list[ValidationIssue] = []
        self.total_count = 0

    def add(self, code: str, pointer: str, message: str) -> None:
        self.total_count += 1
        if len(self.items) < MAX_VALIDATION_ISSUES:
            self.items.append(ValidationIssue(code=code, pointer=pointer, message=message))

    def __bool__(self) -> bool:
        return self.total_count > 0


def _issue(issues: _BoundedIssues, code: str, pointer: str, message: str) -> None:
    issues.add(code, pointer, message)


def _object(
    value: Any,
    pointer: str,
    issues: _BoundedIssues,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if type(value) is not dict:
        _issue(issues, "DCL_TYPE_MISMATCH", pointer, "value must be a JSON object")
        return {}
    if any(type(key) is not str for key in value):
        _issue(issues, "DCL_TYPE_MISMATCH", pointer, "JSON object keys must be strings")
        return {}
    optional = optional or set()
    for key in sorted(required - value.keys()):
        _issue(issues, "DCL_REQUIRED_FIELD", f"{pointer}/{key}", "required field is missing")
    if value.keys() - required - optional:
        _issue(issues, "DCL_UNKNOWN_FIELD", pointer, "object contains one or more unknown fields")
    return value


def _array(value: Any, pointer: str, issues: _BoundedIssues, *, limit: int) -> list[Any]:
    if type(value) is not list:
        _issue(issues, "DCL_TYPE_MISMATCH", pointer, "value must be a JSON array")
        return []
    if len(value) > limit:
        _issue(issues, "DCL_ARRAY_BUDGET", pointer, "array exceeds its item budget")
        return value[:limit]
    return value


def _identifier(value: Any, pointer: str, issues: _BoundedIssues) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _issue(
            issues,
            "DCL_INVALID_IDENTIFIER",
            pointer,
            "identifier must match lowercase ASCII [a-z][a-z0-9_-]{0,63}",
        )
        return "invalid"
    return value


def _date(value: Any, pointer: str, issues: _BoundedIssues) -> date:
    if type(value) is not str or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        _issue(issues, "DCL_INVALID_DATE", pointer, "date must be an existing ISO 8601 civil date")
        return date(1970, 1, 1)
    try:
        return date.fromisoformat(value)
    except ValueError:
        _issue(issues, "DCL_INVALID_DATE", pointer, "date must be an existing ISO 8601 civil date")
        return date(1970, 1, 1)


def _money(value: Any, pointer: str, issues: _BoundedIssues, currency: str) -> MoneyValue:
    document = _object(value, pointer, issues, required={"currency", "value"})
    observed_currency = document.get("currency")
    if type(observed_currency) is not str or observed_currency != currency:
        _issue(issues, "DCL_CURRENCY_MISMATCH", f"{pointer}/currency", "money currency must equal base_currency")
    try:
        amount = parse_money(document.get("value"))
    except ValueError:
        _issue(
            issues,
            "DCL_INVALID_MONEY",
            f"{pointer}/value",
            "money must be finite ASCII decimal text with exactly two fractional digits",
        )
        amount = Decimal("0.00")
    return MoneyValue(amount, currency)


def _decimal(
    value: Any,
    pointer: str,
    issues: _BoundedIssues,
    *,
    domain: DecimalDomain,
    positive: bool = False,
    minimum: Decimal | None = None,
) -> Decimal:
    try:
        return parse_decimal(value, domain=domain, positive=positive, minimum=minimum)
    except ValueError:
        _issue(issues, "DCL_INVALID_DECIMAL", pointer, "decimal text violates the bounded exact-number contract")
        return Decimal(0)


def _parse_use_context(value: Any, issues: _BoundedIssues) -> tuple[str, bool, bool, bool]:
    pointer = "/use_context"
    document = _object(
        value,
        pointer,
        issues,
        required={"purpose", "client_specific", "recommendation_enabled", "execution_enabled"},
    )
    purpose = document.get("purpose")
    if type(purpose) is not str or purpose not in {"education", "scientific_evaluation", "software_testing"}:
        _issue(issues, "DCL_USE_OUT_OF_SCOPE", f"{pointer}/purpose", "purpose is outside the local research boundary")
        purpose = "software_testing"
    flags: list[bool] = []
    for name in ("client_specific", "recommendation_enabled", "execution_enabled"):
        observed = document.get(name)
        if type(observed) is not bool:
            _issue(issues, "DCL_TYPE_MISMATCH", f"{pointer}/{name}", "field must be a JSON boolean")
            observed = True
        flags.append(observed)
    if any(flags):
        _issue(
            issues,
            "DCL_USE_OUT_OF_SCOPE",
            pointer,
            "client-specific, recommendation, and execution modes are unavailable in this local slice",
        )
    return purpose, flags[0], flags[1], flags[2]


def _root_json_snapshot(data: object) -> JsonObject:
    if type(data) is not dict:
        raise InputValidationError(
            [ValidationIssue("DCL_TYPE_MISMATCH", "", "request must be one exact built-in JSON object")]
        ) from None
    try:
        payload = canonical_json_bytes(
            data,
            max_bytes=MAX_INPUT_BYTES,
            max_nodes=MAX_DETERMINISTIC_REQUEST_NODES,
        )
        snapshot = loads_strict(
            payload,
            max_bytes=MAX_INPUT_BYTES,
            max_nodes=MAX_DETERMINISTIC_REQUEST_NODES,
        )
    except JsonContractError:
        raise InputValidationError(
            [ValidationIssue("DCL_JSON_INPUT", "", "request violates the bounded exact JSON input contract")]
        ) from None
    if type(snapshot) is not dict:  # exact root precondition and canonical round-trip invariant
        raise InputValidationError(
            [ValidationIssue("DCL_TYPE_MISMATCH", "", "request must be one exact built-in JSON object")]
        ) from None
    return snapshot


def _parse_deterministic_request(data: object) -> _DeterministicRequest:
    issues = _BoundedIssues()
    root = _root_json_snapshot(data)
    document = _object(
        root,
        "",
        issues,
        required={
            "contract_version",
            "calculation_id",
            "valuation_date",
            "base_currency",
            "use_context",
            "discount_factors",
            "cashflows",
            "accounts",
            "events",
        },
    )
    observed_version = document.get("contract_version")
    if type(observed_version) is not str or observed_version != CONTRACT_VERSION:
        _issue(issues, "DCL_CONTRACT_VERSION", "/contract_version", "unsupported deterministic contract version")
    calculation_id = _identifier(document.get("calculation_id"), "/calculation_id", issues)
    valuation_date = _date(document.get("valuation_date"), "/valuation_date", issues)
    base_currency = document.get("base_currency")
    if type(base_currency) is not str or base_currency != "BRL":
        _issue(issues, "DCL_UNSUPPORTED_CURRENCY", "/base_currency", "this vertical supports BRL only")
        base_currency = "BRL"
    purpose, client_specific, recommendation_enabled, execution_enabled = _parse_use_context(
        document.get("use_context"), issues
    )

    factors: list[DiscountFactor] = []
    factor_dates: set[date] = set()
    for index, raw in enumerate(_array(document.get("discount_factors"), "/discount_factors", issues, limit=512)):
        pointer = f"/discount_factors/{index}"
        item = _object(raw, pointer, issues, required={"date", "factor"})
        event_date = _date(item.get("date"), f"{pointer}/date", issues)
        factor = _decimal(
            item.get("factor"),
            f"{pointer}/factor",
            issues,
            domain="discount_factor",
            positive=True,
        )
        if event_date < valuation_date:
            _issue(
                issues, "DCL_DATE_BEFORE_VALUATION", f"{pointer}/date", "discount-factor date precedes valuation_date"
            )
        if event_date in factor_dates:
            _issue(issues, "DCL_DUPLICATE_DATE", f"{pointer}/date", "discount-factor date must be unique")
        factor_dates.add(event_date)
        if event_date == valuation_date and factor != 1:
            _issue(
                issues, "DCL_INVALID_DISCOUNT_FACTOR", f"{pointer}/factor", "factor at valuation_date must equal one"
            )
        factors.append(DiscountFactor(event_date, factor))
    if factors != sorted(factors, key=lambda item: item.event_date):
        _issue(issues, "DCL_NONCANONICAL_ORDER", "/discount_factors", "discount factors must be ordered by date")

    cashflows: list[CashFlow] = []
    cashflow_ids: set[str] = set()
    claim_dates: set[tuple[str, date]] = set()
    for index, raw in enumerate(_array(document.get("cashflows"), "/cashflows", issues, limit=4096)):
        pointer = f"/cashflows/{index}"
        item = _object(raw, pointer, issues, required={"cashflow_id", "claim_id", "event_date", "amount"})
        cashflow_id = _identifier(item.get("cashflow_id"), f"{pointer}/cashflow_id", issues)
        claim_id = _identifier(item.get("claim_id"), f"{pointer}/claim_id", issues)
        event_date = _date(item.get("event_date"), f"{pointer}/event_date", issues)
        amount = _money(item.get("amount"), f"{pointer}/amount", issues, base_currency)
        if cashflow_id in cashflow_ids:
            _issue(issues, "DCL_DUPLICATE_ID", f"{pointer}/cashflow_id", "cashflow_id must be unique")
        cashflow_ids.add(cashflow_id)
        if (claim_id, event_date) in claim_dates:
            _issue(issues, "DCL_DUPLICATE_CLAIM", pointer, "claim_id and event_date pair must be unique")
        claim_dates.add((claim_id, event_date))
        if event_date < valuation_date:
            _issue(issues, "DCL_DATE_BEFORE_VALUATION", f"{pointer}/event_date", "cashflow precedes valuation_date")
        if event_date not in factor_dates:
            _issue(
                issues,
                "DCL_DISCOUNT_FACTOR_MISSING",
                f"{pointer}/event_date",
                "cashflow requires an explicit factor on its date",
            )
        cashflows.append(CashFlow(cashflow_id, claim_id, event_date, amount))
    if cashflows != sorted(cashflows, key=lambda item: (item.event_date, item.cashflow_id)):
        _issue(
            issues, "DCL_NONCANONICAL_ORDER", "/cashflows", "cashflows must be ordered by event_date and cashflow_id"
        )

    accounts: list[Account] = []
    account_ids: set[str] = set()
    for index, raw in enumerate(_array(document.get("accounts"), "/accounts", issues, limit=256)):
        pointer = f"/accounts/{index}"
        item = _object(raw, pointer, issues, required={"account_id", "opening_balance", "return_basis"})
        account_id = _identifier(item.get("account_id"), f"{pointer}/account_id", issues)
        opening = _money(item.get("opening_balance"), f"{pointer}/opening_balance", issues, base_currency)
        return_basis = item.get("return_basis")
        if type(return_basis) is not str or return_basis not in _RETURN_BASES:
            _issue(issues, "DCL_RETURN_BASIS", f"{pointer}/return_basis", "return_basis is unsupported")
            return_basis = "none"
        if opening.value < 0:
            _issue(issues, "DCL_NEGATIVE_BALANCE", f"{pointer}/opening_balance", "opening balance cannot be negative")
        if account_id in account_ids:
            _issue(issues, "DCL_DUPLICATE_ID", f"{pointer}/account_id", "account_id must be unique")
        account_ids.add(account_id)
        accounts.append(Account(account_id, opening, return_basis))
    if accounts != sorted(accounts, key=lambda item: item.account_id):
        _issue(issues, "DCL_NONCANONICAL_ORDER", "/accounts", "accounts must be ordered by account_id")

    events: list[LedgerEvent] = []
    event_ids: set[str] = set()
    event_orders: set[tuple[date, int]] = set()
    transfer_sources: set[str] = set()
    for index, raw in enumerate(_array(document.get("events"), "/events", issues, limit=4096)):
        pointer = f"/events/{index}"
        if type(raw) is not dict:
            _issue(issues, "DCL_TYPE_MISMATCH", pointer, "ledger event must be a JSON object")
            continue
        event_type = raw.get("event_type")
        common = {"event_type", "event_id", "effective_date", "sequence"}
        if type(event_type) is str and event_type == "posting":
            required = common | {"account_id", "category", "claim_id", "amount"}
        elif type(event_type) is str and event_type == "transfer":
            required = common | {"from_account_id", "to_account_id", "economic_source_id", "amount"}
        elif type(event_type) is str and event_type == "return":
            required = common | {"account_id", "return_basis", "rate", "cash_distribution"}
        else:
            required = common
            _issue(issues, "DCL_EVENT_TYPE", f"{pointer}/event_type", "event_type is unsupported")
        item = _object(raw, pointer, issues, required=required)
        event_id = _identifier(item.get("event_id"), f"{pointer}/event_id", issues)
        effective_date = _date(item.get("effective_date"), f"{pointer}/effective_date", issues)
        sequence = item.get("sequence")
        if type(sequence) is not int or sequence < 0 or sequence > 2_147_483_647:
            _issue(issues, "DCL_SEQUENCE", f"{pointer}/sequence", "sequence must be a non-negative 32-bit JSON integer")
            sequence = 0
        if event_id in event_ids:
            _issue(issues, "DCL_DUPLICATE_ID", f"{pointer}/event_id", "event_id must be unique")
        event_ids.add(event_id)
        if (effective_date, sequence) in event_orders:
            _issue(issues, "DCL_EVENT_ORDER_DUPLICATE", pointer, "effective_date and sequence pair must be unique")
        event_orders.add((effective_date, sequence))
        if effective_date < valuation_date:
            _issue(issues, "DCL_DATE_BEFORE_VALUATION", f"{pointer}/effective_date", "event precedes valuation_date")
        if type(event_type) is str and event_type == "posting":
            account_id = _identifier(item.get("account_id"), f"{pointer}/account_id", issues)
            category = item.get("category")
            if type(category) is not str or category not in _POSTING_CATEGORIES:
                _issue(issues, "DCL_POSTING_CATEGORY", f"{pointer}/category", "posting category is unsupported")
                category = "adjustment"
            claim_id = _identifier(item.get("claim_id"), f"{pointer}/claim_id", issues)
            amount = _money(item.get("amount"), f"{pointer}/amount", issues, base_currency)
            if category in {"contribution", "income"} and amount.value <= 0:
                _issue(issues, "DCL_POSTING_SIGN", f"{pointer}/amount", "posting category requires a positive amount")
            if category in {"withdrawal", "fee", "tax"} and amount.value >= 0:
                _issue(issues, "DCL_POSTING_SIGN", f"{pointer}/amount", "posting category requires a negative amount")
            events.append(PostingEvent(event_id, effective_date, sequence, account_id, category, claim_id, amount))
        elif type(event_type) is str and event_type == "transfer":
            from_id = _identifier(item.get("from_account_id"), f"{pointer}/from_account_id", issues)
            to_id = _identifier(item.get("to_account_id"), f"{pointer}/to_account_id", issues)
            source_id = _identifier(item.get("economic_source_id"), f"{pointer}/economic_source_id", issues)
            amount = _money(item.get("amount"), f"{pointer}/amount", issues, base_currency)
            if from_id == to_id:
                _issue(issues, "DCL_TRANSFER_ACCOUNTS", pointer, "transfer accounts must be distinct")
            if amount.value <= 0:
                _issue(issues, "DCL_TRANSFER_AMOUNT", f"{pointer}/amount", "transfer amount must be positive")
            if source_id in transfer_sources:
                _issue(
                    issues,
                    "DCL_DUPLICATE_CLAIM",
                    f"{pointer}/economic_source_id",
                    "transfer economic_source_id must be unique",
                )
            transfer_sources.add(source_id)
            events.append(TransferEvent(event_id, effective_date, sequence, from_id, to_id, source_id, amount))
        elif type(event_type) is str and event_type == "return":
            account_id = _identifier(item.get("account_id"), f"{pointer}/account_id", issues)
            return_basis = item.get("return_basis")
            if type(return_basis) is not str or return_basis not in {"price_return", "total_return"}:
                _issue(
                    issues,
                    "DCL_RETURN_BASIS",
                    f"{pointer}/return_basis",
                    "return event requires price_return or total_return",
                )
                return_basis = "price_return"
            rate = _decimal(
                item.get("rate"),
                f"{pointer}/rate",
                issues,
                domain="return_rate",
                minimum=Decimal("-1"),
            )
            distribution = _money(item.get("cash_distribution"), f"{pointer}/cash_distribution", issues, base_currency)
            if distribution.value < 0:
                _issue(
                    issues,
                    "DCL_DISTRIBUTION_SIGN",
                    f"{pointer}/cash_distribution",
                    "cash distribution cannot be negative",
                )
            if return_basis == "total_return" and distribution.value != 0:
                _issue(
                    issues,
                    "DCL_RETURN_BASIS_DOUBLE_COUNT",
                    f"{pointer}/cash_distribution",
                    "total_return requires a zero separate distribution",
                )
            events.append(ReturnEvent(event_id, effective_date, sequence, account_id, return_basis, rate, distribution))
    if events != sorted(events, key=lambda item: (item.effective_date, item.sequence)):
        _issue(issues, "DCL_NONCANONICAL_ORDER", "/events", "events must be ordered by effective_date and sequence")

    account_by_id = {account.account_id: account for account in accounts}
    for index, event in enumerate(events):
        pointer = f"/events/{index}"
        referenced = (
            [event.account_id]
            if isinstance(event, (PostingEvent, ReturnEvent))
            else [event.from_account_id, event.to_account_id]
        )
        for account_id in referenced:
            if account_id not in account_by_id:
                _issue(issues, "DCL_ACCOUNT_NOT_FOUND", pointer, "event references an unknown account")
        if isinstance(event, PostingEvent):
            account = account_by_id.get(event.account_id)
            if account and account.return_basis == "total_return" and event.category == "income":
                _issue(
                    issues,
                    "DCL_RETURN_BASIS_DOUBLE_COUNT",
                    pointer,
                    "total_return account cannot receive a separate income posting",
                )
        if isinstance(event, ReturnEvent):
            account = account_by_id.get(event.account_id)
            if account and account.return_basis != event.return_basis:
                _issue(issues, "DCL_RETURN_BASIS", pointer, "event return_basis must match its account convention")

    if issues:
        raise InputValidationError(issues.items, total_issue_count=issues.total_count)
    request = _DeterministicRequest(
        calculation_id=calculation_id,
        valuation_date=valuation_date,
        base_currency=base_currency,
        purpose=purpose,
        client_specific=client_specific,
        recommendation_enabled=recommendation_enabled,
        execution_enabled=execution_enabled,
        discount_factors=tuple(factors),
        cashflows=tuple(cashflows),
        accounts=tuple(accounts),
        events=tuple(events),
    )
    _replay_ledger(request, validate_only=True)
    return request


def validate_deterministic_request(data: JsonObject) -> ValidationReport:
    """Validate one deterministic request without computing or mutating it."""

    try:
        request = _parse_deterministic_request(data)
        factor_by_date = {factor.event_date: factor.factor for factor in request.discount_factors}
        exact_present_value = _exact_add(
            *(
                _exact_multiply(cashflow.amount.value, factor_by_date[cashflow.event_date], "/cashflows")
                for cashflow in request.cashflows
            ),
            pointer="/cashflows",
        )
        _bounded_money(exact_present_value, "/cashflows")
    except InputValidationError as exc:
        return exc.report
    except (DecimalException, NumericContractError):
        return _numeric_validation_error(None, "").report
    return ValidationReport(valid=True, issues=())


def _numeric_validation_error(error: NumericContractError | None, pointer: str) -> InputValidationError:
    overflow = error is not None and error.failure == "overflow"
    code = "DCL_NUMERIC_OVERFLOW" if overflow else "DCL_NUMERIC_INVARIANT_FAILED"
    message = (
        "monetary result exceeds the bounded output domain"
        if overflow
        else "numeric operation violated the closed arithmetic context"
    )
    return InputValidationError([ValidationIssue(code, pointer, message)])


def _exact_multiply(left: Decimal, right: Decimal, pointer: str) -> Decimal:
    try:
        return multiply(left, right)
    except NumericContractError as exc:
        raise _numeric_validation_error(exc, pointer) from None


def _exact_add(*values: Decimal, pointer: str) -> Decimal:
    try:
        return add(*values)
    except NumericContractError as exc:
        raise _numeric_validation_error(exc, pointer) from None


def _bounded_money(value: Decimal, pointer: str) -> Decimal:
    try:
        return money(value)
    except NumericContractError as exc:
        raise _numeric_validation_error(exc, pointer) from None


def _bounded_minor_units(value: int, pointer: str) -> int:
    try:
        return bounded_minor_units(value)
    except NumericContractError as exc:
        raise _numeric_validation_error(exc, pointer) from None


def _minor_units(value: Decimal, pointer: str) -> int:
    try:
        return money_to_minor_units(value)
    except NumericContractError as exc:
        raise _numeric_validation_error(exc, pointer) from None


def _replay_ledger(request: _DeterministicRequest, *, validate_only: bool = False) -> dict[str, Any]:
    states = {
        account.account_id: _minor_units(account.opening_balance.value, f"/accounts/{index}/opening_balance")
        for index, account in enumerate(request.accounts)
    }
    account_rules = {account.account_id: account for account in request.accounts}
    opening = _bounded_minor_units(sum(states.values()), "/accounts")
    posting_change = 0
    return_change = 0
    transfer_change = 0
    event_results: list[dict[str, Any]] = []

    for index, event in enumerate(request.events):
        pointer = f"/events/{index}"
        if isinstance(event, PostingEvent):
            before = states[event.account_id]
            delta = _minor_units(event.amount.value, f"{pointer}/amount")
            after = _bounded_minor_units(before + delta, pointer)
            if after < 0:
                raise InputValidationError(
                    [ValidationIssue("DCL_NEGATIVE_BALANCE", pointer, "event would make an account balance negative")]
                )
            states[event.account_id] = after
            posting_change += delta
            if not validate_only:
                event_results.append(
                    {
                        "event_id": event.event_id,
                        "event_type": event.event_type,
                        "effective_date": event.effective_date.isoformat(),
                        "sequence": event.sequence,
                        "category": event.category,
                        "claim_id": event.claim_id,
                        "postings": [
                            {
                                "account_id": event.account_id,
                                "before_balance": format_minor_units(before),
                                "delta": format_minor_units(delta),
                                "after_balance": format_minor_units(after),
                            }
                        ],
                    }
                )
        elif isinstance(event, TransferEvent):
            before_from = states[event.from_account_id]
            before_to = states[event.to_account_id]
            amount = _minor_units(event.amount.value, f"{pointer}/amount")
            after_from = _bounded_minor_units(before_from - amount, pointer)
            after_to = _bounded_minor_units(before_to + amount, pointer)
            if after_from < 0:
                raise InputValidationError(
                    [
                        ValidationIssue(
                            "DCL_NEGATIVE_BALANCE", pointer, "transfer would make the source account negative"
                        )
                    ]
            )
            states[event.from_account_id] = after_from
            states[event.to_account_id] = after_to
            transfer_delta = -amount + amount
            transfer_change += transfer_delta
            if not validate_only:
                event_results.append(
                    {
                        "event_id": event.event_id,
                        "event_type": event.event_type,
                        "effective_date": event.effective_date.isoformat(),
                        "sequence": event.sequence,
                        "economic_source_id": event.economic_source_id,
                        "postings": [
                            {
                                "account_id": event.from_account_id,
                                "before_balance": format_minor_units(before_from),
                                "delta": format_minor_units(-amount),
                                "after_balance": format_minor_units(after_from),
                            },
                            {
                                "account_id": event.to_account_id,
                                "before_balance": format_minor_units(before_to),
                                "delta": format_minor_units(amount),
                                "after_balance": format_minor_units(after_to),
                            },
                        ],
                    }
                )
        else:
            before = states[event.account_id]
            gain_value = _bounded_money(
                _exact_multiply(minor_units_decimal(before), event.rate, pointer),
                pointer,
            )
            gain = _minor_units(gain_value, pointer)
            distribution = _minor_units(event.cash_distribution.value, f"{pointer}/cash_distribution")
            asset_after_return = _bounded_minor_units(before + gain, pointer)
            after = _bounded_minor_units(asset_after_return + distribution, pointer)
            if after < 0:
                raise InputValidationError(
                    [ValidationIssue("DCL_NEGATIVE_BALANCE", pointer, "return event would make an account negative")]
                )
            states[event.account_id] = after
            delta = gain + distribution
            return_change += delta
            if not validate_only:
                event_results.append(
                    {
                        "event_id": event.event_id,
                        "event_type": event.event_type,
                        "effective_date": event.effective_date.isoformat(),
                        "sequence": event.sequence,
                        "return_basis": event.return_basis,
                        "rate": format_decimal(event.rate),
                        "gain": format_minor_units(gain),
                        "asset_value_after_return": format_minor_units(asset_after_return),
                        "cash_distribution": format_minor_units(distribution),
                        "postings": [
                            {
                                "account_id": event.account_id,
                                "before_balance": format_minor_units(before),
                                "delta": format_minor_units(delta),
                                "after_balance": format_minor_units(after),
                            }
                        ],
                    }
                )

    closing = _bounded_minor_units(sum(states.values()), "/accounts")
    posting_change = _bounded_minor_units(posting_change, "/events")
    return_change = _bounded_minor_units(return_change, "/events")
    transfer_change = _bounded_minor_units(transfer_change, "/events")
    expected = _bounded_minor_units(opening + posting_change + return_change + transfer_change, "/events")
    reconciled = closing == expected and transfer_change == 0
    if not reconciled:
        raise InputValidationError(
            [ValidationIssue("DCL_LEDGER_RECONCILIATION_FAILED", "/events", "ledger identity did not reconcile")]
        )
    if validate_only:
        return {}
    return {
        "opening_consolidated_wealth": format_minor_units(opening),
        "closing_consolidated_wealth": format_minor_units(closing),
        "posting_net_change": format_minor_units(posting_change),
        "return_net_change": format_minor_units(return_change),
        "consolidated_transfer_contribution": format_minor_units(transfer_change),
        "reconciled": True,
        "accounts": [
            {
                "account_id": account.account_id,
                "return_basis": account_rules[account.account_id].return_basis,
                "opening_balance": format_minor_units(_minor_units(account.opening_balance.value, "/accounts")),
                "closing_balance": format_minor_units(states[account.account_id]),
                "net_change": format_minor_units(
                    states[account.account_id] - _minor_units(account.opening_balance.value, "/accounts")
                ),
            }
            for account in request.accounts
        ],
        "events": event_results,
    }


def _compute_parsed(request: _DeterministicRequest) -> DeterministicResult:
    factor_by_date = {factor.event_date: factor.factor for factor in request.discount_factors}
    exact_contributions: list[Decimal] = []
    cashflow_results: list[dict[str, Any]] = []
    for cashflow in request.cashflows:
        factor = factor_by_date[cashflow.event_date]
        exact = _exact_multiply(cashflow.amount.value, factor, f"/cashflows/{len(exact_contributions)}")
        exact_contributions.append(exact)
        cashflow_results.append(
            {
                "cashflow_id": cashflow.cashflow_id,
                "claim_id": cashflow.claim_id,
                "event_date": cashflow.event_date.isoformat(),
                "amount": cashflow.amount.to_dict(),
                "discount_factor": format_decimal(factor),
                "present_value_exact": format_decimal(exact),
            }
        )
    exact_present_value = _exact_add(*exact_contributions, pointer="/cashflows")
    rounded_present_value = _bounded_money(exact_present_value, "/cashflows")
    payload: dict[str, Any] = {
        "result_format": "finplanbr.deterministic-cashflow-ledger-result.v1",
        "contract_version": request.contract_version,
        "engine_version": ENGINE_VERSION,
        "calculation_id": request.calculation_id,
        "artifact_status": "draft",
        "computational_status": "computed",
        "authority": "none",
        "deployment_eligibility": "not_authorized",
        "warnings": [
            "LOCAL_DRAFT_NOT_FINANCIAL_ADVICE",
            "NO_REGULATORY_OR_POLICY_AUTHORITY",
            "CALLER_SUPPLIED_DISCOUNT_FACTORS_NOT_VERIFIED",
            "NO_TAX_INFLATION_OR_PRODUCT_ENGINE",
        ],
        "valuation": {
            "valuation_date": request.valuation_date.isoformat(),
            "currency": request.base_currency,
            "rounding": {"mode": "half_even", "minor_units": 2, "stage": "final_money_boundary"},
            "present_value": format_money(rounded_present_value),
            "present_value_exact": format_decimal(exact_present_value),
            "cashflows": cashflow_results,
        },
        "ledger": _replay_ledger(request),
    }
    return DeterministicResult._from_canonical_payload(
        canonical_json_bytes(
            payload,
            max_bytes=MAX_DETERMINISTIC_RESULT_BYTES,
            max_nodes=MAX_DETERMINISTIC_RESULT_NODES,
        )
    )


def compute_deterministic(data: JsonObject) -> DeterministicResult:
    """Compute one request only after the exact built-in JSON contract is snapshotted."""

    try:
        return _compute_parsed(_parse_deterministic_request(data))
    except InputValidationError:
        raise
    except (DecimalException, NumericContractError):
        raise _numeric_validation_error(None, "") from None
