"""Stable, value-redacted validation diagnostics."""

from __future__ import annotations

import re
from typing import cast

from ._value_object import _opaque_state, _OpaqueValueObject, _register_opaque_state
from .contracts import _assert_public_schema
from .jsonio import JsonContractError, JsonObject, canonical_json_bytes, loads_strict

MAX_VALIDATION_ISSUES = 128
MAX_VALIDATION_TOTAL_ISSUES = 1_000_000
MAX_VALIDATION_OMITTED_ISSUES = MAX_VALIDATION_TOTAL_ISSUES - MAX_VALIDATION_ISSUES
MAX_VALIDATION_REPORT_BYTES = 131_072
MAX_VALIDATION_REPORT_NODES = 1_024
MAX_VALIDATION_POINTER_CHARACTERS = 128
MAX_VALIDATION_MESSAGE_CHARACTERS = 128

DETERMINISTIC_REASON_CODES = frozenset(
    {
        "DCL_ACCOUNT_NOT_FOUND",
        "DCL_ARRAY_BUDGET",
        "DCL_CONTRACT_VERSION",
        "DCL_CURRENCY_MISMATCH",
        "DCL_DATE_BEFORE_VALUATION",
        "DCL_DISCOUNT_FACTOR_MISSING",
        "DCL_DISTRIBUTION_SIGN",
        "DCL_DUPLICATE_CLAIM",
        "DCL_DUPLICATE_DATE",
        "DCL_DUPLICATE_ID",
        "DCL_EVENT_ORDER_DUPLICATE",
        "DCL_EVENT_TYPE",
        "DCL_INVALID_DATE",
        "DCL_INVALID_DECIMAL",
        "DCL_INVALID_DISCOUNT_FACTOR",
        "DCL_INVALID_IDENTIFIER",
        "DCL_INVALID_MONEY",
        "DCL_JSON_INPUT",
        "DCL_LEDGER_RECONCILIATION_FAILED",
        "DCL_NEGATIVE_BALANCE",
        "DCL_NONCANONICAL_ORDER",
        "DCL_NUMERIC_INVARIANT_FAILED",
        "DCL_NUMERIC_OVERFLOW",
        "DCL_OUTPUT_WRITE",
        "DCL_POSTING_CATEGORY",
        "DCL_POSTING_SIGN",
        "DCL_REQUIRED_FIELD",
        "DCL_RETURN_BASIS",
        "DCL_RETURN_BASIS_DOUBLE_COUNT",
        "DCL_SEQUENCE",
        "DCL_TRANSFER_ACCOUNTS",
        "DCL_TRANSFER_AMOUNT",
        "DCL_TYPE_MISMATCH",
        "DCL_UNKNOWN_FIELD",
        "DCL_UNSUPPORTED_CURRENCY",
        "DCL_USE_OUT_OF_SCOPE",
    }
)

_INVALID_JSON_POINTER_ESCAPE = re.compile(r"~(?![01])")


def _ascii_contract_text(value: object, *, name: str, maximum: int, allow_empty: bool) -> str:
    if type(value) is not str:
        raise ValueError(f"validation issue {name} must be one exact string")
    text = value
    if (not allow_empty and not text) or len(text) > maximum:
        raise ValueError(f"validation issue {name} is outside its character budget")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in text):
        raise ValueError(f"validation issue {name} must contain printable ASCII only")
    return text


class ValidationIssue(_OpaqueValueObject):
    """One machine-readable validation issue.

    Messages intentionally describe the rule and JSON pointer, never the rejected
    value. This keeps CLI diagnostics useful without echoing user data.
    """

    __slots__ = ()

    def __new__(cls, code: str, pointer: str, message: str) -> ValidationIssue:
        if cls is not ValidationIssue:
            raise TypeError("ValidationIssue is an exact sealed public type")
        if type(code) is not str or code not in DETERMINISTIC_REASON_CODES:
            raise ValueError("unknown deterministic reason code")
        checked_pointer = _ascii_contract_text(
            pointer,
            name="pointer",
            maximum=MAX_VALIDATION_POINTER_CHARACTERS,
            allow_empty=True,
        )
        if checked_pointer and not checked_pointer.startswith("/"):
            raise ValueError("validation issue pointer must be empty or an absolute JSON Pointer")
        if _INVALID_JSON_POINTER_ESCAPE.search(checked_pointer) is not None:
            raise ValueError("validation issue pointer contains an invalid JSON Pointer escape")
        checked_message = _ascii_contract_text(
            message,
            name="message",
            maximum=MAX_VALIDATION_MESSAGE_CHARACTERS,
            allow_empty=False,
        )
        document = cast(
            JsonObject,
            {"code": code, "pointer": checked_pointer, "message": checked_message},
        )
        payload = canonical_json_bytes(
            document,
            max_bytes=MAX_VALIDATION_REPORT_BYTES,
            max_nodes=MAX_VALIDATION_REPORT_NODES,
        )
        _assert_public_schema("validation-report.schema.json", document, fragment="#/$defs/issue")
        instance = object.__new__(cls)
        _register_opaque_state(instance, payload, exact_type=ValidationIssue)
        return instance

    def _document(self) -> JsonObject:
        state = _opaque_state(self, exact_type=ValidationIssue)
        if type(state) is not bytes:
            raise ValueError("validation issue state is not immutable canonical bytes")
        payload = state
        try:
            document = loads_strict(
                payload,
                max_bytes=MAX_VALIDATION_REPORT_BYTES,
                max_nodes=MAX_VALIDATION_REPORT_NODES,
            )
            canonical = canonical_json_bytes(
                document,
                max_bytes=MAX_VALIDATION_REPORT_BYTES,
                max_nodes=MAX_VALIDATION_REPORT_NODES,
            )
        except JsonContractError as exc:
            raise ValueError("validation issue state is outside the canonical JSON contract") from exc
        if type(document) is not dict or canonical != payload:
            raise ValueError("validation issue state is not one canonical JSON object")
        _assert_public_schema("validation-report.schema.json", document, fragment="#/$defs/issue")
        return document

    def _validated_sequence(self) -> tuple[object, ...]:
        document = ValidationIssue._document(self)
        return (document["code"], document["pointer"], document["message"])

    @property
    def code(self) -> str:
        return cast(str, ValidationIssue._document(self)["code"])

    @property
    def pointer(self) -> str:
        return cast(str, ValidationIssue._document(self)["pointer"])

    @property
    def message(self) -> str:
        return cast(str, ValidationIssue._document(self)["message"])

    def to_dict(self) -> JsonObject:
        return ValidationIssue._document(self)


def _validation_report_document(
    *,
    valid: bool,
    issues: tuple[ValidationIssue, ...],
    omitted_issue_count: int,
    contract_version: str,
    authority: str,
) -> JsonObject:
    truncation: JsonObject = (
        {"status": "truncated", "omitted_issue_count": omitted_issue_count}
        if omitted_issue_count
        else {"status": "complete"}
    )
    return cast(
        JsonObject,
        {
            "report_format": "finplanbr.validation-report.v2",
            "contract_version": contract_version,
            "valid": valid,
            "issues": [issue.to_dict() for issue in issues],
            "truncation": truncation,
            "authority": authority,
            "deployment_eligibility": "not_authorized",
        },
    )


class ValidationReport(_OpaqueValueObject):
    """Opaque immutable validation value whose wire has no redundant count."""

    __slots__ = ()

    def __new__(
        cls,
        valid: bool,
        issues: tuple[ValidationIssue, ...],
        omitted_issue_count: int = 0,
        contract_version: str = "0.1.0-draft.1",
        authority: str = "none",
    ) -> ValidationReport:
        if cls is not ValidationReport:
            raise TypeError("ValidationReport is an exact sealed public type")
        if type(valid) is not bool:
            raise ValueError("validation report valid flag must be one boolean")
        if type(issues) is not tuple or any(type(issue) is not ValidationIssue for issue in issues):
            raise ValueError("validation report issues must be one exact tuple of ValidationIssue values")
        if len(issues) > MAX_VALIDATION_ISSUES:
            raise ValueError("validation report exceeds the reported-issue budget")
        if (
            type(omitted_issue_count) is not int
            or omitted_issue_count < 0
            or omitted_issue_count > MAX_VALIDATION_OMITTED_ISSUES
        ):
            raise ValueError("validation report omitted issue count is outside the closed total budget")
        if valid and (issues or omitted_issue_count):
            raise ValueError("valid report cannot contain issues")
        if not valid and not issues:
            raise ValueError("invalid report must contain at least one reported issue")
        if omitted_issue_count and len(issues) != MAX_VALIDATION_ISSUES:
            raise ValueError("truncated report must fill the reported-issue budget")
        if type(contract_version) is not str or contract_version != "0.1.0-draft.1":
            raise ValueError("validation report contract version is unsupported")
        if type(authority) is not str or authority != "none":
            raise ValueError("validation report authority must remain none")
        document = _validation_report_document(
            valid=valid,
            issues=issues,
            omitted_issue_count=omitted_issue_count,
            contract_version=contract_version,
            authority=authority,
        )
        try:
            payload = canonical_json_bytes(
                document,
                max_bytes=MAX_VALIDATION_REPORT_BYTES,
                max_nodes=MAX_VALIDATION_REPORT_NODES,
            )
        except JsonContractError as exc:  # constructor must never admit an unserializable value
            raise ValueError("validation report exceeds its closed serialization budget") from exc
        _assert_public_schema("validation-report.schema.json", document)
        instance = object.__new__(cls)
        _register_opaque_state(instance, payload, exact_type=ValidationReport)
        return instance

    def _document(self) -> JsonObject:
        state = _opaque_state(self, exact_type=ValidationReport)
        if type(state) is not bytes:
            raise ValueError("validation report state is not immutable canonical bytes")
        payload = state
        try:
            document = loads_strict(
                payload,
                max_bytes=MAX_VALIDATION_REPORT_BYTES,
                max_nodes=MAX_VALIDATION_REPORT_NODES,
            )
            canonical = canonical_json_bytes(
                document,
                max_bytes=MAX_VALIDATION_REPORT_BYTES,
                max_nodes=MAX_VALIDATION_REPORT_NODES,
            )
        except JsonContractError as exc:
            raise ValueError("validation report state is outside the canonical JSON contract") from exc
        if type(document) is not dict or canonical != payload:
            raise ValueError("validation report state is not one canonical JSON object")
        _assert_public_schema("validation-report.schema.json", document)
        return document

    @staticmethod
    def _issues_from_document(document: JsonObject) -> tuple[ValidationIssue, ...]:
        values = cast(list[JsonObject], document["issues"])
        return tuple(
            ValidationIssue(
                cast(str, value["code"]),
                cast(str, value["pointer"]),
                cast(str, value["message"]),
            )
            for value in values
        )

    @staticmethod
    def _omitted_from_document(document: JsonObject) -> int:
        truncation = cast(JsonObject, document["truncation"])
        return cast(int, truncation.get("omitted_issue_count", 0))

    def _validated_sequence(self) -> tuple[object, ...]:
        document = ValidationReport._document(self)
        return (
            document["valid"],
            ValidationReport._issues_from_document(document),
            ValidationReport._omitted_from_document(document),
            document["contract_version"],
            document["authority"],
        )

    @property
    def valid(self) -> bool:
        return cast(bool, ValidationReport._document(self)["valid"])

    @property
    def issues(self) -> tuple[ValidationIssue, ...]:
        return ValidationReport._issues_from_document(ValidationReport._document(self))

    @property
    def omitted_issue_count(self) -> int:
        return ValidationReport._omitted_from_document(ValidationReport._document(self))

    @property
    def contract_version(self) -> str:
        return cast(str, ValidationReport._document(self)["contract_version"])

    @property
    def authority(self) -> str:
        return cast(str, ValidationReport._document(self)["authority"])

    @property
    def issue_count(self) -> int:
        document = ValidationReport._document(self)
        return len(cast(list[object], document["issues"])) + ValidationReport._omitted_from_document(document)

    @property
    def issues_truncated(self) -> bool:
        return ValidationReport._omitted_from_document(ValidationReport._document(self)) > 0

    def to_dict(self) -> JsonObject:
        return ValidationReport._document(self)

    def to_json_bytes(self) -> bytes:
        document = ValidationReport._document(self)
        return canonical_json_bytes(
            document,
            max_bytes=MAX_VALIDATION_REPORT_BYTES,
            max_nodes=MAX_VALIDATION_REPORT_NODES,
        )


class InputValidationError(ValueError):
    """Raised when a deterministic request violates its closed contract."""

    def __init__(
        self,
        issues: tuple[ValidationIssue, ...] | list[ValidationIssue],
        *,
        total_issue_count: int | None = None,
    ):
        if type(issues) not in {tuple, list}:
            raise ValueError("discovered issues must be one exact tuple or list")
        discovered = tuple(issues)
        total = len(discovered) if total_issue_count is None else total_issue_count
        if any(type(issue) is not ValidationIssue for issue in discovered):
            raise ValueError("discovered issues must contain exact ValidationIssue values")
        if (
            type(total) is not int
            or total < len(discovered)
            or total > MAX_VALIDATION_TOTAL_ISSUES
        ):
            raise ValueError("total issue count is outside the closed report contract")
        ordered = tuple(sorted(discovered[:MAX_VALIDATION_ISSUES]))
        if total > len(ordered) and len(ordered) != MAX_VALIDATION_ISSUES:
            raise ValueError("truncated validation error must supply the complete retained prefix")
        self.issues = ordered
        self.total_issue_count = total
        super().__init__(f"deterministic request rejected with {total} issue(s)")

    @property
    def report(self) -> ValidationReport:
        return ValidationReport(
            valid=False,
            issues=self.issues,
            omitted_issue_count=self.total_issue_count - len(self.issues),
        )
