"""Bundled, synthetic reference-acceptance runner for the local draft slice.

The bundled pack is repository-local and untrusted.  It is useful for checking
that one installed SDK/CLI build reproduces fixed candidate expectations, but
it is not an independent mathematical reference, approval, or release gate.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Literal, cast

from ._value_object import _opaque_state, _OpaqueValueObject, _register_opaque_state
from .contracts import _assert_public_schema
from .deterministic import (
    CONTRACT_VERSION,
    ENGINE_VERSION,
    compute_deterministic,
    validate_deterministic_request,
)
from .errors import InputValidationError
from .jsonio import (
    MAX_INPUT_BYTES,
    JsonContractError,
    canonical_json_bytes,
    loads_strict,
    read_limited_bytes,
)

PACK_ID = "deterministic_cashflow_ledger_reference_v2"
PACK_VERSION = "2.0.0-draft.1"
PACK_RESOURCE = "reference-acceptance-pack.v2.json"
REPORT_FORMAT = "finplanbr.reference-acceptance-report.v2"
PACK_PROVENANCE = "repository_local_untrusted"
REFERENCE_INDEPENDENCE = "not_claimed"
ACCEPTANCE_SCOPE = "bundled_synthetic_deterministic_cases_only"
MAX_REFERENCE_REPORT_BYTES = 65_536

ReferenceStatus = Literal[
    "local_technical_acceptance_passed",
    "local_technical_acceptance_failed",
    "local_technical_acceptance_invalid_pack",
]
_REFERENCE_STATUSES: tuple[ReferenceStatus, ...] = (
    "local_technical_acceptance_passed",
    "local_technical_acceptance_failed",
    "local_technical_acceptance_invalid_pack",
)
_MAX_ASSERTIONS_PER_CASE = 16
_MAX_POINTER_INDEX_DIGITS = 10

_EXPECTED_PACK_SHA256 = "2ffed5c0a763cec1f2b8aae44f457af59b5827407fa353c47ecf01d9029e71cd"


@dataclass(frozen=True, slots=True)
class _ExpectedCase:
    operation: str
    derivation_id: str
    request_sha256: str
    expected_output_sha256: str
    assertions_sha256: str


_EXPECTED_CASES = {
    "pv_final_rounding_half_even": _ExpectedCase(
        operation="compute",
        derivation_id="pv_sum_and_half_even_manual_derivation_v1",
        request_sha256="6f50e78ccecb7a250570f391b21fd6d6d273996508e64637b21b8f6ed4c19956",
        expected_output_sha256="a9ebee05b11992b63dcfd9d02001dba4ac4c620a3eddbee0fb8e835324d73972",
        assertions_sha256="efff688dc7e79e5a30a654640e3ecb45cadfa4af72d9d52216ac06528f411393",
    ),
    "ledger_transfer_and_return": _ExpectedCase(
        operation="compute",
        derivation_id="cent_ledger_replay_manual_derivation_v1",
        request_sha256="cb736af1fbf0325119343da7bd099f0f2e9914be3cb2894097dff27d1a2ee749",
        expected_output_sha256="9623331aae1738c45ba0e2ae0e0233693126c7d483fcd06850e72d5a349a2ec2",
        assertions_sha256="4ad4fa9dd8d7b4fffc9b434f3932f730765609b2a7451785b8e3dd048bd9ce45",
    ),
    "total_return_double_count_rejection": _ExpectedCase(
        operation="validate",
        derivation_id="total_return_exclusivity_contract_derivation_v1",
        request_sha256="6f56e6a0495f5e8202ad171d565aeeeda3cc15a3c0440853a79ec442050be41e",
        expected_output_sha256="8ea8fc92906c8598eb31bcd5a46afec1b4bd81af8f2c7eb55a68f3129eb7ae70",
        assertions_sha256="b30dd8e05788f78eb8b167513900afbf6bd3324d090e19fe0f29b7cac7faace4",
    ),
}
_EXPECTED_CASE_ROSTER = tuple(_EXPECTED_CASES)
_EXPECTED_ROSTER_SHA256 = "b9ffe0d563482d2620355e2f51432889f451fbfdc4018824b65fca90a78ab965"
_EXPECTED_MANIFEST_SHA256 = "0e2ffcfde1d2ce7086b22504e26dfd0189f4e9a7339e93cdbfc1dab2b057fe73"
_PACK_KEYS = {
    "pack_format",
    "pack_id",
    "pack_version",
    "artifact_status",
    "provenance",
    "reference_independence",
    "authority",
    "deployment_eligibility",
    "contract_version",
    "engine_version",
    "case_roster",
    "cases",
}
_CASE_KEYS = {
    "case_id",
    "operation",
    "derivation_id",
    "request",
    "expected_output_sha256",
    "expected_output",
    "assertions",
}
_REQUEST_KEYS = {
    "contract_version",
    "calculation_id",
    "valuation_date",
    "base_currency",
    "use_context",
    "discount_factors",
    "cashflows",
    "accounts",
    "events",
}
_ASSERTION_KEYS = {"assertion_id", "rule_id", "json_pointer", "expected"}
_TOKEN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LIMITATIONS = (
    "BUNDLED_EXPECTATIONS_ARE_REPOSITORY_LOCAL_AND_UNTRUSTED",
    "REFERENCE_INDEPENDENCE_NOT_CLAIMED",
    "SYNTHETIC_CASES_ONLY",
    "NO_REGULATORY_POLICY_OR_RELEASE_AUTHORITY",
)

_PACK_DIAGNOSTIC_POLICY = {
    "REFERENCE_PACK_RESOURCE_MISSING": ("resource", "reinstall_distribution"),
    "REFERENCE_PACK_RESOURCE_UNREADABLE": ("resource", "reinstall_distribution"),
    "REFERENCE_PACK_JSON_INVALID": ("document", "reinstall_distribution"),
    "REFERENCE_PACK_DEPTH_BUDGET": ("document", "reinstall_distribution"),
    "REFERENCE_PACK_INPUT_LIMIT": ("document", "reinstall_distribution"),
    "REFERENCE_PACK_DIGEST_MISMATCH": ("pack_integrity", "reinstall_distribution"),
    "REFERENCE_PACK_VERSION_MISMATCH": ("compatibility", "verify_installed_versions"),
    "REFERENCE_PACK_CONSTANT_MISMATCH": ("pack_contract", "inspect_bundled_pack_drift"),
    "REFERENCE_PACK_STRUCTURE_INVALID": ("pack_contract", "inspect_bundled_pack_drift"),
    "REFERENCE_PACK_ROSTER_MISMATCH": ("roster", "inspect_bundled_pack_drift"),
    "REFERENCE_PACK_ROUTE_MISMATCH": ("case_route", "inspect_bundled_pack_drift"),
    "REFERENCE_PACK_DERIVATION_MISMATCH": ("case_derivation", "inspect_bundled_pack_drift"),
    "REFERENCE_PACK_REQUEST_INVALID": ("case_request", "inspect_bundled_pack_drift"),
    "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID": ("expected_output", "inspect_bundled_pack_drift"),
    "REFERENCE_CASE_FAILED": ("case_execution", "inspect_case_output_mismatch"),
}


@dataclass(frozen=True, slots=True)
class _PackDiagnostic:
    code: str
    location: str

    def __post_init__(self) -> None:
        if self.code not in _PACK_DIAGNOSTIC_POLICY:
            raise ValueError("unknown reference-pack diagnostic code")
        if self.location != PACK_RESOURCE and self.location != "" and not self.location.startswith("/"):
            raise ValueError("reference-pack diagnostic location must be the resource or a JSON Pointer")
        if len(self.location) > 256 or "\n" in self.location or "\r" in self.location:
            raise ValueError("reference-pack diagnostic location is outside the closed budget")

    def to_dict(self) -> dict[str, str]:
        scope, remediation_id = _PACK_DIAGNOSTIC_POLICY[self.code]
        return {
            "code": self.code,
            "location": self.location,
            "scope": scope,
            "remediation_id": remediation_id,
        }


class _PackConfigurationError(ValueError):
    """Internal fail-closed signal for a malformed or drifted bundled pack."""

    def __init__(self, code: str, location: str) -> None:
        self.diagnostic = _PackDiagnostic(code=code, location=location)
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _ValidatedCase:
    case_id: str
    operation: str
    derivation_id: str
    request_payload: bytes
    expected_output_payload: bytes
    expected_output_sha256: str
    assertions_payload: bytes


class ReferenceAcceptanceReport(_OpaqueValueObject):
    """Immutable canonical report returned by the bundled acceptance runner."""

    __slots__ = ()

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> ReferenceAcceptanceReport:
        raise TypeError("reference reports can only be created by the acceptance runner")

    @classmethod
    def _from_canonical_payload(
        cls,
        payload: bytes,
        status: ReferenceStatus,
    ) -> ReferenceAcceptanceReport:
        if cls is not ReferenceAcceptanceReport:
            raise TypeError("ReferenceAcceptanceReport is an exact sealed public type")
        if type(payload) is not bytes:
            raise TypeError("reference report payload must be immutable bytes")
        if not payload or len(payload) + 1 > MAX_REFERENCE_REPORT_BYTES:
            raise ValueError("reference report is outside the canonical output budget")
        if type(status) is not str or status not in _REFERENCE_STATUSES:
            raise ValueError("reference report status is outside the closed vocabulary")
        try:
            document = loads_strict(payload)
            canonical_payload = canonical_json_bytes(document)
        except JsonContractError as exc:
            raise ValueError("reference report payload is not canonical strict JSON") from exc
        if type(document) is not dict or canonical_payload != payload:
            raise ValueError("reference report payload is not one canonical JSON object")
        if document.get("report_format") != REPORT_FORMAT or document.get("status") != status:
            raise ValueError("reference report payload and cached status are inconsistent")
        _assert_public_schema("reference-acceptance-report.schema.json", document)
        instance = object.__new__(cls)
        _register_opaque_state(
            instance,
            (payload, status),
            exact_type=ReferenceAcceptanceReport,
        )
        return instance

    def _validated_pair(self) -> tuple[bytes, ReferenceStatus]:
        state = _opaque_state(self, exact_type=ReferenceAcceptanceReport)
        if type(state) is not tuple or len(state) != 2:
            raise ValueError("reference report state is outside the closed arity")
        payload, status = state
        if type(payload) is not bytes:
            raise ValueError("reference report state payload is not immutable bytes")
        if type(status) is not str or status not in _REFERENCE_STATUSES:
            raise ValueError("reference report state status is outside the closed vocabulary")
        if not payload or len(payload) + 1 > MAX_REFERENCE_REPORT_BYTES:
            raise ValueError("reference report state is outside the canonical output budget")
        try:
            document = loads_strict(payload)
            canonical_payload = canonical_json_bytes(document)
        except JsonContractError as exc:
            raise ValueError("reference report state is not canonical strict JSON") from exc
        if type(document) is not dict or canonical_payload != payload:
            raise ValueError("reference report state is not one canonical JSON object")
        if document.get("report_format") != REPORT_FORMAT or document.get("status") != status:
            raise ValueError("reference report state and cached status are inconsistent")
        _assert_public_schema("reference-acceptance-report.schema.json", document)
        return payload, cast(ReferenceStatus, status)

    def _validated_sequence(self) -> tuple[object, ...]:
        return ReferenceAcceptanceReport._validated_pair(self)

    @property
    def _canonical_payload(self) -> bytes:
        return ReferenceAcceptanceReport._validated_pair(self)[0]

    @property
    def _status(self) -> ReferenceStatus:
        return ReferenceAcceptanceReport._validated_pair(self)[1]

    @property
    def status(self) -> ReferenceStatus:
        return ReferenceAcceptanceReport._validated_pair(self)[1]

    def to_dict(self) -> dict[str, Any]:
        payload, _status = ReferenceAcceptanceReport._validated_pair(self)
        return cast(dict[str, Any], loads_strict(payload))

    def to_json_bytes(self) -> bytes:
        return ReferenceAcceptanceReport._validated_pair(self)[0]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _object(
    value: Any,
    *,
    location: str,
    keys: set[str] | None = None,
    failure_code: str = "REFERENCE_PACK_STRUCTURE_INVALID",
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _PackConfigurationError(failure_code, location)
    document = cast(dict[str, Any], value)
    if keys is not None and set(document) != keys:
        raise _PackConfigurationError(failure_code, location)
    return document


def _string(
    value: Any,
    *,
    location: str,
    token: bool = False,
    failure_code: str = "REFERENCE_PACK_STRUCTURE_INVALID",
) -> str:
    if not isinstance(value, str) or not value:
        raise _PackConfigurationError(failure_code, location)
    if token and not _TOKEN.fullmatch(value):
        raise _PackConfigurationError(failure_code, location)
    return value


def _same_scalar(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right


def _scalar(
    value: Any,
    *,
    location: str,
    failure_code: str = "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
) -> str | int | bool | None:
    if value is None or type(value) in {str, bool}:
        return cast(str | int | bool | None, value)
    if type(value) is int and -9_999_999_999 <= value <= 9_999_999_999:
        return value
    raise _PackConfigurationError(failure_code, location)


def _pointer_get(document: Any, pointer: str, *, diagnostic_location: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise _PackConfigurationError("REFERENCE_PACK_EXPECTED_OUTPUT_INVALID", diagnostic_location)
    current = document
    for raw_token in pointer[1:].split("/"):
        if re.search(r"~(?:[^01]|$)", raw_token):
            raise _PackConfigurationError("REFERENCE_PACK_EXPECTED_OUTPUT_INVALID", diagnostic_location)
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise _PackConfigurationError("REFERENCE_PACK_EXPECTED_OUTPUT_INVALID", diagnostic_location)
            current = current[token]
        elif isinstance(current, list):
            if not token.isascii() or not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                raise _PackConfigurationError("REFERENCE_PACK_EXPECTED_OUTPUT_INVALID", diagnostic_location)
            if len(token) > _MAX_POINTER_INDEX_DIGITS:
                raise _PackConfigurationError("REFERENCE_PACK_EXPECTED_OUTPUT_INVALID", diagnostic_location)
            index = int(token)
            if index >= len(current):
                raise _PackConfigurationError("REFERENCE_PACK_EXPECTED_OUTPUT_INVALID", diagnostic_location)
            current = current[index]
        else:
            raise _PackConfigurationError("REFERENCE_PACK_EXPECTED_OUTPUT_INVALID", diagnostic_location)
    return current


def _validate_pack(document: dict[str, Any]) -> tuple[_ValidatedCase, ...]:
    if set(document) != _PACK_KEYS:
        raise _PackConfigurationError("REFERENCE_PACK_STRUCTURE_INVALID", "")
    version_constants = {
        "pack_format": "finplanbr.reference-acceptance-pack.v2",
        "pack_version": PACK_VERSION,
        "contract_version": CONTRACT_VERSION,
        "engine_version": ENGINE_VERSION,
    }
    fixed_constants = {
        "pack_id": PACK_ID,
        "artifact_status": "draft",
        "provenance": PACK_PROVENANCE,
        "reference_independence": REFERENCE_INDEPENDENCE,
        "authority": "none",
        "deployment_eligibility": "not_authorized",
    }
    for name, expected_constant in version_constants.items():
        if document.get(name) != expected_constant:
            raise _PackConfigurationError("REFERENCE_PACK_VERSION_MISMATCH", f"/{name}")
    for name, expected_constant in fixed_constants.items():
        if document.get(name) != expected_constant:
            raise _PackConfigurationError("REFERENCE_PACK_CONSTANT_MISMATCH", f"/{name}")

    raw_roster = document.get("case_roster")
    if not isinstance(raw_roster, list):
        raise _PackConfigurationError("REFERENCE_PACK_ROSTER_MISMATCH", "/case_roster")
    roster = tuple(
        _string(
            item,
            location=f"/case_roster/{index}",
            token=True,
            failure_code="REFERENCE_PACK_ROSTER_MISMATCH",
        )
        for index, item in enumerate(raw_roster)
    )
    if roster != _EXPECTED_CASE_ROSTER or _sha256(canonical_json_bytes(raw_roster)) != _EXPECTED_ROSTER_SHA256:
        raise _PackConfigurationError("REFERENCE_PACK_ROSTER_MISMATCH", "/case_roster")

    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list):
        raise _PackConfigurationError("REFERENCE_PACK_STRUCTURE_INVALID", "/cases")
    cases = tuple(
        _object(item, location=f"/cases/{index}", keys=_CASE_KEYS) for index, item in enumerate(raw_cases)
    )
    if tuple(case.get("case_id") for case in cases) != roster:
        raise _PackConfigurationError("REFERENCE_PACK_ROSTER_MISMATCH", "/cases")

    validated_cases: list[_ValidatedCase] = []
    manifest_cases: list[dict[str, str]] = []
    for case_index, case in enumerate(cases):
        case_location = f"/cases/{case_index}"
        case_id = _string(
            case.get("case_id"),
            location=f"{case_location}/case_id",
            token=True,
            failure_code="REFERENCE_PACK_ROSTER_MISMATCH",
        )
        operation = _string(
            case.get("operation"),
            location=f"{case_location}/operation",
            token=True,
            failure_code="REFERENCE_PACK_ROUTE_MISMATCH",
        )
        derivation_id = _string(
            case.get("derivation_id"),
            location=f"{case_location}/derivation_id",
            token=True,
            failure_code="REFERENCE_PACK_DERIVATION_MISMATCH",
        )
        expected_case = _EXPECTED_CASES[case_id]
        if operation != expected_case.operation:
            raise _PackConfigurationError("REFERENCE_PACK_ROUTE_MISMATCH", f"{case_location}/operation")
        if derivation_id != expected_case.derivation_id:
            raise _PackConfigurationError(
                "REFERENCE_PACK_DERIVATION_MISMATCH",
                f"{case_location}/derivation_id",
            )
        request = _object(
            case.get("request"),
            location=f"{case_location}/request",
            keys=_REQUEST_KEYS,
            failure_code="REFERENCE_PACK_REQUEST_INVALID",
        )
        use_context = _object(
            request.get("use_context"),
            location=f"{case_location}/request/use_context",
            failure_code="REFERENCE_PACK_REQUEST_INVALID",
        )
        if use_context != {
            "purpose": "software_testing",
            "client_specific": False,
            "recommendation_enabled": False,
            "execution_enabled": False,
        }:
            raise _PackConfigurationError(
                "REFERENCE_PACK_REQUEST_INVALID",
                f"{case_location}/request/use_context",
            )
        request_payload = canonical_json_bytes(request)
        request_sha256 = _sha256(request_payload)
        if request_sha256 != expected_case.request_sha256:
            raise _PackConfigurationError(
                "REFERENCE_PACK_REQUEST_INVALID",
                f"{case_location}/request",
            )

        expected_output = _object(
            case.get("expected_output"),
            location=f"{case_location}/expected_output",
            failure_code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
        )
        expected_output_sha256 = _string(
            case.get("expected_output_sha256"),
            location=f"{case_location}/expected_output_sha256",
            failure_code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
        )
        if not _SHA256.fullmatch(expected_output_sha256):
            raise _PackConfigurationError(
                "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
                f"{case_location}/expected_output_sha256",
            )
        expected_output_payload = canonical_json_bytes(expected_output)
        observed_expected_sha256 = _sha256(expected_output_payload)
        if (
            expected_output_sha256 != observed_expected_sha256
            or expected_output_sha256 != expected_case.expected_output_sha256
        ):
            raise _PackConfigurationError(
                "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
                f"{case_location}/expected_output",
            )
        if (
            expected_output.get("authority") != "none"
            or expected_output.get("deployment_eligibility") != "not_authorized"
        ):
            raise _PackConfigurationError(
                "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
                f"{case_location}/expected_output",
            )
        if operation == "compute":
            if (
                expected_output.get("result_format") != "finplanbr.deterministic-cashflow-ledger-result.v1"
                or expected_output.get("artifact_status") != "draft"
                or expected_output.get("computational_status") != "computed"
            ):
                raise _PackConfigurationError(
                    "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
                    f"{case_location}/expected_output",
                )
        elif operation == "validate":
            if expected_output.get("report_format") != "finplanbr.validation-report.v2":
                raise _PackConfigurationError(
                    "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
                    f"{case_location}/expected_output",
                )
        else:  # guarded by the fixed route tuple, retained as a local invariant
            raise _PackConfigurationError("REFERENCE_PACK_ROUTE_MISMATCH", f"{case_location}/operation")

        raw_assertions = case.get("assertions")
        if (
            not isinstance(raw_assertions, list)
            or not raw_assertions
            or len(raw_assertions) > _MAX_ASSERTIONS_PER_CASE
        ):
            raise _PackConfigurationError(
                "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
                f"{case_location}/assertions",
            )
        assertion_ids: set[str] = set()
        for assertion_index, raw_assertion in enumerate(raw_assertions):
            assertion_location = f"{case_location}/assertions/{assertion_index}"
            assertion = _object(
                raw_assertion,
                location=assertion_location,
                keys=_ASSERTION_KEYS,
                failure_code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
            )
            assertion_id = _string(
                assertion.get("assertion_id"),
                location=f"{assertion_location}/assertion_id",
                token=True,
                failure_code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
            )
            _string(
                assertion.get("rule_id"),
                location=f"{assertion_location}/rule_id",
                token=True,
                failure_code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
            )
            pointer = _string(
                assertion.get("json_pointer"),
                location=f"{assertion_location}/json_pointer",
                failure_code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
            )
            expected_scalar = _scalar(
                assertion.get("expected"),
                location=f"{assertion_location}/expected",
            )
            if assertion_id in assertion_ids:
                raise _PackConfigurationError(
                    "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
                    f"{assertion_location}/assertion_id",
                )
            assertion_ids.add(assertion_id)
            fixed_value = _scalar(
                _pointer_get(
                    expected_output,
                    pointer,
                    diagnostic_location=f"{assertion_location}/json_pointer",
                ),
                location=f"{assertion_location}/expected",
            )
            if not _same_scalar(expected_scalar, fixed_value):
                raise _PackConfigurationError(
                    "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
                    f"{assertion_location}/expected",
                )

        assertions_payload = canonical_json_bytes(raw_assertions)
        assertions_sha256 = _sha256(assertions_payload)
        if assertions_sha256 != expected_case.assertions_sha256:
            raise _PackConfigurationError(
                "REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
                f"{case_location}/assertions",
            )
        manifest_cases.append(
            {
                "case_id": case_id,
                "operation": operation,
                "derivation_id": derivation_id,
                "request_sha256": request_sha256,
                "expected_output_sha256": expected_output_sha256,
                "assertions_sha256": assertions_sha256,
            }
        )
        validated_cases.append(
            _ValidatedCase(
                case_id=case_id,
                operation=operation,
                derivation_id=derivation_id,
                request_payload=request_payload,
                expected_output_payload=expected_output_payload,
                expected_output_sha256=expected_output_sha256,
                assertions_payload=assertions_payload,
            )
        )

    manifest = {"case_roster": list(roster), "cases": manifest_cases}
    if _sha256(canonical_json_bytes(manifest)) != _EXPECTED_MANIFEST_SHA256:
        raise _PackConfigurationError("REFERENCE_PACK_STRUCTURE_INVALID", "")
    return tuple(validated_cases)


def _assertion_report(raw_assertion: Any, observed_output: dict[str, Any]) -> dict[str, Any]:
    assertion = _object(
        raw_assertion,
        location="/cases",
        keys=_ASSERTION_KEYS,
        failure_code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
    )
    assertion_id = cast(str, assertion["assertion_id"])
    pointer = cast(str, assertion["json_pointer"])
    expected = _scalar(assertion["expected"], location="/cases")
    try:
        observed_candidate = _scalar(
            _pointer_get(observed_output, pointer, diagnostic_location="/cases"),
            location="/cases",
        )
    except _PackConfigurationError:
        observed_candidate = None
    passed = _same_scalar(expected, observed_candidate)
    observed = observed_candidate if passed else None
    return {
        "assertion_id": assertion_id,
        "rule_id": cast(str, assertion["rule_id"]),
        "json_pointer": pointer,
        "status": "passed" if passed else "failed",
        "expected": expected,
        "observed": observed,
    }


def _case_report(case: _ValidatedCase) -> dict[str, Any]:
    request = _object(
        loads_strict(case.request_payload),
        location="/cases",
        failure_code="REFERENCE_PACK_REQUEST_INVALID",
    )
    _object(
        loads_strict(case.expected_output_payload),
        location="/cases",
        failure_code="REFERENCE_PACK_EXPECTED_OUTPUT_INVALID",
    )
    raw_assertions = loads_strict(case.assertions_payload)
    if not isinstance(raw_assertions, list):  # frozen validation invariant
        raise _PackConfigurationError("REFERENCE_PACK_EXPECTED_OUTPUT_INVALID", "/cases")
    execution_failed = False
    try:
        if case.operation == "compute":
            observed_output = compute_deterministic(request).to_dict()
        else:
            observed_output = validate_deterministic_request(request).to_dict()
    except InputValidationError as exc:
        observed_output = exc.report.to_dict()
    except Exception:  # the report must fail closed without leaking an implementation traceback
        observed_output = {}
        execution_failed = True

    if not isinstance(observed_output, dict):
        observed_output = {}
        execution_failed = True
    try:
        observed_bytes = canonical_json_bytes(observed_output)
    except (JsonContractError, TypeError, ValueError, RecursionError):
        observed_output = {}
        observed_bytes = b"{}"
        execution_failed = True
    observed_sha256 = _sha256(observed_bytes)
    expected_sha256 = case.expected_output_sha256
    exact_match = observed_sha256 == expected_sha256 and observed_bytes == case.expected_output_payload
    assertions = [
        _assertion_report(raw_assertion, observed_output)
        for raw_assertion in raw_assertions
    ]
    passed = exact_match and all(assertion["status"] == "passed" for assertion in assertions)
    diagnostic: str | None
    if passed:
        diagnostic = None
    elif execution_failed:
        diagnostic = "REFERENCE_CASE_EXECUTION_FAILED"
    else:
        diagnostic = "REFERENCE_OUTPUT_MISMATCH"
    return {
        "case_id": case.case_id,
        "operation": case.operation,
        "derivation_id": case.derivation_id,
        "status": "passed" if passed else "failed",
        "diagnostic": diagnostic,
        "expected_output_sha256": expected_sha256,
        "observed_output_sha256": observed_sha256,
        "exact_output_match": exact_match,
        "assertions": assertions,
    }


def _report(
    *,
    pack_sha256: str | None,
    pack_sha256_basis: str,
    status: ReferenceStatus,
    diagnostics: list[_PackDiagnostic],
    cases: list[dict[str, Any]],
) -> ReferenceAcceptanceReport:
    passed_count = sum(case.get("status") == "passed" for case in cases)
    payload: dict[str, Any] = {
        "report_format": REPORT_FORMAT,
        "pack_id": PACK_ID,
        "pack_version": PACK_VERSION,
        "artifact_status": "draft",
        "status": status,
        "scope": ACCEPTANCE_SCOPE,
        "provenance": PACK_PROVENANCE,
        "reference_independence": REFERENCE_INDEPENDENCE,
        "pack_sha256": pack_sha256,
        "pack_sha256_basis": pack_sha256_basis,
        "contract_version": CONTRACT_VERSION,
        "engine_version": ENGINE_VERSION,
        "case_count": len(cases),
        "passed_count": passed_count,
        "failed_count": len(cases) - passed_count,
        "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics],
        "cases": cases,
        "authority": "none",
        "deployment_eligibility": "not_authorized",
        "release_authorized": False,
        "limitations": list(_LIMITATIONS),
    }
    return ReferenceAcceptanceReport._from_canonical_payload(canonical_json_bytes(payload), status)


def _evaluate_reference_acceptance_pack_bytes(payload: bytes) -> ReferenceAcceptanceReport:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_INPUT_BYTES:
        return _report(
            pack_sha256=None,
            pack_sha256_basis="not_available",
            status="local_technical_acceptance_invalid_pack",
            diagnostics=[_PackDiagnostic(code="REFERENCE_PACK_INPUT_LIMIT", location="")],
            cases=[],
        )
    pack_sha256 = _sha256(payload)
    pack_sha256_basis = "raw_input"
    try:
        document = _object(loads_strict(payload), location="")
        pack_sha256 = _sha256(canonical_json_bytes(document))
        pack_sha256_basis = "fpbr_c14n_1"
        cases = _validate_pack(document)
        if pack_sha256 != _EXPECTED_PACK_SHA256:
            raise _PackConfigurationError("REFERENCE_PACK_DIGEST_MISMATCH", "")
    except JsonContractError as exc:
        code = "REFERENCE_PACK_DEPTH_BUDGET" if exc.reason == "depth_budget" else "REFERENCE_PACK_JSON_INVALID"
        return _report(
            pack_sha256=pack_sha256,
            pack_sha256_basis=pack_sha256_basis,
            status="local_technical_acceptance_invalid_pack",
            diagnostics=[_PackDiagnostic(code=code, location="")],
            cases=[],
        )
    except _PackConfigurationError as exc:
        return _report(
            pack_sha256=pack_sha256,
            pack_sha256_basis=pack_sha256_basis,
            status="local_technical_acceptance_invalid_pack",
            diagnostics=[exc.diagnostic],
            cases=[],
        )

    case_reports = [_case_report(case) for case in cases]
    passed = all(case["status"] == "passed" for case in case_reports)
    return _report(
        pack_sha256=pack_sha256,
        pack_sha256_basis=pack_sha256_basis,
        status="local_technical_acceptance_passed" if passed else "local_technical_acceptance_failed",
        diagnostics=[]
        if passed
        else [_PackDiagnostic(code="REFERENCE_CASE_FAILED", location="/cases")],
        cases=case_reports,
    )


def run_reference_acceptance_pack() -> ReferenceAcceptanceReport:
    """Execute the immutable bundled draft pack through the public SDK paths.

    A passing report establishes only exact reproduction of the bundled
    repository-local expectations for this installed build.
    """

    try:
        resource = files("financial_planning_sdk_br").joinpath(PACK_RESOURCE)
        with resource.open("rb") as stream:
            payload = read_limited_bytes(stream)
    except FileNotFoundError:
        return _report(
            pack_sha256=None,
            pack_sha256_basis="not_available",
            status="local_technical_acceptance_invalid_pack",
            diagnostics=[
                _PackDiagnostic(code="REFERENCE_PACK_RESOURCE_MISSING", location=PACK_RESOURCE)
            ],
            cases=[],
        )
    except (OSError, AttributeError, TypeError):
        return _report(
            pack_sha256=None,
            pack_sha256_basis="not_available",
            status="local_technical_acceptance_invalid_pack",
            diagnostics=[
                _PackDiagnostic(code="REFERENCE_PACK_RESOURCE_UNREADABLE", location=PACK_RESOURCE)
            ],
            cases=[],
        )
    except Exception:  # resource backend failures are classified without exposing values
        return _report(
            pack_sha256=None,
            pack_sha256_basis="not_available",
            status="local_technical_acceptance_invalid_pack",
            diagnostics=[
                _PackDiagnostic(code="REFERENCE_PACK_RESOURCE_UNREADABLE", location=PACK_RESOURCE)
            ],
            cases=[],
        )
    return _evaluate_reference_acceptance_pack_bytes(payload)
