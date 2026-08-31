"""Public SDK for the local deterministic Financial Planning SDK Brasil slice."""

from .contracts import (
    deterministic_request_schema,
    deterministic_result_schema,
    reference_acceptance_report_schema,
    validation_report_schema,
)
from .deterministic import (
    DeterministicResult,
    compute_deterministic,
    validate_deterministic_request,
)
from .errors import (
    DETERMINISTIC_REASON_CODES,
    MAX_VALIDATION_ISSUES,
    InputValidationError,
    ValidationIssue,
    ValidationReport,
)
from .jsonio import JsonObject, JsonScalar, JsonValue
from .reference import ReferenceAcceptanceReport, run_reference_acceptance_pack

__all__ = [
    "DeterministicResult",
    "DETERMINISTIC_REASON_CODES",
    "InputValidationError",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "MAX_VALIDATION_ISSUES",
    "ReferenceAcceptanceReport",
    "ValidationIssue",
    "ValidationReport",
    "compute_deterministic",
    "deterministic_request_schema",
    "deterministic_result_schema",
    "reference_acceptance_report_schema",
    "run_reference_acceptance_pack",
    "validate_deterministic_request",
    "validation_report_schema",
]

__version__ = "0.1.0.dev0"
