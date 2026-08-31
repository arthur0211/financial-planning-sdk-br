"""Access to the versioned public JSON Schemas bundled with the SDK."""

from __future__ import annotations

import hashlib
from importlib.resources import files

from ._schema_validation import assert_schema_instance, assert_supported_schema
from .jsonio import JsonContractError, JsonObject, loads_strict, read_limited_bytes

_SCHEMA_IDS = {
    "deterministic-request.schema.json": "urn:finplanbr:schema:deterministic-cashflow-ledger-request:0.1.0-draft.1",
    "deterministic-result.schema.json": "urn:finplanbr:schema:deterministic-cashflow-ledger-result:0.1.0-draft.1",
    "reference-acceptance-report.schema.json": "urn:finplanbr:schema:reference-acceptance-report:2.0.0-draft.3",
    "validation-report.schema.json": "urn:finplanbr:schema:validation-report:2.0.0-draft.2",
}
_SCHEMA_SHA256 = {
    "deterministic-request.schema.json": "46776bfb416d3b18898aca55da4e44bf9ce229209c6180d1f6018ff20ed86ba9",
    "deterministic-result.schema.json": "7264cd620bf32999eb53c17f9779c4fe9c73fd3955818a29577a374edf4dce43",
    "reference-acceptance-report.schema.json": "9019eaa881279123e6b805beb7af907b04d487c7b270693743b7799696a0ed82",
    "validation-report.schema.json": "7bdbbeabdce9636d9428bf028d6d584724c0c2e5524aa5fe15dde2e841ddfb44",
}


def _load(name: str) -> JsonObject:
    resource = files("financial_planning_sdk_br").joinpath(name)
    with resource.open("rb") as stream:
        payload = read_limited_bytes(stream)
    if name in _SCHEMA_SHA256 and hashlib.sha256(payload).hexdigest() != _SCHEMA_SHA256[name]:
        raise JsonContractError("packaged public schema digest mismatch")
    document = loads_strict(payload)
    if not isinstance(document, dict):
        raise JsonContractError("bundled JSON Schema must be one object")
    if name not in _SCHEMA_IDS:
        raise JsonContractError("unknown packaged public schema")
    assert_supported_schema(document, expected_id=_SCHEMA_IDS[name])
    return document


def _assert_public_schema(name: str, instance: object, *, fragment: str | None = None) -> None:
    schema = _load(name)
    assert_schema_instance(schema, instance, fragment=fragment)


def deterministic_request_schema() -> JsonObject:
    """Return an isolated copy of the supported deterministic request schema."""

    return _load("deterministic-request.schema.json")


def deterministic_result_schema() -> JsonObject:
    """Return an isolated copy of the supported deterministic result schema."""

    return _load("deterministic-result.schema.json")


def validation_report_schema() -> JsonObject:
    """Return an isolated copy of the public validation report schema."""

    return _load("validation-report.schema.json")


def reference_acceptance_report_schema() -> JsonObject:
    """Return an isolated copy of the reference acceptance report schema."""

    return _load("reference-acceptance-report.schema.json")
