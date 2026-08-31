"""Validate the implemented SDK against its closed local conformance slice.

This diagnostic is deliberately narrower than the 21-vector mathematical SUT
gate.  It executes the public SDK in a fixed subprocess, checks the seven
vectors implemented by the 0.1 deterministic slice, runs independent seeded
properties, and applies a closed set of source mutations.  A green result is
local technical evidence only: it is not release, regulatory, scientific, or
financial-advice authority.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import random
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path, PurePosixPath
from typing import Any, Literal

if __package__:
    from .bounded_subprocess import (
        BoundedProcessCleanupError,
        BoundedProcessOutputLimit,
        BoundedProcessStartError,
        BoundedProcessTimeout,
        process_tree_claim,
        run_bounded,
    )
else:
    boundary_path = Path(__file__).resolve().with_name("bounded_subprocess.py")
    boundary_spec = importlib.util.spec_from_file_location(
        "_finplanbr_sdk_bounded_subprocess",
        boundary_path,
    )
    if boundary_spec is None or boundary_spec.loader is None:
        raise RuntimeError("bounded subprocess helper could not be loaded")
    boundary_module = importlib.util.module_from_spec(boundary_spec)
    boundary_spec.loader.exec_module(boundary_module)
    BoundedProcessCleanupError = boundary_module.BoundedProcessCleanupError
    BoundedProcessOutputLimit = boundary_module.BoundedProcessOutputLimit
    BoundedProcessStartError = boundary_module.BoundedProcessStartError
    BoundedProcessTimeout = boundary_module.BoundedProcessTimeout
    process_tree_claim = boundary_module.process_tree_claim
    run_bounded = boundary_module.run_bounded

REPORT_FORMAT = "finplanbr.local-sdk-conformance-report.v1"
MANIFEST_FORMAT = "finplanbr.sdk-vector-bridge-manifest.v1"
BATCH_PROTOCOL = "finplanbr.local-sdk-conformance-batch.v1"
RESPONSE_PROTOCOL = "finplanbr.local-sdk-conformance-batch-response.v1"
MATH_SUT_PROTOCOL = "financial-planning-sdk-br.math-sut.v1"
VECTOR_CANONICALIZATION = "sorted-key-json-utf8-excluding-fingerprint"
SDK_VERSION = "0.1.0.dev0"
SDK_CONTRACT_VERSION = "0.1.0-draft.1"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_WORKER_OUTPUT_BYTES = 4 * 1024 * 1024
WORKER_TIMEOUT_SECONDS = 20


class DiagnosticConfigurationError(ValueError):
    pass


class WorkerCrash(RuntimeError):
    pass


class WorkerTimeout(RuntimeError):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DiagnosticConfigurationError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise DiagnosticConfigurationError("non-finite JSON number")


def _decode_json(payload: bytes, label: str) -> Any:
    if len(payload) > MAX_JSON_BYTES:
        raise DiagnosticConfigurationError(f"{label} exceeds the JSON byte budget")
    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiagnosticConfigurationError(f"{label} is not strict UTF-8 JSON") from exc


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    path: Path
    relative_path: str
    payload: bytes
    sha256: str
    identity: tuple[int, int, int, int]

    def recheck(self) -> None:
        current = _read_snapshot(self.path, self.relative_path)
        if current.identity != self.identity or current.payload != self.payload or current.sha256 != self.sha256:
            raise DiagnosticConfigurationError(f"file changed during diagnostic: {self.relative_path}")


def _read_snapshot(path: Path, relative_path: str) -> FileSnapshot:
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise DiagnosticConfigurationError(f"cannot acquire required file: {relative_path}") from exc
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise DiagnosticConfigurationError(f"required path is not one regular non-symlink file: {relative_path}")
    try:
        payload = path.read_bytes()
        after = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise DiagnosticConfigurationError(f"cannot read required file: {relative_path}") from exc
    first_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    second_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if first_identity != second_identity:
        raise DiagnosticConfigurationError(f"required file changed while read: {relative_path}")
    return FileSnapshot(path, relative_path, payload, _sha256(payload), first_identity)


def _repo_file(repository_root: Path, relative_path: str) -> Path:
    logical = PurePosixPath(relative_path)
    if (
        not re.fullmatch(r"[A-Za-z0-9_./-]+", relative_path)
        or logical.is_absolute()
        or not logical.parts
        or any(part in {"", ".", ".."} for part in logical.parts)
    ):
        raise DiagnosticConfigurationError("manifest path is not one canonical repository-relative path")
    root = repository_root.resolve(strict=True)
    candidate = (root / Path(relative_path)).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise DiagnosticConfigurationError("manifest path escapes the repository root") from exc
    return candidate


def _vector_fingerprint(vector: dict[str, Any]) -> str:
    material = {key: value for key, value in vector.items() if key != "fingerprint"}
    return _sha256(_canonical_json(material))


@dataclass(frozen=True, slots=True)
class BridgeVector:
    vector_id: str
    topic: str
    expected_status: str
    expected_output: dict[str, Any]
    vector_input: dict[str, Any]
    snapshot: FileSnapshot


@dataclass(frozen=True, slots=True)
class BridgeBundle:
    manifest_snapshot: FileSnapshot
    corpus_manifest_snapshot: FileSnapshot
    vectors: tuple[BridgeVector, ...]
    out_of_scope_vector_ids: tuple[str, ...]
    all_snapshots: tuple[FileSnapshot, ...]

    def recheck(self) -> None:
        for snapshot in self.all_snapshots:
            snapshot.recheck()


def load_bridge_bundle(repository_root: Path) -> BridgeBundle:
    manifest_path = repository_root / "tests" / "vectors" / "sdk" / "v1" / "manifest.json"
    manifest_snapshot = _read_snapshot(manifest_path, "tests/vectors/sdk/v1/manifest.json")
    manifest = _decode_json(manifest_snapshot.payload, manifest_snapshot.relative_path)
    required = {
        "manifest_format",
        "artifact_status",
        "sdk_distribution",
        "sdk_version",
        "sdk_contract_version",
        "source_corpus",
        "supported_vectors",
        "out_of_scope_vector_ids",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise DiagnosticConfigurationError("SDK bridge manifest does not use the closed field set")
    if manifest.get("manifest_format") != MANIFEST_FORMAT or manifest.get("artifact_status") != "draft":
        raise DiagnosticConfigurationError("SDK bridge manifest format/status is invalid")
    if manifest.get("sdk_distribution") != "finplanbr":
        raise DiagnosticConfigurationError("SDK bridge distribution is not finplanbr")
    if manifest.get("sdk_version") != SDK_VERSION or manifest.get("sdk_contract_version") != SDK_CONTRACT_VERSION:
        raise DiagnosticConfigurationError("SDK bridge version does not match the implemented local slice")

    source = manifest.get("source_corpus")
    source_fields = {"manifest_path", "manifest_sha256", "digest_provenance", "digest_authentication"}
    if not isinstance(source, dict) or set(source) != source_fields:
        raise DiagnosticConfigurationError("source_corpus does not use the closed field set")
    if (
        source.get("digest_provenance") != "repository_local_untrusted"
        or source.get("digest_authentication") != "not_provided"
    ):
        raise DiagnosticConfigurationError("source_corpus must retain the bounded unauthenticated digest claim")
    source_path = source.get("manifest_path")
    source_digest = source.get("manifest_sha256")
    if not isinstance(source_path, str) or not isinstance(source_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", source_digest
    ):
        raise DiagnosticConfigurationError("source_corpus path/digest is invalid")
    corpus_manifest_snapshot = _read_snapshot(_repo_file(repository_root, source_path), source_path)
    if corpus_manifest_snapshot.sha256 != source_digest:
        raise DiagnosticConfigurationError("math corpus manifest drifted from the SDK bridge pin")
    corpus = _decode_json(corpus_manifest_snapshot.payload, source_path)
    if (
        not isinstance(corpus, dict)
        or corpus.get("manifest_format") != "financial-planning-sdk-br.math-vector-manifest.v1"
    ):
        raise DiagnosticConfigurationError("source corpus manifest format is invalid")
    corpus_entries = corpus.get("vectors")
    if not isinstance(corpus_entries, list) or len(corpus_entries) != 21:
        raise DiagnosticConfigurationError("source corpus must contain the closed 21-vector roster")
    corpus_by_id: dict[str, dict[str, Any]] = {}
    for entry in corpus_entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or entry["id"] in corpus_by_id:
            raise DiagnosticConfigurationError("source corpus vector roster is malformed or duplicated")
        corpus_by_id[entry["id"]] = entry

    raw_supported = manifest.get("supported_vectors")
    raw_out = manifest.get("out_of_scope_vector_ids")
    if not isinstance(raw_supported, list) or not isinstance(raw_out, list):
        raise DiagnosticConfigurationError("SDK bridge vector partitions must be arrays")
    if len(raw_supported) != 7 or len(raw_out) != 14:
        raise DiagnosticConfigurationError(
            "SDK bridge must partition the corpus into exactly 7 supported and 14 out-of-scope vectors"
        )
    if (
        raw_out != sorted(raw_out)
        or any(not isinstance(item, str) for item in raw_out)
        or len(set(raw_out)) != len(raw_out)
    ):
        raise DiagnosticConfigurationError("out_of_scope_vector_ids must be unique sorted strings")

    entry_fields = {"id", "path", "topic", "fingerprint", "expected_status", "adapter_route"}
    supported_ids: set[str] = set()
    vectors: list[BridgeVector] = []
    snapshots: list[FileSnapshot] = [manifest_snapshot, corpus_manifest_snapshot]
    for index, entry in enumerate(raw_supported):
        if not isinstance(entry, dict) or set(entry) != entry_fields:
            raise DiagnosticConfigurationError(f"supported vector entry {index} does not use the closed field set")
        vector_id = entry.get("id")
        vector_path = entry.get("path")
        topic = entry.get("topic")
        fingerprint = entry.get("fingerprint")
        expected_status = entry.get("expected_status")
        if (
            not isinstance(vector_id, str)
            or vector_id in supported_ids
            or not isinstance(vector_path, str)
            or not isinstance(topic, str)
            or not isinstance(fingerprint, str)
            or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
            or expected_status not in {"computed", "rejected"}
            or entry.get("adapter_route") != vector_id
        ):
            raise DiagnosticConfigurationError(f"supported vector entry {index} is invalid")
        supported_ids.add(vector_id)
        corpus_entry = corpus_by_id.get(vector_id)
        if not corpus_entry:
            raise DiagnosticConfigurationError(f"supported vector is absent from the math manifest: {vector_id}")
        if (
            corpus_entry.get("path") != Path(vector_path).name
            or corpus_entry.get("fingerprint") != fingerprint
            or corpus_entry.get("expected_status") != expected_status
        ):
            raise DiagnosticConfigurationError(f"bridge/corpus manifest mismatch for {vector_id}")
        vector_snapshot = _read_snapshot(_repo_file(repository_root, vector_path), vector_path)
        vector = _decode_json(vector_snapshot.payload, vector_path)
        if not isinstance(vector, dict):
            raise DiagnosticConfigurationError(f"vector is not an object: {vector_id}")
        block = vector.get("fingerprint")
        observed_fingerprint = _vector_fingerprint(vector)
        if (
            vector.get("id") != vector_id
            or vector.get("topic") != topic
            or vector.get("expected_status") != expected_status
            or not isinstance(block, dict)
            or block.get("algorithm") != "sha256"
            or block.get("canonicalization") != VECTOR_CANONICALIZATION
            or block.get("value") != observed_fingerprint
            or observed_fingerprint != fingerprint
        ):
            raise DiagnosticConfigurationError(f"vector content/fingerprint mismatch for {vector_id}")
        vector_input = vector.get("input")
        expected_output = vector.get("expected_output")
        if not isinstance(vector_input, dict) or not isinstance(expected_output, dict):
            raise DiagnosticConfigurationError(f"vector input/output is not an object: {vector_id}")
        snapshots.append(vector_snapshot)
        vectors.append(
            BridgeVector(
                vector_id=vector_id,
                topic=topic,
                expected_status=expected_status,
                expected_output=expected_output,
                vector_input=vector_input,
                snapshot=vector_snapshot,
            )
        )
    if [vector.vector_id for vector in vectors] != sorted(supported_ids):
        raise DiagnosticConfigurationError("supported vector entries must be sorted by id")
    if set(raw_out) != set(corpus_by_id) - supported_ids or supported_ids & set(raw_out):
        raise DiagnosticConfigurationError("supported/out-of-scope vectors do not form the exact corpus partition")
    return BridgeBundle(
        manifest_snapshot=manifest_snapshot,
        corpus_manifest_snapshot=corpus_manifest_snapshot,
        vectors=tuple(vectors),
        out_of_scope_vector_ids=tuple(raw_out),
        all_snapshots=tuple(snapshots),
    )


def _package_snapshots(repository_root: Path) -> tuple[FileSnapshot, ...]:
    package_root = repository_root / "src" / "financial_planning_sdk_br"
    if not package_root.is_dir() or package_root.is_symlink():
        raise DiagnosticConfigurationError("SDK package source root is unavailable or redirected")
    snapshots: list[FileSnapshot] = []
    for path in sorted(package_root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(repository_root).as_posix()
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_dir():
            if path.is_symlink():
                raise DiagnosticConfigurationError(f"SDK source directory is redirected: {relative}")
            continue
        snapshots.append(_read_snapshot(path, relative))
    if not snapshots or not any(item.relative_path.endswith("/__init__.py") for item in snapshots):
        raise DiagnosticConfigurationError("SDK source snapshot is incomplete")
    return tuple(snapshots)


def _tree_digest(snapshots: tuple[FileSnapshot, ...]) -> str:
    material = bytearray()
    for snapshot in sorted(snapshots, key=lambda item: item.relative_path):
        material.extend(snapshot.relative_path.encode("utf-8"))
        material.extend(b"\0")
        material.extend(snapshot.sha256.encode("ascii"))
        material.extend(b"\n")
    return _sha256(bytes(material))


@dataclass(frozen=True, slots=True)
class DiagnosticCase:
    case_id: str
    family: str
    operation: Literal[
        "vector",
        "compute",
        "validate",
        "reference",
        "compute_hostile_context",
        "compute_pv_hostile_context",
        "compute_parsed_object",
        "compute_replaced_object",
    ]
    payload: dict[str, Any]
    expected: dict[str, Any]
    comparison: Literal["exact", "subset"]

    def worker_payload(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "operation": self.operation, "payload": self.payload}


def _base_request(calculation_id: str) -> dict[str, Any]:
    return {
        "contract_version": SDK_CONTRACT_VERSION,
        "calculation_id": calculation_id,
        "valuation_date": "2026-01-01",
        "base_currency": "BRL",
        "use_context": {
            "purpose": "software_testing",
            "client_specific": False,
            "recommendation_enabled": False,
            "execution_enabled": False,
        },
        "discount_factors": [],
        "cashflows": [],
        "accounts": [],
        "events": [],
    }


def _precision_bound_request(calculation_id: str) -> dict[str, Any]:
    request = _base_request(calculation_id)
    request["discount_factors"] = [
        {"date": "2026-01-02", "factor": "0.000000000000000001"},
        {"date": "2026-01-03", "factor": "99999999999999999999999999999999999999"},
        {"date": "2026-01-04", "factor": "99999999999999999999999999999999999999"},
    ]
    request["cashflows"] = [
        {
            "cashflow_id": f"a_tiny_{index:04d}",
            "claim_id": f"a_tiny_claim_{index:04d}",
            "event_date": "2026-01-02",
            "amount": {"currency": "BRL", "value": "0.01"},
        }
        for index in range(2)
    ] + [
        {
            "cashflow_id": f"b_positive_{index:04d}",
            "claim_id": f"b_positive_claim_{index:04d}",
            "event_date": "2026-01-03",
            "amount": {"currency": "BRL", "value": "999999999999999999999999999999999999.99"},
        }
        for index in range(2047)
    ] + [
        {
            "cashflow_id": f"c_negative_{index:04d}",
            "claim_id": f"c_negative_claim_{index:04d}",
            "event_date": "2026-01-04",
            "amount": {"currency": "BRL", "value": "-999999999999999999999999999999999999.99"},
        }
        for index in range(2047)
    ]
    return request


def _money_from_cents(cents: int) -> dict[str, str]:
    return {"currency": "BRL", "value": _cents_text(cents)}


def _cents_text(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    absolute = abs(cents)
    return f"{sign}{absolute // 100}.{absolute % 100:02d}"


def _fraction_decimal(value: Fraction) -> str:
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    numerator = abs(value.numerator)
    denominator = value.denominator
    twos = fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        raise DiagnosticConfigurationError("property oracle produced a non-terminating decimal")
    places = max(twos, fives)
    scaled = numerator * (2 ** (places - twos)) * (5 ** (places - fives))
    if places == 0:
        return f"{sign}{scaled}"
    digits = str(scaled).rjust(places + 1, "0")
    rendered = f"{sign}{digits[:-places]}.{digits[-places:]}".rstrip("0").rstrip(".")
    return "0" if rendered in {"", "-0"} else rendered


def _round_fraction_to_cents(value: Fraction) -> int:
    sign = -1 if value < 0 else 1
    scaled_numerator = abs(value.numerator) * 100
    quotient, remainder = divmod(scaled_numerator, value.denominator)
    doubled = remainder * 2
    if doubled > value.denominator or (doubled == value.denominator and quotient % 2 == 1):
        quotient += 1
    return sign * quotient


def _vector_cases(bundle: BridgeBundle) -> list[DiagnosticCase]:
    return [
        DiagnosticCase(
            case_id=f"vector::{vector.vector_id}",
            family="math_vector_bridge",
            operation="vector",
            payload={
                "protocol": MATH_SUT_PROTOCOL,
                "id": vector.vector_id,
                "topic": vector.topic,
                "input": vector.vector_input,
            },
            expected=vector.expected_output,
            comparison="exact",
        )
        for vector in bundle.vectors
    ]


def _pv_property_cases() -> list[DiagnosticCase]:
    cases: list[DiagnosticCase] = []
    for label, amount_cents, factor, exact, rounded in (
        ("positive_005", 100, "0.005", "0.005", "0.00"),
        ("positive_015", 100, "0.015", "0.015", "0.02"),
        ("negative_005", -100, "0.005", "-0.005", "0.00"),
        ("negative_015", -100, "0.015", "-0.015", "-0.02"),
    ):
        tie = _base_request(f"property_pv_tie_{label}")
        tie["discount_factors"] = [{"date": "2027-01-01", "factor": factor}]
        tie["cashflows"] = [
            {
                "cashflow_id": "tie_cashflow",
                "claim_id": "tie_claim",
                "event_date": "2027-01-01",
                "amount": _money_from_cents(amount_cents),
            }
        ]
        cases.append(
            DiagnosticCase(
                f"property::pv::tie_half_even::{label}",
                "pv_fraction_half_even",
                "compute",
                tie,
                {
                    "authority": "none",
                    "deployment_eligibility": "not_authorized",
                    "valuation": {"present_value_exact": exact, "present_value": rounded},
                },
                "subset",
            )
        )
    generator = random.Random(20260809)
    for run in range(15):
        request = _base_request(f"property_pv_{run}")
        factors: list[dict[str, str]] = []
        cashflows: list[dict[str, Any]] = []
        expected = Fraction(0)
        for index in range(1, generator.randint(2, 8) + 1):
            amount_cents = generator.randint(-100_000, 100_000)
            factor_millis = generator.randint(1, 2_000)
            event_date = f"{2026 + index}-01-01"
            factors.append({"date": event_date, "factor": _fraction_decimal(Fraction(factor_millis, 1000))})
            cashflows.append(
                {
                    "cashflow_id": f"cashflow_{index}",
                    "claim_id": f"claim_{index}",
                    "event_date": event_date,
                    "amount": _money_from_cents(amount_cents),
                }
            )
            expected += Fraction(amount_cents, 100) * Fraction(factor_millis, 1000)
        request["discount_factors"] = factors
        request["cashflows"] = cashflows
        cases.append(
            DiagnosticCase(
                f"property::pv::{run:02d}",
                "pv_fraction_half_even",
                "compute",
                request,
                {
                    "authority": "none",
                    "deployment_eligibility": "not_authorized",
                    "valuation": {
                        "present_value_exact": _fraction_decimal(expected),
                        "present_value": _cents_text(_round_fraction_to_cents(expected)),
                    },
                },
                "subset",
            )
        )
    return cases


def _transfer_property_cases() -> list[DiagnosticCase]:
    generator = random.Random(20260810)
    cases: list[DiagnosticCase] = []
    for run in range(16):
        left = generator.randint(1, 1_000_000)
        right = generator.randint(1, 1_000_000)
        amount = generator.randint(1, right)
        request = _base_request(f"property_transfer_{run}")
        request["accounts"] = [
            {"account_id": "a", "opening_balance": _money_from_cents(left), "return_basis": "none"},
            {"account_id": "b", "opening_balance": _money_from_cents(right), "return_basis": "none"},
        ]
        request["events"] = [
            {
                "event_type": "transfer",
                "event_id": f"transfer_{run}",
                "effective_date": "2026-01-02",
                "sequence": run,
                "from_account_id": "b",
                "to_account_id": "a",
                "economic_source_id": f"source_{run}",
                "amount": _money_from_cents(amount),
            }
        ]
        cases.append(
            DiagnosticCase(
                f"property::transfer::{run:02d}",
                "transfer_integer_cents",
                "compute",
                request,
                {
                    "ledger": {
                        "opening_consolidated_wealth": _cents_text(left + right),
                        "closing_consolidated_wealth": _cents_text(left + right),
                        "consolidated_transfer_contribution": "0.00",
                        "reconciled": True,
                        "accounts": [
                            {"account_id": "a", "closing_balance": _cents_text(left + amount)},
                            {"account_id": "b", "closing_balance": _cents_text(right - amount)},
                        ],
                        "events": [
                            {
                                "postings": [
                                    {"account_id": "b", "delta": _cents_text(-amount)},
                                    {"account_id": "a", "delta": _cents_text(amount)},
                                ]
                            }
                        ],
                    }
                },
                "subset",
            )
        )
    return cases


def _return_property_cases() -> list[DiagnosticCase]:
    generator = random.Random(20260811)
    cases: list[DiagnosticCase] = []
    for label, rate, rounded, closing in (
        ("positive_005", "0.005", "0.00", "1.00"),
        ("positive_015", "0.015", "0.02", "1.02"),
        ("negative_005", "-0.005", "0.00", "1.00"),
        ("negative_015", "-0.015", "-0.02", "0.98"),
    ):
        request = _base_request(f"property_return_tie_{label}")
        request["accounts"] = [
            {"account_id": "portfolio", "opening_balance": _money_from_cents(100), "return_basis": "price_return"}
        ]
        request["events"] = [
            {
                "event_type": "return",
                "event_id": "tie_return",
                "effective_date": "2026-01-02",
                "sequence": 1,
                "account_id": "portfolio",
                "return_basis": "price_return",
                "rate": rate,
                "cash_distribution": _money_from_cents(0),
            }
        ]
        cases.append(
            DiagnosticCase(
                f"property::return::tie_half_even::{label}",
                "return_basis_integer_fraction",
                "compute",
                request,
                {
                    "ledger": {
                        "closing_consolidated_wealth": closing,
                        "return_net_change": rounded,
                        "events": [{"gain": rounded, "postings": [{"after_balance": closing}]}],
                    }
                },
                "subset",
            )
        )

    sequential = _base_request("property_return_sequential_current")
    sequential["accounts"] = [
        {"account_id": "portfolio", "opening_balance": _money_from_cents(10_000), "return_basis": "price_return"}
    ]
    sequential["events"] = [
        {
            "event_type": "return",
            "event_id": f"sequential_{index}",
            "effective_date": f"2026-01-0{index + 1}",
            "sequence": index,
            "account_id": "portfolio",
            "return_basis": "price_return",
            "rate": "0.1",
            "cash_distribution": _money_from_cents(0),
        }
        for index in (1, 2)
    ]
    cases.append(
        DiagnosticCase(
            "property::return::sequential_current_balance",
            "return_basis_integer_fraction",
            "compute",
            sequential,
            {
                "ledger": {
                    "closing_consolidated_wealth": "121.00",
                    "return_net_change": "21.00",
                    "events": [
                        {"gain": "10.00", "postings": [{"before_balance": "100.00", "after_balance": "110.00"}]},
                        {"gain": "11.00", "postings": [{"before_balance": "110.00", "after_balance": "121.00"}]},
                    ],
                }
            },
            "subset",
        )
    )

    for run in range(16):
        basis = "price_return" if run < 8 else "total_return"
        opening = generator.randint(10_000, 1_000_000)
        rate_millis = generator.randint(1, 250)
        distribution = generator.randint(0, 20_000) if basis == "price_return" else 0
        gain_fraction = Fraction(opening, 100) * Fraction(rate_millis, 1000)
        gain = _round_fraction_to_cents(gain_fraction)
        closing = opening + gain + distribution
        request = _base_request(f"property_return_{run}")
        request["accounts"] = [
            {"account_id": "portfolio", "opening_balance": _money_from_cents(opening), "return_basis": basis}
        ]
        request["events"] = [
            {
                "event_type": "return",
                "event_id": f"return_{run}",
                "effective_date": "2026-12-31",
                "sequence": run,
                "account_id": "portfolio",
                "return_basis": basis,
                "rate": _fraction_decimal(Fraction(rate_millis, 1000)),
                "cash_distribution": _money_from_cents(distribution),
            }
        ]
        cases.append(
            DiagnosticCase(
                f"property::return::{run:02d}",
                "return_basis_integer_fraction",
                "compute",
                request,
                {
                    "ledger": {
                        "closing_consolidated_wealth": _cents_text(closing),
                        "return_net_change": _cents_text(gain + distribution),
                        "accounts": [{"account_id": "portfolio", "closing_balance": _cents_text(closing)}],
                        "events": [
                            {
                                "return_basis": basis,
                                "gain": _cents_text(gain),
                                "asset_value_after_return": _cents_text(opening + gain),
                                "cash_distribution": _cents_text(distribution),
                                "postings": [{"account_id": "portfolio", "delta": _cents_text(gain + distribution)}],
                            }
                        ],
                    }
                },
                "subset",
            )
        )
    return cases


def _use_context_property_cases() -> list[DiagnosticCase]:
    cases: list[DiagnosticCase] = []
    for flag in ("client_specific", "recommendation_enabled", "execution_enabled"):
        request = _base_request(f"property_use_{flag}")
        request["use_context"][flag] = True
        cases.append(
            DiagnosticCase(
                f"property::use_context::{flag}",
                "use_context_fail_closed",
                "validate",
                request,
                {
                    "valid": False,
                    "authority": "none",
                    "deployment_eligibility": "not_authorized",
                    "issues": [{"code": "DCL_USE_OUT_OF_SCOPE", "pointer": "/use_context"}],
                },
                "subset",
            )
        )
    return cases


def _numeric_boundary_property_cases() -> list[DiagnosticCase]:
    minimum = _base_request("property_minimum_product")
    minimum["discount_factors"] = [{"date": "2026-01-02", "factor": "0.000000000000000001"}]
    minimum["cashflows"] = [
        {
            "cashflow_id": "minimum",
            "claim_id": "minimum_claim",
            "event_date": "2026-01-02",
            "amount": {"currency": "BRL", "value": "0.01"},
        }
    ]

    cancellation = _base_request("property_pv_cancellation")
    cancellation["discount_factors"] = [{"date": "2026-01-02", "factor": "1"}]
    cancellation["cashflows"] = [
        {
            "cashflow_id": "a_large_positive",
            "claim_id": "positive_claim",
            "event_date": "2026-01-02",
            "amount": {"currency": "BRL", "value": "999999999999999999999999999999999999.99"},
        },
        {
            "cashflow_id": "b_cent",
            "claim_id": "cent_claim",
            "event_date": "2026-01-02",
            "amount": {"currency": "BRL", "value": "0.01"},
        },
        {
            "cashflow_id": "c_large_negative",
            "claim_id": "negative_claim",
            "event_date": "2026-01-02",
            "amount": {"currency": "BRL", "value": "-999999999999999999999999999999999999.99"},
        },
    ]

    hostile = _base_request("property_hostile_context")
    hostile["discount_factors"] = [{"date": "2026-01-02", "factor": "1.515"}]
    hostile["cashflows"] = [
        {
            "cashflow_id": "hostile_pv",
            "claim_id": "hostile_pv_claim",
            "event_date": "2026-01-02",
            "amount": {"currency": "BRL", "value": "1.00"},
        }
    ]
    hostile["accounts"] = [
        {"account_id": "cash", "opening_balance": {"currency": "BRL", "value": "99.00"}, "return_basis": "none"}
    ]
    hostile["events"] = [
        {
            "event_type": "posting",
            "event_id": "hostile_posting",
            "effective_date": "2026-01-02",
            "sequence": 1,
            "account_id": "cash",
            "category": "adjustment",
            "claim_id": "hostile_posting_claim",
            "amount": {"currency": "BRL", "value": "2.00"},
        }
    ]

    money_38 = _base_request("property_money_38_digits")
    money_38["accounts"] = [
        {
            "account_id": "cash",
            "opening_balance": {
                "currency": "BRL",
                "value": "999999999999999999999999999999999999.99",
            },
            "return_basis": "none",
        }
    ]
    money_39 = _base_request("property_money_39_digits")
    money_39["accounts"] = [
        {
            "account_id": "cash",
            "opening_balance": {
                "currency": "BRL",
                "value": "9999999999999999999999999999999999999.99",
            },
            "return_basis": "none",
        }
    ]

    factor_38 = _base_request("property_discount_factor_38_digits")
    factor_38["discount_factors"] = [{"date": "2026-01-02", "factor": "9" * 38}]
    factor_39 = _base_request("property_discount_factor_39_digits")
    factor_39["discount_factors"] = [{"date": "2026-01-02", "factor": "9" * 39}]

    rate_38 = _base_request("property_return_rate_38_digits")
    rate_38["accounts"] = [
        {"account_id": "portfolio", "opening_balance": _money_from_cents(0), "return_basis": "price_return"}
    ]
    rate_38["events"] = [
        {
            "event_type": "return",
            "event_id": "rate_limit",
            "effective_date": "2026-01-02",
            "sequence": 1,
            "account_id": "portfolio",
            "return_basis": "price_return",
            "rate": "9" * 38,
            "cash_distribution": _money_from_cents(0),
        }
    ]
    rate_39 = _base_request("property_return_rate_39_digits")
    rate_39["accounts"] = rate_38["accounts"]
    rate_39["events"] = [{**rate_38["events"][0], "rate": "9" * 39}]

    rejected_object = {
        "raised_validation_error": {
            "valid": False,
            "authority": "none",
            "deployment_eligibility": "not_authorized",
            "issues": [{"code": "DCL_TYPE_MISMATCH", "pointer": ""}],
        }
    }
    precision_bound = _precision_bound_request("property_precision_bound")
    precision_bound_expected = Fraction(2, 10**20)
    return [
        DiagnosticCase(
            "property::pv::large_cancellation",
            "pv_fraction_half_even",
            "compute",
            cancellation,
            {"valuation": {"present_value_exact": "0.01", "present_value": "0.01"}},
            "subset",
        ),
        DiagnosticCase(
            "property::numeric::hostile_context",
            "numeric_context_isolation",
            "compute_hostile_context",
            hostile,
            {
                "context_preserved": True,
                "result": {
                    "valuation": {"present_value_exact": "1.515", "present_value": "1.52"},
                    "ledger": {
                        "closing_consolidated_wealth": "101.00",
                        "posting_net_change": "2.00",
                        "reconciled": True,
                    },
                },
            },
            "subset",
        ),
        DiagnosticCase(
            "property::numeric::precision_98_bound",
            "numeric_context_isolation",
            "compute_pv_hostile_context",
            precision_bound,
            {
                "context_preserved": True,
                "valuation": {
                    "present_value_exact": _fraction_decimal(precision_bound_expected),
                    "present_value": _cents_text(_round_fraction_to_cents(precision_bound_expected)),
                },
            },
            "subset",
        ),
        DiagnosticCase(
            "property::pv::minimum_product",
            "pv_fraction_half_even",
            "compute",
            minimum,
            {"valuation": {"present_value_exact": "0.00000000000000000001", "present_value": "0.00"}},
            "subset",
        ),
        DiagnosticCase(
            "property::api::parsed_object_rejected",
            "public_mapping_boundary",
            "compute_parsed_object",
            _base_request("property_parsed_object"),
            rejected_object,
            "subset",
        ),
        DiagnosticCase(
            "property::api::replaced_object_rejected",
            "public_mapping_boundary",
            "compute_replaced_object",
            _base_request("property_replaced_object"),
            rejected_object,
            "subset",
        ),
        DiagnosticCase(
            "property::numeric::money_38_accepted",
            "numeric_digit_budget",
            "validate",
            money_38,
            {"valid": True, "issues": []},
            "subset",
        ),
        DiagnosticCase(
            "property::numeric::money_39_rejected",
            "numeric_digit_budget",
            "validate",
            money_39,
            {
                "valid": False,
                "issues": [{"code": "DCL_INVALID_MONEY", "pointer": "/accounts/0/opening_balance/value"}],
            },
            "subset",
        ),
        DiagnosticCase(
            "property::numeric::discount_factor_38_accepted",
            "numeric_digit_budget",
            "validate",
            factor_38,
            {"valid": True, "issues": []},
            "subset",
        ),
        DiagnosticCase(
            "property::numeric::discount_factor_39_rejected",
            "numeric_digit_budget",
            "validate",
            factor_39,
            {
                "valid": False,
                "issues": [{"code": "DCL_INVALID_DECIMAL", "pointer": "/discount_factors/0/factor"}],
            },
            "subset",
        ),
        DiagnosticCase(
            "property::numeric::return_rate_38_accepted",
            "numeric_digit_budget",
            "validate",
            rate_38,
            {"valid": True, "issues": []},
            "subset",
        ),
        DiagnosticCase(
            "property::numeric::return_rate_39_rejected",
            "numeric_digit_budget",
            "validate",
            rate_39,
            {
                "valid": False,
                "issues": [{"code": "DCL_INVALID_DECIMAL", "pointer": "/events/0/rate"}],
            },
            "subset",
        ),
    ]


def _reference_pack_cases() -> list[DiagnosticCase]:
    return [
        DiagnosticCase(
            "gate::reference_pack::current_balance_return",
            "reference_acceptance_pack",
            "reference",
            {},
            {
                "status": "local_technical_acceptance_passed",
                "case_count": 3,
                "passed_count": 3,
                "failed_count": 0,
                "authority": "none",
                "release_authorized": False,
                "cases": [
                    {},
                    {
                        "case_id": "ledger_transfer_and_return",
                        "status": "passed",
                        "exact_output_match": True,
                    },
                    {},
                ],
            },
            "subset",
        )
    ]


def build_cases(bundle: BridgeBundle) -> tuple[DiagnosticCase, ...]:
    cases = [
        *_vector_cases(bundle),
        *_pv_property_cases(),
        *_transfer_property_cases(),
        *_return_property_cases(),
        *_use_context_property_cases(),
        *_numeric_boundary_property_cases(),
        *_reference_pack_cases(),
    ]
    identifiers = [case.case_id for case in cases]
    if len(cases) != 79 or len(set(identifiers)) != len(identifiers):
        raise DiagnosticConfigurationError("closed SDK diagnostic case roster is inconsistent")
    return tuple(cases)


def _isolated_environment(temp_root: Path) -> dict[str, str]:
    allowed = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(
        {
            "HOME": str(temp_root),
            "USERPROFILE": str(temp_root),
            "TMP": str(temp_root),
            "TEMP": str(temp_root),
            "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
    )
    return environment


def _run_worker(
    repository_root: Path,
    source_root: Path,
    cases: tuple[DiagnosticCase, ...],
    worker_snapshot: FileSnapshot,
) -> dict[str, Any]:
    request = {"protocol": BATCH_PROTOCOL, "cases": [case.worker_payload() for case in cases]}
    with tempfile.TemporaryDirectory(prefix="finplanbr-sdk-diagnostic-") as temporary:
        temp_root = Path(temporary)
        command = [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(worker_snapshot.path),
            "--source-root",
            str(source_root),
            "--repository-root",
            str(repository_root),
        ]
        try:
            completed = run_bounded(
                command,
                input_bytes=_canonical_json(request),
                cwd=temp_root,
                env=_isolated_environment(temp_root),
                timeout_seconds=WORKER_TIMEOUT_SECONDS,
                stdout_limit=MAX_WORKER_OUTPUT_BYTES,
                stderr_limit=MAX_WORKER_OUTPUT_BYTES,
            )
        except BoundedProcessTimeout as exc:
            raise WorkerTimeout("fixed SDK worker exceeded its time limit") from exc
        except BoundedProcessOutputLimit as exc:
            raise WorkerCrash(f"fixed SDK worker exceeded its {exc.stream} output budget") from exc
        except (BoundedProcessStartError, BoundedProcessCleanupError) as exc:
            raise WorkerCrash("fixed SDK worker process boundary failed") from exc
    if completed.returncode != 0:
        digest = _sha256(completed.stderr)
        raise WorkerCrash(f"fixed SDK worker exited non-zero (stderr_sha256={digest})")
    try:
        response = _decode_json(completed.stdout, "SDK worker response")
    except DiagnosticConfigurationError as exc:
        raise WorkerCrash("fixed SDK worker response is not closed strict JSON") from exc
    expected_fields = {"protocol", "responses", "subject"}
    if not isinstance(response, dict) or set(response) != expected_fields:
        raise WorkerCrash("fixed SDK worker response does not use the closed envelope")
    if response.get("protocol") != RESPONSE_PROTOCOL:
        raise WorkerCrash("fixed SDK worker response protocol is invalid")
    subject = response.get("subject")
    if subject != {"distribution": "finplanbr", "module": "financial_planning_sdk_br", "version": SDK_VERSION}:
        raise WorkerCrash("fixed SDK worker loaded an unexpected subject")
    return response


def _compare_subset(actual: Any, expected: Any, path: str) -> list[str]:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{path}: expected object"]
        missing = set(expected) - set(actual)
        errors = [f"{path}: missing keys {sorted(missing)}"] if missing else []
        for key in sorted(set(expected) & set(actual)):
            errors.extend(_compare_subset(actual[key], expected[key], f"{path}.{key}"))
        return errors
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return [f"{path}: list shape differs"]
        errors: list[str] = []
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            errors.extend(_compare_subset(left, right, f"{path}[{index}]"))
        return errors
    return [] if actual == expected else [f"{path}: expected {expected!r}, got {actual!r}"]


def _evaluate_responses(cases: tuple[DiagnosticCase, ...], response: dict[str, Any]) -> list[str]:
    raw_responses = response.get("responses")
    if not isinstance(raw_responses, list) or len(raw_responses) != len(cases):
        return ["worker response count does not match the closed case roster"]
    by_id: dict[str, Any] = {}
    for item in raw_responses:
        if not isinstance(item, dict) or set(item) != {"case_id", "output"} or not isinstance(item.get("case_id"), str):
            return ["worker returned a malformed case response"]
        if item["case_id"] in by_id:
            return ["worker returned a duplicate case response"]
        by_id[item["case_id"]] = item["output"]
    if set(by_id) != {case.case_id for case in cases}:
        return ["worker response IDs do not match the closed case roster"]
    errors: list[str] = []
    for case in cases:
        actual = by_id[case.case_id]
        if case.comparison == "exact":
            if actual != case.expected:
                errors.extend(_compare_subset(actual, case.expected, case.case_id))
                if isinstance(actual, dict):
                    extra = set(actual) - set(case.expected)
                    if extra:
                        errors.append(f"{case.case_id}: unexpected keys {sorted(extra)}")
        else:
            errors.extend(_compare_subset(actual, case.expected, case.case_id))
    return errors


@dataclass(frozen=True, slots=True)
class MutationDefinition:
    mutation_id: str
    patches: tuple[tuple[str, str, str], ...]
    composition: Literal["atomic", "compound"] = "atomic"
    required_kill_case_ids: tuple[str, ...] = ()


REQUIRED_COMPOUND_MUTATIONS = frozenset(
    {
        "negative_money_rounding_half_down",
        "return_uses_opening_balance",
        "false_reconciliation_after_omitted_posting",
    }
)


MUTATIONS = (
    MutationDefinition(
        "pv_ignores_discount_factor",
        (
            (
                "deterministic.py",
                'exact = _exact_multiply(cashflow.amount.value, factor, f"/cashflows/{len(exact_contributions)}")',
                'exact = _exact_multiply(cashflow.amount.value, Decimal("1"), '
                'f"/cashflows/{len(exact_contributions)}")',
            ),
        ),
    ),
    MutationDefinition(
        "rounding_half_up",
        (
            (
                "numeric.py",
                "    ROUND_HALF_EVEN,\n    Context,",
                "    ROUND_HALF_EVEN,\n    ROUND_HALF_UP,\n    Context,",
            ),
            ("numeric.py", "rounding=ROUND_HALF_EVEN", "rounding=ROUND_HALF_UP"),
        ),
    ),
    MutationDefinition(
        "rounding_half_down",
        (
            (
                "numeric.py",
                "    ROUND_HALF_EVEN,\n    Context,",
                "    ROUND_HALF_DOWN,\n    ROUND_HALF_EVEN,\n    Context,",
            ),
            ("numeric.py", "rounding=ROUND_HALF_EVEN", "rounding=ROUND_HALF_DOWN"),
        ),
    ),
    MutationDefinition(
        "negative_money_rounding_half_down",
        (
            (
                "numeric.py",
                "    ROUND_HALF_EVEN,\n    Context,",
                "    ROUND_HALF_DOWN,\n    ROUND_HALF_EVEN,\n    Context,",
            ),
            (
                "numeric.py",
                "            rounded = context.quantize(value, MONEY_QUANTUM)",
                "            if value < 0:\n"
                "                context.rounding = ROUND_HALF_DOWN\n"
                "            rounded = context.quantize(value, MONEY_QUANTUM)",
            ),
        ),
        composition="compound",
        required_kill_case_ids=(
            "property::pv::tie_half_even::negative_015",
            "property::return::tie_half_even::negative_015",
        ),
    ),
    MutationDefinition(
        "transfer_output_sign",
        (
            (
                "deterministic.py",
                '"delta": format_minor_units(-amount)',
                '"delta": format_minor_units(amount)',
            ),
        ),
    ),
    MutationDefinition(
        "return_distribution_hidden",
        (
            (
                "deterministic.py",
                '"cash_distribution": format_minor_units(distribution)',
                '"cash_distribution": "0.00"',
            ),
        ),
    ),
    MutationDefinition(
        "use_context_requires_all_flags",
        (("deterministic.py", "if any(flags):", "if all(flags):"),),
    ),
    MutationDefinition(
        "posting_change_uses_return_change",
        (
            (
                "deterministic.py",
                '"posting_net_change": format_minor_units(posting_change)',
                '"posting_net_change": format_minor_units(return_change)',
            ),
        ),
    ),
    MutationDefinition(
        "total_return_double_count_allowed",
        (
            (
                "deterministic.py",
                'if return_basis == "total_return" and distribution.value != 0:',
                'if False and return_basis == "total_return" and distribution.value != 0:',
            ),
        ),
    ),
    MutationDefinition(
        "arithmetic_precision_28",
        (("numeric.py", "ARITHMETIC_PRECISION = 128", "ARITHMETIC_PRECISION = 28"),),
    ),
    MutationDefinition(
        "arithmetic_precision_97",
        (("numeric.py", "ARITHMETIC_PRECISION = 128", "ARITHMETIC_PRECISION = 97"),),
    ),
    MutationDefinition(
        "arithmetic_emax_narrow",
        (("numeric.py", "ARITHMETIC_EMAX = 127", "ARITHMETIC_EMAX = 1"),),
    ),
    MutationDefinition(
        "arithmetic_emin_narrow",
        (("numeric.py", "ARITHMETIC_EMIN = -127", "ARITHMETIC_EMIN = -1"),),
    ),
    MutationDefinition(
        "typed_request_bypass_restored",
        (
            (
                "deterministic.py",
                "return _compute_parsed(_parse_deterministic_request(data))",
                "return _compute_parsed(data if isinstance(data, _DeterministicRequest) "
                "and data.base_currency == \"BRL\" and not any((data.client_specific, "
                "data.recommendation_enabled, data.execution_enabled)) "
                "else _parse_deterministic_request(data))",
            ),
        ),
        required_kill_case_ids=("property::api::parsed_object_rejected",),
    ),
    MutationDefinition(
        "money_digit_budget_relaxed_to_39",
        (
            (
                "numeric.py",
                'if text == "-0.00" or _significant_digits(text) > MAX_MONEY_SIGNIFICANT_DIGITS:',
                'if text == "-0.00" or _significant_digits(text) > MAX_MONEY_SIGNIFICANT_DIGITS + 1:',
            ),
        ),
    ),
    MutationDefinition(
        "decimal_digit_budget_relaxed_to_39",
        (
            (
                "numeric.py",
                "    if _significant_digits(text) > max_significant_digits:",
                "    if _significant_digits(text) > max_significant_digits + 1:",
            ),
        ),
        required_kill_case_ids=(
            "property::numeric::discount_factor_39_rejected",
            "property::numeric::return_rate_39_rejected",
        ),
    ),
    MutationDefinition(
        "multiply_inherits_caller_context",
        (
            (
                "numeric.py",
                "with localcontext(_context(allow_money_rounding=False)) as context:\n"
                "            result = context.multiply(left, right)",
                "with localcontext() as context:\n"
                "            context.prec = ARITHMETIC_PRECISION\n"
                "            context.clear_flags()\n"
                "            result = context.multiply(left, right)",
            ),
        ),
    ),
    MutationDefinition(
        "add_inherits_caller_context",
        (
            (
                "numeric.py",
                "with localcontext(_context(allow_money_rounding=False)) as context:\n"
                "            total = Decimal(0)",
                "with localcontext() as context:\n"
                "            context.prec = ARITHMETIC_PRECISION\n"
                "            context.clear_flags()\n"
                "            total = Decimal(0)",
            ),
        ),
    ),
    MutationDefinition(
        "posting_change_omitted",
        (("deterministic.py", "posting_change += delta", "posting_change += 0"),),
    ),
    MutationDefinition(
        "false_reconciliation_after_omitted_posting",
        (
            ("deterministic.py", "posting_change += delta", "posting_change += 0"),
            (
                "deterministic.py",
                "reconciled = closing == expected and transfer_change == 0",
                "reconciled = transfer_change == 0",
            ),
        ),
        composition="compound",
    ),
    MutationDefinition(
        "money_rounding_boundary_traps_rounding",
        (("numeric.py", "if allow_money_rounding:", "if False and allow_money_rounding:"),),
    ),
    MutationDefinition(
        "money_inherits_caller_context_after_clear_flags",
        (
            (
                "numeric.py",
                "with localcontext(_context(allow_money_rounding=True)) as context:\n"
                "            rounded = context.quantize(value, MONEY_QUANTUM)",
                "with localcontext() as context:\n"
                "            context.prec = ARITHMETIC_PRECISION\n"
                "            context.clear_flags()\n"
                "            rounded = context.quantize(value, MONEY_QUANTUM)",
            ),
        ),
    ),
    MutationDefinition(
        "return_uses_opening_balance",
        (
            (
                "deterministic.py",
                "    account_rules = {account.account_id: account for account in request.accounts}\n"
                "    opening = _bounded_minor_units(sum(states.values()), \"/accounts\")",
                "    account_rules = {account.account_id: account for account in request.accounts}\n"
                "    opening_states = dict(states)\n"
                "    opening = _bounded_minor_units(sum(states.values()), \"/accounts\")",
            ),
            (
                "deterministic.py",
                "_exact_multiply(minor_units_decimal(before), event.rate, pointer)",
                "_exact_multiply(minor_units_decimal(opening_states[event.account_id]), event.rate, pointer)",
            ),
        ),
        composition="compound",
        required_kill_case_ids=(
            "property::return::sequential_current_balance",
            "gate::reference_pack::current_balance_return",
        ),
    ),
)


def _validate_mutation_contract(cases: tuple[DiagnosticCase, ...]) -> None:
    mutation_ids = [mutation.mutation_id for mutation in MUTATIONS]
    if len(mutation_ids) != len(set(mutation_ids)):
        raise DiagnosticConfigurationError("mutation roster contains duplicate IDs")
    compound_ids = {mutation.mutation_id for mutation in MUTATIONS if mutation.composition == "compound"}
    if compound_ids != REQUIRED_COMPOUND_MUTATIONS:
        raise DiagnosticConfigurationError("compound mutation roster drifted from the explicit gate")
    case_ids = {case.case_id for case in cases}
    for mutation in MUTATIONS:
        if not mutation.patches:
            raise DiagnosticConfigurationError(f"mutation has no patch: {mutation.mutation_id}")
        if mutation.composition == "compound" and len(mutation.patches) < 2:
            raise DiagnosticConfigurationError(f"compound mutation has fewer than two patches: {mutation.mutation_id}")
        if not set(mutation.required_kill_case_ids) <= case_ids:
            raise DiagnosticConfigurationError(f"mutation required-kill case is absent: {mutation.mutation_id}")


def _write_mutated_source(
    temp_root: Path,
    snapshots: tuple[FileSnapshot, ...],
    mutation: MutationDefinition,
) -> Path:
    source_root = temp_root / "src"
    package_root = source_root / "financial_planning_sdk_br"
    package_root.mkdir(parents=True)
    for snapshot in snapshots:
        relative = Path(snapshot.relative_path).relative_to("src/financial_planning_sdk_br")
        target = package_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(snapshot.payload)
    for relative_name, old, new in mutation.patches:
        target = package_root / relative_name
        try:
            text = target.read_text(encoding="utf-8")
        except OSError as exc:
            raise DiagnosticConfigurationError(f"mutation source unavailable: {mutation.mutation_id}") from exc
        if text.count(old) != 1:
            raise DiagnosticConfigurationError(
                f"mutation patch is no longer single-match: {mutation.mutation_id}/{relative_name}"
            )
        target.write_text(text.replace(old, new), encoding="utf-8", newline="\n")
    return source_root


def _mutation_results(
    repository_root: Path,
    source_snapshots: tuple[FileSnapshot, ...],
    cases: tuple[DiagnosticCase, ...],
    worker_snapshot: FileSnapshot,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    categories = {name: [] for name in ("semantic_kill", "assertion_kill", "crash", "timeout", "nonviable", "survived")}
    semantic_case_ids = {
        case.case_id for case in cases if case.family in {"math_vector_bridge", "reference_acceptance_pack"}
    }
    kill_case_ids: dict[str, list[str]] = {}
    for mutation in MUTATIONS:
        try:
            with tempfile.TemporaryDirectory(prefix=f"finplanbr-mutant-{mutation.mutation_id}-") as temporary:
                source_root = _write_mutated_source(Path(temporary), source_snapshots, mutation)
                response = _run_worker(repository_root, source_root, cases, worker_snapshot)
                errors = _evaluate_responses(cases, response)
        except WorkerTimeout:
            categories["timeout"].append(mutation.mutation_id)
            continue
        except WorkerCrash:
            categories["crash"].append(mutation.mutation_id)
            continue
        except (DiagnosticConfigurationError, OSError):
            categories["nonviable"].append(mutation.mutation_id)
            continue
        if not errors:
            categories["survived"].append(mutation.mutation_id)
            kill_case_ids[mutation.mutation_id] = []
            continue
        observed_cases = sorted(
            case.case_id for case in cases if any(case.case_id in error for error in errors)
        )
        kill_case_ids[mutation.mutation_id] = observed_cases
        if any(case_id in semantic_case_ids for case_id in observed_cases):
            categories["semantic_kill"].append(mutation.mutation_id)
        else:
            categories["assertion_kill"].append(mutation.mutation_id)
    return categories, kill_case_ids


def _failure_report(stage: str, errors: list[str], *, configuration: bool = False) -> tuple[dict[str, Any], int]:
    return (
        {
            "report_format": REPORT_FORMAT,
            "status": "configuration_failed" if configuration else "local_sdk_conformance_failed",
            "authority": "technical_validation_only_not_release_authority",
            "release_authorized": False,
            "official_21_vector_sut_conformance": "not_evaluated",
            "failure": {"stage": stage, "errors": errors},
        },
        2 if configuration else 1,
    )


def evaluate_repository(repository_root: Path, *, include_mutations: bool = True) -> tuple[dict[str, Any], int]:
    try:
        root = repository_root.resolve(strict=True)
        bundle = load_bridge_bundle(root)
        source_snapshots = _package_snapshots(root)
        worker_snapshot = _read_snapshot(
            root / "scripts" / "sdk_conformance_worker.py",
            "scripts/sdk_conformance_worker.py",
        )
        adapter_snapshot = _read_snapshot(root / "tests" / "sdk" / "vector_adapter.py", "tests/sdk/vector_adapter.py")
        cases = build_cases(bundle)
        _validate_mutation_contract(cases)
    except (DiagnosticConfigurationError, OSError) as exc:
        return _failure_report("configuration", [str(exc)], configuration=True)

    try:
        first = _run_worker(root, root / "src", cases, worker_snapshot)
        base_errors = _evaluate_responses(cases, first)
        if base_errors:
            return _failure_report("base_evaluation", base_errors)
        second = _run_worker(root, root / "src", cases, worker_snapshot)
        if _canonical_json(first) != _canonical_json(second):
            return _failure_report("repeatability", ["fixed SDK worker response changed across two identical batches"])
        mutations, mutation_kill_cases = (
            _mutation_results(root, source_snapshots, cases, worker_snapshot)
            if include_mutations
            else (
                {
                    name: []
                    for name in ("semantic_kill", "assertion_kill", "crash", "timeout", "nonviable", "survived")
                },
                {},
            )
        )
        if include_mutations:
            mutation_failures = [
                f"{category}: {mutation_id}"
                for category in ("crash", "timeout", "nonviable", "survived")
                for mutation_id in mutations[category]
            ]
            killed = len(mutations["semantic_kill"]) + len(mutations["assertion_kill"])
            required_case_failures = [
                f"required_kill_cases: {mutation.mutation_id}"
                for mutation in MUTATIONS
                if not set(mutation.required_kill_case_ids) <= set(mutation_kill_cases.get(mutation.mutation_id, []))
            ]
            controlled_kills = set(mutations["semantic_kill"]) | set(mutations["assertion_kill"])
            compound_failures = sorted(REQUIRED_COMPOUND_MUTATIONS - controlled_kills)
            if mutation_failures or required_case_failures or compound_failures or killed != len(MUTATIONS):
                return _failure_report(
                    "mutation_sensitivity",
                    mutation_failures
                    + required_case_failures
                    + [f"compound_not_controlled_kill: {mutation_id}" for mutation_id in compound_failures]
                    or ["mutation roster was not fully killed"],
                )
        bundle.recheck()
        worker_snapshot.recheck()
        adapter_snapshot.recheck()
        for snapshot in source_snapshots:
            snapshot.recheck()
    except WorkerTimeout as exc:
        return _failure_report("execution_timeout", [str(exc)])
    except WorkerCrash as exc:
        return _failure_report("execution_crash", [str(exc)])
    except DiagnosticConfigurationError as exc:
        return _failure_report("post_execution_recheck", [str(exc)], configuration=True)

    family_counts: dict[str, int] = {}
    for case in cases:
        family_counts[case.family] = family_counts.get(case.family, 0) + 1
    reference_pack_case_count = family_counts.get("reference_acceptance_pack", 0)
    mutation_evaluated = include_mutations
    compound_controlled_kills = sorted(
        REQUIRED_COMPOUND_MUTATIONS & (set(mutations["semantic_kill"]) | set(mutations["assertion_kill"]))
    )
    report = {
        "report_format": REPORT_FORMAT,
        "status": "local_sdk_conformance_passed" if include_mutations else "local_sdk_conformance_partial",
        "authority": "technical_validation_only_not_release_authority",
        "release_authorized": False,
        "official_21_vector_sut_conformance": "not_evaluated",
        "scope": {
            "implemented_vertical": "deterministic_cashflow_ledger",
            "sdk_contract_version": SDK_CONTRACT_VERSION,
            "corpus_vectors_total": 21,
            "supported_vectors": len(bundle.vectors),
            "out_of_scope_vectors": len(bundle.out_of_scope_vector_ids),
            "out_of_scope_vector_ids": list(bundle.out_of_scope_vector_ids),
        },
        "subject": {
            "distribution": "finplanbr",
            "module": "financial_planning_sdk_br",
            "version": SDK_VERSION,
            "source_tree_sha256": _tree_digest(source_snapshots),
            "source_digest_provenance": "repository_local_untrusted",
            "source_digest_authentication": "not_provided",
            "execution": "fixed_subprocess_public_sdk",
        },
        "bridge_manifest": {
            "sha256": bundle.manifest_snapshot.sha256,
            "source_corpus_manifest_sha256": bundle.corpus_manifest_snapshot.sha256,
            "digest_provenance": "repository_local_untrusted",
            "digest_authentication": "not_provided",
        },
        "counts": {
            "vector_cases": len(bundle.vectors),
            "reference_pack_cases": reference_pack_case_count,
            "property_families": len(family_counts) - 2,
            "property_cases": len(cases) - len(bundle.vectors) - reference_pack_case_count,
            "case_families": dict(sorted(family_counts.items())),
            "repeatability_batches": 2,
            "mutation": {
                "evaluated": mutation_evaluated,
                "declared": len(MUTATIONS),
                "compound_declared": len(REQUIRED_COMPOUND_MUTATIONS),
                "compound_controlled_kill": len(compound_controlled_kills),
                "compound_roster": sorted(REQUIRED_COMPOUND_MUTATIONS),
                "compound_controlled_kills": compound_controlled_kills,
                "required_kill_case_coverage": mutation_kill_cases,
                **{name: len(values) for name, values in mutations.items()},
                "outcomes": mutations,
            },
        },
        "limits": {
            "network_isolation": "not_enforced",
            "filesystem_isolation": "not_enforced",
            "process_tree_isolation": process_tree_claim(),
            "runtime_authentication": "not_provided",
            "timeout_seconds_per_batch": WORKER_TIMEOUT_SECONDS,
            "max_worker_output_bytes": MAX_WORKER_OUTPUT_BYTES,
            "mutation_association": "repository_local_declared_not_externally_pinned",
        },
        "failure": None,
    }
    return report, 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--skip-mutations",
        action="store_true",
        help=(
            "development-only diagnostic; a successful result remains explicit "
            "that mutation sensitivity was not evaluated"
        ),
    )
    args = parser.parse_args(argv)
    repository_root = Path(__file__).resolve().parents[1]
    report, exit_code = evaluate_repository(repository_root, include_mutations=not args.skip_mutations)
    if args.output_format == "json":
        print(_canonical_json(report).decode("utf-8"))
    elif exit_code == 0:
        counts = report["counts"]
        mutation = counts["mutation"]
        label = "PASSED" if mutation["evaluated"] else "PARTIAL"
        print(
            f"Local SDK conformance {label}: "
            f"vectors={counts['vector_cases']}/21; properties={counts['property_cases']} "
            f"in {counts['property_families']} families; mutation_kills="
            f"{mutation['semantic_kill'] + mutation['assertion_kill']}/{mutation['declared']}; "
            "official_21_vector_sut_conformance=not_evaluated; "
            "authority=technical_validation_only_not_release_authority; release_authorized=false."
        )
    else:
        failure = report.get("failure", {})
        print(
            f"Local SDK conformance FAILED: stage={failure.get('stage', 'unknown')}; "
            f"errors={len(failure.get('errors', []))}; release_authorized=false.",
            file=sys.stderr,
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
