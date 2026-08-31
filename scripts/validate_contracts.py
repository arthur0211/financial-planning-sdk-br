"""Diagnose the draft JSON contract pack without network access or file writes.

JSON Schema validates shape. This module also runs the named semantic controls
that Draft 2020-12 cannot express and treats malformed packs as diagnostics,
never as uncaught resolver/parser exceptions.  This candidate Python process is
not an authority boundary: it never consumes external trust, approves an
artifact, or accepts a computed operational result.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections import Counter
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple
from urllib.parse import unquote

MIN_JSONSCHEMA_VERSION = (4, 18, 0)
MAX_INPUT_BYTES = 65_536
MAX_DOCUMENT_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_DECIMAL_DIGITS = 64
MAX_BASE64_SCAN_BYTES = 4_096
MAX_BASE64_SCAN_LAYERS = 2
FORBIDDEN_CLASS_A_PROPERTY_NAMES = {
    "best",
    "best_product",
    "buy",
    "recommended",
    "sell",
    "should_buy",
    "top_pick",
}
PROJECT_URN_PREFIX = "urn:financial-planning-sdk-br:schema:"
CLASS_RANK = {
    "A_RESEARCH_CORE": 0,
    "B_PROFESSIONAL_ASSIST": 1,
    "C_REGULATED_ADVICE": 2,
    "D_EXECUTION": 3,
}
SCHEMA_IDS = {
    "common": PROJECT_URN_PREFIX + "common:0.0.0",
    "diagnostic": PROJECT_URN_PREFIX + "diagnostic:0.0.0",
    "execution": PROJECT_URN_PREFIX + "execution-envelope:0.0.0",
    "governance": PROJECT_URN_PREFIX + "governance-envelope:0.0.0",
    "input": PROJECT_URN_PREFIX + "execution-input:0.0.0",
    "manifest": PROJECT_URN_PREFIX + "conformance-manifest:0.0.0",
    "model": PROJECT_URN_PREFIX + "model-card:0.0.0",
    "reason": PROJECT_URN_PREFIX + "reason-code:0.0.0",
    "regulatory": PROJECT_URN_PREFIX + "regulatory-use-context:0.0.0",
    "run_manifest": PROJECT_URN_PREFIX + "run-manifest:0.0.0",
}
EXPECTED_SCHEMA_FILE_IDS = {
    "common.schema.json": SCHEMA_IDS["common"],
    "conformance-manifest.schema.json": SCHEMA_IDS["manifest"],
    "diagnostic.schema.json": SCHEMA_IDS["diagnostic"],
    "execution-envelope.schema.json": SCHEMA_IDS["execution"],
    "governance-envelope.schema.json": SCHEMA_IDS["governance"],
    "input.schema.json": SCHEMA_IDS["input"],
    "model-card.schema.json": SCHEMA_IDS["model"],
    "reason-codes.schema.json": SCHEMA_IDS["reason"],
    "regulatory-use-context.schema.json": SCHEMA_IDS["regulatory"],
    "run-manifest.schema.json": SCHEMA_IDS["run_manifest"],
}
EXPECTED_CONFORMANCE_CASES = {
    "invalid-common-identifier": ("examples/invalid/common-invalid-identifier.json", SCHEMA_IDS["common"], False, "pattern", "/value"),
    "invalid-conformance-manifest-duplicate-schema": ("examples/invalid/conformance-manifest-duplicate-schema.json", SCHEMA_IDS["manifest"], False, "uniqueItems", "/schema_files"),
    "invalid-diagnostic-pii-context": ("examples/invalid/diagnostic-pii-context.json", SCHEMA_IDS["diagnostic"], False, "semantic:PII_IN_PUBLIC_ARTIFACT", "/safe_context/subject_id"),
    "invalid-execution-computed-with-null-result": ("examples/invalid/execution-envelope-computed-with-null-result.json", SCHEMA_IDS["execution"], False, "type", "/result"),
    "invalid-governance-approved-blockers": ("examples/invalid/governance-envelope-approved-blockers.json", SCHEMA_IDS["governance"], False, "semantic:GOVERNANCE_APPROVAL_BLOCKED", "/model_use_status"),
    "invalid-governance-class-mismatch": ("examples/invalid/governance-envelope-class-mismatch.json", SCHEMA_IDS["governance"], False, "semantic:GOVERNANCE_DEPLOYMENT_CLASS_PARITY", "/effective_deployment_class"),
    "invalid-governance-missing-prohibited-use": ("examples/invalid/governance-envelope-missing-prohibited-use.json", SCHEMA_IDS["governance"], False, "contains", "/prohibited_uses"),
    "invalid-input-duplicate-key": ("examples/invalid/input-duplicate-key.json", SCHEMA_IDS["input"], False, "duplicateKey", ""),
    "invalid-input-missing-regulatory-context": ("examples/invalid/input-missing-regulatory-context.json", SCHEMA_IDS["input"], False, "required", ""),
    "invalid-input-non-rfc3339": ("examples/invalid/input-non-rfc3339-date-time.json", SCHEMA_IDS["input"], False, "pattern", "/information_set/known_at"),
    "invalid-input-sensitive-and-decimal": ("examples/invalid/input-adversarial-sensitive-and-decimal.json", SCHEMA_IDS["input"], False, "semantic:PII_IN_PUBLIC_ARTIFACT", "/request_id"),
    "invalid-model-card-approval-bypasses": ("examples/invalid/model-card-approval-bypasses.json", SCHEMA_IDS["model"], False, "semantic:MODEL_APPROVAL_INTEGRITY_FAILED", "/independent_reviewer"),
    "invalid-model-card-approved-without-reviewer": ("examples/invalid/model-card-approved-without-reviewer.json", SCHEMA_IDS["model"], False, "type", "/independent_reviewer"),
    "invalid-model-card-draft-approved-status": ("examples/invalid/model-card-draft-approved-status.json", SCHEMA_IDS["model"], False, "semantic:MODEL_APPROVAL_INTEGRITY_FAILED", "/model_use_status"),
    "invalid-reason-code-direct": ("examples/invalid/reason-code-unknown.json", SCHEMA_IDS["reason"], False, "enum", ""),
    "invalid-regulatory-class-a-ranking": ("examples/invalid/regulatory-use-context-class-a-ranking.json", SCHEMA_IDS["regulatory"], False, "const", "/ranking_enabled"),
    "invalid-regulatory-derived-overstated": ("examples/invalid/regulatory-use-context-derived-overstated.json", SCHEMA_IDS["regulatory"], False, "semantic:REGULATED_USE_CLASS_MISMATCH", "/derived_minimum_deployment_class"),
    "invalid-regulatory-effective-downgrade": ("examples/invalid/regulatory-use-context-effective-downgrade.json", SCHEMA_IDS["regulatory"], False, "const", "/effective_deployment_class"),
    "invalid-regulatory-null-material-field": ("examples/invalid/regulatory-use-context-null-material-field.json", SCHEMA_IDS["regulatory"], False, "anyOf", "/operator_legal_entity"),
    "invalid-run-manifest-public-linkable": ("examples/invalid/run-manifest-public-linkable.json", SCHEMA_IDS["run_manifest"], False, "const", "/linkability_scope"),
    "invalid-test-only-execution-computed-with-warnings": ("examples/invalid/execution-envelope-computed-with-warnings.json", SCHEMA_IDS["execution"], False, "enum", "/computational_status"),
    "invalid-unknown-reason-code": ("examples/invalid/diagnostic-unknown-reason-code.json", SCHEMA_IDS["diagnostic"], False, "enum", "/code"),
    "valid-common-identifier": ("examples/valid/common-identifier.json", SCHEMA_IDS["common"], True, None, None),
    "valid-conformance-manifest": ("examples/valid/conformance-manifest-minimal.json", SCHEMA_IDS["manifest"], True, None, None),
    "valid-diagnostic-execution-disabled": ("examples/valid/diagnostic-execution-disabled.json", SCHEMA_IDS["diagnostic"], True, None, None),
    "valid-execution-indeterminate": ("examples/valid/execution-envelope-indeterminate.json", SCHEMA_IDS["execution"], True, None, None),
    "valid-execution-rejected": ("examples/valid/execution-envelope-rejected.json", SCHEMA_IDS["execution"], True, None, None),
    "valid-governance-research": ("examples/valid/governance-envelope-research.json", SCHEMA_IDS["governance"], True, None, None),
    "valid-input-contract-probe": ("examples/valid/input-contract-probe.json", SCHEMA_IDS["input"], True, None, None),
    "valid-model-card-research": ("examples/valid/model-card-research.json", SCHEMA_IDS["model"], True, None, None),
    "valid-reason-code-rounding": ("examples/valid/reason-code-rounding.json", SCHEMA_IDS["reason"], True, None, None),
    "valid-regulatory-class-a": ("examples/valid/regulatory-use-context-class-a.json", SCHEMA_IDS["regulatory"], True, None, None),
    "valid-run-manifest-private": ("examples/valid/run-manifest-private.json", SCHEMA_IDS["run_manifest"], True, None, None),
}
EXPECTED_REASON_CODES = frozenset(
    {
        "AUTHORITY_CONFLICT", "CONTRACT_DUPLICATE_KEY", "CONTRACT_INPUT_LIMIT_EXCEEDED",
        "CONTRACT_REQUIRED_FIELD_MISSING", "CONTRACT_SCHEMA_UNSUPPORTED", "DATA_CHECKSUM_MISMATCH",
        "DATA_LICENSE_RESTRICTED", "DATA_LICENSE_UNKNOWN", "DATA_QUALITY_BELOW_GATE",
        "DATA_REVISION_UNRESOLVED", "DATA_SCHEMA_MISMATCH", "DATA_SIGNATURE_INVALID",
        "DATA_SNAPSHOT_MISSING", "DATE_INTERVAL_INVALID", "DEPLOYMENT_CAPABILITY_FORBIDDEN",
        "DIAGNOSTIC_CATALOG_MISMATCH", "ECONOMIC_CLAIM_CYCLE", "ECONOMIC_CLAIM_DUPLICATE",
        "EXECUTION_DISABLED", "EXECUTION_STATUS_INCOHERENT", "GOVERNANCE_APPROVAL_BLOCKED",
        "GOVERNANCE_ARTIFACT_APPROVAL_REVIEW", "GOVERNANCE_DEPLOYMENT_CLASS_PARITY",
        "HOUSEHOLD_STATE_UNDEFINED", "HUMAN_REVIEW_REQUIRED", "LEDGER_RECONCILIATION_FAILED",
        "LEGAL_AUTHORITY_MISSING", "LEGAL_STATUS_CONTESTED", "LEGAL_STATUS_UNKNOWN", "MIP_GAP_EXCEEDED",
        "MODEL_APPROVAL_INTEGRITY_FAILED", "MODEL_OUT_OF_SCOPE", "MODEL_PARAMETER_UNIDENTIFIED",
        "MODEL_REVIEW_EXPIRED", "NON_ANTICIPATIVITY_VIOLATION", "NUMERIC_ROUNDING_APPLIED",
        "PII_IN_PUBLIC_ARTIFACT", "POLICY_KNOWLEDGE_GAP", "POLICY_REVIEW_EXPIRED",
        "POLICY_SIGNATURE_INVALID", "RATE_DOMAIN_INVALID", "REGULATED_USE_CLASS_MISMATCH",
        "REGULATED_USE_UNDECLARED", "RETROACTIVITY_UNMODELED", "RETURN_INCOME_DOUBLE_COUNT",
        "RNG_SPEC_MISSING", "RULE_UNSUPPORTED_CASE", "RUN_MANIFEST_PRIVACY_INVALID",
        "SCENARIO_WEIGHT_INVALID", "SECRET_IN_INPUT_OR_LOG", "SIMULATION_NOT_CONVERGED",
        "SOLVER_GLOBAL_STATUS_UNKNOWN", "SOLVER_INFEASIBLE", "SOLVER_TOLERANCE_EXCEEDED",
        "SOLVER_UNBOUNDED", "SUITABILITY_RECORD_MISSING", "SURVIVAL_TREATMENT_DOUBLE_WEIGHTED",
        "UNIT_CURRENCY_MISMATCH", "UNIT_PRICE_BASIS_MISMATCH", "UNIT_VALUATION_DATE_MISMATCH",
        "VALUATION_CONTEXT_MISSING", "VALUATION_MEASURE_INCOMPATIBLE",
    }
)
# Pins the catalog metadata plus its only declared shared-remediation map.  This
# is candidate-pack integrity, not release trust or external authority.
EXPECTED_REASON_SEMANTIC_MAP_SHA256 = "3765A2A0A9D66876CCAD92B58215F4075E0967EFC6902D6D8ED3E37A0D5A413C"
EXPECTED_CASE_COUNTS = {True: 11, False: 22}
CATALOG_BLOCK_START = "## 🔍 Namespaces mínimos"
CATALOG_BLOCK_END = "## 🔧 Exit codes CLI propostos"
RFC3339_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:[0-2][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
ISO_DATE_RE = re.compile(r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$")
DECIMAL_RE = re.compile(
    r"^(?:(?:0|[1-9][0-9]*)(?:\.[0-9]+)?|-(?:(?:[1-9][0-9]*)(?:\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*))$"
)
CANONICAL_JSON_DECIMAL_RE = re.compile(
    r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$"
)
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")
CPF_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d{3}[.\s-]?){2}\d{3}[-.\s]?\d{2}(?!\d)")
BASE64_RE = re.compile(r"^[A-Za-z0-9_+/=-]+$")
HEX_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
EXAMPLE_INSTANCE_PATH_RE = re.compile(
    r"^examples/(?P<expectation>valid|invalid)/[a-z0-9]+(?:-[a-z0-9]+)*\.json$",
    re.ASCII,
)
EXAMPLE_FILENAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\.json$", re.ASCII)
REASON_CODE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$", re.ASCII)
CATALOG_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$"
CATALOG_IDENTIFIER_RE = re.compile(CATALOG_IDENTIFIER_PATTERN, re.ASCII)
BACKTICK_TOKEN_RE = re.compile(r"`([^`\r\n]+)`")
MARKDOWN_BULLET_RE = re.compile(r"^[ \t]*[-*+][ \t]+")
MARKDOWN_LIST_ITEM_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<marker>[-*+]|[0-9]+[.)])[ \t]+(?P<body>.*?)[ \t]*$"
)
MARKDOWN_FENCE_RE = re.compile(r"^[ ]{0,3}(?P<fence>`{3,}|~{3,})")
WINDOWS_DEFAULT_DATA_STREAM = "::$DATA"
WIN32_ERROR_HANDLE_EOF = 38
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I),
    re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{12,}", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", re.I),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{12,}\b", re.I),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", re.I),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.I),
    re.compile(r"\b(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}", re.I),
)

CONFUSABLES = str.maketrans(
    {
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j",
        "\u0410": "a", "\u0412": "b", "\u0415": "e", "\u041a": "k", "\u041c": "m", "\u041d": "h", "\u041e": "o", "\u0420": "p", "\u0421": "c", "\u0422": "t", "\u0425": "x",
        "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t", "\u03c5": "y", "\u03c7": "x",
        "\u0391": "a", "\u0392": "b", "\u0395": "e", "\u0397": "h", "\u0399": "i", "\u039a": "k", "\u039c": "m", "\u039d": "n", "\u039f": "o", "\u03a1": "p", "\u03a4": "t", "\u03a7": "x",
    }
)

Finding = tuple[str, str, str]
StreamSnapshot = tuple[tuple[str, int], ...] | None


class ExampleInventoryEntry(NamedTuple):
    kind: str
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int
    device: int
    inode: int
    file_attributes: int
    streams: StreamSnapshot


class ExampleInventorySnapshot(NamedTuple):
    root_streams: StreamSnapshot
    entries: dict[str, ExampleInventoryEntry]


class SchemasInventorySnapshot(NamedTuple):
    repository_root_streams: StreamSnapshot
    schemas_root_streams: StreamSnapshot
    entries: dict[str, ExampleInventoryEntry]


class DuplicateKeyError(ValueError):
    def __init__(self, _key: str = "") -> None:
        super().__init__("duplicate JSON key after canonical normalization")


class InputLimitError(ValueError):
    """Raised before parsing an untrusted JSON document beyond its byte budget."""


class NumericLiteralError(ValueError):
    """Raised for non-finite, non-canonical, or over-budget JSON numbers."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        normalized = canonical_identity(key)
        if any(canonical_identity(existing) == normalized for existing in result):
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def unicode_skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    normalized = "".join(
        character
        for character in normalized
        if unicodedata.category(character) != "Cf"
    )
    normalized = normalized.casefold().translate(CONFUSABLES)
    return "".join(
        character
        for character in unicodedata.normalize("NFKD", normalized)
        if unicodedata.category(character) not in {"Mn", "Cf"}
    )


def canonical_identity(value: str) -> str:
    return re.sub(r"\s+", " ", unicode_skeleton(value)).strip()


def _numeric_digit_count(literal: str) -> int:
    return sum(character.isdigit() for character in literal)


def _parse_json_int(literal: str) -> int:
    if _numeric_digit_count(literal) > MAX_DECIMAL_DIGITS:
        raise NumericLiteralError(f"JSON integer exceeds {MAX_DECIMAL_DIGITS} digits")
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", literal) is None or literal == "-0":
        raise NumericLiteralError("JSON integer is not canonical")
    return int(literal)


def _parse_json_float(literal: str) -> Decimal:
    if _numeric_digit_count(literal) > MAX_DECIMAL_DIGITS:
        raise NumericLiteralError(f"JSON number exceeds {MAX_DECIMAL_DIGITS} digits")
    if CANONICAL_JSON_DECIMAL_RE.fullmatch(literal) is None:
        raise NumericLiteralError("JSON number must be finite canonical decimal without exponent or negative zero")
    try:
        value = Decimal(literal)
    except InvalidOperation as exc:
        raise NumericLiteralError("JSON number is invalid") from exc
    if not value.is_finite():
        raise NumericLiteralError("JSON number must be finite")
    return value


def _reject_json_constant(literal: str) -> None:
    raise NumericLiteralError(f"non-finite JSON constant is forbidden: {literal}")


def _preparse_depth(raw: bytes, max_depth: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        character = chr(byte)
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > max_depth:
                raise InputLimitError(f"JSON depth exceeds {max_depth}")
        elif character in "]}":
            depth -= 1


def _safe_read_bytes(path: Path, max_bytes: int | None, label: str = "JSON document") -> bytes:
    absolute = path.absolute()
    boundary = Path(absolute.anchor) if absolute.anchor else absolute.parent
    if not _path_chain_is_safe(absolute, boundary):
        raise InputLimitError(f"{label} parent chain contains a symlink/junction/reparse point")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise InputLimitError(f"{label} must be a regular file with nlink=1")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 65_536)
            if not block:
                break
            total += len(block)
            if max_bytes is not None and total > max_bytes:
                raise InputLimitError(f"UTF-8 input exceeds {max_bytes} bytes")
            chunks.append(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after) or identity(before) != identity(absolute.stat()):
        raise InputLimitError(f"{label} changed while being snapshotted")
    return b"".join(chunks)


def load_json(
    path: Path,
    max_bytes: int | None = MAX_DOCUMENT_BYTES,
    max_depth: int | None = MAX_JSON_DEPTH,
) -> Any:
    raw = _safe_read_bytes(path, max_bytes)
    return load_json_bytes(raw, max_depth=max_depth)


def load_json_bytes(raw: bytes, max_depth: int | None = MAX_JSON_DEPTH) -> Any:
    """Parse exactly one already-acquired immutable diagnostic byte snapshot."""

    if raw.startswith(b"\xef\xbb\xbf"):
        raise InputLimitError("UTF-8 BOM is forbidden in strict JSON")
    if max_depth is not None:
        _preparse_depth(raw, max_depth)
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_int=_parse_json_int,
        parse_float=_parse_json_float,
        parse_constant=_reject_json_constant,
    )


def _canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest().upper()


def _windows_stream_snapshot(path: Path, kind: str, label: str) -> StreamSnapshot:
    """Enumerate Win32 streams without opening any attacker-selected stream."""

    if os.name != "nt":
        # None is an explicit not-applicable marker: NTFS ADS semantics do not
        # exist on this platform, so an empty tuple would overstate coverage.
        return None

    try:
        import ctypes
        from ctypes import wintypes

        class WIN32_FIND_STREAM_DATA(ctypes.Structure):
            _fields_ = [
                ("StreamSize", ctypes.c_longlong),
                ("cStreamName", wintypes.WCHAR * (260 + 36)),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        find_first_stream = kernel32.FindFirstStreamW
        find_first_stream.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_int,
            ctypes.POINTER(WIN32_FIND_STREAM_DATA),
            wintypes.DWORD,
        ]
        find_first_stream.restype = wintypes.HANDLE
        find_next_stream = kernel32.FindNextStreamW
        find_next_stream.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(WIN32_FIND_STREAM_DATA),
        ]
        find_next_stream.restype = wintypes.BOOL
        find_close = kernel32.FindClose
        find_close.argtypes = [wintypes.HANDLE]
        find_close.restype = wintypes.BOOL
    except Exception as exc:
        raise InputLimitError(
            f"{label} Win32 stream capability initialization failed: {type(exc).__name__}"
        ) from exc

    absolute = str(path.absolute())
    if absolute.startswith("\\\\?\\"):
        api_path = absolute
    elif absolute.startswith("\\\\"):
        api_path = "\\\\?\\UNC\\" + absolute[2:]
    else:
        api_path = "\\\\?\\" + absolute

    data = WIN32_FIND_STREAM_DATA()
    ctypes.set_last_error(0)
    handle = find_first_stream(api_path, 0, ctypes.byref(data), 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        if error == WIN32_ERROR_HANDLE_EOF and kind == "directory":
            return ()
        raise InputLimitError(
            f"{label} Win32 stream enumeration failed at FindFirstStreamW (error={error})"
        )

    streams: list[tuple[str, int]] = []
    try:
        while True:
            stream_name = str(data.cStreamName)
            stream_size = int(data.StreamSize)
            if not stream_name or stream_size < 0:
                raise InputLimitError(
                    f"{label} Win32 stream enumeration returned invalid metadata"
                )
            streams.append((stream_name, stream_size))

            ctypes.set_last_error(0)
            if find_next_stream(handle, ctypes.byref(data)):
                continue
            error = ctypes.get_last_error()
            if error != WIN32_ERROR_HANDLE_EOF:
                raise InputLimitError(
                    f"{label} Win32 stream enumeration failed at FindNextStreamW (error={error})"
                )
            break
    finally:
        ctypes.set_last_error(0)
        if not find_close(handle):
            error = ctypes.get_last_error()
            raise InputLimitError(
                f"{label} Win32 stream enumeration failed at FindClose (error={error})"
            )

    ordered = tuple(sorted(streams))
    if len({name for name, _ in ordered}) != len(ordered):
        raise InputLimitError(
            f"{label} Win32 stream enumeration returned duplicate stream names"
        )
    return ordered


def _stream_policy_failures(
    label: str,
    kind: str,
    size: int,
    streams: StreamSnapshot,
) -> list[str]:
    """Accept only the unnamed default stream where Win32 exposes one."""

    if streams is None:
        return []
    named = tuple((name, stream_size) for name, stream_size in streams if name != WINDOWS_DEFAULT_DATA_STREAM)
    if named:
        safe_named = [(ascii(name), stream_size) for name, stream_size in named]
        return [
            f"{label} contains forbidden named or non-default streams: {safe_named}"
        ]
    if kind == "regular_file" and streams != ((WINDOWS_DEFAULT_DATA_STREAM, size),):
        return [
            f"{label} must expose exactly the unnamed default ::$DATA stream with the file size"
        ]
    if kind == "directory" and streams not in (
        (),
        ((WINDOWS_DEFAULT_DATA_STREAM, 0),),
    ):
        return [
            f"{label} exposes an unexpected unnamed default stream shape"
        ]
    return []


def _snapshot_tree_entries(root: Path, label: str) -> dict[str, ExampleInventoryEntry]:
    """Snapshot every descendant without following attacker-controlled links."""

    snapshots: dict[str, ExampleInventoryEntry] = {}
    pending = [root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if relative in snapshots:
                raise InputLimitError(f"{label} inventory contains a duplicate path")
            info = path.lstat()
            reparse = _is_reparse_point(path)
            if reparse:
                kind = "reparse"
            elif stat.S_ISDIR(info.st_mode):
                kind = "directory"
            elif stat.S_ISREG(info.st_mode):
                kind = "regular_file"
            else:
                kind = "other"
            streams = (
                None
                if reparse
                else _windows_stream_snapshot(
                    path,
                    kind,
                    f"{label} inventory {relative}",
                )
            )
            snapshots[relative] = ExampleInventoryEntry(
                kind=kind,
                mode=info.st_mode,
                nlink=info.st_nlink,
                size=info.st_size,
                mtime_ns=info.st_mtime_ns,
                ctime_ns=info.st_ctime_ns,
                device=info.st_dev,
                inode=info.st_ino,
                file_attributes=getattr(info, "st_file_attributes", 0),
                streams=streams,
            )
            if kind == "directory":
                pending.append(path)
    return snapshots


def _snapshot_schemas_inventory(
    repo_root: Path, schemas_root: Path
) -> SchemasInventorySnapshot:
    """Bind repository/schemas roots and every entry under ``schemas/``."""

    for path, label in (
        (repo_root, "repository root"),
        (schemas_root, "schemas root"),
    ):
        if not path.exists() or not path.is_dir() or _is_reparse_point(path):
            raise InputLimitError(
                f"{label} must be an existing non-reparse directory"
            )
    return SchemasInventorySnapshot(
        repository_root_streams=_windows_stream_snapshot(
            repo_root, "directory", "repository root"
        ),
        schemas_root_streams=_windows_stream_snapshot(
            schemas_root, "directory", "schemas root"
        ),
        entries=_snapshot_tree_entries(schemas_root, "schemas"),
    )


def _expected_schemas_inventory() -> dict[str, str]:
    expected = {
        "conformance-manifest.json": "regular_file",
        "examples": "directory",
        "examples/invalid": "directory",
        "examples/valid": "directory",
    }
    expected.update(
        {name: "regular_file" for name in EXPECTED_SCHEMA_FILE_IDS}
    )
    expected.update(
        {
            semantics[0]: "regular_file"
            for semantics in EXPECTED_CONFORMANCE_CASES.values()
        }
    )
    return expected


def _schemas_inventory_failures(
    inventory_snapshot: SchemasInventorySnapshot,
) -> list[str]:
    """Compare the complete schemas tree to the independently pinned roster."""

    failures: list[str] = []
    failures.extend(
        _stream_policy_failures(
            "repository root",
            "directory",
            0,
            inventory_snapshot.repository_root_streams,
        )
    )
    failures.extend(
        _stream_policy_failures(
            "schemas root",
            "directory",
            0,
            inventory_snapshot.schemas_root_streams,
        )
    )
    inventory = inventory_snapshot.entries
    expected = _expected_schemas_inventory()
    actual_types = {relative: entry.kind for relative, entry in inventory.items()}
    missing = sorted(set(expected) - set(actual_types))
    extra = sorted(set(actual_types) - set(expected))
    wrong_type = sorted(
        relative
        for relative in set(expected) & set(actual_types)
        if expected[relative] != actual_types[relative]
    )
    if missing or extra or wrong_type:
        failures.append(
            "schemas full inventory mismatch against embedded roster; "
            f"missing={missing}, extra={extra}, wrong_type={wrong_type}"
        )

    normalized_actual: dict[str, list[str]] = {}
    for relative in inventory:
        normalized_actual.setdefault(canonical_identity(relative), []).append(relative)
    aliases = sorted(
        sorted(paths)
        for paths in normalized_actual.values()
        if len(paths) != 1
    )
    expected_by_identity = {
        canonical_identity(relative): relative for relative in expected
    }
    spelling_aliases = sorted(
        relative
        for relative in inventory
        if canonical_identity(relative) in expected_by_identity
        and relative != expected_by_identity[canonical_identity(relative)]
    )
    if aliases or spelling_aliases:
        failures.append(
            "schemas inventory contains Unicode/case aliases; "
            f"collisions={aliases}, noncanonical_spellings={spelling_aliases}"
        )

    for relative, entry in inventory.items():
        failures.extend(
            _stream_policy_failures(
                f"schemas/{relative}",
                entry.kind,
                entry.size,
                entry.streams,
            )
        )
        if entry.kind == "reparse":
            failures.append(
                f"schemas/{relative}: symlink/junction/reparse points are forbidden"
            )
        elif entry.kind == "regular_file" and entry.nlink != 1:
            failures.append(
                f"schemas/{relative}: regular files must have nlink=1"
            )
    return failures


def _example_inventory_from_schemas_inventory(
    inventory_snapshot: SchemasInventorySnapshot,
) -> ExampleInventorySnapshot:
    examples_entry = inventory_snapshot.entries.get("examples")
    root_streams = examples_entry.streams if examples_entry is not None else None
    prefix = "examples/"
    return ExampleInventorySnapshot(
        root_streams=root_streams,
        entries={
            relative.removeprefix(prefix): entry
            for relative, entry in inventory_snapshot.entries.items()
            if relative.startswith(prefix)
        },
    )


def _snapshot_contract_json_tree(schemas_root: Path) -> dict[str, bytes]:
    """Acquire the only bytes parsed during one diagnostic repository run."""

    snapshots: dict[str, bytes] = {}
    expected_files = sorted(
        relative
        for relative, kind in _expected_schemas_inventory().items()
        if kind == "regular_file"
    )
    for relative in expected_files:
        path = schemas_root / relative
        try:
            snapshots[relative] = _safe_read_bytes(
                path,
                MAX_DOCUMENT_BYTES,
                f"contract JSON snapshot {relative}",
            )
        except (InputLimitError, OSError):
            # The complete metadata inventory already records the closed-roster
            # failure.  Continue with other immutable bytes for total diagnostics.
            continue
    if not snapshots:
        raise InputLimitError("contract JSON snapshot is empty")
    return snapshots


def _snapshot_example_inventory(examples_root: Path) -> ExampleInventorySnapshot:
    """Snapshot every directory entry below examples without following links."""

    if (
        not examples_root.exists()
        or not examples_root.is_dir()
        or _is_reparse_point(examples_root)
    ):
        raise InputLimitError("examples root must be an existing non-reparse directory")
    root_streams = _windows_stream_snapshot(
        examples_root, "directory", "schemas/examples root"
    )
    snapshots: dict[str, ExampleInventoryEntry] = {}
    pending = [examples_root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(examples_root).as_posix()
            if relative in snapshots:
                raise InputLimitError("examples inventory contains a duplicate path")
            # pathlib's lstat exposes stable nlink/dev/ino on Windows where
            # DirEntry.stat(follow_symlinks=False) may return placeholder zeros.
            info = path.lstat()
            reparse = _is_reparse_point(path)
            if reparse:
                kind = "reparse"
            elif stat.S_ISDIR(info.st_mode):
                kind = "directory"
            elif stat.S_ISREG(info.st_mode):
                kind = "regular_file"
            else:
                kind = "other"
            streams = (
                None
                if reparse
                else _windows_stream_snapshot(
                    path,
                    kind,
                    f"schemas/examples inventory {relative}",
                )
            )
            snapshots[relative] = ExampleInventoryEntry(
                kind=kind,
                mode=info.st_mode,
                nlink=info.st_nlink,
                size=info.st_size,
                mtime_ns=info.st_mtime_ns,
                ctime_ns=info.st_ctime_ns,
                device=info.st_dev,
                inode=info.st_ino,
                file_attributes=getattr(info, "st_file_attributes", 0),
                streams=streams,
            )
            if kind == "directory":
                pending.append(path)
    return ExampleInventorySnapshot(root_streams=root_streams, entries=snapshots)


def _example_inventory_failures(
    inventory_snapshot: ExampleInventorySnapshot, declared_instances: set[str]
) -> list[str]:
    """Bind the complete examples tree to the manifest's direct fixture set."""

    failures: list[str] = []
    inventory = inventory_snapshot.entries
    failures.extend(
        _stream_policy_failures(
            "schemas/examples root",
            "directory",
            0,
            inventory_snapshot.root_streams,
        )
    )
    expected: dict[str, str] = {"valid": "directory", "invalid": "directory"}
    for instance_path in declared_instances:
        if EXAMPLE_INSTANCE_PATH_RE.fullmatch(instance_path) is not None:
            expected[instance_path.removeprefix("examples/")] = "regular_file"

    actual_types = {relative: entry.kind for relative, entry in inventory.items()}
    missing = sorted(set(expected) - set(actual_types))
    extra = sorted(set(actual_types) - set(expected))
    wrong_type = sorted(
        relative
        for relative in set(expected) & set(actual_types)
        if expected[relative] != actual_types[relative]
    )
    if missing or extra or wrong_type:
        failures.append(
            "examples full inventory mismatch against manifest; "
            f"missing={missing}, extra={extra}, wrong_type={wrong_type}"
        )

    normalized_actual: dict[str, list[str]] = {}
    for relative in inventory:
        normalized_actual.setdefault(canonical_identity(relative), []).append(relative)
    aliases = sorted(
        sorted(paths)
        for paths in normalized_actual.values()
        if len(paths) != 1
    )
    expected_by_identity = {canonical_identity(path): path for path in expected}
    spelling_aliases = sorted(
        relative
        for relative in inventory
        if canonical_identity(relative) in expected_by_identity
        and relative != expected_by_identity[canonical_identity(relative)]
    )
    if aliases or spelling_aliases:
        failures.append(
            "examples inventory contains Unicode/case aliases; "
            f"collisions={aliases}, noncanonical_spellings={spelling_aliases}"
        )

    direct_counts = {"valid": 0, "invalid": 0}
    for relative, entry in inventory.items():
        failures.extend(
            _stream_policy_failures(
                f"schemas/examples/{relative}",
                entry.kind,
                entry.size,
                entry.streams,
            )
        )
        parts = relative.split("/")
        if len(parts) == 1:
            if relative not in direct_counts:
                failures.append(f"examples top-level entry is forbidden: {relative}")
            elif entry.kind != "directory":
                failures.append(f"examples/{relative} must be a direct non-reparse directory")
            continue
        if len(parts) != 2 or parts[0] not in direct_counts:
            failures.append(f"nested or out-of-contract examples entry is forbidden: {relative}")
            continue
        expectation, filename = parts
        if entry.kind == "directory":
            failures.append(f"nested or empty examples directory is forbidden: {relative}")
            continue
        if entry.kind != "regular_file" or entry.nlink != 1:
            failures.append(
                f"examples fixture must be a direct non-reparse regular file with nlink=1: {relative}"
            )
            continue
        direct_counts[expectation] += 1
        if not filename.isascii() or EXAMPLE_FILENAME_RE.fullmatch(filename) is None:
            failures.append(
                f"examples fixture filename must be canonical ASCII lowercase *.json: {relative}"
            )
    for expectation, count in direct_counts.items():
        if count == 0:
            failures.append(f"examples/{expectation} must contain at least one direct fixture")
    return failures


def pointer(parts: Iterable[Any]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "" if not escaped else "/" + "/".join(escaped)


def prefix_pointer(prefix: str, child: str) -> str:
    if not prefix:
        return child
    return prefix + child if child else prefix


def walk(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def walk_paths(value: Any, parts: tuple[Any, ...] = ()) -> Iterable[tuple[tuple[Any, ...], Any]]:
    stack = [(parts, value)]
    while stack:
        current_parts, current = stack.pop()
        yield current_parts, current
        if isinstance(current, dict):
            stack.extend(
                (current_parts + (key,), child)
                for key, child in reversed(tuple(current.items()))
            )
        elif isinstance(current, list):
            stack.extend(
                (current_parts + (index,), child)
                for index, child in reversed(tuple(enumerate(current)))
            )


def flatten_errors(errors: Iterable[Any]) -> Iterable[Any]:
    for error in errors:
        yield error
        yield from flatten_errors(error.context)


def json_depth(value: Any) -> int:
    maximum = 0
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        maximum = max(maximum, depth)
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return maximum


def _valid_cpf(digits: str) -> bool:
    if len(digits) != 11 or not digits.isdigit() or len(set(digits)) == 1:
        return False
    first = (sum(int(digits[i]) * (10 - i) for i in range(9)) * 10) % 11
    first = 0 if first == 10 else first
    second = (sum(int(digits[i]) * (11 - i) for i in range(10)) * 10) % 11
    second = 0 if second == 10 else second
    return digits[-2:] == f"{first}{second}"


def _contains_cpf(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value)
    return any(
        _valid_cpf(re.sub(r"\D", "", match.group(0)))
        for match in CPF_CANDIDATE_RE.finditer(normalized)
    )


def _decoded_base64_text(value: str) -> str | None:
    compact = "".join(value.split())
    if not (16 <= len(compact) <= MAX_BASE64_SCAN_BYTES) or BASE64_RE.fullmatch(compact) is None:
        return None
    padded = compact.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded or len(decoded) > MAX_BASE64_SCAN_BYTES:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(character.isprintable() or character.isspace() for character in text)
    return text if printable / max(1, len(text)) >= 0.85 else None


def _looks_like_raw_hash(value: str) -> bool:
    if re.fullmatch(r"(?i)[a-f0-9]{64}", value):
        return True
    compact = value.strip().replace("-", "+").replace("_", "/")
    if not (43 <= len(compact) <= 44) or BASE64_RE.fullmatch(compact) is None:
        return False
    compact += "=" * (-len(compact) % 4)
    try:
        return len(base64.b64decode(compact, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def _privacy_text_candidates(value: str) -> list[str]:
    candidates: list[str] = []
    current: str | None = value
    consumed = 0
    for _layer in range(MAX_BASE64_SCAN_LAYERS + 1):
        if current is None:
            break
        normalized = unicodedata.normalize("NFKC", current)
        consumed += len(normalized.encode("utf-8", errors="ignore"))
        if consumed > MAX_BASE64_SCAN_BYTES * (MAX_BASE64_SCAN_LAYERS + 1):
            break
        candidates.extend([normalized, unicode_skeleton(normalized)])
        current = _decoded_base64_text(current)
    return list(dict.fromkeys(candidates))


def _text_privacy_flags(value: str) -> tuple[bool, bool]:
    candidates = _privacy_text_candidates(value)
    pii = any(EMAIL_RE.search(candidate) or _contains_cpf(candidate) for candidate in candidates)
    secret = any(
        pattern.search(candidate)
        for candidate in candidates
        for pattern in SECRET_PATTERNS
    )
    return pii, secret


def _redacted_pointer(parts: tuple[Any, ...]) -> str:
    safe_parts: list[Any] = []
    for part in parts:
        if isinstance(part, str) and any(_text_privacy_flags(part)):
            safe_parts.append("<redacted-key>")
        else:
            safe_parts.append(part)
    return pointer(safe_parts)


def privacy_findings(value: Any) -> list[Finding]:
    findings: list[Finding] = []
    for parts, node in walk_paths(value):
        candidates: list[tuple[tuple[Any, ...], str]] = []
        if isinstance(node, str):
            candidates.append((parts, node))
        elif isinstance(node, dict):
            candidates.extend((parts + (key,), key) for key in node)
        for candidate_parts, candidate in candidates:
            location = _redacted_pointer(candidate_parts)
            pii, secret = _text_privacy_flags(candidate)
            if pii:
                findings.append(("PII_IN_PUBLIC_ARTIFACT", location, "possible PII, including encoded PII, is forbidden"))
            if secret:
                findings.append(("SECRET_IN_INPUT_OR_LOG", location, "possible credential or encoded secret is forbidden"))
    return findings


def prescriptive_key_findings(value: Any, parts: tuple[Any, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    for node_parts, node in walk_paths(value, parts):
        if not isinstance(node, dict):
            continue
        for key in node:
            skeleton = unicode_skeleton(key).replace("-", "_")
            if skeleton in FORBIDDEN_CLASS_A_PROPERTY_NAMES:
                findings.append(("DEPLOYMENT_CAPABILITY_FORBIDDEN", pointer(node_parts + (key,)), "prescriptive output key is forbidden after Unicode normalization"))
    return findings


def budget_findings(value: Any, raw_size: int | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if raw_size is not None and raw_size > MAX_INPUT_BYTES:
        findings.append(("CONTRACT_INPUT_LIMIT_EXCEEDED", "", f"UTF-8 input exceeds {MAX_INPUT_BYTES} bytes"))
    depth = json_depth(value)
    if depth > MAX_JSON_DEPTH:
        findings.append(("CONTRACT_INPUT_LIMIT_EXCEEDED", "", f"JSON depth {depth} exceeds {MAX_JSON_DEPTH}"))
    for parts, node in walk_paths(value):
        if isinstance(node, str):
            decimal_like = re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", node)
            if decimal_like and _numeric_digit_count(node) > MAX_DECIMAL_DIGITS:
                findings.append(("CONTRACT_INPUT_LIMIT_EXCEEDED", pointer(parts), f"decimal exceeds {MAX_DECIMAL_DIGITS} digits"))
    return findings


def derived_minimum_class(context: dict[str, Any]) -> str:
    if context.get("execution_enabled") is True:
        return "D_EXECUTION"
    specific_instrument = context.get("instrument_scope") in {"security", "insurance", "pension_product"}
    prescriptive = (
        context.get("recommendation_language_enabled") is True
        or context.get("alternatives_origin") == "system_generated"
        or (context.get("client_specific") is True and context.get("ranking_enabled") is True)
        or (specific_instrument and (context.get("client_specific") is True or context.get("ranking_enabled") is True))
    )
    if prescriptive:
        return "C_REGULATED_ADVICE"
    if (
        context.get("client_specific") is True
        or context.get("ranking_enabled") is True
        or specific_instrument
        or context.get("compensation_model") != "none"
    ):
        return "B_PROFESSIONAL_ASSIST"
    return "A_RESEARCH_CORE"


def regulatory_findings(context: dict[str, Any]) -> list[Finding]:
    if not isinstance(context, dict):
        return []
    findings: list[Finding] = []
    expected_derived = derived_minimum_class(context)
    actual_derived = context.get("derived_minimum_deployment_class")
    if actual_derived != expected_derived:
        findings.append(("REGULATED_USE_CLASS_MISMATCH", "/derived_minimum_deployment_class", f"must equal exact capability-derived class {expected_derived}"))
    declared = context.get("declared_deployment_class")
    if declared in CLASS_RANK and expected_derived in CLASS_RANK:
        expected_effective = max((declared, expected_derived), key=CLASS_RANK.__getitem__)
        if context.get("effective_deployment_class") != expected_effective:
            findings.append(("REGULATED_USE_CLASS_MISMATCH", "/effective_deployment_class", f"must equal {expected_effective}"))
    return findings


def _parse_rfc3339(value: Any) -> datetime | None:
    if (
        not isinstance(value, str)
        or RFC3339_RE.fullmatch(value) is None
        or value.endswith("-00:00")
    ):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _parse_iso_date(value: Any) -> date | None:
    if not isinstance(value, str) or ISO_DATE_RE.fullmatch(value) is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _evaluation_datetime(value: datetime | str | None) -> datetime | None:
    if isinstance(value, str):
        value = _parse_rfc3339(value)
    if not isinstance(value, datetime) or value.tzinfo is None:
        return None
    return value.astimezone(timezone.utc)


def _is_reparse_point(path: Path) -> bool:
    try:
        stat_result = path.lstat()
    except OSError:
        return False
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return path.is_symlink() or bool(attributes & 0x400)


def _path_chain_is_safe(path: Path, stop: Path) -> bool:
    try:
        current = path.absolute()
        boundary = stop.absolute()
    except (OSError, ValueError):
        return False
    while True:
        if _is_reparse_point(current):
            return False
        if current == boundary:
            return True
        if current.parent == current:
            return False
        current = current.parent


def _regular_file_within(root: Path, relative: Any) -> Path | None:
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        return None
    candidate = Path(relative)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        return None
    try:
        root_resolved = root.resolve(strict=True)
        joined = root / candidate
        if not _path_chain_is_safe(joined, root):
            return None
        resolved = joined.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    if resolved.parent != root_resolved and root_resolved not in resolved.parents:
        return None
    try:
        info = resolved.stat()
        regular_nonempty = resolved.is_file() and info.st_size > 0 and info.st_nlink == 1
    except OSError:
        regular_nonempty = False
    return resolved if regular_nonempty and not _is_reparse_point(resolved) else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _nonzero_sha256(value: Any) -> bool:
    return isinstance(value, str) and HEX_SHA256_RE.fullmatch(value) is not None and value != "0" * 64


def _exact_fields(value: Any, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def load_external_trust(
    repo_root: Path,
    bootstrap_result_path: Path | str | None,
    bootstrap_result_public_key_path: Path | str | None = None,
    bootstrap_result_public_key_fingerprint: str | None = None,
    bootstrap_result_sha256: str | None = None,
    evaluation_time: datetime | str | None = None,
) -> tuple[None, list[str]]:
    """Refuse authority material without reading or interpreting it.

    The direct Python validator is candidate code and therefore cannot
    authenticate itself or establish approval/computation authority.
    """

    del repo_root, bootstrap_result_public_key_path
    del bootstrap_result_public_key_fingerprint, bootstrap_result_sha256, evaluation_time
    if bootstrap_result_path is None:
        return None, []
    return None, [
        "candidate validate_contracts.py is diagnostic/draft-only and cannot consume or establish external trust"
    ]


def _approval_evidence_findings(
    evidence: Any,
    *,
    code: str,
    base_pointer: str,
    repo_root: Path | None,
    evaluation_time: datetime | None,
    require_status: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(evidence, list) or not evidence:
        return [(code, base_pointer, "approval requires non-empty dated, hashed evidence")]
    seen_ids: set[str] = set()
    for index, item in enumerate(evidence):
        item_pointer = f"{base_pointer}/{index}"
        if not isinstance(item, dict):
            findings.append((code, item_pointer, "approval evidence item must be an object"))
            continue
        evidence_id = item.get("evidence_id", item.get("comparator_id"))
        canonical_id = canonical_identity(evidence_id) if isinstance(evidence_id, str) else ""
        if not canonical_id or canonical_id in seen_ids:
            findings.append((code, f"{item_pointer}/evidence_id", "evidence identities must be unique after Unicode normalization"))
        seen_ids.add(canonical_id)
        if require_status and item.get("status") != "passed":
            findings.append((code, f"{item_pointer}/status", "approval evidence must be passed"))
        summary = item.get("evidence_summary")
        if not isinstance(summary, str) or not summary.strip():
            findings.append((code, f"{item_pointer}/evidence_summary", "approval evidence requires a non-empty content summary"))
        evaluated_at = _parse_rfc3339(item.get("evaluated_at"))
        if evaluated_at is None:
            findings.append((code, f"{item_pointer}/evaluated_at", "approval evidence requires a real RFC3339 timestamp"))
        elif evaluation_time is not None and evaluated_at.astimezone(timezone.utc) > evaluation_time:
            findings.append((code, f"{item_pointer}/evaluated_at", "approval evidence is dated after evaluation_time"))
        artifact_ref = item.get("artifact_ref")
        expected_hash = artifact_ref.get("sha256") if isinstance(artifact_ref, dict) else None
        if not isinstance(artifact_ref, dict) or artifact_ref.get("applicability") != "applicable" or not _nonzero_sha256(expected_hash):
            findings.append((code, f"{item_pointer}/artifact_ref", "approval evidence requires a non-zero applicable SHA-256 fingerprint"))
            continue
        if repo_root is None:
            findings.append((code, f"{item_pointer}/artifact_path", "approval evidence cannot be verified without repository context"))
            continue
        artifact_path = _regular_file_within(repo_root, item.get("artifact_path"))
        if artifact_path is None:
            findings.append((code, f"{item_pointer}/artifact_path", "approval evidence path must be a regular non-reparse repository file"))
        elif _sha256_file(artifact_path) != expected_hash:
            findings.append((code, f"{item_pointer}/artifact_ref/sha256", "approval evidence hash does not match artifact content"))
    return findings


def _approval_trust_findings(
    *,
    code: str,
    owner: Any,
    reviewer: Any,
    reviewed_at: Any,
    expires_at: Any,
    approval_attestation: Any,
    trust_context: Any | None,
    evaluation_time: datetime | str | None,
    base_pointer: str = "",
    owner_field: str = "owner_id",
    reviewer_field: str = "reviewer_id",
    reviewed_field: str = "reviewed_at",
    expires_field: str = "review_expires_at",
    attestation_field: str = "approval_attestation",
) -> list[Finding]:
    findings: list[Finding] = [
        (
            code,
            f"{base_pointer}/{attestation_field}",
            "candidate validate_contracts.py is diagnostic/draft-only and cannot authenticate or authorize approved status",
        )
    ]
    evaluation = _evaluation_datetime(evaluation_time)
    if evaluation is None:
        findings.append((code, f"{base_pointer}/{expires_field}", "approved artifacts require an explicit timezone-aware evaluation_time"))
    approved = _parse_rfc3339(reviewed_at)
    expires = _parse_rfc3339(expires_at)
    if approved is None:
        findings.append((code, f"{base_pointer}/{reviewed_field}", "approval timestamp must be a real RFC3339 instant"))
    if expires is None:
        findings.append((code, f"{base_pointer}/{expires_field}", "review expiry must be a real RFC3339 instant"))
    if approved is not None and expires is not None and approved >= expires:
        findings.append((code, f"{base_pointer}/{expires_field}", "review expiry must be after approval"))
    if evaluation is not None and approved is not None and approved.astimezone(timezone.utc) > evaluation:
        findings.append((code, f"{base_pointer}/{reviewed_field}", "approval is dated after evaluation_time"))
    if evaluation is not None and expires is not None and expires.astimezone(timezone.utc) <= evaluation:
        findings.append((code, f"{base_pointer}/{expires_field}", "approval is expired at evaluation_time"))
    if trust_context is None:
        return findings
    findings.append(
        (
            code,
            f"{base_pointer}/{attestation_field}",
            "authority contexts are refused by the candidate Python diagnostic boundary",
        )
    )
    return findings
def model_findings(
    card: dict[str, Any],
    trust_context: Any | None = None,
    repo_root: Path | None = None,
    evaluation_time: datetime | str | None = None,
) -> list[Finding]:
    if not isinstance(card, dict):
        return []
    findings: list[Finding] = privacy_findings(card)
    findings.extend(budget_findings(card))
    artifact_status = card.get("artifact_status")
    use_status = card.get("model_use_status")
    if trust_context is not None:
        findings.append(("MODEL_APPROVAL_INTEGRITY_FAILED", "/approval_attestation", "authority contexts are refused by the candidate Python diagnostic boundary"))
    if artifact_status == "approved" or use_status == "approved_for_declared_use":
        findings.append(
            (
                "MODEL_APPROVAL_INTEGRITY_FAILED",
                "/model_use_status"
                if use_status == "approved_for_declared_use"
                else "/artifact_status",
                "candidate validate_contracts.py is diagnostic/draft-only and refuses effective approval",
            )
        )
    if card.get("test_only") is True and (artifact_status == "approved" or use_status == "approved_for_declared_use"):
        findings.append(("MODEL_APPROVAL_INTEGRITY_FAILED", "/test_only", "test-only model probes can never receive operational approval"))
    if (artifact_status == "approved") != (use_status == "approved_for_declared_use"):
        findings.append(("MODEL_APPROVAL_INTEGRITY_FAILED", "/model_use_status", "artifact and use approval statuses must agree"))
    if artifact_status == "draft" and (
        card.get("approved_at") is not None
        or card.get("review_expires_at") is not None
        or card.get("approval_attestation") is not None
    ):
        findings.append(("MODEL_APPROVAL_INTEGRITY_FAILED", "/approved_at", "draft model cards cannot carry an approval window"))
    if artifact_status != "approved":
        return findings
    owner = card.get("owner")
    reviewer = card.get("independent_reviewer")
    if isinstance(owner, str) and isinstance(reviewer, str) and canonical_identity(owner) == canonical_identity(reviewer):
        findings.append(("MODEL_APPROVAL_INTEGRITY_FAILED", "/independent_reviewer", "owner and independent reviewer are the same normalized identity"))
    approved_at = _parse_rfc3339(card.get("approved_at"))
    expires_at = _parse_rfc3339(card.get("review_expires_at"))
    if approved_at is not None and expires_at is not None and approved_at > expires_at:
        findings.append(("MODEL_APPROVAL_INTEGRITY_FAILED", "/review_expires_at", "review expiry precedes approval"))
    evaluation = _evaluation_datetime(evaluation_time)
    findings.extend(
        _approval_trust_findings(
            code="MODEL_APPROVAL_INTEGRITY_FAILED",
            owner=owner,
            reviewer=reviewer,
            reviewed_at=card.get("approved_at"),
            expires_at=card.get("review_expires_at"),
            approval_attestation=card.get("approval_attestation"),
            trust_context=trust_context,
            evaluation_time=evaluation_time,
            owner_field="owner",
            reviewer_field="independent_reviewer",
            reviewed_field="approved_at",
        )
    )
    findings.extend(
        _approval_evidence_findings(
            card.get("validation_evidence"),
            code="MODEL_APPROVAL_INTEGRITY_FAILED",
            base_pointer="/validation_evidence",
            repo_root=repo_root,
            evaluation_time=evaluation,
        )
    )
    benchmark = card.get("benchmark_protocol")
    if not isinstance(benchmark, dict) or benchmark.get("status") != "completed":
        findings.append(("MODEL_APPROVAL_INTEGRITY_FAILED", "/benchmark_protocol/status", "approval requires a completed benchmark"))
    else:
        preregistered = [{
            "evidence_id": benchmark.get("protocol_id"),
            "status": "passed",
            "artifact_ref": benchmark.get("preregistered_artifact"),
            "artifact_path": benchmark.get("preregistered_artifact_path"),
            "evaluated_at": benchmark.get("preregistered_at"),
            "evidence_summary": benchmark.get("evidence_summary"),
        }]
        findings.extend(
            _approval_evidence_findings(
                preregistered,
                code="MODEL_APPROVAL_INTEGRITY_FAILED",
                base_pointer="/benchmark_protocol/preregistered_artifact",
                repo_root=repo_root,
                evaluation_time=evaluation,
            )
        )
        findings.extend(
            _approval_evidence_findings(
                benchmark.get("comparators"),
                code="MODEL_APPROVAL_INTEGRITY_FAILED",
                base_pointer="/benchmark_protocol/comparators",
                repo_root=repo_root,
                evaluation_time=evaluation,
                require_status=False,
            )
        )
    return findings


def governance_findings(
    governance: dict[str, Any],
    trust_context: Any | None = None,
    repo_root: Path | None = None,
    evaluation_time: datetime | str | None = None,
) -> list[Finding]:
    if not isinstance(governance, dict):
        return []
    findings: list[Finding] = privacy_findings(governance)
    findings.extend(budget_findings(governance))
    if trust_context is not None:
        findings.append(("GOVERNANCE_ARTIFACT_APPROVAL_REVIEW", "/human_review", "authority contexts are refused by the candidate Python diagnostic boundary"))
    artifact_approved = governance.get("artifact_status") == "approved"
    use_approved = (
        governance.get("model_use_status") == "approved_for_declared_use"
    )
    effective_approval = artifact_approved or use_approved
    if effective_approval:
        approval_pointer = (
            "/model_use_status" if use_approved else "/artifact_status"
        )
        findings.append(
            (
                "GOVERNANCE_ARTIFACT_APPROVAL_REVIEW",
                approval_pointer,
                "candidate validate_contracts.py is diagnostic/draft-only and refuses effective approval",
            )
        )
    if use_approved and not artifact_approved:
        findings.append(
            (
                "GOVERNANCE_ARTIFACT_APPROVAL_REVIEW",
                "/artifact_status",
                "approved_for_declared_use requires artifact_status approved",
            )
        )
    if governance.get("test_only") is True and (
        effective_approval
    ):
        findings.append(("GOVERNANCE_ARTIFACT_APPROVAL_REVIEW", "/test_only", "test-only governance probes can never receive operational approval"))
    context = governance.get("regulatory_use_context")
    if isinstance(context, dict):
        findings.extend((code, prefix_pointer("/regulatory_use_context", path), message) for code, path, message in regulatory_findings(context))
        for field in ("declared_deployment_class", "derived_minimum_deployment_class", "effective_deployment_class"):
            if governance.get(field) != context.get(field):
                findings.append(("GOVERNANCE_DEPLOYMENT_CLASS_PARITY", f"/{field}", f"must equal regulatory_use_context/{field}"))
    if effective_approval:
        review = governance.get("human_review")
        if not isinstance(review, dict) or review.get("required") is not True or review.get("completed") is not True:
            findings.append(("GOVERNANCE_ARTIFACT_APPROVAL_REVIEW", "/human_review", "approved artifact requires completed human review"))
            if use_approved:
                findings.append(
                    (
                        "GOVERNANCE_ARTIFACT_APPROVAL_REVIEW",
                        "/human_review/completed",
                        "approved_for_declared_use requires completed human review",
                    )
                )
        else:
            findings.extend(
                _approval_trust_findings(
                    code="GOVERNANCE_ARTIFACT_APPROVAL_REVIEW",
                    owner=review.get("owner_id"),
                    reviewer=review.get("reviewer_id"),
                    reviewed_at=review.get("reviewed_at"),
                    expires_at=review.get("review_expires_at"),
                    approval_attestation=review.get("approval_attestation"),
                    trust_context=trust_context,
                    evaluation_time=evaluation_time,
                    base_pointer="/human_review",
                )
            )
            findings.extend(
                _approval_evidence_findings(
                    review.get("evidence"),
                    code="GOVERNANCE_ARTIFACT_APPROVAL_REVIEW",
                    base_pointer="/human_review/evidence",
                    repo_root=repo_root,
                    evaluation_time=_evaluation_datetime(evaluation_time),
                )
            )
        blockers = {
            "model_use_status": {"blocked", "research_only", "reviewed_non_production"},
            "policy_status": {"provisional", "contested", "unknown", "expired", "rejected"},
            "data_quality_status": {"warning", "unknown", "failed"},
            "data_license_status": {"restricted", "contract_required", "unknown", "prohibited"},
            "regulatory_use_status": {"reviews_required", "indeterminate", "forbidden"},
        }
        for field, forbidden in blockers.items():
            if governance.get(field) in forbidden:
                findings.append(("GOVERNANCE_APPROVAL_BLOCKED", f"/{field}", f"approved governance cannot carry {governance.get(field)}"))
    return findings


def manifest_findings(manifest: dict[str, Any]) -> list[Finding]:
    if not isinstance(manifest, dict):
        return []
    findings: list[Finding] = privacy_findings(manifest)
    input_reference = manifest.get("input_reference")
    privacy_class = manifest.get("manifest_privacy_class")
    linkability = manifest.get("linkability_scope")
    if isinstance(input_reference, dict):
        strategy = input_reference.get("strategy")
        if strategy == "none" and linkability != "none":
            findings.append(("RUN_MANIFEST_PRIVACY_INVALID", "/linkability_scope", "non-linkable input strategy requires linkability_scope none"))
        if strategy in {"operator_local_id", "keyed_hmac_sha256"}:
            if privacy_class != "restricted_pseudonymous" or linkability not in {"single_case", "single_operator"}:
                findings.append(("RUN_MANIFEST_PRIVACY_INVALID", "/manifest_privacy_class", "linkable input references require restricted bounded linkability"))
        local_id = input_reference.get("local_id")
        if strategy == "operator_local_id" and isinstance(local_id, str) and _looks_like_raw_hash(local_id):
            findings.append(("RUN_MANIFEST_PRIVACY_INVALID", "/input_reference/local_id", "raw unkeyed hashes are forbidden as local identifiers"))
        hmac_value = input_reference.get("hmac_sha256")
        if strategy == "keyed_hmac_sha256" and not _nonzero_sha256(hmac_value):
            findings.append(("RUN_MANIFEST_PRIVACY_INVALID", "/input_reference/hmac_sha256", "HMAC must be a non-zero lowercase SHA-256 value"))
    artifact_fields = ("software_artifact", "contract_schema", "model_specification", "calibration_parameters", "policy_pack", "data_snapshot")
    seen: dict[str, str] = {}
    for field in artifact_fields:
        artifact = manifest.get(field)
        if not isinstance(artifact, dict):
            continue
        artifact_id = artifact.get("artifact_id")
        if artifact.get("applicability") not in (None, "applicable"):
                findings.append(("RUN_MANIFEST_PRIVACY_INVALID", f"/{field}/applicability", "omit non-applicable fingerprints"))
        sha256 = artifact.get("sha256")
        if sha256 is not None and not _nonzero_sha256(sha256):
            findings.append(("RUN_MANIFEST_PRIVACY_INVALID", f"/{field}/sha256", "artifact fingerprints require a non-zero SHA-256"))
        if isinstance(artifact_id, str):
            canonical_id = canonical_identity(artifact_id)
            if canonical_id in seen:
                findings.append(("RUN_MANIFEST_PRIVACY_INVALID", f"/{field}/artifact_id", f"duplicates {seen[canonical_id]}"))
            seen[canonical_id] = field
    return findings


def diagnostic_findings(diagnostic: dict[str, Any], catalog: dict[str, Any], raw_size: int | None = None) -> list[Finding]:
    if not isinstance(diagnostic, dict):
        return []
    findings = privacy_findings(diagnostic)
    findings.extend(budget_findings(diagnostic, raw_size))
    metadata = catalog.get(diagnostic.get("code"))
    if isinstance(metadata, dict):
        comparisons = {"category": "category", "severity": "default_severity", "computational_status": "default_status", "remediation_id": "remediation_id"}
        for field, catalog_field in comparisons.items():
            if diagnostic.get(field) != metadata.get(catalog_field):
                findings.append(("DIAGNOSTIC_CATALOG_MISMATCH", f"/{field}", f"must equal catalog {catalog_field}"))
    return findings


STATUS_RANK = {
    "computed": 0,
    "computed_with_warnings": 1,
    "indeterminate": 2,
    "rejected": 3,
}


def _merge_status(current: str, candidate: str) -> str:
    return candidate if STATUS_RANK.get(candidate, 3) > STATUS_RANK.get(current, 3) else current


def _expected_execution_status(envelope: dict[str, Any], catalog: dict[str, Any]) -> str:
    expected = "computed"
    governance = envelope.get("governance")
    if isinstance(governance, dict):
        if governance.get("test_only") is True:
            expected = _merge_status(expected, "indeterminate")
        if governance.get("artifact_status") != "approved":
            expected = _merge_status(expected, "computed_with_warnings")
        model_status = governance.get("model_use_status")
        if model_status == "blocked":
            expected = _merge_status(expected, "rejected")
        elif model_status != "approved_for_declared_use":
            expected = _merge_status(expected, "computed_with_warnings")
        policy_status = governance.get("policy_status")
        if policy_status in {"contested", "unknown", "expired", "rejected"}:
            expected = _merge_status(expected, "indeterminate")
        elif policy_status == "provisional":
            expected = _merge_status(expected, "computed_with_warnings")
        quality_status = governance.get("data_quality_status")
        if quality_status in {"unknown", "failed"}:
            expected = _merge_status(expected, "indeterminate")
        elif quality_status == "warning":
            expected = _merge_status(expected, "computed_with_warnings")
        license_status = governance.get("data_license_status")
        if license_status == "prohibited":
            expected = _merge_status(expected, "rejected")
        elif license_status == "unknown":
            expected = _merge_status(expected, "indeterminate")
        elif license_status in {"restricted", "contract_required"}:
            expected = _merge_status(expected, "computed_with_warnings")
        regulatory_status = governance.get("regulatory_use_status")
        if regulatory_status == "forbidden":
            expected = _merge_status(expected, "rejected")
        elif regulatory_status == "indeterminate":
            expected = _merge_status(expected, "indeterminate")
        elif regulatory_status == "reviews_required":
            expected = _merge_status(expected, "computed_with_warnings")
        for code in governance.get("governance_reason_codes", []):
            metadata = catalog.get(code)
            if not isinstance(metadata, dict):
                expected = _merge_status(expected, "rejected")
                continue
            default = metadata.get("default_status", "rejected")
            severity = metadata.get("default_severity", "fatal")
            if severity in {"error", "fatal"} and default in {"computed", "computed_with_warnings"}:
                default = "rejected"
            expected = _merge_status(expected, default)
    diagnostics = envelope.get("diagnostics")
    if isinstance(diagnostics, list):
        for diagnostic in diagnostics:
            if not isinstance(diagnostic, dict):
                expected = _merge_status(expected, "rejected")
                continue
            metadata = catalog.get(diagnostic.get("code"))
            default = metadata.get("default_status", "rejected") if isinstance(metadata, dict) else "rejected"
            expected = _merge_status(expected, default)
    return expected


def execution_findings(
    envelope: dict[str, Any],
    catalog: dict[str, Any],
    trust_context: Any | None = None,
    repo_root: Path | None = None,
    evaluation_time: datetime | str | None = None,
) -> list[Finding]:
    if not isinstance(envelope, dict):
        return []
    findings: list[Finding] = privacy_findings(envelope)
    findings.extend(budget_findings(envelope))
    if trust_context is not None:
        findings.append(("EXECUTION_STATUS_INCOHERENT", "/computational_status", "authority contexts are refused by the candidate Python diagnostic boundary"))
    if envelope.get("computational_status") in {"computed", "computed_with_warnings"}:
        findings.append(("EXECUTION_STATUS_INCOHERENT", "/computational_status", "candidate validate_contracts.py is diagnostic/draft-only and refuses computed operational states"))
    if isinstance(envelope.get("result"), dict):
        findings.extend(prescriptive_key_findings(envelope["result"], ("result",)))
    governance = envelope.get("governance")
    if isinstance(governance, dict):
        findings.extend(
            (code, prefix_pointer("/governance", path), message)
            for code, path, message in governance_findings(
                governance,
                trust_context=trust_context,
                repo_root=repo_root,
                evaluation_time=evaluation_time,
            )
        )
    manifest = envelope.get("run_manifest")
    if isinstance(manifest, dict):
        findings.extend((code, prefix_pointer("/run_manifest", path), message) for code, path, message in manifest_findings(manifest))
    diagnostics = envelope.get("diagnostics")
    if isinstance(diagnostics, list):
        for index, diagnostic in enumerate(diagnostics):
            if isinstance(diagnostic, dict):
                findings.extend((code, prefix_pointer(f"/diagnostics/{index}", path), message) for code, path, message in diagnostic_findings(diagnostic, catalog))
    expected = _expected_execution_status(envelope, catalog)
    if isinstance(governance, dict) and governance.get("test_only") is True and envelope.get("computational_status") in {"computed", "computed_with_warnings"}:
        findings.append(("EXECUTION_STATUS_INCOHERENT", "/computational_status", "test-only probes can never yield a computed operational status"))
    if envelope.get("computational_status") != expected:
        findings.append(("EXECUTION_STATUS_INCOHERENT", "/computational_status", f"complete governance and diagnostic matrix requires {expected}"))
    return findings


def semantic_findings(
    schema_id: str,
    instance: Any,
    catalog: dict[str, Any],
    raw_size: int | None = None,
    trust_context: Any | None = None,
    repo_root: Path | None = None,
    evaluation_time: datetime | str | None = None,
) -> list[Finding]:
    if not isinstance(instance, dict) and schema_id not in {SCHEMA_IDS["reason"]}:
        return []
    findings = budget_findings(instance, raw_size)
    findings.extend(privacy_findings(instance))
    if schema_id == SCHEMA_IDS["regulatory"]:
        findings.extend(regulatory_findings(instance))
    if schema_id == SCHEMA_IDS["input"]:
        context = instance.get("regulatory_use_context")
        if isinstance(context, dict):
            findings.extend((code, prefix_pointer("/regulatory_use_context", path), message) for code, path, message in regulatory_findings(context))
        if isinstance(instance.get("case"), dict):
            findings.extend(prescriptive_key_findings(instance["case"], ("case",)))
    elif schema_id == SCHEMA_IDS["model"]:
        findings.extend(model_findings(instance, trust_context, repo_root, evaluation_time))
    elif schema_id == SCHEMA_IDS["governance"]:
        findings.extend(governance_findings(instance, trust_context, repo_root, evaluation_time))
    elif schema_id == SCHEMA_IDS["diagnostic"]:
        findings.extend(diagnostic_findings(instance, catalog, raw_size))
    elif schema_id == SCHEMA_IDS["execution"]:
        findings.extend(execution_findings(instance, catalog, trust_context, repo_root, evaluation_time))
    elif schema_id == SCHEMA_IDS["run_manifest"]:
        findings.extend(manifest_findings(instance))
    return list(dict.fromkeys(findings))


def _fragment_exists(document: Any, fragment: str) -> bool:
    return _fragment_node(document, fragment) is not None


def _fragment_node(document: Any, fragment: str) -> Any | None:
    if fragment in ("", "#"):
        return document
    if fragment.startswith("#") and not fragment.startswith("#/"):
        anchor = fragment[1:]
        matches = [
            node
            for node in walk(document)
            if isinstance(node, dict) and anchor in {node.get("$anchor"), node.get("$dynamicAnchor")}
        ]
        return matches[0] if len(matches) == 1 else None
    if not fragment.startswith("#/"):
        return None
    current = document
    for raw_part in fragment[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def _canonical_schema_id(value: str) -> str:
    return canonical_identity(unquote(value))


def _inside_composition_keyword(parts: tuple[Any, ...]) -> bool:
    """Distinguish applicator edges from definitions/properties named alike."""

    named_schema_maps = {
        "$defs",
        "definitions",
        "properties",
        "patternProperties",
        "dependentSchemas",
    }
    for index, part in enumerate(parts):
        if part in {"allOf", "anyOf", "oneOf"}:
            if index + 1 < len(parts) and isinstance(parts[index + 1], int):
                return True
        elif part in {"if", "then", "else"}:
            if index == 0 or parts[index - 1] not in named_schema_maps:
                return True
    return False


def _schema_structure_failures(schema_name: str, schema: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    anchors: dict[str, str] = {}
    for parts, node in walk_paths(schema):
        if not isinstance(node, dict):
            continue
        if parts and "$id" in node:
            failures.append(f"{schema_name}{pointer(parts)}: nested $id aliases are forbidden")
        for anchor_keyword in ("$anchor", "$dynamicAnchor"):
            anchor = node.get(anchor_keyword)
            if anchor is None:
                continue
            location = pointer(parts + (anchor_keyword,))
            if not isinstance(anchor, str) or re.fullmatch(r"[A-Za-z][A-Za-z0-9._:-]*", anchor) is None:
                failures.append(f"{schema_name}{location}: anchor must be a canonical plain-name fragment")
                continue
            normalized_anchor = canonical_identity(anchor)
            if normalized_anchor in anchors:
                failures.append(f"{schema_name}{location}: duplicate anchor after canonical normalization")
            anchors[normalized_anchor] = location
        dynamic_ref = node.get("$dynamicRef")
        if isinstance(dynamic_ref, str) and not dynamic_ref.startswith("#"):
            base_ref = dynamic_ref.split("#", 1)[0]
            if not base_ref.startswith(PROJECT_URN_PREFIX):
                failures.append(f"{schema_name}{pointer(parts + ('$dynamicRef',))}: external $dynamicRef is forbidden")
        properties = node.get("properties")
        if isinstance(properties, dict):
            normalized: dict[str, str] = {}
            for property_name in properties:
                skeleton = unicode_skeleton(property_name).replace("-", "_")
                if skeleton in normalized:
                    failures.append(f"{schema_name}{pointer(parts + ('properties', property_name))}: duplicate Unicode-normalized property alias")
                normalized[skeleton] = property_name
                if skeleton in FORBIDDEN_CLASS_A_PROPERTY_NAMES:
                    failures.append(f"{schema_name}: forbidden prescriptive property name: {property_name}")
            composition_fragment = _inside_composition_keyword(parts)
            if not composition_fragment and node.get("additionalProperties") is not False and node.get("unevaluatedProperties") is not False:
                failures.append(f"{schema_name}{pointer(parts)}: object field set must be closed")
    return failures


def _ref_cycle_failures(
    schemas: dict[str, dict[str, Any]], schema_name_by_id: dict[str, str]
) -> list[str]:
    failures: list[str] = []
    reported: set[tuple[str, ...]] = set()

    def target(source_id: str, ref: str) -> tuple[str, str] | None:
        if ref.startswith("#"):
            return source_id, ref
        base, separator, suffix = ref.partition("#")
        canonical = _canonical_schema_id(base)
        matches = [schema_id for schema_id in schemas if _canonical_schema_id(schema_id) == canonical]
        if len(matches) != 1:
            return None
        return matches[0], ("#" + suffix if separator else "")

    def visit(node_key: tuple[str, str], active: list[tuple[str, str]], completed: set[tuple[str, str]]) -> None:
        if node_key in active:
            cycle_nodes = active[active.index(node_key):] + [node_key]
            label = tuple(f"{schema_id}{fragment}" for schema_id, fragment in cycle_nodes)
            if label not in reported:
                reported.add(label)
                failures.append(f"{schema_name_by_id.get(node_key[0], node_key[0])}: $ref cycle detected: {' -> '.join(label)}")
            return
        if node_key in completed:
            return
        schema_id, fragment = node_key
        node = _fragment_node(schemas[schema_id], fragment)
        if node is None:
            return
        active.append(node_key)
        for descendant in walk(node):
            if not isinstance(descendant, dict):
                continue
            for keyword in ("$ref", "$dynamicRef"):
                reference = descendant.get(keyword)
                if isinstance(reference, str):
                    next_key = target(schema_id, reference)
                    if next_key is not None and _fragment_node(schemas[next_key[0]], next_key[1]) is not None:
                        visit(next_key, active, completed)
        active.pop()
        completed.add(node_key)

    completed: set[tuple[str, str]] = set()
    for schema_id, schema in schemas.items():
        for node in walk(schema):
            if not isinstance(node, dict):
                continue
            for keyword in ("$ref", "$dynamicRef"):
                reference = node.get(keyword)
                if isinstance(reference, str):
                    resolved = target(schema_id, reference)
                    if resolved is not None:
                        visit(resolved, [], completed)
    return failures


def _strip_html_comments(
    line: str, in_comment: bool
) -> tuple[str, bool, bool]:
    """Return visible Markdown while carrying multiline HTML-comment state."""

    visible: list[str] = []
    cursor = 0
    touched = in_comment
    while cursor < len(line):
        if in_comment:
            end = line.find("-->", cursor)
            touched = True
            if end < 0:
                return "".join(visible), True, touched
            cursor = end + 3
            in_comment = False
            continue
        start = line.find("<!--", cursor)
        if start < 0:
            visible.append(line[cursor:])
            break
        visible.append(line[cursor:start])
        touched = True
        cursor = start + 4
        in_comment = True
    return "".join(visible), in_comment, touched


def _catalog_reason_entries(
    text: str, enum_codes: set[str]
) -> tuple[list[str], list[str], list[str]]:
    """Parse only the delimited, rendered normative Markdown list block."""

    known_by_skeleton = {unicode_skeleton(code): code for code in enum_codes}
    documented: list[str] = []
    noncanonical: list[str] = []
    structural: list[str] = []
    in_comment = False
    fence: tuple[str, int] | None = None
    in_normative_block = False
    start_lines: list[int] = []
    end_lines: list[int] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if fence is not None:
            fence_character, minimum_length = fence
            if re.fullmatch(
                rf"[ ]{{0,3}}{re.escape(fence_character)}{{{minimum_length},}}[ \t]*",
                raw_line,
            ) is not None:
                fence = None
            continue

        visible_line, in_comment, comment_touched = _strip_html_comments(
            raw_line, in_comment
        )
        fence_match = MARKDOWN_FENCE_RE.match(visible_line)
        if fence_match is not None:
            marker = fence_match.group("fence")
            fence = (marker[0], len(marker))
            continue

        if visible_line == CATALOG_BLOCK_START:
            start_lines.append(line_number)
            in_normative_block = True
            continue
        if visible_line == CATALOG_BLOCK_END:
            end_lines.append(line_number)
            in_normative_block = False
            continue
        if not in_normative_block:
            continue

        item_match = MARKDOWN_LIST_ITEM_RE.fullmatch(visible_line)
        if item_match is None:
            continue
        body = item_match.group("body")
        backtick_match = re.fullmatch(r"`([^`\r\n]+)`", body)
        html_code_match = re.fullmatch(
            r"<code>([^<>\r\n]+)</code>", body, flags=re.IGNORECASE
        )
        plain_match = re.fullmatch(r"[^\s]+", body)
        token = (
            backtick_match.group(1)
            if backtick_match is not None
            else html_code_match.group(1)
            if html_code_match is not None
            else plain_match.group(0)
            if plain_match is not None
            else None
        )
        if token is None:
            # A list item that discusses an ID in prose is not a catalog entry.
            continue

        exact_entry = re.fullmatch(
            r"- `([A-Z][A-Z0-9_]+)`", visible_line, flags=re.ASCII
        )
        if (
            exact_entry is not None
            and raw_line == visible_line
            and not comment_touched
        ):
            documented.append(exact_entry.group(1))
            continue

        aliased_code = known_by_skeleton.get(unicode_skeleton(token))
        if aliased_code is not None:
            noncanonical.append(f"line {line_number} aliases {aliased_code}")

    if in_comment:
        structural.append("unterminated HTML comment")
    if fence is not None:
        structural.append("unterminated fenced code block")
    if len(start_lines) != 1 or len(end_lines) != 1:
        structural.append(
            "normative block delimiters must each occur exactly once outside comments/fences"
        )
    elif start_lines[0] >= end_lines[0]:
        structural.append("normative block delimiters are out of order")
    return documented, noncanonical, structural


def _validate_repository(
    repo_root: Path,
    bootstrap_result_path: Path | str | None = None,
    evaluation_time: datetime | str | None = None,
    bootstrap_result_public_key_path: Path | str | None = None,
    bootstrap_result_public_key_fingerprint: str | None = None,
    bootstrap_result_sha256: str | None = None,
    _after_schema_snapshot: Callable[[], None] | None = None,
) -> list[str]:
    if any(
        value is not None
        for value in (
            bootstrap_result_path,
            bootstrap_result_public_key_path,
            bootstrap_result_public_key_fingerprint,
            bootstrap_result_sha256,
        )
    ):
        return ["candidate validate_contracts.py is diagnostic/draft-only and refuses all external trust arguments"]
    evaluation = _evaluation_datetime(evaluation_time) if evaluation_time is not None else datetime.now(timezone.utc)
    if evaluation is None:
        return ["evaluation_time must be a real timezone-aware RFC3339 instant"]
    if not repo_root.exists() or not repo_root.is_dir() or _is_reparse_point(repo_root):
        return ["repository root must be an existing non-reparse directory"]
    schemas_root = repo_root / "schemas"
    examples_root = schemas_root / "examples"
    failures: list[str] = []
    if not schemas_root.exists() or not schemas_root.is_dir() or _is_reparse_point(schemas_root):
        return ["schemas root must be an existing non-reparse directory"]
    try:
        schemas_inventory_snapshot = _snapshot_schemas_inventory(
            repo_root, schemas_root
        )
    except Exception as exc:
        failures.append(
            f"schemas full inventory snapshot failed: {type(exc).__name__}: {exc}"
        )
        schemas_inventory_snapshot = SchemasInventorySnapshot(None, None, {})
    failures.extend(_schemas_inventory_failures(schemas_inventory_snapshot))
    example_inventory_snapshot = _example_inventory_from_schemas_inventory(
        schemas_inventory_snapshot
    )
    try:
        schema_byte_snapshots = _snapshot_contract_json_tree(schemas_root)
    except Exception as exc:
        return [*failures, f"schemas immutable byte snapshot failed: {type(exc).__name__}: {exc}"]
    if _after_schema_snapshot is not None:
        _after_schema_snapshot()

    def cached_json(
        path: Path,
        *,
        max_bytes: int | None = MAX_DOCUMENT_BYTES,
        max_depth: int | None = MAX_JSON_DEPTH,
    ) -> Any:
        try:
            relative = path.relative_to(schemas_root).as_posix()
        except ValueError as exc:
            raise InputLimitError("contract JSON path escapes the immutable schema snapshot") from exc
        raw = schema_byte_snapshots.get(relative)
        if raw is None:
            raise InputLimitError("contract JSON path is absent from the immutable schema snapshot")
        if max_bytes is not None and len(raw) > max_bytes:
            raise InputLimitError(f"UTF-8 input exceeds {max_bytes} bytes")
        return load_json_bytes(raw, max_depth=max_depth)
    trust_context = None
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource
    schema_paths = sorted(schemas_root.glob("*.schema.json"))
    schemas: dict[str, dict[str, Any]] = {}
    schema_name_by_id: dict[str, str] = {}

    for schema_path in schema_paths:
        try:
            schema = cached_json(schema_path)
            if not isinstance(schema, dict):
                raise TypeError("schema document must be an object")
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            failures.append(f"{schema_path.name}: invalid schema ({type(exc).__name__}); instance values redacted")
            continue
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id.startswith(PROJECT_URN_PREFIX):
            failures.append(f"{schema_path.name}: missing or invalid project URN $id")
            continue
        canonical_schema_id = _canonical_schema_id(schema_id)
        aliases = [existing for existing in schemas if _canonical_schema_id(existing) == canonical_schema_id]
        if schema_id in schemas or aliases:
            failures.append(f"{schema_path.name}: duplicate schema $id {schema_id}")
            continue
        if canonical_schema_id != schema_id:
            failures.append(f"{schema_path.name}: schema $id must be canonical ASCII lowercase without URI aliases")
            continue
        expected_schema_id = EXPECTED_SCHEMA_FILE_IDS.get(schema_path.name)
        if expected_schema_id is None or schema_id != expected_schema_id:
            failures.append(
                f"{schema_path.name}: schema filename/$id binding differs from embedded roster"
            )
            continue
        schemas[schema_id] = schema
        schema_name_by_id[schema_id] = schema_path.name
        failures.extend(_schema_structure_failures(schema_path.name, schema))
        for node in walk(schema):
            if not isinstance(node, dict):
                continue
            for keyword in ("$ref", "$dynamicRef"):
                ref = node.get(keyword)
                if isinstance(ref, str) and not ref.startswith("#"):
                    base_ref = ref.split("#", 1)[0]
                    if not base_ref.startswith(PROJECT_URN_PREFIX):
                        failures.append(f"{schema_path.name}: non-local {keyword} is forbidden")

    for schema_id, schema in schemas.items():
        for node in walk(schema):
            if not isinstance(node, dict):
                continue
            for keyword in ("$ref", "$dynamicRef"):
                ref = node.get(keyword)
                if not isinstance(ref, str):
                    continue
                if ref.startswith("#"):
                    target, fragment = schema, ref
                else:
                    base_ref, separator, suffix = ref.partition("#")
                    matches = [candidate for candidate in schemas if _canonical_schema_id(candidate) == _canonical_schema_id(base_ref)]
                    target = schemas[matches[0]] if len(matches) == 1 else None
                    fragment = "#" + suffix if separator else ""
                    if target is None:
                        failures.append(f"{schema_name_by_id[schema_id]}: unresolved local {keyword}")
                        continue
                if not _fragment_exists(target, fragment):
                    failures.append(f"{schema_name_by_id[schema_id]}: unresolved local {keyword} fragment")

    failures.extend(_ref_cycle_failures(schemas, schema_name_by_id))

    registry = Registry()
    for schema_id, schema in schemas.items():
        try:
            registry = registry.with_resource(schema_id, Resource.from_contents(schema))
        except Exception as exc:
            failures.append(f"{schema_name_by_id[schema_id]}: cannot register schema ({type(exc).__name__})")
    format_checker = FormatChecker()
    format_checker.checks("date")(_parse_iso_date)
    format_checker.checks("date-time")(_parse_rfc3339)

    manifest_path = schemas_root / "conformance-manifest.json"
    try:
        manifest = cached_json(manifest_path)
    except Exception as exc:
        failures.append(f"conformance-manifest.json: cannot parse ({type(exc).__name__}); values redacted")
        manifest = {}
    if not isinstance(manifest, dict):
        failures.append("conformance-manifest.json: root must be an object")
        manifest = {}

    if SCHEMA_IDS["manifest"] in schemas:
        try:
            for error in Draft202012Validator(schemas[SCHEMA_IDS["manifest"]], registry=registry, format_checker=format_checker).iter_errors(manifest):
                failures.append(f"conformance-manifest.json{_redacted_pointer(tuple(error.absolute_path))}: {error.validator}: schema assertion failed; instance value redacted")
        except Exception as exc:
            failures.append(f"conformance-manifest.json: validation could not complete ({type(exc).__name__}); values redacted")

    raw_schema_files = manifest.get("schema_files")
    declared_schema_files = set(raw_schema_files) if isinstance(raw_schema_files, list) and all(isinstance(item, str) for item in raw_schema_files) else set()
    actual_schema_files = {path.name for path in schema_paths}
    expected_schema_files = set(EXPECTED_SCHEMA_FILE_IDS)
    if declared_schema_files != expected_schema_files:
        failures.append(
            "manifest schema_files mismatch against embedded roster; "
            f"missing={sorted(expected_schema_files - declared_schema_files)}, "
            f"unexpected_count={len(declared_schema_files - expected_schema_files)}"
        )
    if actual_schema_files != expected_schema_files:
        failures.append(
            "filesystem schema files mismatch against embedded roster; "
            f"missing={sorted(expected_schema_files - actual_schema_files)}, "
            f"unexpected_count={len(actual_schema_files - expected_schema_files)}"
        )

    catalog: dict[str, Any] = {}
    if SCHEMA_IDS["reason"] in schemas:
        reason_schema = schemas[SCHEMA_IDS["reason"]]
        if reason_schema.get("pattern") != REASON_CODE_RE.pattern:
            failures.append("reason-code schema must declare the canonical closed ASCII ID pattern")
        raw_enum = reason_schema.get("enum")
        if isinstance(raw_enum, list) and all(isinstance(code, str) for code in raw_enum):
            enum_codes = set(raw_enum)
            if len(raw_enum) != len(enum_codes):
                failures.append("reason-code enum contains duplicate IDs")
            normalized_codes = [canonical_identity(code) for code in raw_enum]
            if len(normalized_codes) != len(set(normalized_codes)):
                failures.append("reason-code enum contains Unicode/case aliases")
            for code in raw_enum:
                if REASON_CODE_RE.fullmatch(code) is None:
                    failures.append(f"reason code is not canonical closed ASCII: {code}")
        else:
            enum_codes = set()
            failures.append("reason-code enum must be an array of strings")
        if enum_codes != EXPECTED_REASON_CODES:
            failures.append(
                "reason-code enum differs from embedded 62-ID roster; "
                f"missing={sorted(EXPECTED_REASON_CODES - enum_codes)}, "
                f"unexpected_count={len(enum_codes - EXPECTED_REASON_CODES)}"
            )
        raw_catalog = reason_schema.get("x-reason-code-catalog")
        if isinstance(raw_catalog, dict):
            catalog = raw_catalog
        else:
            catalog = {}
            failures.append("x-reason-code-catalog must be an object")
        if enum_codes != set(catalog):
            failures.append("reason-code enum and x-reason-code-catalog keys differ")

        required_fields = {"category", "default_severity", "default_status", "owner", "remediation_id"}
        reason_defs = reason_schema.get("$defs")
        metadata_contract = (
            reason_defs.get("catalog_metadata") if isinstance(reason_defs, dict) else None
        )
        raw_metadata_properties = (
            metadata_contract.get("properties")
            if isinstance(metadata_contract, dict)
            else None
        )
        metadata_properties = raw_metadata_properties if isinstance(raw_metadata_properties, dict) else {}
        raw_required_fields = (
            metadata_contract.get("required")
            if isinstance(metadata_contract, dict)
            else None
        )
        if (
            not isinstance(metadata_contract, dict)
            or metadata_contract.get("type") != "object"
            or metadata_contract.get("additionalProperties") is not False
            or not isinstance(raw_required_fields, list)
            or not all(isinstance(field, str) for field in raw_required_fields)
            or len(raw_required_fields) != len(required_fields)
            or set(raw_required_fields) != required_fields
            or set(metadata_properties) != required_fields
        ):
            failures.append("reason-code catalog_metadata must normatively declare the exact metadata field set")

        def declared_string_enum(field: str) -> set[str]:
            constraint = metadata_properties.get(field)
            raw_values = constraint.get("enum") if isinstance(constraint, dict) else None
            if (
                not isinstance(raw_values, list)
                or not all(isinstance(value, str) for value in raw_values)
                or len(raw_values) != len(set(raw_values))
            ):
                failures.append(f"reason-code catalog_metadata/{field} must declare a unique string enum")
                return set()
            return set(raw_values)

        diagnostic_schema = schemas.get(SCHEMA_IDS["diagnostic"], {})
        raw_diagnostic_properties = (
            diagnostic_schema.get("properties") if isinstance(diagnostic_schema, dict) else None
        )
        diagnostic_properties = raw_diagnostic_properties if isinstance(raw_diagnostic_properties, dict) else {}

        def diagnostic_string_enum(field: str) -> set[str]:
            constraint = diagnostic_properties.get(field)
            raw_values = constraint.get("enum") if isinstance(constraint, dict) else None
            return (
                set(raw_values)
                if isinstance(raw_values, list)
                and all(isinstance(value, str) for value in raw_values)
                and len(raw_values) == len(set(raw_values))
                else set()
            )

        declared_categories = declared_string_enum("category")
        declared_severities = declared_string_enum("default_severity")
        declared_default_statuses = declared_string_enum("default_status")
        diagnostic_categories = diagnostic_string_enum("category")
        diagnostic_severities = diagnostic_string_enum("severity")
        diagnostic_statuses = diagnostic_string_enum("computational_status")
        allowed_default_statuses = diagnostic_statuses - {"computed", "approved"}
        if not diagnostic_categories or declared_categories != diagnostic_categories:
            failures.append("reason-code category enum must exactly match diagnostic.schema.json")
        if not diagnostic_severities or declared_severities != diagnostic_severities:
            failures.append("reason-code default_severity enum must exactly match diagnostic.schema.json")
        if (
            not diagnostic_statuses
            or declared_default_statuses != allowed_default_statuses
            or {"computed", "approved"} & declared_default_statuses
        ):
            failures.append(
                "reason-code default_status enum must be allowed by diagnostic.schema.json and exclude computed/approved"
            )
        for field in ("owner", "remediation_id"):
            constraint = metadata_properties.get(field)
            if (
                not isinstance(constraint, dict)
                or constraint.get("type") != "string"
                or constraint.get("minLength") != 1
                or constraint.get("maxLength") != 128
                or constraint.get("pattern") != CATALOG_IDENTIFIER_PATTERN
            ):
                failures.append(
                    f"reason-code catalog_metadata/{field} must declare the canonical nonempty identifier constraint"
                )

        remediation_groups: dict[str, list[str]] = {}
        for code, metadata in catalog.items():
            if REASON_CODE_RE.fullmatch(code) is None:
                failures.append(f"reason code catalog key is not canonical closed ASCII: {code}")
            if not isinstance(metadata, dict) or set(metadata) != required_fields:
                failures.append(f"reason code {code}: incomplete or extra catalog metadata")
                continue
            category = metadata.get("category")
            severity = metadata.get("default_severity")
            default_status = metadata.get("default_status")
            owner = metadata.get("owner")
            remediation_id = metadata.get("remediation_id")
            if not isinstance(category, str) or category not in diagnostic_categories:
                failures.append(f"reason code {code}: category is outside the normative enum")
            if not isinstance(severity, str) or severity not in diagnostic_severities:
                failures.append(f"reason code {code}: default_severity is outside the normative enum")
            if (
                not isinstance(default_status, str)
                or default_status not in allowed_default_statuses
                or default_status in {"computed", "approved"}
            ):
                failures.append(
                    f"reason code {code}: default_status must be an allowed non-computed, non-approved status"
                )
            if (
                not isinstance(owner, str)
                or len(owner) > 128
                or CATALOG_IDENTIFIER_RE.fullmatch(owner) is None
            ):
                failures.append(f"reason code {code}: owner must be a nonempty canonical identifier")
            if (
                not isinstance(remediation_id, str)
                or len(remediation_id) > 128
                or CATALOG_IDENTIFIER_RE.fullmatch(remediation_id) is None
            ):
                failures.append(f"reason code {code}: remediation_id must be a nonempty canonical identifier")
            else:
                remediation_groups.setdefault(remediation_id, []).append(code)

        actual_shared_remediations = {
            remediation_id: sorted(codes)
            for remediation_id, codes in remediation_groups.items()
            if len(codes) > 1
        }
        raw_shared_remediations = reason_schema.get("x-shared-remediation-ids")
        declared_shared_remediations: dict[str, list[str]] = {}
        if not isinstance(raw_shared_remediations, dict):
            failures.append("x-shared-remediation-ids must be an object")
        else:
            for remediation_id, codes in raw_shared_remediations.items():
                if CATALOG_IDENTIFIER_RE.fullmatch(remediation_id) is None:
                    failures.append("shared remediation_id must be a canonical identifier")
                    continue
                if (
                    not isinstance(codes, list)
                    or len(codes) < 2
                    or not all(isinstance(code, str) for code in codes)
                    or len(codes) != len(set(codes))
                ):
                    failures.append(
                        f"shared remediation {remediation_id}: code references must be a unique list with multiplicity >= 2"
                    )
                    continue
                declared_shared_remediations[remediation_id] = sorted(codes)
                for code in codes:
                    metadata = catalog.get(code)
                    if not isinstance(metadata, dict) or metadata.get("remediation_id") != remediation_id:
                        failures.append(
                            f"shared remediation {remediation_id}: {code} is not referentially bound to that remediation_id"
                        )
        if declared_shared_remediations != actual_shared_remediations:
            failures.append(
                "shared remediation multiplicity differs from x-shared-remediation-ids"
            )
        try:
            semantic_map_digest = _canonical_json_sha256(
                {
                    "catalog": raw_catalog,
                    "shared_remediation_ids": raw_shared_remediations,
                }
            )
        except Exception as exc:
            failures.append(
                "reason-code semantic map is not canonically serializable "
                f"({type(exc).__name__})"
            )
        else:
            if semantic_map_digest != EXPECTED_REASON_SEMANTIC_MAP_SHA256:
                failures.append(
                    "reason-code semantic map differs from embedded canonical digest"
                )
        try:
            text = (repo_root / "docs" / "specification" / "error-catalog.md").read_text(encoding="utf-8")
            (
                documented_occurrences,
                noncanonical_candidates,
                catalog_structure_failures,
            ) = _catalog_reason_entries(text, enum_codes)
            if catalog_structure_failures:
                failures.append(
                    "error catalog normative block is invalid: "
                    + "; ".join(catalog_structure_failures)
                )
            documented_counts = Counter(documented_occurrences)
            missing_documented = sorted(code for code in enum_codes if documented_counts[code] == 0)
            duplicate_documented = {
                code: count for code, count in sorted(documented_counts.items()) if count != 1
            }
            docs_only = sorted(set(documented_counts) - enum_codes)
            if (
                missing_documented
                or duplicate_documented
                or docs_only
                or noncanonical_candidates
            ):
                failures.append(
                    "reason-code schema and docs/specification/error-catalog.md require exact 1:1 bullet multiplicity; "
                    f"missing={missing_documented}, multiplicity={duplicate_documented}, "
                    f"docs_only={docs_only}, noncanonical_candidates={noncanonical_candidates}"
                )
        except Exception as exc:
            failures.append(f"error catalog cannot be read: {exc}")

    raw_cases = manifest.get("cases")
    cases = raw_cases if isinstance(raw_cases, list) else []
    actual_case_semantics: dict[str, tuple[Any, Any, Any, Any, Any]] = {}
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("case_id"), str):
            continue
        actual_case_semantics.setdefault(
            case["case_id"],
            tuple(
                case.get(field)
                for field in (
                    "instance_path",
                    "schema_id",
                    "expected_valid",
                    "expected_keyword",
                    "expected_instance_pointer",
                )
            ),
        )
    expected_case_ids = set(EXPECTED_CONFORMANCE_CASES)
    actual_case_ids = set(actual_case_semantics)
    changed_expected_cases = sorted(
        case_id
        for case_id in expected_case_ids & actual_case_ids
        if actual_case_semantics[case_id] != EXPECTED_CONFORMANCE_CASES[case_id]
    )
    validity_counts = {
        expected_valid: sum(
            isinstance(case, dict)
            and case.get("expected_valid") is expected_valid
            for case in cases
        )
        for expected_valid in (True, False)
    }
    if (
        len(cases) != len(EXPECTED_CONFORMANCE_CASES)
        or actual_case_ids != expected_case_ids
        or changed_expected_cases
        or validity_counts != EXPECTED_CASE_COUNTS
    ):
        failures.append(
            "manifest cases differ from embedded 33-case roster; "
            f"missing={sorted(expected_case_ids - actual_case_ids)}, "
            f"unexpected_count={len(actual_case_ids - expected_case_ids)}, "
            f"changed={changed_expected_cases}, counts={validity_counts}"
        )
    case_ids: set[str] = set()
    instance_paths: set[str] = set()
    resolved_instance_paths: dict[str, str] = {}
    coverage: dict[str, set[bool]] = {schema_id: set() for schema_id in schemas}
    declared_instances: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            failures.append(f"manifest cases/{index}: case must be an object")
            continue
        case_id = case.get("case_id", f"<missing-case-id-{index}>")
        instance_rel = case.get("instance_path")
        schema_id = case.get("schema_id")
        if isinstance(case_id, str):
            canonical_case_id = canonical_identity(case_id)
            if canonical_case_id in case_ids:
                failures.append(f"manifest cases/{index}: duplicate case_id {case_id}")
            case_ids.add(canonical_case_id)
        if isinstance(instance_rel, str):
            normalized_instance_rel = canonical_identity(instance_rel.replace("\\", "/"))
            if normalized_instance_rel in instance_paths:
                failures.append(f"manifest cases/{index}: duplicate instance_path {instance_rel}")
            instance_paths.add(normalized_instance_rel)
            declared_instances.add(instance_rel)
            example_path_match = EXAMPLE_INSTANCE_PATH_RE.fullmatch(instance_rel)
            if example_path_match is None:
                failures.append(
                    f"manifest cases/{index}: instance_path must be a canonical examples/valid or examples/invalid JSON path"
                )
            else:
                path_expected_valid = example_path_match.group("expectation") == "valid"
                if case.get("expected_valid") is not path_expected_valid:
                    failures.append(
                        f"{case_id}: {instance_rel} requires expected_valid={json.dumps(path_expected_valid)} from its examples directory"
                    )
        if not isinstance(instance_rel, str) or not isinstance(schema_id, str):
            continue
        if schema_id in coverage and isinstance(case.get("expected_valid"), bool):
            coverage[schema_id].add(case["expected_valid"])
        try:
            unresolved_instance_path = schemas_root / instance_rel
            if not _path_chain_is_safe(unresolved_instance_path, schemas_root):
                failures.append(f"{case_id}: instance path contains a symlink/junction/reparse component")
                continue
            instance_path = unresolved_instance_path.resolve(strict=True)
        except (OSError, ValueError) as exc:
            failures.append(f"{case_id}: invalid instance path ({type(exc).__name__})")
            continue
        if schemas_root.resolve() not in instance_path.parents:
            failures.append(f"{case_id}: instance path escapes schemas directory")
            continue
        if not instance_path.is_file():
            failures.append(f"{case_id}: missing instance {instance_rel}")
            continue
        resolved_key = canonical_identity(str(instance_path))
        if resolved_key in resolved_instance_paths:
            failures.append(f"{case_id}: duplicate resolved instance path aliases {resolved_instance_paths[resolved_key]}")
            continue
        resolved_instance_paths[resolved_key] = str(case_id)
        if schema_id not in schemas:
            failures.append(f"{case_id}: unknown schema_id {schema_id}")
            continue
        try:
            instance_budget = (
                MAX_INPUT_BYTES
                if schema_id in {SCHEMA_IDS["input"], SCHEMA_IDS["diagnostic"]}
                else MAX_DOCUMENT_BYTES
            )
            instance = cached_json(
                instance_path,
                max_bytes=instance_budget,
                max_depth=MAX_JSON_DEPTH,
            )
        except InputLimitError as exc:
            expected_keyword = case.get("expected_keyword")
            expected_pointer = case.get("expected_instance_pointer")
            if case.get("expected_valid") is False and isinstance(expected_keyword, str) and isinstance(expected_pointer, str) and (expected_keyword, expected_pointer) == (
                "semantic:CONTRACT_INPUT_LIMIT_EXCEEDED",
                "",
            ):
                continue
            failures.append(f"{case_id}: CONTRACT_INPUT_LIMIT_EXCEEDED: {exc}")
            continue
        except DuplicateKeyError as exc:
            if not (case.get("expected_valid") is False and case.get("expected_keyword") == "duplicateKey" and case.get("expected_instance_pointer") == ""):
                failures.append(f"{case_id}: unexpected duplicate JSON key; key value redacted")
            continue
        except Exception as exc:
            failures.append(f"{case_id}: JSON parse failed ({type(exc).__name__}); values redacted")
            continue
        try:
            errors = list(Draft202012Validator(schemas[schema_id], registry=registry, format_checker=format_checker).iter_errors(instance))
        except Exception as exc:
            failures.append(f"{case_id}: validation could not complete ({type(exc).__name__}); values redacted")
            continue
        findings = semantic_findings(
            schema_id,
            instance,
            catalog,
            len(schema_byte_snapshots[instance_path.relative_to(schemas_root).as_posix()]),
            trust_context=trust_context,
            repo_root=repo_root,
            evaluation_time=evaluation,
        )
        observed = {(error.validator, _redacted_pointer(tuple(error.absolute_path))) for error in flatten_errors(errors)}
        observed.update((f"semantic:{code}", finding_pointer) for code, finding_pointer, _ in findings)
        if case.get("expected_valid") is True and observed:
            failures.append(f"{case_id}: expected valid; observed={sorted(f'{keyword}@{path}' for keyword, path in observed)}")
        elif case.get("expected_valid") is False:
            expected_keyword = case.get("expected_keyword")
            expected_pointer = case.get("expected_instance_pointer")
            if not isinstance(expected_keyword, str) or not isinstance(expected_pointer, str):
                continue
            expected = (expected_keyword, expected_pointer)
            if expected not in observed:
                failures.append(f"{case_id}: expected {expected[0]}@{expected[1]}; observed={sorted(f'{keyword}@{path}' for keyword, path in observed)}")

    for schema_id, outcomes in coverage.items():
        missing = {True, False} - outcomes
        if missing:
            failures.append(f"manifest direct coverage incomplete for {schema_id}: missing expected_valid={sorted(missing)}")

    failures.extend(
        _example_inventory_failures(example_inventory_snapshot, declared_instances)
    )
    try:
        final_schemas_inventory = _snapshot_schemas_inventory(
            repo_root, schemas_root
        )
        failures.extend(_schemas_inventory_failures(final_schemas_inventory))
        if final_schemas_inventory != schemas_inventory_snapshot:
            failures.append(
                "schemas full inventory drifted after immutable diagnostic snapshot acquisition"
            )
        if (
            _example_inventory_from_schemas_inventory(final_schemas_inventory)
            != example_inventory_snapshot
        ):
            failures.append(
                "examples full inventory drifted after immutable diagnostic snapshot acquisition"
            )
    except Exception as exc:
        failures.append(
            f"schemas full inventory final recheck failed: {type(exc).__name__}: {exc}"
        )
    try:
        for relative, expected_bytes in schema_byte_snapshots.items():
            current = _safe_read_bytes(
                schemas_root / relative,
                MAX_DOCUMENT_BYTES,
                f"contract JSON final recheck {relative}",
            )
            if current != expected_bytes:
                failures.append(f"contract JSON path drifted after immutable diagnostic snapshot acquisition: {relative}")
    except Exception as exc:
        failures.append(f"contract JSON final immutable recheck failed: {type(exc).__name__}: {exc}")
    return failures


def validate_repository(
    repo_root: Path,
    bootstrap_result_path: Path | str | None = None,
    evaluation_time: datetime | str | None = None,
    bootstrap_result_public_key_path: Path | str | None = None,
    bootstrap_result_public_key_fingerprint: str | None = None,
    bootstrap_result_sha256: str | None = None,
    _after_schema_snapshot: Callable[[], None] | None = None,
) -> list[str]:
    """Total validation boundary: corrupt packs become stable diagnostics."""

    try:
        return _validate_repository(
            Path(repo_root),
            bootstrap_result_path,
            evaluation_time,
            bootstrap_result_public_key_path,
            bootstrap_result_public_key_fingerprint,
            bootstrap_result_sha256,
            _after_schema_snapshot,
        )
    except Exception as exc:
        return [f"internal validator boundary caught {type(exc).__name__}: {exc}"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diagnose the local draft JSON contract pack; never an approval or computation authority")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="absolute candidate repository root; required when validator runs from an immutable snapshot")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        print("Contract validation failed: Python 3.11 or later is required.", file=sys.stderr)
        return 2
    try:
        installed_version = version("jsonschema")
    except PackageNotFoundError:
        print("Contract validation failed: install jsonschema>=4.18.0.", file=sys.stderr)
        return 2
    numeric_version = tuple(int(part) for part in re.findall(r"\d+", installed_version)[:3])
    if numeric_version < MIN_JSONSCHEMA_VERSION:
        print(f"Contract validation failed: jsonschema {installed_version} is older than 4.18.0.", file=sys.stderr)
        return 2
    failures = validate_repository(
        args.root.resolve(),
    )
    if failures:
        print(f"Contract validation failed with {len(failures)} issue(s):", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1
    repo_root = args.root.resolve()
    schemas_root = repo_root / "schemas"
    try:
        manifest = load_json(schemas_root / "conformance-manifest.json")
        case_count = len(manifest.get("cases", [])) if isinstance(manifest, dict) else 0
        reason_schema = load_json(schemas_root / "reason-codes.schema.json")
        reason_count = len(reason_schema.get("enum", [])) if isinstance(reason_schema, dict) else 0
    except Exception:
        case_count = reason_count = 0
    print(f"Draft contract diagnostics passed: {len(list(schemas_root.glob('*.schema.json')))} Draft 2020-12 schemas, {case_count} conformance cases, {reason_count} closed reason codes (jsonschema {installed_version}); no trust, approval, or computed state was authorized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
