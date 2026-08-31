"""Bounded strict JSON and deterministic FPBR-C14N-1 serialization."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Literal, Protocol, TypeAlias, cast

MAX_INPUT_BYTES = 1_048_576
MAX_NODES = 20_000
MAX_DEPTH = 32
MAX_JSON_INTEGER_DIGITS = 10
MAX_JSON_INTEGER_ABS = 9_999_999_999

# Closed deterministic-request maximum from its public schema:
# root/use-context/lists (14) + 512 factors (3 nodes each) +
# 4,096 cashflows (7 each) + 256 accounts (6 each) +
# 4,096 events (11 each).
MAX_DETERMINISTIC_REQUEST_NODES = 76_814

# Closed deterministic-result maxima from its public schema.  The node count is
# fixed/root material (33) + 4,096 cashflows (9 each) + 256 accounts (6 each) +
# 4,096 transfer results (17 each).  The byte count is the exact FPBR-C14N-1
# length of that shape with every schema-bounded string at maximum length.
MAX_DETERMINISTIC_RESULT_NODES = 108_065
MAX_DETERMINISTIC_RESULT_BYTES = 5_180_619

JsonScalar: TypeAlias = None | bool | int | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


JsonContractReason = Literal["invalid", "depth_budget", "input_budget"]


class JsonContractError(ValueError):
    """Stable internal classification for strict-JSON acquisition failures."""

    def __init__(self, message: str, *, reason: JsonContractReason = "invalid") -> None:
        self.reason = reason
        super().__init__(message)


class BinaryReader(Protocol):
    """Minimal blocking binary-reader contract used by bounded acquisition."""

    def read(self, size: int = -1) -> bytes: ...


def read_limited_bytes(stream: BinaryReader, *, limit: int = MAX_INPUT_BYTES) -> bytes:
    """Read through EOF or ``limit + 1`` bytes, tolerating legal short reads.

    A single ``read(size)`` is not an EOF proof: binary streams may return fewer
    bytes than requested.  The returned value is capped at ``limit + 1`` so the
    caller can distinguish an in-budget payload from an oversized one without
    buffering the remainder.
    """

    if type(limit) is not int or limit < 0:
        raise ValueError("binary input limit must be one non-negative integer")
    ceiling = limit + 1
    chunks: list[bytes] = []
    acquired = 0
    while acquired < ceiling:
        remaining = ceiling - acquired
        chunk = stream.read(remaining)
        if type(chunk) is not bytes:
            raise JsonContractError("binary reader did not return immutable bytes")
        if not chunk:
            break
        if len(chunk) > remaining:
            chunk = chunk[:remaining]
        chunks.append(chunk)
        acquired += len(chunk)
    return b"".join(chunks)


def _pairs(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise JsonContractError("duplicate JSON object key")
        result[key] = value
    return result


def _integer(text: str) -> int:
    if len(text.lstrip("-")) > MAX_JSON_INTEGER_DIGITS:
        raise JsonContractError("JSON integer exceeds the 10-digit budget")
    return int(text)


def _forbid_number(_: str) -> None:
    raise JsonContractError("JSON decimals must be represented as strings")


def _forbid_constant(_: str) -> None:
    raise JsonContractError("non-finite JSON constants are forbidden")


def _reject_lone_surrogates(value: str) -> None:
    """Reject code points that cannot be encoded as strict UTF-8.

    Python's JSON decoder intentionally preserves escaped lone surrogates.  The
    restricted contract domain does not: accepting one would defer failure until
    canonical UTF-8 serialization and could escape the closed diagnostic path.
    """

    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise JsonContractError("JSON strings must not contain lone surrogate code points")


def _check_structural_depth(text: str) -> None:
    """Reject excessive container nesting without relying on decoder recursion.

    ``_check_budget`` counts the root at depth zero, so at most
    ``MAX_DEPTH + 1`` nested containers can be present.  This lexical pass only
    recognizes brackets outside JSON strings; the decoder remains responsible
    for all JSON grammar validation.
    """

    container_depth = 0
    in_string = False
    escaped = False
    for character in text:
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
            container_depth += 1
            if container_depth > MAX_DEPTH + 1:
                raise JsonContractError(
                    "JSON document exceeds the depth budget",
                    reason="depth_budget",
                )
        elif character in "]}" and container_depth:
            container_depth -= 1


def _check_budget(
    value: object,
    depth: int = 0,
    counter: list[int] | None = None,
    *,
    max_nodes: int = MAX_NODES,
) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > max_nodes:
        raise JsonContractError("JSON document exceeds the node budget")
    if depth > MAX_DEPTH:
        raise JsonContractError("JSON document exceeds the depth budget", reason="depth_budget")
    value_type = type(value)
    if value_type is dict:
        document = cast(dict[object, object], value)
        for key, child in document.items():
            if type(key) is not str or len(key) > 128:
                raise JsonContractError("JSON object key exceeds the string budget")
            _reject_lone_surrogates(key)
            _check_budget(child, depth + 1, counter, max_nodes=max_nodes)
    elif value_type is list:
        for child in cast(list[object], value):
            _check_budget(child, depth + 1, counter, max_nodes=max_nodes)
    elif value_type is str:
        text = cast(str, value)
        if len(text) > 4096:
            raise JsonContractError("JSON string exceeds the character budget")
        _reject_lone_surrogates(text)
    elif value_type is int:
        integer = cast(int, value)
        # Numeric comparison is total for exact built-in integers.  Converting
        # an attacker-sized Python int to text can itself raise under
        # PYTHONINTMAXSTRDIGITS before the contract has a chance to reject it.
        if integer < -MAX_JSON_INTEGER_ABS or integer > MAX_JSON_INTEGER_ABS:
            raise JsonContractError("JSON integer exceeds the 10-digit budget")
    elif value is None or value_type is bool:
        return
    else:
        raise JsonContractError("value is outside the exact JSON type boundary")


def _validate_budgets(*, max_bytes: int, max_nodes: int) -> None:
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("JSON byte budget must be one positive integer")
    if type(max_nodes) is not int or max_nodes < 1:
        raise ValueError("JSON node budget must be one positive integer")


def loads_strict(
    payload: bytes,
    *,
    max_bytes: int = MAX_INPUT_BYTES,
    max_nodes: int = MAX_NODES,
) -> JsonValue:
    _validate_budgets(max_bytes=max_bytes, max_nodes=max_nodes)
    if not payload or len(payload) > max_bytes:
        raise JsonContractError(
            "input must be non-empty and within the byte budget",
            reason="input_budget",
        )
    if payload.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        raise JsonContractError("JSON must be UTF-8 without a byte-order mark")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise JsonContractError("input is not strict UTF-8 JSON") from exc
    _check_structural_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_forbid_number,
            parse_constant=_forbid_constant,
        )
    except (json.JSONDecodeError, JsonContractError) as exc:
        if isinstance(exc, JsonContractError):
            raise
        raise JsonContractError("input is not strict UTF-8 JSON") from exc
    except RecursionError as exc:
        raise JsonContractError("JSON document exceeds the depth budget", reason="depth_budget") from exc
    try:
        _check_budget(value, max_nodes=max_nodes)
    except RecursionError as exc:  # defensive if the budget traversal changes independently
        raise JsonContractError("JSON document exceeds the depth budget", reason="depth_budget") from exc
    return cast(JsonValue, value)


def read_json_file(
    path: Path,
    *,
    max_bytes: int = MAX_INPUT_BYTES,
    max_nodes: int = MAX_NODES,
) -> JsonValue:
    _validate_budgets(max_bytes=max_bytes, max_nodes=max_nodes)
    supplied = path.absolute()
    supplied_metadata = supplied.lstat()
    if stat.S_ISLNK(supplied_metadata.st_mode):
        raise JsonContractError("input path cannot be a symbolic link")
    if os.name == "nt" and ":" in supplied.name:
        raise JsonContractError("input path cannot name an alternate data stream")
    path = supplied.resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise JsonContractError("input path must be one regular, non-hardlinked file")
    if metadata.st_size <= 0 or metadata.st_size > max_bytes:
        raise JsonContractError("input file is outside the byte budget")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise JsonContractError("input file identity changed before acquisition")
        payload = read_limited_bytes(stream, limit=max_bytes)
        after = os.fstat(stream.fileno())
    if len(payload) > max_bytes:
        raise JsonContractError("input file is outside the byte budget")
    if (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise JsonContractError("input file changed while being read")
    return loads_strict(payload, max_bytes=max_bytes, max_nodes=max_nodes)


def canonical_json_bytes(
    value: object,
    *,
    max_bytes: int = MAX_INPUT_BYTES,
    max_nodes: int = MAX_NODES,
) -> bytes:
    """Serialize the restricted contract domain as FPBR-C14N-1.

    FPBR-C14N-1 is sorted-key, UTF-8 JSON with no insignificant whitespace.
    It is deliberately not advertised as RFC 8785; contract decimals are strings
    and the only JSON numbers in this slice are bounded non-negative integers.
    """

    _validate_budgets(max_bytes=max_bytes, max_nodes=max_nodes)
    try:
        _check_budget(value, max_nodes=max_nodes)
    except (RecursionError, RuntimeError) as exc:
        raise JsonContractError("value could not be traversed inside the exact JSON boundary") from exc
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError, RecursionError, RuntimeError) as exc:
        raise JsonContractError("value cannot be serialized as strict canonical UTF-8 JSON") from exc
    if len(payload) > max_bytes:
        raise JsonContractError("JSON document exceeds the byte budget", reason="input_budget")
    return payload


def write_atomic(path: Path, payload: bytes, *, overwrite: bool = False) -> None:
    supplied = path.absolute()
    if os.name == "nt" and ":" in supplied.name:
        raise OSError("output path cannot name an alternate data stream")
    parent = supplied.parent.resolve(strict=True)
    target = parent / supplied.name
    if supplied.exists() or supplied.is_symlink():
        metadata = supplied.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError("existing output must be one regular, non-hardlinked file")
        if not overwrite:
            raise FileExistsError("output exists; pass --force to replace it")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
