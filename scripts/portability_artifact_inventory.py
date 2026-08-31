#!/usr/bin/env python3
"""Closed logical inventory/content binding for portability artifacts."""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import json
import math
import os
import platform
import re
import stat
import struct
import tarfile
import tomllib
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

try:
    from .validate_release_artifacts import (
        MAX_TAR_STREAM_BYTES,
        validate_raw_gzip_tar,
        validate_raw_zip,
        validate_tarfile_view,
        validate_zipfile_view,
    )
except ImportError:
    from validate_release_artifacts import (  # type: ignore[no-redef]
        MAX_TAR_STREAM_BYTES,
        validate_raw_gzip_tar,
        validate_raw_zip,
        validate_tarfile_view,
        validate_zipfile_view,
    )

FORMAT = "finplanbr.portability-package-binding.v2"
METADATA_POLICY = "finplanbr-setuptools-84.0.0-metadata.v5"
WHEEL_ARCHIVE_POLICY = "finplanbr-wheel-zip32-stored-canonical.v2"
SDIST_ARCHIVE_POLICY = "finplanbr-sdist-gzip-ustar-stored-canonical.v1"
DIST_INFO = "finplanbr-0.1.0.dev0.dist-info"
SDIST_ROOT = "finplanbr-0.1.0.dev0"
PACKAGE = "financial_planning_sdk_br"
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
CANONICAL_ARCHIVE_MTIME = 0
CANONICAL_WHEEL_DATE_TIME = (1980, 1, 1, 0, 0, 0)
CANONICAL_WHEEL_DOS_TIME = 0
CANONICAL_WHEEL_DOS_DATE = 33
CANONICAL_WHEEL_FLAGS = 0
CANONICAL_WHEEL_METHOD = zipfile.ZIP_STORED
CANONICAL_WHEEL_VERSION_NEEDED = 20
CANONICAL_WHEEL_VERSION_MADE_BY = (3 << 8) | 20
CANONICAL_WHEEL_INTERNAL_ATTRIBUTES = 0
CANONICAL_WHEEL_EXTERNAL_ATTRIBUTES = (stat.S_IFREG | 0o644) << 16
CANONICAL_GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
DEFLATE_STORED_BLOCK_MAX = 0xFFFF
TAR_BLOCK_SIZE = 512
TAR_RECORD_BLOCKS = 20
TAR_RECORD_SIZE = TAR_BLOCK_SIZE * TAR_RECORD_BLOCKS
_PAX_MTIME = re.compile(rb"(?:0|[1-9][0-9]*)\.(?:0|[0-9]*[1-9])")

EXPECTED_PACKAGE_FILES = (
    f"{PACKAGE}/__init__.py",
    f"{PACKAGE}/__main__.py",
    f"{PACKAGE}/_schema_validation.py",
    f"{PACKAGE}/_value_object.py",
    f"{PACKAGE}/cli.py",
    f"{PACKAGE}/contracts.py",
    f"{PACKAGE}/deterministic-request.schema.json",
    f"{PACKAGE}/deterministic-result.schema.json",
    f"{PACKAGE}/deterministic.py",
    f"{PACKAGE}/errors.py",
    f"{PACKAGE}/jsonio.py",
    f"{PACKAGE}/numeric.py",
    f"{PACKAGE}/py.typed",
    f"{PACKAGE}/reference-acceptance-pack.v1.json",
    f"{PACKAGE}/reference-acceptance-pack.v2.json",
    f"{PACKAGE}/reference-acceptance-report.schema.json",
    f"{PACKAGE}/reference.py",
    f"{PACKAGE}/validation-report.schema.json",
)
WHEEL_LICENSE_FILE = f"{DIST_INFO}/licenses/LICENSE"
WHEEL_METADATA_FILES = ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD")
EXPECTED_WHEEL_FILES = (
    EXPECTED_PACKAGE_FILES
    + (WHEEL_LICENSE_FILE,)
    + tuple(f"{DIST_INFO}/{name}" for name in WHEEL_METADATA_FILES)
)
SDIST_ROOT_FILES = ("LICENSE", "PKG-INFO", "README.md", "pyproject.toml", "setup.cfg")
SDIST_EGG_INFO_FILES = (
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "entry_points.txt",
    "requires.txt",
    "top_level.txt",
)
EXPECTED_SDIST_FILES = (
    tuple(f"{SDIST_ROOT}/{name}" for name in SDIST_ROOT_FILES)
    + tuple(f"{SDIST_ROOT}/src/{name}" for name in EXPECTED_PACKAGE_FILES)
    + tuple(f"{SDIST_ROOT}/src/finplanbr.egg-info/{name}" for name in SDIST_EGG_INFO_FILES)
)
EXPECTED_SDIST_DIRECTORIES = (
    SDIST_ROOT,
    f"{SDIST_ROOT}/src",
    f"{SDIST_ROOT}/src/{PACKAGE}",
    f"{SDIST_ROOT}/src/finplanbr.egg-info",
)
EXPECTED_RAW_SDIST_MEMBERS = (
    SDIST_ROOT,
    *(f"{SDIST_ROOT}/{name}" for name in SDIST_ROOT_FILES),
    f"{SDIST_ROOT}/src",
    f"{SDIST_ROOT}/src/{PACKAGE}",
    *(f"{SDIST_ROOT}/src/{name}" for name in EXPECTED_PACKAGE_FILES),
    f"{SDIST_ROOT}/src/finplanbr.egg-info",
    *(f"{SDIST_ROOT}/src/finplanbr.egg-info/{name}" for name in SDIST_EGG_INFO_FILES),
)


@dataclass(frozen=True, slots=True)
class _RawSdistProfile:
    system: str
    directory_mode: int
    file_mode: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class _RawSdistMember:
    name: str
    directory: bool
    mode: int
    uid: int
    gid: int
    size: int
    raw_mtime: int
    pax_mtime: str


_RAW_SDIST_PROFILES = {
    "Windows": _RawSdistProfile("Windows", 0o777, 0o666, 0, 0),
    "Linux": _RawSdistProfile("Linux", 0o755, 0o644, 65532, 65532),
}
_ENTRY_POINTS = b"[console_scripts]\nfinplanbr = financial_planning_sdk_br.cli:main\n"
_TOP_LEVEL = b"financial_planning_sdk_br\n"
_WHEEL = b"Wheel-Version: 1.0\nGenerator: setuptools (84.0.0)\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
_SETUP_CFG = b"[egg_info]\ntag_build = \ntag_date = 0\n\n"
_REQUIRES = (
    b"\n[dev]\nbuild==1.4.0\ncoverage==7.16.0\njsonschema==4.26.0\n"
    b"mypy==1.19.1\nruff==0.14.14\n\n[test]\njsonschema==4.26.0\n"
)
_EXPECTED_BUILD_SYSTEM = {"requires": ["setuptools==84.0.0"], "build-backend": "setuptools.build_meta"}
_EXPECTED_LICENSE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
_EXPECTED_PROJECT = {
    "name": "finplanbr",
    "version": "0.1.0.dev0",
    "description": "Nucleo deterministico local para planejamento financeiro no Brasil",
    "readme": "README.md",
    "requires-python": ">=3.11",
    "license": "Apache-2.0",
    "license-files": ["LICENSE"],
    "authors": [{"name": "Arthur Amorim"}],
    "maintainers": [{"name": "Arthur Amorim"}],
    "dependencies": [],
    "keywords": ["brasil", "cash-flow", "deterministic", "financial-planning"],
    "classifiers": [
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Typing :: Typed",
    ],
    "urls": {
        "Homepage": "https://github.com/arthur0211/financial-planning-sdk-br",
        "Documentation": "https://github.com/arthur0211/financial-planning-sdk-br/blob/main/docs/README.md",
        "Repository": "https://github.com/arthur0211/financial-planning-sdk-br",
        "Issues": "https://github.com/arthur0211/financial-planning-sdk-br/issues",
    },
    "optional-dependencies": {
        "test": ["jsonschema==4.26.0"],
        "dev": [
            "build==1.4.0",
            "coverage==7.16.0",
            "jsonschema==4.26.0",
            "mypy==1.19.1",
            "ruff==0.14.14",
        ],
    },
    "scripts": {"finplanbr": "financial_planning_sdk_br.cli:main"},
}
_EXPECTED_SETUPTOOLS = {
    "package-dir": {"": "src"},
    "packages": [PACKAGE],
    "package-data": {
        PACKAGE: [
            "py.typed",
            "*.schema.json",
            "reference-acceptance-pack.v1.json",
            "reference-acceptance-pack.v2.json",
        ]
    },
}
_METADATA_HEADER = (
    b"Metadata-Version: 2.4\n"
    b"Name: finplanbr\n"
    b"Version: 0.1.0.dev0\n"
    b"Summary: Nucleo deterministico local para planejamento financeiro no Brasil\n"
    b"Author: Arthur Amorim\n"
    b"Maintainer: Arthur Amorim\n"
    b"License-Expression: Apache-2.0\n"
    b"Project-URL: Homepage, https://github.com/arthur0211/financial-planning-sdk-br\n"
    b"Project-URL: Documentation, https://github.com/arthur0211/financial-planning-sdk-br/blob/main/docs/README.md\n"
    b"Project-URL: Repository, https://github.com/arthur0211/financial-planning-sdk-br\n"
    b"Project-URL: Issues, https://github.com/arthur0211/financial-planning-sdk-br/issues\n"
    b"Keywords: brasil,cash-flow,deterministic,financial-planning\n"
    b"Classifier: Development Status :: 2 - Pre-Alpha\n"
    b"Classifier: Intended Audience :: Developers\n"
    b"Classifier: Programming Language :: Python :: 3\n"
    b"Classifier: Programming Language :: Python :: 3.11\n"
    b"Classifier: Programming Language :: Python :: 3.12\n"
    b"Classifier: Programming Language :: Python :: 3.13\n"
    b"Classifier: Programming Language :: Python :: 3.14\n"
    b"Classifier: Typing :: Typed\n"
    b"Requires-Python: >=3.11\n"
    b"Description-Content-Type: text/markdown\n"
    b"License-File: LICENSE\n"
    b"Provides-Extra: test\n"
    b'Requires-Dist: jsonschema==4.26.0; extra == "test"\n'
    b"Provides-Extra: dev\n"
    b'Requires-Dist: build==1.4.0; extra == "dev"\n'
    b'Requires-Dist: coverage==7.16.0; extra == "dev"\n'
    b'Requires-Dist: jsonschema==4.26.0; extra == "dev"\n'
    b'Requires-Dist: mypy==1.19.1; extra == "dev"\n'
    b'Requires-Dist: ruff==0.14.14; extra == "dev"\n'
    b"Dynamic: license-file\n"
    b"\n"
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _inventory_digest(files: tuple[str, ...], directories: tuple[str, ...] = ()) -> str:
    records = [
        *({"path": path, "type": "directory"} for path in directories),
        *({"path": path, "type": "file"} for path in files),
    ]
    records.sort(key=lambda item: item["path"].encode("utf-8"))
    return _digest(_canonical(records))


EXPECTED_PACKAGE_INVENTORY_SHA256 = _inventory_digest(EXPECTED_PACKAGE_FILES)
EXPECTED_WHEEL_INVENTORY_SHA256 = _inventory_digest(EXPECTED_WHEEL_FILES)
EXPECTED_SDIST_INVENTORY_SHA256 = _inventory_digest(EXPECTED_SDIST_FILES, EXPECTED_SDIST_DIRECTORIES)


def _logical_digest(files: dict[str, bytes]) -> str:
    records = [
        {"path": path, "sha256": _digest(payload), "size": len(payload)}
        for path, payload in sorted(files.items(), key=lambda item: item[0].encode("utf-8"))
    ]
    return _digest(_canonical(records))


def _normalize_generated_metadata(payload: bytes) -> bytes:
    text = payload.decode("utf-8", errors="strict")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _read_regular_blob(path: Path) -> bytes:
    resolved = path.resolve(strict=True)
    before = resolved.stat(follow_symlinks=False)
    if resolved.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError("artifact must be a regular single-link file")
    if before.st_size > MAX_ARCHIVE_BYTES:
        raise RuntimeError("artifact exceeds its compressed-byte budget")
    payload = resolved.read_bytes()
    after = resolved.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(payload) != before.st_size:
        raise RuntimeError("artifact changed while its bytes were snapshotted")
    return payload


def _tar_octal(field: bytes, context: str) -> int:
    if len(field) < 2 or field[-1:] != b"\x00" or any(byte not in b"01234567" for byte in field[:-1]):
        raise RuntimeError(f"{context} is not canonical octal")
    return int(field[:-1], 8)


def _tar_checksum(field: bytes, context: str) -> int:
    if len(field) != 8 or field[6:] != b"\x00 " or any(byte not in b"01234567" for byte in field[:6]):
        raise RuntimeError(f"{context} is not the canonical six-octal-digit encoding")
    return int(field[:6], 8)


def _raw_sdist_profile() -> _RawSdistProfile:
    system = platform.system()
    try:
        return _RAW_SDIST_PROFILES[system]
    except KeyError as exc:
        raise RuntimeError("raw build sdist platform is outside the Windows/Linux backend profile") from exc


def _raw_tar_text(expected: str, width: int, context: str) -> bytes:
    try:
        encoded = expected.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:  # pragma: no cover - constants are ASCII by construction
        raise RuntimeError(f"{context} is not ASCII") from exc
    if not encoded or len(encoded) > width:
        raise RuntimeError(f"{context} exceeds its raw USTAR field")
    return encoded.ljust(width, b"\x00")


def _parse_pax_mtime(payload: bytes) -> tuple[str, int]:
    match = re.fullmatch(rb"([0-9]+) mtime=((?:0|[1-9][0-9]*)\.(?:0|[0-9]*[1-9]))\n", payload)
    if (
        match is None
        or match.group(1) != str(len(payload)).encode("ascii")
        or _PAX_MTIME.fullmatch(match.group(2)) is None
    ):
        raise RuntimeError("raw build TAR PAX payload is not one canonical mtime record")
    encoded = match.group(2)
    if len(encoded) > 32:
        raise RuntimeError("raw build TAR PAX mtime exceeds the closed backend representation")
    text = encoded.decode("ascii", errors="strict")
    value = float(text)
    if not math.isfinite(value) or str(value) != text:
        raise RuntimeError("raw build TAR PAX mtime is not the canonical Python float representation")
    rounded = round(value)
    if rounded < 0 or rounded >= 8**11:
        raise RuntimeError("raw build TAR PAX mtime exceeds the USTAR field")
    return text, rounded


def _gzip_tar_payload(payload: bytes) -> bytes:
    if len(payload) < 19 or payload[:4] != b"\x1f\x8b\x08\x08":
        raise RuntimeError("raw build sdist must use one gzip member with only FNAME")
    if payload[8] != 2 or payload[9] not in {0, 3, 11, 255}:
        raise RuntimeError("raw build sdist gzip XFL/OS fields are outside the closed policy")
    end = payload.find(b"\x00", 10, 10 + 256)
    if end < 0 or payload[10:end] != f"{SDIST_ROOT}.tar".encode("ascii"):
        raise RuntimeError("raw build sdist gzip FNAME is not the exact expected basename")
    inflater = zlib.decompressobj(-zlib.MAX_WBITS)
    tar_payload = inflater.decompress(payload[end + 1 :], MAX_TAR_STREAM_BYTES + 1)
    if len(tar_payload) > MAX_TAR_STREAM_BYTES or inflater.unconsumed_tail:
        raise RuntimeError("raw build sdist TAR exceeds its decompressed-stream budget")
    if not inflater.eof:
        raise RuntimeError("raw build sdist gzip DEFLATE stream is incomplete")
    trailer = inflater.unused_data
    if len(trailer) != 8:
        raise RuntimeError("raw build sdist contains a second member or trailing bytes")
    crc32, size = struct.unpack("<II", trailer)
    if zlib.crc32(tar_payload) & 0xFFFFFFFF != crc32 or len(tar_payload) & 0xFFFFFFFF != size:
        raise RuntimeError("raw build sdist gzip trailer differs from the TAR bytes")
    return tar_payload


def _canonical_gzip_stored(payload: bytes) -> bytes:
    """Serialize one RFC 1952 member without delegating DEFLATE bytes to zlib."""

    blocks = bytearray()
    if payload:
        for offset in range(0, len(payload), DEFLATE_STORED_BLOCK_MAX):
            chunk = payload[offset : offset + DEFLATE_STORED_BLOCK_MAX]
            final = offset + len(chunk) == len(payload)
            blocks.append(1 if final else 0)
            blocks.extend(struct.pack("<HH", len(chunk), len(chunk) ^ 0xFFFF))
            blocks.extend(chunk)
    else:
        blocks.extend(b"\x01\x00\x00\xff\xff")
    trailer = struct.pack(
        "<II",
        binascii.crc32(payload) & 0xFFFFFFFF,
        len(payload) & 0xFFFFFFFF,
    )
    return CANONICAL_GZIP_HEADER + bytes(blocks) + trailer


def _canonical_gzip_tar_payload(payload: bytes) -> bytes:
    if len(payload) < len(CANONICAL_GZIP_HEADER) + 5 + 8 or payload[:10] != CANONICAL_GZIP_HEADER:
        raise RuntimeError("canonical sdist gzip header differs from the closed header policy")

    cursor = len(CANONICAL_GZIP_HEADER)
    tar_payload = bytearray()
    while True:
        if cursor + 5 > len(payload) - 8:
            raise RuntimeError("canonical sdist DEFLATE STORED block is truncated")
        block_header = payload[cursor]
        cursor += 1
        if block_header not in {0, 1}:
            raise RuntimeError("canonical sdist DEFLATE stream is not the closed STORED-block profile")
        length, complement = struct.unpack_from("<HH", payload, cursor)
        cursor += 4
        if complement != length ^ 0xFFFF:
            raise RuntimeError("canonical sdist DEFLATE STORED LEN/NLEN fields disagree")
        end = cursor + length
        if end > len(payload) - 8:
            raise RuntimeError("canonical sdist DEFLATE STORED block payload is truncated")
        if len(tar_payload) + length > MAX_TAR_STREAM_BYTES:
            raise RuntimeError("canonical sdist TAR exceeds its decompressed-stream budget")
        tar_payload.extend(payload[cursor:end])
        cursor = end
        if block_header == 1:
            break
        if length != DEFLATE_STORED_BLOCK_MAX:
            raise RuntimeError("canonical sdist DEFLATE STORED block boundary differs from the closed policy")

    if cursor + 8 != len(payload):
        raise RuntimeError("canonical sdist contains a second gzip member or trailing bytes")
    crc32, size = struct.unpack_from("<II", payload, cursor)
    decoded = bytes(tar_payload)
    if binascii.crc32(decoded) & 0xFFFFFFFF != crc32 or len(decoded) & 0xFFFFFFFF != size:
        raise RuntimeError("canonical sdist gzip trailer differs from the TAR bytes")
    if payload != _canonical_gzip_stored(decoded):
        raise RuntimeError("canonical sdist DEFLATE STORED blocks differ from the closed byte profile")
    return decoded


def _canonical_tar_octal(value: int, width: int, context: str) -> bytes:
    """Encode the one POSIX octal representation admitted by the profile."""

    if type(value) is not int or value < 0 or value >= 8 ** (width - 1):
        raise RuntimeError(f"{context} exceeds its canonical USTAR octal field")
    return f"{value:0{width - 1}o}\0".encode("ascii")


def _canonical_tar_text(value: str, width: int, context: str) -> bytes:
    """Encode an exact ASCII USTAR text field with NUL-only padding."""

    if type(value) is not str or not value or "\x00" in value:
        raise RuntimeError(f"{context} is not a canonical USTAR text value")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise RuntimeError(f"{context} is not ASCII") from exc
    if len(encoded) > width:
        raise RuntimeError(f"{context} exceeds its canonical USTAR field")
    return encoded.ljust(width, b"\x00")


def _canonical_ustar_header(name: str, *, directory: bool, size: int) -> bytes:
    """Serialize one header in the only USTAR field representation admitted here."""

    if name.endswith("/"):
        raise RuntimeError("canonical USTAR logical names must not carry a trailing slash")
    if directory and size != 0:
        raise RuntimeError("canonical USTAR directory cannot carry a payload")
    archive_name = name + "/" if directory else name
    header = bytearray(TAR_BLOCK_SIZE)
    header[0:100] = _canonical_tar_text(archive_name, 100, "canonical USTAR name")
    header[100:108] = _canonical_tar_octal(0o755 if directory else 0o644, 8, "canonical USTAR mode")
    header[108:116] = _canonical_tar_octal(0, 8, "canonical USTAR uid")
    header[116:124] = _canonical_tar_octal(0, 8, "canonical USTAR gid")
    header[124:136] = _canonical_tar_octal(size, 12, "canonical USTAR size")
    header[136:148] = _canonical_tar_octal(CANONICAL_ARCHIVE_MTIME, 12, "canonical USTAR mtime")
    header[148:156] = b"        "
    header[156:157] = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    header[257:263] = b"ustar\x00"
    header[263:265] = b"00"
    checksum = sum(header)
    if checksum >= 8**6:
        raise RuntimeError("canonical USTAR checksum exceeds its field")
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header)


def _canonical_ustar_payload(files: dict[str, bytes]) -> bytes:
    """Serialize the exact sdist roster, field choices, order, padding, and EOF."""

    if set(files) != set(EXPECTED_SDIST_FILES):
        raise RuntimeError("sdist inventory differs from the closed canonical USTAR roster")
    stream = bytearray()
    for name in EXPECTED_SDIST_DIRECTORIES:
        stream.extend(_canonical_ustar_header(name, directory=True, size=0))
    for name in EXPECTED_SDIST_FILES:
        payload = files[name]
        if type(payload) is not bytes:
            raise RuntimeError("canonical USTAR member payload must be exact bytes")
        if len(payload) > MAX_MEMBER_BYTES:
            raise RuntimeError("canonical USTAR member exceeds its byte budget")
        stream.extend(_canonical_ustar_header(name, directory=False, size=len(payload)))
        stream.extend(payload)
        remainder = len(payload) % TAR_BLOCK_SIZE
        if remainder:
            stream.extend(b"\x00" * (TAR_BLOCK_SIZE - remainder))
    stream.extend(b"\x00" * (2 * TAR_BLOCK_SIZE))
    remainder = len(stream) % TAR_RECORD_SIZE
    if remainder:
        stream.extend(b"\x00" * (TAR_RECORD_SIZE - remainder))
    if len(stream) > MAX_TAR_STREAM_BYTES:
        raise RuntimeError("canonical sdist TAR exceeds its decompressed-stream budget")
    return bytes(stream)


def _validate_setuptools_pax_stream(payload: bytes) -> tuple[_RawSdistMember, ...]:
    profile = _raw_sdist_profile()
    if not payload or len(payload) % TAR_RECORD_SIZE:
        raise RuntimeError("raw build TAR is not aligned to the backend 10,240-byte record")
    cursor = 0
    pending_mtime: tuple[str, int] | None = None
    observed: list[_RawSdistMember] = []
    while cursor < len(payload):
        header = payload[cursor : cursor + TAR_BLOCK_SIZE]
        if header == b"\x00" * TAR_BLOCK_SIZE:
            expected_end = (
                (cursor + 2 * TAR_BLOCK_SIZE + TAR_RECORD_SIZE - 1) // TAR_RECORD_SIZE
            ) * TAR_RECORD_SIZE
            if (
                payload[cursor : cursor + 2 * TAR_BLOCK_SIZE] != b"\x00" * (2 * TAR_BLOCK_SIZE)
                or len(payload) != expected_end
                or any(payload[cursor + 2 * TAR_BLOCK_SIZE :])
            ):
                raise RuntimeError("raw build TAR has nonzero bytes after its first EOF marker")
            break
        if header[257:263] != b"ustar\x00" or header[263:265] != b"00" or any(header[500:512]):
            raise RuntimeError("raw build TAR header is not strict POSIX USTAR")
        stored = _tar_checksum(header[148:156], "TAR checksum")
        if stored != sum(header[:148]) + 8 * ord(" ") + sum(header[156:]):
            raise RuntimeError("raw build TAR checksum differs from its header")
        if any(header[157:257]) or any(header[265:345]) or any(header[345:500]):
            raise RuntimeError("raw build TAR contains nonempty link, owner, device, or prefix fields")
        mode = _tar_octal(header[100:108], "TAR mode")
        uid = _tar_octal(header[108:116], "TAR uid")
        gid = _tar_octal(header[116:124], "TAR gid")
        size = _tar_octal(header[124:136], "TAR size")
        raw_mtime = _tar_octal(header[136:148], "TAR mtime")
        if size > MAX_MEMBER_BYTES:
            raise RuntimeError("raw build TAR member exceeds its byte budget")
        typeflag = header[156:157]
        data_start = cursor + TAR_BLOCK_SIZE
        data_end = data_start + size
        next_offset = data_start + ((size + TAR_BLOCK_SIZE - 1) // TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE
        if next_offset > len(payload) or any(payload[data_end:next_offset]):
            raise RuntimeError("raw build TAR member or padding is malformed")
        member_payload = payload[data_start:data_end]
        if typeflag == tarfile.XHDTYPE:
            if header[0:100] != _raw_tar_text("././@PaxHeader", 100, "raw PAX header name"):
                raise RuntimeError("raw build TAR PAX header name is not canonical")
            if mode != 0 or uid != 0 or gid != 0 or raw_mtime != 0:
                raise RuntimeError("raw build TAR PAX header attributes differ from the backend profile")
            if pending_mtime is not None or len(observed) >= len(EXPECTED_RAW_SDIST_MEMBERS):
                raise RuntimeError("raw build TAR contains an unexpected or stacked PAX header")
            pending_mtime = _parse_pax_mtime(member_payload)
        else:
            if pending_mtime is None:
                raise RuntimeError("raw build TAR member is missing its one canonical PAX mtime header")
            if len(observed) >= len(EXPECTED_RAW_SDIST_MEMBERS):
                raise RuntimeError("raw build sdist inventory differs from the closed portability roster")
            name = EXPECTED_RAW_SDIST_MEMBERS[len(observed)]
            directory = name in EXPECTED_SDIST_DIRECTORIES
            archive_name = name + "/" if directory else name
            if header[0:100] != _raw_tar_text(archive_name, 100, f"raw TAR name for {name!r}"):
                raise RuntimeError("raw build sdist inventory name/order differs from the closed backend roster")
            expected_type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
            if typeflag != expected_type:
                raise RuntimeError("raw build TAR contains a link, device, or special member")
            expected_mode = profile.directory_mode if directory else profile.file_mode
            if mode != expected_mode or uid != profile.uid or gid != profile.gid:
                raise RuntimeError(f"raw build TAR member attributes differ from the {profile.system} backend profile")
            pax_mtime, expected_raw_mtime = pending_mtime
            if raw_mtime != expected_raw_mtime:
                raise RuntimeError("raw build TAR USTAR mtime does not match its canonical PAX mtime")
            if directory and size:
                raise RuntimeError("raw build TAR directory has a payload")
            observed.append(
                _RawSdistMember(name, directory, mode, uid, gid, size, raw_mtime, pax_mtime)
            )
            pending_mtime = None
        cursor = next_offset
    else:
        raise RuntimeError("raw build TAR ended without an EOF marker")
    if pending_mtime is not None:
        raise RuntimeError("raw build TAR ends with an orphan PAX header")
    if tuple(member.name for member in observed) != EXPECTED_RAW_SDIST_MEMBERS:
        raise RuntimeError("raw build sdist inventory differs from the closed portability roster")
    return tuple(observed)


def _source_package(source_root: Path) -> dict[str, bytes]:
    package_root = source_root.resolve(strict=True) / "src" / PACKAGE
    entries = sorted(package_root.rglob("*"), key=lambda path: os.fsencode(path.relative_to(package_root)))
    observed: dict[str, bytes] = {}
    for path in entries:
        status = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise RuntimeError("source package contains a non-regular, linked, or directory entry")
        relative = f"{PACKAGE}/{path.relative_to(package_root).as_posix()}"
        payload = path.read_bytes()
        if len(payload) != status.st_size or len(payload) > MAX_MEMBER_BYTES:
            raise RuntimeError("source package member changed or exceeded its byte budget")
        observed[relative] = payload
    if set(observed) != set(EXPECTED_PACKAGE_FILES):
        raise RuntimeError("source package inventory differs from the closed portability roster")
    return observed


def _source_project(source_root: Path) -> tuple[bytes, bytes, bytes, bytes]:
    root = source_root.resolve(strict=True)
    payloads: dict[str, bytes] = {}
    for name in ("LICENSE", "README.md", "pyproject.toml"):
        path = root / name
        before = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"source {name} must be a regular single-link file")
        payload = path.read_bytes()
        after = path.stat(follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(payload) != before.st_size
            or len(payload) > MAX_MEMBER_BYTES
        ):
            raise RuntimeError(f"source {name} changed or exceeded its byte budget")
        payloads[name] = payload
    try:
        configuration = tomllib.loads(payloads["pyproject.toml"].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError("source pyproject.toml is not closed UTF-8 TOML") from exc
    if (
        configuration.get("build-system") != _EXPECTED_BUILD_SYSTEM
        or configuration.get("project") != _EXPECTED_PROJECT
        or configuration.get("tool", {}).get("setuptools") != _EXPECTED_SETUPTOOLS
    ):
        raise RuntimeError("source pyproject packaging/dependency metadata differs from the closed policy")
    if _digest(payloads["LICENSE"]) != _EXPECTED_LICENSE_SHA256:
        raise RuntimeError("source LICENSE bytes differ from the closed Apache-2.0 license policy")
    return (
        payloads["README.md"],
        payloads["pyproject.toml"],
        payloads["LICENSE"],
        _METADATA_HEADER + payloads["README.md"],
    )


def _canonical_sdist_generated_files(files: dict[str, bytes]) -> dict[str, bytes]:
    """Validate generated metadata, then choose its single LF representation."""

    prefix = f"{SDIST_ROOT}/"
    egg = prefix + "src/finplanbr.egg-info/"
    sources = [
        "LICENSE",
        "README.md",
        "pyproject.toml",
        *("src/" + name for name in EXPECTED_PACKAGE_FILES),
        *("src/finplanbr.egg-info/" + name for name in SDIST_EGG_INFO_FILES),
    ]
    metadata = _METADATA_HEADER + files[prefix + "README.md"]
    expected = {
        prefix + "PKG-INFO": metadata,
        prefix + "setup.cfg": _SETUP_CFG,
        egg + "PKG-INFO": metadata,
        egg + "SOURCES.txt": b"\n".join(name.encode("utf-8") for name in sources),
        egg + "dependency_links.txt": b"\n",
        egg + "entry_points.txt": _ENTRY_POINTS,
        egg + "requires.txt": _REQUIRES,
        egg + "top_level.txt": _TOP_LEVEL,
    }
    for name, canonical in expected.items():
        if _normalize_generated_metadata(files[name]) != canonical:
            raise RuntimeError(f"raw build sdist generated metadata {name!r} differs from the closed policy")
    return expected


def _decoded_wheel_snapshot(path: Path) -> tuple[bytes, dict[str, bytes]]:
    """Decode one backend wheel only after the generic raw/zipfile views agree."""

    payload = _read_regular_blob(path)
    failures: list[str] = []
    raw_entries = validate_raw_zip(payload, path.name, failures)
    if raw_entries is None:
        raise RuntimeError("; ".join(failures))
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        infos = archive.infolist()
        if not validate_zipfile_view(raw_entries, archive, infos, path.name, failures):
            raise RuntimeError("; ".join(failures))
        names = [info.filename for info in infos]
        if len(names) != len(set(names)) or set(names) != set(EXPECTED_WHEEL_FILES):
            raise RuntimeError("wheel inventory differs from the closed portability roster")
        for info in infos:
            unix_mode = info.external_attr >> 16
            if (
                info.is_dir()
                or info.file_size > MAX_MEMBER_BYTES
                or not stat.S_ISREG(unix_mode)
                or unix_mode & 0o777 not in {0o644, 0o664, 0o666}
                or info.external_attr & 0xFFFF
            ):
                raise RuntimeError("wheel contains a directory, symlink, special mode, or oversized member")
        return payload, {entry.name: entry.decoded_payload for entry in raw_entries}


def _expected_record_hash(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return "sha256=" + encoded.decode("ascii")


def _validate_record_integrity(files: dict[str, bytes]) -> None:
    record_name = f"{DIST_INFO}/RECORD"
    text = files[record_name].decode("utf-8", errors="strict")
    rows = list(csv.reader(io.StringIO(text, newline="")))
    if any(len(row) != 3 for row in rows) or len(rows) != len(files):
        raise RuntimeError("wheel RECORD shape/count is invalid")
    observed: dict[str, tuple[str, str]] = {}
    for name, digest, size in rows:
        if name in observed:
            raise RuntimeError("wheel RECORD contains a duplicate")
        observed[name] = (digest, size)
    if set(observed) != set(files) or observed[record_name] != ("", ""):
        raise RuntimeError("wheel RECORD inventory or self-row is invalid")
    for name, payload in files.items():
        if name == record_name:
            continue
        if observed[name] != (_expected_record_hash(payload), str(len(payload))):
            raise RuntimeError("wheel RECORD digest/size differs from decoded bytes")


def _canonical_record(files: dict[str, bytes]) -> bytes:
    record_name = f"{DIST_INFO}/RECORD"
    if set(files) != set(EXPECTED_WHEEL_FILES) or EXPECTED_WHEEL_FILES[-1] != record_name:
        raise RuntimeError("wheel RECORD cannot be generated outside the closed ordered roster")
    rows: list[str] = []
    for name in EXPECTED_WHEEL_FILES:
        if name == record_name:
            rows.append(f"{name},,")
            continue
        payload = files[name]
        rows.append(f"{name},{_expected_record_hash(payload)},{len(payload)}")
    return ("\n".join(rows) + "\n").encode("ascii")


def _canonical_wheel_payload(files: dict[str, bytes]) -> bytes:
    """Serialize the closed wheel profile without a backend or zipfile writer."""

    if set(files) != set(EXPECTED_WHEEL_FILES):
        raise RuntimeError("wheel inventory differs from the closed portability roster")
    canonical_files = dict(files)
    canonical_files[f"{DIST_INFO}/RECORD"] = _canonical_record(canonical_files)
    local_stream = bytearray()
    central_rows: list[tuple[bytes, int, int, int]] = []
    for name in EXPECTED_WHEEL_FILES:
        try:
            encoded_name = name.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise RuntimeError("canonical wheel roster contains a non-ASCII name") from exc
        member_payload = canonical_files[name]
        if len(member_payload) > MAX_MEMBER_BYTES:
            raise RuntimeError("canonical wheel member exceeds its byte budget")
        local_offset = len(local_stream)
        crc32 = zlib.crc32(member_payload) & 0xFFFFFFFF
        size = len(member_payload)
        local_stream.extend(
            struct.pack(
                "<4s5H3I2H",
                b"PK\x03\x04",
                CANONICAL_WHEEL_VERSION_NEEDED,
                CANONICAL_WHEEL_FLAGS,
                CANONICAL_WHEEL_METHOD,
                CANONICAL_WHEEL_DOS_TIME,
                CANONICAL_WHEEL_DOS_DATE,
                crc32,
                size,
                size,
                len(encoded_name),
                0,
            )
        )
        local_stream.extend(encoded_name)
        local_stream.extend(member_payload)
        central_rows.append((encoded_name, local_offset, crc32, size))

    central_offset = len(local_stream)
    central_stream = bytearray()
    for encoded_name, local_offset, crc32, size in central_rows:
        central_stream.extend(
            struct.pack(
                "<4s6H3I5H2I",
                b"PK\x01\x02",
                CANONICAL_WHEEL_VERSION_MADE_BY,
                CANONICAL_WHEEL_VERSION_NEEDED,
                CANONICAL_WHEEL_FLAGS,
                CANONICAL_WHEEL_METHOD,
                CANONICAL_WHEEL_DOS_TIME,
                CANONICAL_WHEEL_DOS_DATE,
                crc32,
                size,
                size,
                len(encoded_name),
                0,
                0,
                0,
                CANONICAL_WHEEL_INTERNAL_ATTRIBUTES,
                CANONICAL_WHEEL_EXTERNAL_ATTRIBUTES,
                local_offset,
            )
        )
        central_stream.extend(encoded_name)
    central_size = len(central_stream)
    member_count = len(central_rows)
    if max(central_offset, central_size, len(local_stream) + central_size) > 0xFFFFFFFF:
        raise RuntimeError("canonical wheel exceeds the ZIP32 offset budget")
    end_record = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        member_count,
        member_count,
        central_size,
        central_offset,
        0,
    )
    return bytes(local_stream + central_stream + end_record)


def _canonical_generated_wheel_files(
    files: dict[str, bytes], source_root: Path
) -> tuple[dict[str, bytes], bytes, bytes]:
    """Bind backend-generated wheel metadata to one source-derived LF form."""

    _, _, source_license, expected_metadata = _source_project(source_root)
    if files[WHEEL_LICENSE_FILE] != source_license:
        raise RuntimeError("wheel LICENSE bytes differ from the frozen source")
    expected = {
        "METADATA": expected_metadata,
        "WHEEL": _WHEEL,
        "entry_points.txt": _ENTRY_POINTS,
        "top_level.txt": _TOP_LEVEL,
    }
    canonical_files = dict(files)
    for name, payload in expected.items():
        archive_name = f"{DIST_INFO}/{name}"
        if _normalize_generated_metadata(files[archive_name]) != payload:
            if name == "METADATA":
                raise RuntimeError("wheel METADATA/readme/dependency roster differs from the closed source policy")
            raise RuntimeError(f"wheel {name} differs from the closed metadata policy")
        canonical_files[archive_name] = payload
    return canonical_files, expected_metadata, source_license


def canonicalize_wheel(raw_path: Path, target: Path, *, source_root: Path) -> Path:
    """Erase backend ZIP and generated-metadata channels into one wheel."""

    _, files = _decoded_wheel_snapshot(raw_path)
    _validate_record_integrity(files)
    canonical_files, expected_metadata, source_license = _canonical_generated_wheel_files(files, source_root)
    canonical_payload = _canonical_wheel_payload(canonical_files)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise RuntimeError("canonical wheel target already exists")
    target.write_bytes(canonical_payload)
    written_files, _ = _wheel_files(target)
    _validate_metadata(written_files, expected_metadata, source_license)
    return target


def _wheel_files(path: Path) -> tuple[dict[str, bytes], str]:
    payload, files = _decoded_wheel_snapshot(path)
    if payload != _canonical_wheel_payload(files):
        raise RuntimeError("wheel bytes differ from the canonical stored ZIP32 policy")
    return files, _digest(payload)


def _validate_metadata(files: dict[str, bytes], expected_metadata: bytes, source_license: bytes) -> bytes:
    metadata = files[f"{DIST_INFO}/METADATA"]
    if metadata != expected_metadata:
        raise RuntimeError("wheel METADATA/readme/dependency roster differs from the closed source policy")
    if files[WHEEL_LICENSE_FILE] != source_license:
        raise RuntimeError("wheel LICENSE bytes differ from the frozen source")
    expected = {
        "WHEEL": _WHEEL,
        "entry_points.txt": _ENTRY_POINTS,
        "top_level.txt": _TOP_LEVEL,
    }
    for name, payload in expected.items():
        if files[f"{DIST_INFO}/{name}"] != payload:
            raise RuntimeError(f"wheel {name} differs from the closed metadata policy")
    if files[f"{DIST_INFO}/RECORD"] != _canonical_record(files):
        raise RuntimeError("wheel RECORD bytes/order differ from the canonical policy")
    _validate_record_integrity(files)
    return metadata


def _wheel_binding(path: Path, expected_metadata: bytes, source_license: bytes) -> tuple[str, str, bytes, str]:
    files, archive_digest = _wheel_files(path)
    metadata = _validate_metadata(files, expected_metadata, source_license)
    package = {name: files[name] for name in EXPECTED_PACKAGE_FILES}
    logical = dict(package)
    for name in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt"):
        logical[f"dist-info/{name}"] = files[f"{DIST_INFO}/{name}"]
    logical["dist-info/licenses/LICENSE"] = files[WHEEL_LICENSE_FILE]
    return _logical_digest(package), _logical_digest(logical), metadata, archive_digest


def _sdist_files(path: Path) -> tuple[dict[str, bytes], str]:
    archive_payload = _read_regular_blob(path)
    tar_payload = _canonical_gzip_tar_payload(archive_payload)
    failures: list[str] = []
    raw_entries = validate_raw_gzip_tar(archive_payload, path.name, failures)
    if raw_entries is None:
        raise RuntimeError("; ".join(failures))
    with tarfile.open(fileobj=io.BytesIO(archive_payload), mode="r:gz", encoding="utf-8", errors="strict") as archive:
        members = archive.getmembers()
        if not validate_tarfile_view(raw_entries, members, path.name, failures):
            raise RuntimeError("; ".join(failures))
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise RuntimeError("sdist contains a duplicate member")
        files = {member.name for member in members if member.isfile()}
        directories = {member.name for member in members if member.isdir()}
        if files != set(EXPECTED_SDIST_FILES) or directories != set(EXPECTED_SDIST_DIRECTORIES):
            raise RuntimeError("sdist inventory differs from the closed portability roster")
        if any(not (member.isfile() or member.isdir()) for member in members):
            raise RuntimeError("sdist contains an unsupported member type")
        for member in members:
            allowed_modes = {0o755} if member.isdir() else {0o644}
            if (
                member.mode not in allowed_modes
                or member.uid != 0
                or member.gid != 0
                or member.uname
                or member.gname
                or member.mtime != CANONICAL_ARCHIVE_MTIME
                or member.pax_headers
                or member.sparse is not None
            ):
                raise RuntimeError("sdist member attributes differ from the canonical USTAR policy")
        result: dict[str, bytes] = {}
        for member in members:
            if not member.isfile():
                continue
            if member.size > MAX_MEMBER_BYTES:
                raise RuntimeError("sdist member exceeds its byte budget")
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError("sdist regular member could not be read")
            payload = stream.read(MAX_MEMBER_BYTES + 1)
            if len(payload) != member.size:
                raise RuntimeError("sdist member size differs from decoded bytes")
            result[member.name] = payload
        if tar_payload != _canonical_ustar_payload(result):
            raise RuntimeError("sdist TAR bytes differ from the canonical USTAR policy")
        return result, _digest(archive_payload)


def canonicalize_sdist(raw_path: Path, target: Path) -> Path:
    """Close backend PAX/timestamp channels into one deterministic USTAR+gzip sdist."""

    raw_payload = _read_regular_blob(raw_path)
    tar_payload = _gzip_tar_payload(raw_payload)
    raw_members = _validate_setuptools_pax_stream(tar_payload)
    profile = _raw_sdist_profile()
    with tarfile.open(fileobj=io.BytesIO(raw_payload), mode="r:gz", encoding="utf-8", errors="strict") as archive:
        members = archive.getmembers()
        if len(members) != len(raw_members):
            raise RuntimeError("raw build sdist exposes attributes outside the canonicalization policy")
        files: dict[str, bytes] = {}
        directories: set[str] = set()
        for member, raw in zip(members, raw_members, strict=True):
            expected_mode = profile.directory_mode if raw.directory else profile.file_mode
            if (
                member.name != raw.name
                or member.type != (tarfile.DIRTYPE if raw.directory else tarfile.REGTYPE)
                or member.isdir() != raw.directory
                or member.isfile() == raw.directory
                or member.mode != raw.mode
                or member.mode != expected_mode
                or member.uid != raw.uid
                or member.uid != profile.uid
                or member.gid != raw.gid
                or member.gid != profile.gid
                or member.size != raw.size
                or member.mtime != float(raw.pax_mtime)
                or str(member.mtime) != raw.pax_mtime
                or member.uname != ""
                or member.gname != ""
                or member.pax_headers != {"mtime": raw.pax_mtime}
                or member.sparse is not None
                or member.linkname != ""
                or member.devmajor != 0
                or member.devminor != 0
            ):
                raise RuntimeError("raw build sdist exposes attributes outside the canonicalization policy")
            name = raw.name
            if member.isdir():
                directories.add(name)
                continue
            if member.size > MAX_MEMBER_BYTES:
                raise RuntimeError("raw build sdist member exceeds its byte budget")
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError("raw build sdist regular member could not be read")
            payload = stream.read(MAX_MEMBER_BYTES + 1)
            if len(payload) != member.size:
                raise RuntimeError("raw build sdist member size differs from decoded bytes")
            files[name] = payload
    if set(files) != set(EXPECTED_SDIST_FILES) or directories != set(EXPECTED_SDIST_DIRECTORIES):
        raise RuntimeError("raw build sdist inventory differs from the closed portability roster")
    files.update(_canonical_sdist_generated_files(files))

    canonical_tar = _canonical_ustar_payload(files)
    canonical_payload = _canonical_gzip_stored(canonical_tar)
    if len(canonical_payload) > MAX_ARCHIVE_BYTES:
        raise RuntimeError("canonical sdist exceeds its compressed-byte budget")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise RuntimeError("canonical sdist target already exists")
    target.write_bytes(canonical_payload)
    _sdist_files(target)
    return target


def _validate_sdist_metadata(
    files: dict[str, bytes],
    wheel_metadata: bytes,
    source_readme: bytes,
    source_pyproject: bytes,
    source_license: bytes,
) -> None:
    prefix = f"{SDIST_ROOT}/"
    egg = prefix + "src/finplanbr.egg-info/"
    if files[prefix + "PKG-INFO"] != wheel_metadata:
        raise RuntimeError("sdist PKG-INFO differs from wheel METADATA")
    if files[egg + "PKG-INFO"] != wheel_metadata:
        raise RuntimeError("sdist egg-info PKG-INFO differs from wheel METADATA")
    if files[prefix + "README.md"] != source_readme:
        raise RuntimeError("sdist README.md bytes differ from the frozen source")
    if files[prefix + "pyproject.toml"] != source_pyproject:
        raise RuntimeError("sdist pyproject.toml bytes differ from the frozen source")
    if files[prefix + "LICENSE"] != source_license:
        raise RuntimeError("sdist LICENSE bytes differ from the frozen source")
    expected = {
        prefix + "setup.cfg": _SETUP_CFG,
        egg + "dependency_links.txt": b"\n",
        egg + "entry_points.txt": _ENTRY_POINTS,
        egg + "requires.txt": _REQUIRES,
        egg + "top_level.txt": _TOP_LEVEL,
    }
    for name, payload in expected.items():
        if files[name] != payload:
            raise RuntimeError("sdist generated metadata differs from the closed policy")
    expected_sources = [
        "LICENSE",
        "README.md",
        "pyproject.toml",
        *("src/" + name for name in EXPECTED_PACKAGE_FILES),
        *("src/finplanbr.egg-info/" + name for name in SDIST_EGG_INFO_FILES),
    ]
    sources = b"\n".join(name.encode("utf-8") for name in expected_sources)
    if files[egg + "SOURCES.txt"] != sources:
        raise RuntimeError("sdist SOURCES.txt differs from the closed inventory")


def _sdist_binding(
    path: Path,
    wheel_metadata: bytes,
    source_readme: bytes,
    source_pyproject: bytes,
    source_license: bytes,
) -> tuple[str, str, str]:
    files, archive_digest = _sdist_files(path)
    _validate_sdist_metadata(files, wheel_metadata, source_readme, source_pyproject, source_license)
    prefix = f"{SDIST_ROOT}/src/"
    package = {name: files[prefix + name] for name in EXPECTED_PACKAGE_FILES}
    logical: dict[str, bytes] = {}
    for name, payload in files.items():
        relative = name.removeprefix(f"{SDIST_ROOT}/")
        logical[relative] = payload
    return _logical_digest(package), _logical_digest(logical), archive_digest


def inspect_package_artifacts(
    *, source_root: Path, direct_wheel: Path, sdist: Path, rebuilt_wheel: Path
) -> dict[str, object]:
    source_package = _source_package(source_root)
    source_readme, source_pyproject, source_license, expected_metadata = _source_project(source_root)
    source_package_digest = _logical_digest(source_package)
    direct_package_digest, direct_wheel_digest, direct_metadata, direct_archive_digest = _wheel_binding(
        direct_wheel, expected_metadata, source_license
    )
    rebuilt_package_digest, rebuilt_wheel_digest, rebuilt_metadata, rebuilt_archive_digest = _wheel_binding(
        rebuilt_wheel, expected_metadata, source_license
    )
    if direct_metadata != rebuilt_metadata:
        raise RuntimeError("direct and sdist-built wheel metadata differ")
    sdist_package_digest, sdist_digest, sdist_archive_digest = _sdist_binding(
        sdist, direct_metadata, source_readme, source_pyproject, source_license
    )
    package_digests = {
        source_package_digest,
        direct_package_digest,
        rebuilt_package_digest,
        sdist_package_digest,
    }
    if len(package_digests) != 1:
        raise RuntimeError("source/wheel/sdist package content differs")
    if direct_wheel_digest != rebuilt_wheel_digest:
        raise RuntimeError("direct and sdist-built wheel logical content differs")
    if direct_archive_digest != rebuilt_archive_digest:
        raise RuntimeError("direct and sdist-built canonical wheel bytes differ")
    return {
        "format": FORMAT,
        "metadata_policy": METADATA_POLICY,
        "wheel_archive_policy": WHEEL_ARCHIVE_POLICY,
        "sdist_archive_policy": SDIST_ARCHIVE_POLICY,
        "package_member_count": len(EXPECTED_PACKAGE_FILES),
        "wheel_member_count": len(EXPECTED_WHEEL_FILES),
        "sdist_file_count": len(EXPECTED_SDIST_FILES),
        "sdist_member_count": len(EXPECTED_SDIST_FILES) + len(EXPECTED_SDIST_DIRECTORIES),
        "package_inventory_sha256": EXPECTED_PACKAGE_INVENTORY_SHA256,
        "wheel_inventory_sha256": EXPECTED_WHEEL_INVENTORY_SHA256,
        "sdist_inventory_sha256": EXPECTED_SDIST_INVENTORY_SHA256,
        "package_logical_sha256": source_package_digest,
        "wheel_logical_sha256": direct_wheel_digest,
        "wheel_archive_sha256": direct_archive_digest,
        "sdist_logical_sha256": sdist_digest,
        "sdist_archive_sha256": sdist_archive_digest,
        "source_wheel_sdist_package_identical": True,
        "direct_sdist_wheel_logical_identical": True,
        "direct_sdist_wheel_archive_identical": True,
    }
