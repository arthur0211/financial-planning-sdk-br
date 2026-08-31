"""Candidate-side static artifact diagnostics over revalidated local byte snapshots.

This module never builds, installs, imports, or executes candidate code. Its
output records only observations made by this local candidate-side inspector;
it cannot establish build equivalence, promotion, or release authority.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import tarfile
import tomllib
import unicodedata
import zipfile
import zlib
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, NamedTuple

try:
    from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
    from packaging.version import Version
except ImportError:  # reported as a gate failure in main
    canonicalize_name = parse_sdist_filename = parse_wheel_filename = Version = None  # type: ignore[assignment]


MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_COUNT = 4096
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_PATH_LENGTH = 240
EXECUTABLE_SUFFIXES = {".exe", ".dll", ".com", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".so", ".dylib", ".pyd"}
EXECUTABLE_MAGICS = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")
WIN32_FORBIDDEN_NAME_CHARS = frozenset('<>:"\\|?*')
DOS_DEVICE_BASENAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{suffix}" for suffix in "123456789¹²³"}
    | {f"lpt{suffix}" for suffix in "123456789¹²³"}
)
ZIP_LOCAL_HEADER = struct.Struct("<4s5H3I2H")
ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3I5H2I")
ZIP_END_OF_CENTRAL_DIRECTORY = struct.Struct("<4s4H2IH")
ZIP_LOCAL_SIGNATURE = b"PK\x03\x04"
ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
ZIP_END_SIGNATURE = b"PK\x05\x06"
ZIP_ALLOWED_FLAGS = 0x0800
ZIP_ALLOWED_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
ZIP_ALLOWED_CREATOR_HOSTS = frozenset({0, 3})  # MS-DOS/FAT and Unix
ZIP_DOS_DIRECTORY_ATTRIBUTE = 0x10
GZIP_FIXED_HEADER_SIZE = 10
GZIP_TRAILER_SIZE = 8
GZIP_FLAG_FTEXT = 0x01
GZIP_FLAG_FHCRC = 0x02
GZIP_FLAG_FEXTRA = 0x04
GZIP_FLAG_FNAME = 0x08
GZIP_FLAG_FCOMMENT = 0x10
GZIP_RESERVED_FLAGS = 0xE0
MAX_GZIP_HEADER_BYTES = 8 * 1024
MAX_GZIP_EXTRA_BYTES = 4 * 1024
MAX_GZIP_EXTRA_SUBFIELDS = 64
MAX_GZIP_COMMENT_BYTES = 1024
TAR_BLOCK_SIZE = 512
MAX_TAR_STREAM_BYTES = MAX_TOTAL_UNCOMPRESSED_BYTES + MAX_MEMBER_COUNT * (2 * TAR_BLOCK_SIZE) + 10_240


class ArtifactBlob(tuple):
    """One C-level immutable (name, payload, digest) artifact snapshot."""

    __slots__ = ()

    def __new__(cls, name: str, payload: bytes) -> ArtifactBlob:
        if type(name) is not str:
            raise TypeError("artifact name must be str")
        if type(payload) is not bytes:
            payload = bytes(payload)
        return tuple.__new__(cls, (name, payload, hashlib.sha256(payload).hexdigest()))

    @property
    def name(self) -> str:
        return self[0]

    @property
    def payload(self) -> bytes:
        return self[1]

    @property
    def sha256(self) -> str:
        return self[2]


class RawZipEntry(NamedTuple):
    name: str
    encoded_name: bytes
    local_offset: int
    flags: int
    method: int
    modified_time: int
    modified_date: int
    crc32: int
    compressed_size: int
    file_size: int
    version_needed: int
    version_made_by: int
    internal_attributes: int
    external_attributes: int
    data_offset: int
    decoded_payload: bytes


class RawTarEntry(NamedTuple):
    name: str
    header_offset: int
    data_offset: int
    size: int
    mode: int
    uid: int
    gid: int
    mtime: int
    typeflag: bytes
    linkname: str
    uname: str
    gname: str
    devmajor: int
    devminor: int


def artifact_blob_integrity(blob: object, label: str, failures: list[str]) -> bool:
    """Fail closed unless the tuple snapshot still binds its bytes to its digest."""

    try:
        name = blob.name  # type: ignore[attr-defined]
        payload = blob.payload  # type: ignore[attr-defined]
        digest = blob.sha256  # type: ignore[attr-defined]
    except (AttributeError, IndexError, TypeError) as exc:
        failures.append(f"{label}: artifact snapshot fields are unavailable: {exc}")
        return False
    valid = (
        isinstance(blob, ArtifactBlob)
        and type(name) is str
        and type(payload) is bytes
        and type(digest) is str
        and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        and hashlib.sha256(payload).hexdigest() == digest
    )
    if not valid:
        failures.append(f"{label}: artifact snapshot SHA-256 integrity is not established")
    return valid


def regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not path.is_symlink() and not bool(getattr(info, "st_file_attributes", 0) & 0x400)


def is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    return path.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def safe_chain(path: Path, boundary: Path) -> bool:
    current = path.absolute()
    stop = boundary.absolute()
    while True:
        if is_reparse(current):
            return False
        if current == stop:
            return True
        if current.parent == current:
            return False
        current = current.parent


def stable_bytes(path: Path, boundary: Path, label: str, max_bytes: int | None = None) -> bytes:
    if not safe_chain(path, boundary):
        raise ValueError(f"{label}: parent chain contains a symlink/junction/reparse point")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"{label}: requires a regular file with nlink=1")
        if max_bytes is not None and before.st_size > max_bytes:
            raise ValueError(f"{label}: exceeds byte snapshot budget {max_bytes}")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 65_536)
            if not block:
                break
            total += len(block)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"{label}: exceeds byte snapshot budget {max_bytes}")
            chunks.append(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.stat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after) or identity(before) != identity(current):
        raise ValueError(f"{label}: changed during byte snapshot")
    return b"".join(chunks)


def closed_dist_manifest(dist: Path, boundary: Path | None = None) -> dict[str, str]:
    boundary = boundary or dist.parent
    if not dist.is_dir() or is_reparse(dist) or not safe_chain(dist, boundary):
        raise ValueError("dist: must be a local non-reparse directory")
    rows: dict[str, str] = {}
    with os.scandir(dist) as entries:
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                raise ValueError(f"dist: nested directories are forbidden: {entry.name}")
            path = dist / entry.name
            payload = stable_bytes(path, dist, f"dist/{entry.name}", MAX_ARCHIVE_BYTES)
            rows[entry.name] = hashlib.sha256(payload).hexdigest()
    return dict(sorted(rows.items()))


def snapshot_dist(dist: Path, boundary: Path | None = None) -> dict[str, ArtifactBlob]:
    """Read each original dist entry once into an immutable byte snapshot."""

    boundary = boundary or dist.parent
    if not dist.is_dir() or is_reparse(dist) or not safe_chain(dist, boundary):
        raise ValueError("dist: must be a local non-reparse directory")
    with os.scandir(dist) as entries:
        initial_entries = sorted(entries, key=lambda entry: entry.name)
    initial_names = [entry.name for entry in initial_entries]
    normalized_names = [unicodedata.normalize("NFC", name.casefold()) for name in initial_names]
    if len(normalized_names) != len(set(normalized_names)):
        raise ValueError("dist: artifact filenames contain case or Unicode-normalization collisions")
    blobs: dict[str, ArtifactBlob] = {}
    for entry in initial_entries:
        if entry.is_dir(follow_symlinks=False):
            raise ValueError(f"dist: nested directories are forbidden: {entry.name}")
        name = entry.name
        payload = stable_bytes(dist / name, dist, f"dist/{name}", MAX_ARCHIVE_BYTES)
        blobs[name] = ArtifactBlob(name, payload)
    with os.scandir(dist) as entries:
        final_names = sorted(entry.name for entry in entries)
    if final_names != initial_names:
        raise ValueError("dist: closed filename inventory drifted during byte snapshot")
    return blobs


def safe_archive_name(name: str) -> bool:
    if (
        type(name) is not str
        or not name
        or len(name) > MAX_PATH_LENGTH
        or unicodedata.normalize("NFC", name) != name
        or any(unicodedata.category(character).startswith("C") for character in name)
    ):
        return False
    body = name[:-1] if name.endswith("/") else name
    if not body or body.startswith("/"):
        return False
    parts = body.split("/")
    return all(
        part not in {"", ".", ".."}
        and not part.endswith((".", " "))
        and not any(character in WIN32_FORBIDDEN_NAME_CHARS for character in part)
        and part.split(".", 1)[0].casefold() not in DOS_DEVICE_BASENAMES
        for part in parts
    )


def archive_path_key(name: str) -> tuple[str, ...]:
    """Return the single normative archive/RECORD path identity."""

    body = name[:-1] if name.endswith("/") else name
    return tuple(unicodedata.normalize("NFC", part.casefold()) for part in body.split("/"))


def normalized_archive_parts(name: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    body = name[:-1] if name.endswith("/") else name
    raw = tuple(body.split("/"))
    normalized = archive_path_key(name)
    return raw, normalized


def validate_archive_path_trie(
    entries: Iterable[tuple[str, bool]],
    label: str,
    failures: list[str],
) -> bool:
    """Reject ambiguous archive paths under case-folded NFC semantics."""

    before = len(failures)
    rows = list(entries)
    unsafe = sorted(name for name, _ in rows if not safe_archive_name(name))
    if unsafe:
        failures.append(f"{label}: contains unsafe member paths: {unsafe}")

    # key -> (kind, explicit, exact spelling, originating member)
    nodes: dict[tuple[str, ...], tuple[str, bool, tuple[str, ...], str]] = {}
    for name, is_directory in rows:
        if not name or not (name[:-1] if name.endswith("/") else name):
            continue
        raw, normalized = normalized_archive_parts(name)
        for depth in range(1, len(normalized)):
            key = normalized[:depth]
            spelling = raw[:depth]
            existing = nodes.get(key)
            if existing is None:
                nodes[key] = ("directory", False, spelling, name)
                continue
            kind, explicit, previous_spelling, previous_name = existing
            if previous_spelling != spelling:
                failures.append(
                    f"{label}: normalized path collision between {previous_name!r} and {name!r}"
                )
            if kind == "file":
                failures.append(
                    f"{label}: file member {previous_name!r} is an ancestor of {name!r}"
                )
            elif not explicit and previous_spelling == spelling:
                nodes[key] = (kind, explicit, previous_spelling, previous_name)

        key = normalized
        kind = "directory" if is_directory else "file"
        existing = nodes.get(key)
        if existing is None:
            nodes[key] = (kind, True, raw, name)
            continue
        previous_kind, previous_explicit, previous_spelling, previous_name = existing
        if previous_spelling != raw:
            failures.append(f"{label}: normalized path collision between {previous_name!r} and {name!r}")
            continue
        if previous_kind != kind:
            failures.append(f"{label}: file/directory same-path collision at {name!r}")
            continue
        if kind == "file" or previous_explicit:
            failures.append(f"{label}: duplicate explicit member path {name!r}")
            continue
        # An explicit directory may safely materialize a previously implicit parent.
        nodes[key] = ("directory", True, raw, name)
    file_keys = [archive_path_key(name) for name, is_directory in rows if not is_directory and name]
    for name, is_directory in rows:
        if not is_directory or not name:
            continue
        key = archive_path_key(name)
        if not any(len(candidate) > len(key) and candidate[: len(key)] == key for candidate in file_keys):
            failures.append(f"{label}: empty explicit directory member is forbidden: {name!r}")
    return len(failures) == before


def executable_payload(name: str, mode: int, prefix: bytes) -> bool:
    return (
        PurePosixPath(name).suffix.lower() in EXECUTABLE_SUFFIXES
        or bool(mode & 0o111)
        or any(prefix.startswith(magic) for magic in EXECUTABLE_MAGICS)
    )


def parse_metadata(payload: bytes, label: str, failures: list[str]) -> tuple[str, str]:
    try:
        metadata = BytesParser().parsebytes(payload)
    except Exception as exc:
        failures.append(f"{label}: metadata cannot be parsed: {exc}")
        return "", ""
    name = metadata.get("Name", "").strip()
    version = metadata.get("Version", "").strip()
    if not name or not version:
        failures.append(f"{label}: metadata requires non-empty Name and Version")
    return name, version


def same_project(actual_name: str, actual_version: str, project_name: str, project_version: str) -> bool:
    if canonicalize_name is None or Version is None:
        return False
    try:
        return canonicalize_name(actual_name) == canonicalize_name(project_name) and Version(actual_version) == Version(project_version)
    except Exception:
        return False


def wheel_install_roots(project_name: str, project_version: str) -> tuple[str, str]:
    stem = f"{canonicalize_name(project_name).replace('-', '_')}-{str(Version(project_version)).replace('-', '_')}"
    return f"{stem}.dist-info", f"{stem}.data"


def declared_package_values(document: dict[str, Any]) -> list[str]:
    declarations: list[str] = []

    def walk(value: Any, key: str = "") -> None:
        if key == "packages":
            if isinstance(value, list):
                declarations.extend(item for item in value if isinstance(item, str) and item.strip())
            elif isinstance(value, dict):
                find = value.get("find")
                if isinstance(find, dict):
                    where = find.get("where", [])
                    if isinstance(where, list) and any(item == "src" for item in where):
                        declarations.append("<find:src>")
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, child_key)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    flit_name = document.get("tool", {}).get("flit", {}).get("module", {}).get("name") if isinstance(document.get("tool"), dict) else None
    if isinstance(flit_name, str) and flit_name.strip():
        declarations.append(flit_name)
    return declarations


def any_empty_packages_key(document: Any) -> bool:
    if isinstance(document, dict):
        for key, value in document.items():
            if key == "packages" and (value == [] or value == {} or value == ""):
                return True
            if any_empty_packages_key(value):
                return True
    elif isinstance(document, list):
        return any(any_empty_packages_key(value) for value in document)
    return False


def read_pyproject(payload: bytes, label: str, failures: list[str]) -> tuple[dict[str, Any], str, str]:
    try:
        document = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        failures.append(f"{label}: invalid TOML: {exc}")
        return {}, "", ""
    project = document.get("project")
    build_system = document.get("build-system")
    name = version = ""
    if not isinstance(project, dict):
        failures.append(f"{label}: missing [project] table")
    else:
        name = project.get("name", "")
        version = project.get("version", "")
        if not isinstance(name, str) or not name.strip():
            failures.append(f"{label}: project.name must be a non-empty string")
            name = ""
        if not isinstance(version, str) or not version.strip():
            failures.append(f"{label}: project.version must be a non-empty static string")
            version = ""
    if not isinstance(build_system, dict):
        failures.append(f"{label}: missing [build-system] table")
    else:
        if not isinstance(build_system.get("requires"), list) or not build_system["requires"]:
            failures.append(f"{label}: build-system.requires must be a non-empty array")
        if not isinstance(build_system.get("build-backend"), str) or not build_system["build-backend"].strip():
            failures.append(f"{label}: build-system.build-backend must be a non-empty string")
    if any_empty_packages_key(document):
        failures.append(f"{label}: packages declaration cannot be empty")
    if not declared_package_values(document):
        failures.append(f"{label}: requires a non-empty explicit packages declaration")
    return document, name, version


def archive_budget(label: str, entries: Iterable[tuple[str, int, int]], failures: list[str]) -> bool:
    before = len(failures)
    rows = list(entries)
    if len(rows) > MAX_MEMBER_COUNT:
        failures.append(f"{label}: member count exceeds budget {MAX_MEMBER_COUNT}")
    total = sum(size for _, size, _ in rows)
    if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
        failures.append(f"{label}: total uncompressed size exceeds budget {MAX_TOTAL_UNCOMPRESSED_BYTES}")
    for name, size, compressed in rows:
        if size > MAX_MEMBER_BYTES:
            failures.append(f"{label}: member {name!r} exceeds uncompressed size budget {MAX_MEMBER_BYTES}")
        if size and (compressed == 0 or size / compressed > MAX_COMPRESSION_RATIO):
            failures.append(f"{label}: member {name!r} exceeds compression-ratio budget {MAX_COMPRESSION_RATIO}:1")
    return len(failures) == before


def _decode_zip_name(encoded: bytes, flags: int) -> str:
    if not encoded:
        raise ValueError("empty ZIP filename")
    return encoded.decode("utf-8" if flags & 0x0800 else "cp437", errors="strict")


def _validate_raw_zip_fields(
    *,
    context: str,
    version_needed: int,
    flags: int,
    method: int,
    compressed_size: int,
    file_size: int,
    extra_length: int,
) -> None:
    if method not in ZIP_ALLOWED_METHODS:
        raise ValueError(f"{context} uses unsupported compression method {method}")
    minimum_version = 10 if method == zipfile.ZIP_STORED else 20
    if version_needed < minimum_version or version_needed > 20:
        raise ValueError(
            f"{context} has incoherent version-needed {version_needed} for method {method}; "
            f"the closed ZIP32 profile requires {minimum_version}..20"
        )
    if flags & 0x0008:
        raise ValueError(f"{context} uses a forbidden data descriptor")
    if flags & ~ZIP_ALLOWED_FLAGS:
        raise ValueError(f"{context} uses unsupported or unsafe general-purpose flags 0x{flags:04x}")
    if compressed_size == 0xFFFFFFFF or file_size == 0xFFFFFFFF:
        raise ValueError(f"{context} uses forbidden ZIP64 size sentinels")
    if extra_length:
        raise ValueError(f"{context} contains a forbidden extra field")


def _validate_raw_zip_directory_fields(
    *,
    context: str,
    name: str,
    method: int,
    crc32: int,
    compressed_size: int,
    file_size: int,
) -> None:
    if not name.endswith("/"):
        return
    if method != zipfile.ZIP_STORED or crc32 or compressed_size or file_size:
        raise ValueError(
            f"{context} directory member {name!r} must be a stored empty payload "
            "with compressed-size 0, file-size 0, and CRC32 0"
        )


def _validate_raw_zip_attributes(
    *,
    context: str,
    name: str,
    version_made_by: int,
    version_needed: int,
    internal_attributes: int,
    external_attributes: int,
) -> None:
    creator_host = (version_made_by >> 8) & 0xFF
    creator_version = version_made_by & 0xFF
    if creator_host not in ZIP_ALLOWED_CREATOR_HOSTS:
        raise ValueError(f"{context} uses unsupported version-made-by host {creator_host}")
    if creator_version < version_needed or creator_version > 20:
        raise ValueError(
            f"{context} has incoherent version-made-by {creator_version} for version-needed {version_needed}"
        )
    if internal_attributes:
        raise ValueError(f"{context} contains unsupported internal attributes 0x{internal_attributes:04x}")

    is_directory = name.endswith("/")
    expected_dos_attributes = ZIP_DOS_DIRECTORY_ATTRIBUTE if is_directory else 0
    dos_attributes = external_attributes & 0xFFFF
    if dos_attributes != expected_dos_attributes:
        kind = "directory" if is_directory else "file"
        raise ValueError(
            f"{context} has incoherent DOS attributes 0x{dos_attributes:04x} for {kind} {name!r}; "
            f"expected 0x{expected_dos_attributes:04x}"
        )

    unix_mode = (external_attributes >> 16) & 0xFFFF
    unix_type = unix_mode & 0o170000
    if unix_mode & ~(0o170000 | 0o777):
        raise ValueError(f"{context} uses unsupported Unix mode bits 0o{unix_mode:o} for {name!r}")
    expected_unix_type = stat.S_IFDIR if is_directory else stat.S_IFREG
    if creator_host == 3:
        if unix_type != expected_unix_type:
            kind = "directory" if is_directory else "regular-file"
            raise ValueError(f"{context} must use Unix {kind} type for {name!r}")
    elif unix_type not in {0, expected_unix_type}:
        kind = "directory" if is_directory else "regular-file"
        raise ValueError(f"{context} has incoherent DOS/Unix {kind} type for {name!r}")


def _decode_raw_zip_entry(payload: bytes, entry: RawZipEntry) -> bytes:
    """Decode exactly one bounded local-data slice without trusting zipfile."""

    compressed = payload[entry.data_offset : entry.data_offset + entry.compressed_size]
    if len(compressed) != entry.compressed_size:
        raise ValueError(f"member {entry.name!r} has a truncated local data slice")
    if entry.name.endswith("/"):
        _validate_raw_zip_directory_fields(
            context="decoded local slice",
            name=entry.name,
            method=entry.method,
            crc32=entry.crc32,
            compressed_size=entry.compressed_size,
            file_size=entry.file_size,
        )
        if compressed:
            raise ValueError(f"directory member {entry.name!r} carries hidden raw payload bytes")
        return b""
    if entry.method == zipfile.ZIP_STORED:
        if entry.compressed_size != entry.file_size:
            raise ValueError(
                f"stored member {entry.name!r} compressed size must equal its declared file size"
            )
        decoded = compressed
    else:
        inflater = zlib.decompressobj(-15)
        try:
            decoded = inflater.decompress(compressed, entry.file_size + 1)
        except zlib.error as exc:
            raise ValueError(f"member {entry.name!r} has an invalid raw DEFLATE stream: {exc}") from exc
        if not inflater.eof:
            raise ValueError(f"member {entry.name!r} raw DEFLATE stream does not terminate within its slice")
        if inflater.unused_data:
            raise ValueError(f"member {entry.name!r} contains trailing or concatenated raw DEFLATE streams")
        if inflater.unconsumed_tail:
            raise ValueError(f"member {entry.name!r} exceeds its bounded raw DEFLATE output")
    if len(decoded) != entry.file_size:
        raise ValueError(
            f"member {entry.name!r} decoded size {len(decoded)} does not equal declared size {entry.file_size}"
        )
    if zlib.crc32(decoded) & 0xFFFFFFFF != entry.crc32:
        raise ValueError(f"member {entry.name!r} decoded CRC32 does not match its headers")
    return decoded


def validate_raw_zip(payload: bytes, label: str, failures: list[str]) -> tuple[RawZipEntry, ...] | None:
    """Prove one gap-free ZIP32 local-header/central-directory bijection."""

    try:
        if type(payload) is not bytes or len(payload) < ZIP_END_OF_CENTRAL_DIRECTORY.size:
            raise ValueError("payload is too short for a final ZIP end record")
        eocd_offset = len(payload) - ZIP_END_OF_CENTRAL_DIRECTORY.size
        (
            signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_length,
        ) = ZIP_END_OF_CENTRAL_DIRECTORY.unpack_from(payload, eocd_offset)
        if signature != ZIP_END_SIGNATURE:
            raise ValueError("EOCD must be the final 22-byte record; prefixes/trailing records are forbidden")
        if comment_length:
            raise ValueError("archive comments and bytes after EOCD are forbidden")
        if (
            disk_entries == 0xFFFF
            or total_entries == 0xFFFF
            or central_size == 0xFFFFFFFF
            or central_offset == 0xFFFFFFFF
        ):
            raise ValueError("ZIP64 end records and sentinels are forbidden")
        if disk_number or central_disk or disk_entries != total_entries:
            raise ValueError("multi-disk ZIP archives are forbidden")
        if central_offset + central_size != eocd_offset:
            raise ValueError("central directory is not contiguous with the final EOCD")

        local_entries: list[RawZipEntry] = []
        cursor = 0
        while cursor < central_offset:
            local_offset = cursor
            if cursor + ZIP_LOCAL_HEADER.size > central_offset:
                raise ValueError(f"gap or truncated local header at raw offset {cursor}")
            (
                local_signature,
                version_needed,
                flags,
                method,
                modified_time,
                modified_date,
                crc32,
                compressed_size,
                file_size,
                name_length,
                extra_length,
            ) = ZIP_LOCAL_HEADER.unpack_from(payload, cursor)
            if local_signature != ZIP_LOCAL_SIGNATURE:
                raise ValueError(f"self-extracting prefix, gap, or orphan bytes at raw offset {cursor}")
            _validate_raw_zip_fields(
                context=f"local header at offset {cursor}",
                version_needed=version_needed,
                flags=flags,
                method=method,
                compressed_size=compressed_size,
                file_size=file_size,
                extra_length=extra_length,
            )
            name_start = cursor + ZIP_LOCAL_HEADER.size
            name_end = name_start + name_length
            data_start = name_end + extra_length
            data_end = data_start + compressed_size
            if name_end > central_offset or data_end > central_offset:
                raise ValueError(f"local entry at offset {cursor} overlaps the central directory")
            encoded_name = payload[name_start:name_end]
            name = _decode_zip_name(encoded_name, flags)
            _validate_raw_zip_directory_fields(
                context=f"local header at offset {cursor}",
                name=name,
                method=method,
                crc32=crc32,
                compressed_size=compressed_size,
                file_size=file_size,
            )
            local_entries.append(
                RawZipEntry(
                    name,
                    encoded_name,
                    local_offset,
                    flags,
                    method,
                    modified_time,
                    modified_date,
                    crc32,
                    compressed_size,
                    file_size,
                    version_needed,
                    -1,
                    -1,
                    -1,
                    data_start,
                    b"",
                )
            )
            cursor = data_end
        if cursor != central_offset:
            raise ValueError("local entries do not exactly fill the pre-central byte region")

        central_entries: list[RawZipEntry] = []
        cursor = central_offset
        for index in range(total_entries):
            if cursor + ZIP_CENTRAL_HEADER.size > eocd_offset:
                raise ValueError(f"truncated central header {index}")
            (
                central_signature,
                version_made_by,
                version_needed,
                flags,
                method,
                modified_time,
                modified_date,
                crc32,
                compressed_size,
                file_size,
                name_length,
                extra_length,
                member_comment_length,
                member_disk,
                internal_attributes,
                external_attributes,
                local_offset,
            ) = ZIP_CENTRAL_HEADER.unpack_from(payload, cursor)
            if central_signature != ZIP_CENTRAL_SIGNATURE:
                raise ValueError(f"unexpected record or gap at central offset {cursor}")
            _validate_raw_zip_fields(
                context=f"central header {index}",
                version_needed=version_needed,
                flags=flags,
                method=method,
                compressed_size=compressed_size,
                file_size=file_size,
                extra_length=extra_length,
            )
            if member_comment_length:
                raise ValueError(f"central header {index} contains a forbidden member comment")
            if member_disk:
                raise ValueError(f"central header {index} references a forbidden disk")
            if local_offset == 0xFFFFFFFF:
                raise ValueError(f"central header {index} uses a forbidden ZIP64 offset")
            name_start = cursor + ZIP_CENTRAL_HEADER.size
            name_end = name_start + name_length
            record_end = name_end + extra_length + member_comment_length
            if record_end > eocd_offset:
                raise ValueError(f"central header {index} overlaps EOCD")
            encoded_name = payload[name_start:name_end]
            name = _decode_zip_name(encoded_name, flags)
            _validate_raw_zip_directory_fields(
                context=f"central header {index}",
                name=name,
                method=method,
                crc32=crc32,
                compressed_size=compressed_size,
                file_size=file_size,
            )
            _validate_raw_zip_attributes(
                context=f"central header {index}",
                name=name,
                version_made_by=version_made_by,
                version_needed=version_needed,
                internal_attributes=internal_attributes,
                external_attributes=external_attributes,
            )
            central_entries.append(
                RawZipEntry(
                    name,
                    encoded_name,
                    local_offset,
                    flags,
                    method,
                    modified_time,
                    modified_date,
                    crc32,
                    compressed_size,
                    file_size,
                    version_needed,
                    version_made_by,
                    internal_attributes,
                    external_attributes,
                    -1,
                    b"",
                )
            )
            cursor = record_end
        if cursor != eocd_offset or cursor - central_offset != central_size:
            raise ValueError("central entries do not exactly fill the declared central directory")
        if len(local_entries) != total_entries:
            raise ValueError("local-header count does not equal the central-entry count")

        locals_by_offset = {entry.local_offset: entry for entry in local_entries}
        central_by_offset = {entry.local_offset: entry for entry in central_entries}
        if len(locals_by_offset) != len(local_entries) or len(central_by_offset) != len(central_entries):
            raise ValueError("duplicate local offsets break the local/central bijection")
        if set(locals_by_offset) != set(central_by_offset):
            raise ValueError("orphan local header or central entry breaks the local/central bijection")
        decoded_entries: list[RawZipEntry] = []
        for offset, central_entry in central_by_offset.items():
            local_entry = locals_by_offset[offset]
            coherent = (
                local_entry.name == central_entry.name
                and local_entry.encoded_name == central_entry.encoded_name
                and local_entry.flags == central_entry.flags
                and local_entry.method == central_entry.method
                and local_entry.modified_time == central_entry.modified_time
                and local_entry.modified_date == central_entry.modified_date
                and local_entry.crc32 == central_entry.crc32
                and local_entry.compressed_size == central_entry.compressed_size
                and local_entry.file_size == central_entry.file_size
                and local_entry.version_needed == central_entry.version_needed
            )
            if not coherent:
                raise ValueError(f"local and central metadata disagree for offset {offset}")
        if not archive_budget(
            label,
            ((entry.name, entry.file_size, entry.compressed_size) for entry in central_entries),
            failures,
        ):
            return None
        for central_entry in central_entries:
            local_entry = locals_by_offset[central_entry.local_offset]
            entry = central_entry._replace(data_offset=local_entry.data_offset)
            decoded_entries.append(entry._replace(decoded_payload=_decode_raw_zip_entry(payload, entry)))
        return tuple(decoded_entries)
    except (UnicodeError, struct.error, ValueError) as exc:
        failures.append(f"{label}: raw ZIP layout rejected: {exc}")
        return None


def validate_zipfile_view(
    raw_entries: tuple[RawZipEntry, ...],
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
    label: str,
    failures: list[str],
) -> bool:
    """Require zipfile's decoded view to equal the already-proven raw view."""

    before = len(failures)
    if len(raw_entries) != len(infos):
        failures.append(f"{label}: raw/zipfile entry counts disagree")
        return False
    for raw, info in zip(raw_entries, infos):
        if (
            raw.name != info.filename
            or raw.local_offset != info.header_offset
            or raw.flags != info.flag_bits
            or raw.method != info.compress_type
            or raw.crc32 != info.CRC
            or raw.compressed_size != info.compress_size
            or raw.file_size != info.file_size
            or raw.version_needed != info.extract_version
            or raw.version_made_by != ((info.create_system << 8) | info.create_version)
            or raw.internal_attributes != info.internal_attr
            or raw.external_attributes != info.external_attr
        ):
            failures.append(f"{label}: raw/zipfile metadata view disagrees for {raw.name!r}")
        try:
            decoded = archive.read(info)
        except (OSError, EOFError, zipfile.BadZipFile, RuntimeError, NotImplementedError, ValueError, zlib.error) as exc:
            failures.append(f"{label}: zipfile read failed for {raw.name!r}: {exc}")
            continue
        if decoded != raw.decoded_payload:
            failures.append(f"{label}: raw/zipfile decoded bytes disagree for {raw.name!r}")
    return len(failures) == before


def _parse_tar_octal(field: bytes, context: str) -> int:
    if not field:
        raise ValueError(f"{context} is empty")
    if field[0] & 0x80:
        raise ValueError(f"{context} uses forbidden base-256 numeric encoding")
    value = field.strip(b" \x00")
    if not value:
        return 0
    if any(byte not in b"01234567" for byte in value):
        raise ValueError(f"{context} is not canonical octal")
    return int(value, 8)


def _parse_tar_text(field: bytes, context: str) -> str:
    nul = field.find(b"\x00")
    if nul >= 0:
        if any(field[nul + 1 :]):
            raise ValueError(f"{context} contains hidden bytes after NUL")
        field = field[:nul]
    return field.decode("utf-8", errors="strict")


def _parse_gzip_latin1_text(
    payload: bytes,
    cursor: int,
    *,
    context: str,
    max_bytes: int,
) -> tuple[str, int]:
    search_end = min(len(payload), cursor + max_bytes + 1)
    terminator = payload.find(b"\x00", cursor, search_end)
    if terminator < 0:
        if len(payload) - cursor > max_bytes:
            raise ValueError(f"{context} exceeds its {max_bytes}-byte header budget or lacks a terminator")
        raise ValueError(f"{context} lacks its NUL terminator")
    encoded = payload[cursor:terminator]
    if not encoded:
        raise ValueError(f"{context} is ambiguously empty")
    text = encoded.decode("latin-1", errors="strict")
    if (
        unicodedata.normalize("NFC", text) != text
        or unicodedata.normalize("NFKC", text) != text
        or any(unicodedata.category(character).startswith("C") for character in text)
    ):
        raise ValueError(f"{context} contains control or normalization-ambiguous text")
    return text, terminator + 1


def _parse_raw_gzip_header(payload: bytes) -> int:
    if type(payload) is not bytes or len(payload) < GZIP_FIXED_HEADER_SIZE + GZIP_TRAILER_SIZE:
        raise ValueError("payload is too short for one gzip member")
    if payload[0:2] != b"\x1f\x8b":
        raise ValueError("payload does not begin with one gzip member")
    if payload[2] != 8:
        raise ValueError(f"gzip compression method {payload[2]} is outside the DEFLATE-only profile")

    flags = payload[3]
    if flags & GZIP_RESERVED_FLAGS:
        raise ValueError(f"gzip header sets reserved flags 0x{flags & GZIP_RESERVED_FLAGS:02x}")
    if flags & GZIP_FLAG_FTEXT:
        raise ValueError("gzip FTEXT is outside the closed binary-artifact profile")
    if payload[8] not in {0, 2, 4}:
        raise ValueError(f"gzip XFL value {payload[8]} is outside the modeled DEFLATE profile")
    if payload[9] not in set(range(14)) | {255}:
        raise ValueError(f"gzip OS value {payload[9]} is outside the modeled RFC 1952 set")

    cursor = GZIP_FIXED_HEADER_SIZE
    if flags & GZIP_FLAG_FEXTRA:
        if cursor + 2 > len(payload):
            raise ValueError("gzip FEXTRA lacks XLEN")
        extra_length = int.from_bytes(payload[cursor : cursor + 2], "little")
        cursor += 2
        if not extra_length:
            raise ValueError("gzip FEXTRA cannot be empty in the closed profile")
        if extra_length > MAX_GZIP_EXTRA_BYTES:
            raise ValueError(f"gzip FEXTRA exceeds its {MAX_GZIP_EXTRA_BYTES}-byte budget")
        extra_end = cursor + extra_length
        if extra_end > len(payload):
            raise ValueError("gzip FEXTRA extends beyond the member")
        subfield_ids: set[bytes] = set()
        subfield_count = 0
        while cursor < extra_end:
            if extra_end - cursor < 4:
                raise ValueError("gzip FEXTRA ends with a truncated subfield header")
            subfield_id = payload[cursor : cursor + 2]
            subfield_length = int.from_bytes(payload[cursor + 2 : cursor + 4], "little")
            cursor += 4
            if not all(65 <= byte <= 90 or 97 <= byte <= 122 for byte in subfield_id):
                raise ValueError(f"gzip FEXTRA uses an unsafe subfield id {subfield_id!r}")
            if subfield_id in subfield_ids:
                raise ValueError(f"gzip FEXTRA repeats ambiguous subfield id {subfield_id!r}")
            subfield_ids.add(subfield_id)
            subfield_count += 1
            if subfield_count > MAX_GZIP_EXTRA_SUBFIELDS:
                raise ValueError(f"gzip FEXTRA exceeds its {MAX_GZIP_EXTRA_SUBFIELDS}-subfield budget")
            cursor += subfield_length
            if cursor > extra_end:
                raise ValueError(f"gzip FEXTRA subfield {subfield_id!r} exceeds XLEN")
        if cursor != extra_end:
            raise ValueError("gzip FEXTRA subfields do not exactly fill XLEN")

    if flags & GZIP_FLAG_FNAME:
        filename, cursor = _parse_gzip_latin1_text(
            payload,
            cursor,
            context="gzip FNAME",
            max_bytes=MAX_PATH_LENGTH,
        )
        if "/" in filename or not safe_archive_name(filename):
            raise ValueError(f"gzip FNAME is an unsafe or path-bearing basename: {filename!r}")

    if flags & GZIP_FLAG_FCOMMENT:
        comment, cursor = _parse_gzip_latin1_text(
            payload,
            cursor,
            context="gzip FCOMMENT",
            max_bytes=MAX_GZIP_COMMENT_BYTES,
        )
        if any(separator in comment for separator in ("/", "\\", ":")):
            raise ValueError("gzip FCOMMENT contains path-bearing text outside the closed profile")

    if cursor > MAX_GZIP_HEADER_BYTES:
        raise ValueError(f"gzip optional header exceeds its {MAX_GZIP_HEADER_BYTES}-byte budget")
    if flags & GZIP_FLAG_FHCRC:
        if cursor + 2 > len(payload):
            raise ValueError("gzip FHCRC field is truncated")
        stored_header_crc = int.from_bytes(payload[cursor : cursor + 2], "little")
        computed_header_crc = zlib.crc32(payload[:cursor]) & 0xFFFF
        if stored_header_crc != computed_header_crc:
            raise ValueError("gzip FHCRC does not match the parsed header bytes")
        cursor += 2
    if cursor > MAX_GZIP_HEADER_BYTES:
        raise ValueError(f"gzip header exceeds its {MAX_GZIP_HEADER_BYTES}-byte budget")
    if len(payload) - cursor < GZIP_TRAILER_SIZE:
        raise ValueError("gzip member lacks compressed data and its trailer")
    return cursor


def validate_raw_gzip_tar(payload: bytes, label: str, failures: list[str]) -> tuple[RawTarEntry, ...] | None:
    """Decode exactly one gzip member and prove the entire minimal USTAR stream."""

    try:
        compressed_offset = _parse_raw_gzip_header(payload)
        inflater = zlib.decompressobj(-zlib.MAX_WBITS)
        tar_payload = inflater.decompress(payload[compressed_offset:], MAX_TAR_STREAM_BYTES + 1)
        if len(tar_payload) > MAX_TAR_STREAM_BYTES or inflater.unconsumed_tail:
            raise ValueError(f"decompressed TAR exceeds raw stream budget {MAX_TAR_STREAM_BYTES}")
        if not inflater.eof:
            raise ValueError("gzip DEFLATE stream is truncated or does not terminate")
        trailer_and_tail = inflater.unused_data
        if len(trailer_and_tail) < GZIP_TRAILER_SIZE:
            raise ValueError("gzip member is truncated or lacks its complete trailer")
        expected_crc32, expected_size = struct.unpack_from("<II", trailer_and_tail, 0)
        if zlib.crc32(tar_payload) & 0xFFFFFFFF != expected_crc32:
            raise ValueError("gzip trailer CRC32 does not match the decoded TAR")
        if len(tar_payload) & 0xFFFFFFFF != expected_size:
            raise ValueError("gzip trailer ISIZE does not match the decoded TAR")
        if any(trailer_and_tail[GZIP_TRAILER_SIZE:]):
            raise ValueError("concatenated gzip members and trailing nonzero bytes are forbidden")
        if len(tar_payload) % TAR_BLOCK_SIZE:
            raise ValueError("TAR stream length is not a multiple of 512 bytes")

        entries: list[RawTarEntry] = []
        cursor = 0
        while cursor < len(tar_payload):
            block = tar_payload[cursor : cursor + TAR_BLOCK_SIZE]
            if block == b"\x00" * TAR_BLOCK_SIZE:
                second = tar_payload[cursor + TAR_BLOCK_SIZE : cursor + 2 * TAR_BLOCK_SIZE]
                if len(second) != TAR_BLOCK_SIZE or second != b"\x00" * TAR_BLOCK_SIZE:
                    raise ValueError("TAR EOF requires its first two consecutive zero blocks")
                if any(tar_payload[cursor + 2 * TAR_BLOCK_SIZE :]):
                    raise ValueError("TAR contains a member or nonzero bytes after its first EOF marker")
                return tuple(entries)

            stored_checksum = _parse_tar_octal(block[148:156], f"TAR checksum at offset {cursor}")
            computed_checksum = sum(block[:148]) + (8 * ord(" ")) + sum(block[156:])
            if stored_checksum != computed_checksum:
                raise ValueError(f"TAR header checksum mismatch at offset {cursor}")
            if block[257:263] != b"ustar\x00" or block[263:265] != b"00":
                raise ValueError(f"TAR header at offset {cursor} is not strict POSIX USTAR")
            if any(block[500:512]):
                raise ValueError(f"TAR header at offset {cursor} has nonzero reserved bytes")

            name_field = _parse_tar_text(block[0:100], f"TAR name at offset {cursor}")
            prefix = _parse_tar_text(block[345:500], f"TAR prefix at offset {cursor}")
            name = f"{prefix}/{name_field}" if prefix else name_field
            if not name:
                raise ValueError(f"TAR header at offset {cursor} has an empty name")
            mode = _parse_tar_octal(block[100:108], f"TAR mode for {name!r}")
            uid = _parse_tar_octal(block[108:116], f"TAR uid for {name!r}")
            gid = _parse_tar_octal(block[116:124], f"TAR gid for {name!r}")
            size = _parse_tar_octal(block[124:136], f"TAR size for {name!r}")
            mtime = _parse_tar_octal(block[136:148], f"TAR mtime for {name!r}")
            typeflag = block[156:157]
            linkname = _parse_tar_text(block[157:257], f"TAR linkname for {name!r}")
            uname = _parse_tar_text(block[265:297], f"TAR uname for {name!r}")
            gname = _parse_tar_text(block[297:329], f"TAR gname for {name!r}")
            devmajor = _parse_tar_octal(block[329:337], f"TAR devmajor for {name!r}")
            devminor = _parse_tar_octal(block[337:345], f"TAR devminor for {name!r}")

            if typeflag in {tarfile.XHDTYPE, tarfile.XGLTYPE}:
                raise ValueError(f"PAX extension header is forbidden for {name!r}")
            if typeflag in {tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}:
                raise ValueError(f"GNU long-name/link extension is forbidden for {name!r}")
            if typeflag == tarfile.GNUTYPE_SPARSE:
                raise ValueError(f"GNU sparse member is forbidden for {name!r}")
            if typeflag not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
                raise ValueError(f"links, devices, and special TAR member type {typeflag!r} are forbidden for {name!r}")
            if linkname:
                raise ValueError(f"link target ambiguity is forbidden for {name!r}")
            if devmajor or devminor:
                raise ValueError(f"device-number fields are forbidden for {name!r}")
            if typeflag == tarfile.DIRTYPE and size:
                raise ValueError(f"directory member {name!r} has a nonzero payload")

            data_offset = cursor + TAR_BLOCK_SIZE
            padded_size = ((size + TAR_BLOCK_SIZE - 1) // TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE
            next_offset = data_offset + padded_size
            if next_offset > len(tar_payload):
                raise ValueError(f"member {name!r} extends beyond the TAR stream")
            if any(tar_payload[data_offset + size : next_offset]):
                raise ValueError(f"member {name!r} has nonzero TAR data padding")
            entries.append(
                RawTarEntry(
                    name,
                    cursor,
                    data_offset,
                    size,
                    mode,
                    uid,
                    gid,
                    mtime,
                    typeflag,
                    linkname,
                    uname,
                    gname,
                    devmajor,
                    devminor,
                )
            )
            cursor = next_offset
        raise ValueError("TAR stream ended without two zero EOF blocks")
    except (UnicodeError, ValueError, zlib.error) as exc:
        failures.append(f"{label}: raw gzip/TAR layout rejected: {exc}")
        return None


def validate_tarfile_view(
    raw_entries: tuple[RawTarEntry, ...],
    members: list[tarfile.TarInfo],
    label: str,
    failures: list[str],
) -> bool:
    """Require tarfile's logical members to exactly match raw USTAR headers."""

    before = len(failures)
    if len(raw_entries) != len(members):
        failures.append(f"{label}: raw/tarfile member counts disagree")
        return False
    for raw, member in zip(raw_entries, members):
        normalized_raw_type = tarfile.REGTYPE if raw.typeflag == tarfile.AREGTYPE else raw.typeflag
        names_agree = raw.name == member.name or (
            normalized_raw_type == tarfile.DIRTYPE and raw.name.rstrip("/") == member.name.rstrip("/")
        )
        if (
            not names_agree
            or raw.header_offset != member.offset
            or raw.data_offset != member.offset_data
            or raw.size != member.size
            or raw.mode != member.mode
            or raw.uid != member.uid
            or raw.gid != member.gid
            or raw.mtime != member.mtime
            or normalized_raw_type != member.type
            or raw.linkname != member.linkname
            or raw.uname != member.uname
            or raw.gname != member.gname
            or raw.devmajor != member.devmajor
            or raw.devminor != member.devminor
            or bool(member.pax_headers)
            or member.sparse is not None
        ):
            failures.append(f"{label}: raw/tarfile metadata view disagrees for {raw.name!r}")
    return len(failures) == before


def verify_record(
    archive: zipfile.ZipFile,
    record_name: str,
    infos: list[zipfile.ZipInfo],
    label: str,
    failures: list[str],
) -> None:
    try:
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
    except (KeyError, UnicodeError, csv.Error) as exc:
        failures.append(f"{label}: RECORD cannot be parsed: {exc}")
        return
    mapping: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or not safe_archive_name(row[0]) or row[0] in mapping:
            failures.append(f"{label}: RECORD has malformed, unsafe, or duplicate rows")
            return
        mapping[row[0]] = (row[1], row[2])
    member_kinds = {info.filename: info.is_dir() for info in infos}
    if not validate_archive_path_trie(
        ((name, member_kinds.get(name, name.endswith("/"))) for name in mapping),
        f"{label}: RECORD",
        failures,
    ):
        return
    names = [info.filename for info in infos]
    record_inventory = {archive_path_key(name): name for name in mapping}
    member_inventory = {archive_path_key(name): name for name in names}
    if record_inventory != member_inventory:
        failures.append(f"{label}: RECORD inventory does not exactly match wheel members")
    for name in names:
        digest, size = mapping.get(name, ("", ""))
        if name == record_name:
            if digest or size:
                failures.append(f"{label}: RECORD must leave its own hash and size empty")
            continue
        payload = archive.read(name)
        expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        if digest != expected or size != str(len(payload)):
            failures.append(f"{label}: RECORD hash/size mismatch for {name!r}")


def inspect_wheel(blob: ArtifactBlob, project_name: str, project_version: str, package_names: set[str], failures: list[str]) -> None:
    label = f"wheel {blob.name}"
    if not artifact_blob_integrity(blob, label, failures):
        return
    if len(blob.payload) > MAX_ARCHIVE_BYTES:
        failures.append(f"{label}: compressed archive exceeds budget {MAX_ARCHIVE_BYTES}")
        return
    if parse_wheel_filename is None:
        failures.append(f"{label}: packaging is required to parse wheel filenames and tags")
        return
    try:
        filename_name, filename_version, _, filename_tags = parse_wheel_filename(blob.name)
    except Exception as exc:
        failures.append(f"{label}: invalid wheel filename: {exc}")
        return
    if canonicalize_name(filename_name) != canonicalize_name(project_name) or Version(str(filename_version)) != Version(project_version):
        failures.append(f"{label}: filename project/version does not match pyproject")
    expected_dist_info, expected_data = wheel_install_roots(project_name, project_version)
    raw_entries = validate_raw_zip(blob.payload, label, failures)
    if raw_entries is None:
        return
    if not zipfile.is_zipfile(io.BytesIO(blob.payload)):
        failures.append(f"{label}: is not a valid wheel ZIP archive")
        return
    try:
        with zipfile.ZipFile(io.BytesIO(blob.payload)) as archive:
            infos = archive.infolist()
            if not validate_zipfile_view(raw_entries, archive, infos, label, failures):
                return
            names = [info.filename for info in infos]
            budget_valid = archive_budget(label, ((info.filename, info.file_size, info.compress_size) for info in infos), failures)
            paths_valid = validate_archive_path_trie(
                ((info.filename, info.is_dir()) for info in infos),
                f"{label}: archive",
                failures,
            )
            unmodeled_directories = sorted(
                info.filename
                for info in infos
                if info.is_dir()
                and PurePosixPath(info.filename).parts
                and PurePosixPath(info.filename).parts[0]
                not in package_names | {expected_dist_info, expected_data}
            )
            if unmodeled_directories:
                failures.append(f"{label}: contains unmodeled explicit directories: {unmodeled_directories}")
                paths_valid = False
            for info in infos:
                name = info.filename
                parts = PurePosixPath(name).parts
                dist_info_segments = [part for part in parts if part.casefold().endswith(".dist-info")]
                if dist_info_segments and not (
                    parts[0] == expected_dist_info
                    and dist_info_segments == [expected_dist_info]
                ):
                    failures.append(f"{label}: non-canonical .dist-info path is forbidden: {name}")
                data_segments = [part for part in parts if part.casefold().endswith(".data")]
                if data_segments and not (
                    parts[0] == expected_data
                    and data_segments == [expected_data]
                    and (
                        (info.is_dir() and (len(parts) == 1 or (len(parts) == 2 and parts[1] in {"purelib", "platlib"})))
                        or (not info.is_dir() and len(parts) >= 3 and parts[1] in {"purelib", "platlib"})
                    )
                ):
                    failures.append(f"{label}: non-canonical or unmodeled .data path is forbidden: {name}")
            if any(info.flag_bits & 0x1 for info in infos):
                failures.append(f"{label}: encrypted members are forbidden")
                budget_valid = False
            if not budget_valid or not paths_valid:
                return
            for info in infos:
                unix_mode = info.external_attr >> 16
                unix_type = unix_mode & 0o170000
                if info.is_dir():
                    if unix_type not in {0, 0o040000}:
                        failures.append(f"{label}: wheel directory members must have Unix directory type: {info.filename}")
                    continue
                if unix_type not in {0, 0o100000}:
                    failures.append(f"{label}: wheel members must have Unix regular-file type: {info.filename}")
                    continue
                with archive.open(info, "r") as member_stream:
                    prefix = member_stream.read(8)
                if executable_payload(info.filename, unix_mode, prefix):
                    failures.append(f"{label}: executable payload is forbidden: {info.filename}")
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
            record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
            modeled_dist_info_files = {
                f"{expected_dist_info}/METADATA",
                f"{expected_dist_info}/WHEEL",
                f"{expected_dist_info}/RECORD",
            }
            unmodeled_dist_info = sorted(
                info.filename
                for info in infos
                if PurePosixPath(info.filename).parts
                and PurePosixPath(info.filename).parts[0] == expected_dist_info
                and info.filename not in modeled_dist_info_files
                and not (info.is_dir() and info.filename.rstrip("/") == expected_dist_info)
            )
            if unmodeled_dist_info:
                failures.append(f"{label}: canonical .dist-info contains unmodeled members: {unmodeled_dist_info}")
            if len(metadata_names) != 1 or len(wheel_names) != 1 or len(record_names) != 1:
                failures.append(f"{label}: requires exactly one .dist-info/METADATA, WHEEL, and RECORD")
            for package in package_names:
                if not any(name.startswith(f"{package}/") and not name.endswith("/") for name in names):
                    failures.append(f"{label}: package or namespace {package!r} has no payload")
            if len(metadata_names) != 1 or len(wheel_names) != 1 or len(record_names) != 1:
                return
            dist_info_roots = {PurePosixPath(name).parts[0] for name in metadata_names + wheel_names + record_names}
            if len(dist_info_roots) != 1:
                failures.append(f"{label}: metadata files do not share one .dist-info directory")
            name, version = parse_metadata(archive.read(metadata_names[0]), label, failures)
            if not same_project(name, version, project_name, project_version):
                failures.append(f"{label}: METADATA project/version does not match pyproject")
            wheel_metadata = BytesParser().parsebytes(archive.read(wheel_names[0]))
            wheel_version = wheel_metadata.get("Wheel-Version", "").strip()
            if not re.fullmatch(r"1\.\d+", wheel_version):
                failures.append(f"{label}: WHEEL requires a supported 1.x Wheel-Version")
            wheel_tags = set(wheel_metadata.get_all("Tag", []))
            filename_tag_text = {str(tag) for tag in filename_tags}
            if wheel_tags != filename_tag_text:
                failures.append(f"{label}: WHEEL Tag headers do not exactly match filename tags")
            purelib = wheel_metadata.get("Root-Is-Purelib", "").strip().lower()
            all_any = all(tag.platform == "any" for tag in filename_tags)
            if purelib not in {"true", "false"} or (purelib == "true") != all_any:
                failures.append(f"{label}: Root-Is-Purelib is incoherent with filename platform tags")
            if next(iter(dist_info_roots), "") != expected_dist_info:
                failures.append(f"{label}: .dist-info directory is incoherent with project name/version")
            verify_record(archive, record_names[0], infos, label, failures)
    except (OSError, zipfile.BadZipFile, KeyError, RuntimeError, NotImplementedError, ValueError) as exc:
        failures.append(f"{label}: inspection failed: {exc}")


def inspect_sdist(blob: ArtifactBlob, project_name: str, project_version: str, package_names: set[str], failures: list[str]) -> None:
    label = f"sdist {blob.name}"
    if not artifact_blob_integrity(blob, label, failures):
        return
    if len(blob.payload) > MAX_ARCHIVE_BYTES:
        failures.append(f"{label}: compressed archive exceeds budget {MAX_ARCHIVE_BYTES}")
        return
    if parse_sdist_filename is None:
        failures.append(f"{label}: packaging is required to parse sdist filenames")
        return
    try:
        filename_name, filename_version = parse_sdist_filename(blob.name)
        if canonicalize_name(filename_name) != canonicalize_name(project_name) or Version(str(filename_version)) != Version(project_version):
            failures.append(f"{label}: filename project/version does not match pyproject")
    except Exception as exc:
        failures.append(f"{label}: invalid sdist filename: {exc}")
        return
    expected_top = f"{canonicalize_name(project_name).replace('-', '_')}-{project_version}"
    raw_entries = validate_raw_gzip_tar(blob.payload, label, failures)
    if raw_entries is None:
        return
    try:
        with tarfile.open(fileobj=io.BytesIO(blob.payload), mode="r:gz", encoding="utf-8", errors="strict") as archive:
            members = archive.getmembers()
            if not validate_tarfile_view(raw_entries, members, label, failures):
                return
            names = [member.name for member in members]
            compressed_size = max(len(blob.payload), 1)
            budget_valid = archive_budget(
                label,
                ((member.name, member.size if member.isfile() else 0, compressed_size) for member in members),
                failures,
            )
            total_uncompressed = sum(member.size for member in members if member.isfile())
            if total_uncompressed and total_uncompressed / compressed_size > MAX_COMPRESSION_RATIO:
                failures.append(f"{label}: archive exceeds aggregate compression-ratio budget {MAX_COMPRESSION_RATIO}:1")
                budget_valid = False
            paths_valid = validate_archive_path_trie(
                ((member.name, member.isdir()) for member in members),
                f"{label}: archive",
                failures,
            )
            unmodeled_directories = sorted(
                member.name
                for member in members
                if member.isdir()
                and (
                    not PurePosixPath(member.name).parts
                    or (
                        member.name.rstrip("/") not in {expected_top, f"{expected_top}/src"}
                        and not (
                            len(PurePosixPath(member.name).parts) >= 3
                            and PurePosixPath(member.name).parts[0] == expected_top
                            and PurePosixPath(member.name).parts[1] == "src"
                            and PurePosixPath(member.name).parts[2] in package_names
                        )
                    )
                )
            )
            if unmodeled_directories:
                failures.append(f"{label}: contains unmodeled explicit directories: {unmodeled_directories}")
                paths_valid = False
            trailing_slash_files = sorted(member.name for member in members if member.isfile() and member.name.endswith("/"))
            if trailing_slash_files:
                failures.append(f"{label}: regular files cannot use directory-form names: {trailing_slash_files}")
                paths_valid = False
            if any(not (member.isfile() or member.isdir()) for member in members):
                failures.append(f"{label}: links, devices, and special members are forbidden")
                budget_valid = False
            if not budget_valid or not paths_valid:
                return
            for member in members:
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                prefix = extracted.read(8) if extracted is not None else b""
                if executable_payload(member.name, member.mode, prefix):
                    failures.append(f"{label}: executable payload is forbidden: {member.name}")
            top_levels = {PurePosixPath(name).parts[0] for name in names if PurePosixPath(name).parts}
            if len(top_levels) != 1:
                failures.append(f"{label}: members must share exactly one top-level directory")
                return
            top = next(iter(top_levels))
            if canonicalize_name(top.rsplit("-", 1)[0]) != canonicalize_name(project_name) or not top.endswith(f"-{project_version}"):
                failures.append(f"{label}: top-level directory is incoherent with project name/version")
            unmodeled_members = sorted(
                member.name
                for member in members
                if member.name.rstrip("/") not in {top, f"{top}/src"}
                and member.name not in {f"{top}/PKG-INFO", f"{top}/pyproject.toml"}
                and not member.name.startswith(f"{top}/src/")
            )
            if unmodeled_members:
                failures.append(f"{label}: contains unmodeled archive members: {unmodeled_members}")
            pkg_info = [member for member in members if member.isfile() and member.name == f"{top}/PKG-INFO"]
            pyprojects = [member for member in members if member.isfile() and member.name == f"{top}/pyproject.toml"]
            if len(pkg_info) != 1:
                failures.append(f"{label}: requires exactly one top-level PKG-INFO")
            else:
                payload = archive.extractfile(pkg_info[0])
                name, version = parse_metadata(payload.read() if payload else b"", label, failures)
                if not same_project(name, version, project_name, project_version):
                    failures.append(f"{label}: PKG-INFO project/version does not match pyproject")
            if len(pyprojects) != 1:
                failures.append(f"{label}: requires exactly one top-level pyproject.toml")
            else:
                payload = archive.extractfile(pyprojects[0])
                _, nested_name, nested_version = read_pyproject(payload.read() if payload else b"", f"{label} pyproject.toml", failures)
                if not same_project(nested_name, nested_version, project_name, project_version):
                    failures.append(f"{label}: embedded pyproject project/version does not match repository")
            for package in package_names:
                if not any(name.startswith(f"{top}/src/{package}/") and not name.endswith("/") for name in names):
                    failures.append(f"{label}: package or namespace {package!r} has no src payload")
    except (OSError, tarfile.TarError, KeyError, EOFError, ValueError) as exc:
        failures.append(f"{label}: is not a valid gzip sdist archive: {exc}")


def source_inventory(src: Path, root: Path, failures: list[str]) -> dict[str, bytes]:
    rows: dict[str, bytes] = {}
    if not src.is_dir() or is_reparse(src):
        failures.append("src: must be a local non-reparse directory")
        return rows
    for directory, dirnames, filenames in os.walk(src, followlinks=False):
        here = Path(directory)
        dirnames[:] = sorted(dirnames)
        for dirname in list(dirnames):
            if is_reparse(here / dirname):
                failures.append(f"src: symlink/junction/reparse directory is forbidden: {(here / dirname).relative_to(root)}")
                dirnames.remove(dirname)
        for filename in sorted(filenames):
            path = here / filename
            relative = path.relative_to(src).as_posix()
            if "__pycache__" in Path(relative).parts or filename.endswith((".pyc", ".pyo")):
                failures.append(f"src: generated bytecode/cache is forbidden: {relative}")
                continue
            try:
                rows[relative] = stable_bytes(path, root, f"src/{relative}")
            except (OSError, ValueError) as exc:
                failures.append(str(exc))
    return rows


def test_inventory(tests: Path, root: Path, failures: list[str]) -> dict[str, bytes]:
    """Snapshot candidate Python tests without importing or executing them."""

    rows: dict[str, bytes] = {}
    if not tests.is_dir() or is_reparse(tests) or not safe_chain(tests, root):
        failures.append("tests: must be a local non-reparse directory")
        return rows
    for directory, dirnames, filenames in os.walk(tests, followlinks=False):
        here = Path(directory)
        dirnames[:] = sorted(dirnames)
        for dirname in list(dirnames):
            if is_reparse(here / dirname):
                failures.append(
                    f"tests: symlink/junction/reparse directory is forbidden: "
                    f"{(here / dirname).relative_to(root)}"
                )
                dirnames.remove(dirname)
        for filename in sorted(filenames):
            if not (filename.startswith("test_") and filename.endswith(".py")):
                continue
            path = here / filename
            relative = path.relative_to(tests).as_posix()
            try:
                rows[relative] = stable_bytes(path, root, f"tests/{relative}")
            except (OSError, ValueError) as exc:
                failures.append(str(exc))
    return rows


def archive_source_inventories(
    wheel: ArtifactBlob,
    sdist: ArtifactBlob,
    top: str,
    expected_dist_info: str,
    expected_data: str,
    failures: list[str],
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    wheel_rows: dict[str, bytes] = {}
    sdist_rows: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(wheel.payload)) as archive:
            for info in archive.infolist():
                name = info.filename
                if info.is_dir():
                    continue
                parts = PurePosixPath(name).parts
                if parts and parts[0] == expected_dist_info and not any(
                    part.casefold().endswith(".dist-info") for part in parts[1:]
                ):
                    continue
                logical_name = name
                if any(part.casefold().endswith(".dist-info") for part in parts):
                    failures.append(f"wheel parity inventory rejects non-canonical .dist-info path: {name}")
                    logical_name = "__wheel_dist_info__/" + name
                data_segments = [part for part in parts if part.casefold().endswith(".data")]
                if data_segments:
                    if (
                        parts[0] != expected_data
                        or data_segments != [expected_data]
                        or len(parts) < 3
                        or parts[1] not in {"purelib", "platlib"}
                    ):
                        failures.append(f"wheel parity inventory rejects non-canonical or unmodeled .data path: {name}")
                        logical_name = "__wheel_data__/" + name
                    else:
                        logical_name = PurePosixPath(*parts[2:]).as_posix()
                if logical_name in wheel_rows:
                    failures.append("source/wheel parity mismatch: root/.data purelib or platlib path collision")
                    continue
                wheel_rows[logical_name] = archive.read(info)
    except (OSError, zipfile.BadZipFile, KeyError, RuntimeError, NotImplementedError, ValueError) as exc:
        failures.append(f"wheel parity inventory failed: {exc}")
    try:
        with tarfile.open(fileobj=io.BytesIO(sdist.payload), mode="r:gz") as archive:
            prefix = f"{top}/src/"
            for member in archive.getmembers():
                if member.isfile() and member.name.startswith(prefix):
                    stream = archive.extractfile(member)
                    sdist_rows[member.name[len(prefix):]] = stream.read() if stream else b""
    except (OSError, tarfile.TarError, KeyError, EOFError, ValueError) as exc:
        failures.append(f"sdist parity inventory failed: {exc}")
    return wheel_rows, sdist_rows


def verify_source_artifact_parity(
    source_rows: dict[str, bytes],
    wheel: ArtifactBlob,
    sdist: ArtifactBlob,
    project_name: str,
    project_version: str,
    failures: list[str],
) -> None:
    wheel_valid = artifact_blob_integrity(wheel, f"wheel {wheel.name} before parity", failures)
    sdist_valid = artifact_blob_integrity(sdist, f"sdist {sdist.name} before parity", failures)
    if not wheel_valid or not sdist_valid:
        return
    top = f"{canonicalize_name(project_name).replace('-', '_')}-{project_version}"
    expected_dist_info, expected_data = wheel_install_roots(project_name, project_version)
    wheel_rows, sdist_rows = archive_source_inventories(
        wheel,
        sdist,
        top,
        expected_dist_info,
        expected_data,
        failures,
    )
    source_hashes = {name: hashlib.sha256(payload).hexdigest() for name, payload in source_rows.items()}
    wheel_hashes = {name: hashlib.sha256(payload).hexdigest() for name, payload in wheel_rows.items()}
    sdist_hashes = {name: hashlib.sha256(payload).hexdigest() for name, payload in sdist_rows.items()}
    if sdist_hashes != source_hashes:
        failures.append("source/sdist parity mismatch: sdist src inventory and bytes must equal the snapshotted source tree")
    if wheel_hashes != source_hashes:
        failures.append("source/wheel parity mismatch: wheel package inventory and bytes must equal the snapshotted source tree")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    failures: list[str] = []
    if canonicalize_name is None:
        failures.append("validator dependency 'packaging' is required")

    pyproject = root / "pyproject.toml"
    document: dict[str, Any] = {}
    project_name = project_version = ""
    pyproject_payload = b""
    pyproject_snapshot_valid = False
    if not regular_file(pyproject):
        failures.append("pyproject.toml: must be a local regular file")
    else:
        try:
            pyproject_payload = stable_bytes(pyproject, root, "pyproject.toml")
            pyproject_snapshot_valid = True
            document, project_name, project_version = read_pyproject(pyproject_payload, "pyproject.toml", failures)
        except (OSError, ValueError) as exc:
            failures.append(f"pyproject.toml: cannot be read: {exc}")

    src = root / "src"
    source_failure_start = len(failures)
    source_rows = source_inventory(src, root, failures)
    source_snapshot_valid = len(failures) == source_failure_start
    package_names: set[str] = {PurePosixPath(name).parts[0] for name in source_rows if name.endswith(".py") and PurePosixPath(name).parts}
    if not package_names:
        failures.append("src: requires at least one package or PEP 420 namespace package containing Python source")
    else:
        implementation_files = [src / name for name, payload in source_rows.items() if name.endswith(".py") and PurePosixPath(name).name != "__init__.py" and payload]
        if not implementation_files:
            failures.append("src: requires at least one non-empty implementation module")
        for path in [src / name for name in source_rows if name.endswith(".py")]:
            try:
                ast.parse(source_rows[path.relative_to(src).as_posix()].decode("utf-8"), filename=str(path))
            except (OSError, UnicodeError, SyntaxError) as exc:
                failures.append(f"src: invalid Python module {path.relative_to(root)}: {exc}")

    declarations = declared_package_values(document)
    if declarations and "<find:src>" not in declarations:
        declared_roots = {item.split(".", 1)[0] for item in declarations}
        if package_names and not package_names.issubset(declared_roots):
            failures.append("pyproject.toml: explicit packages do not cover every src package")

    tests = root / "tests"
    test_failure_start = len(failures)
    test_rows = test_inventory(tests, root, failures)
    tests_snapshot_valid = len(failures) == test_failure_start
    real_package_tests = 0
    for relative, payload in test_rows.items():
        if not payload:
            continue
        try:
            tree = ast.parse(payload.decode("utf-8"), filename=str(tests / relative))
        except (UnicodeError, SyntaxError) as exc:
            failures.append(f"tests: invalid Python test {(tests / relative).relative_to(root)}: {exc}")
            continue
        imports_package = any(
            (isinstance(node, ast.Import) and any(alias.name.split(".", 1)[0] in package_names for alias in node.names))
            or (isinstance(node, ast.ImportFrom) and node.module is not None and node.module.split(".", 1)[0] in package_names)
            for node in ast.walk(tree)
        )
        test_nodes = [node for node in tree.body if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")) or (isinstance(node, ast.ClassDef) and node.name.startswith("Test"))]
        if imports_package and test_nodes and any(isinstance(descendant, (ast.Assert, ast.Call)) for node in test_nodes for descendant in ast.walk(node)):
            real_package_tests += 1
    if real_package_tests == 0:
        failures.append("tests: requires at least one valid test that imports the src package and exercises behavior")

    dist = root / "dist"
    initial_manifest: dict[str, str] = {}
    artifact_blobs: dict[str, ArtifactBlob] = {}
    wheels: list[ArtifactBlob] = []
    sdists: list[ArtifactBlob] = []
    try:
        artifact_blobs = snapshot_dist(dist, root)
        for name, blob in artifact_blobs.items():
            artifact_blob_integrity(blob, f"dist/{name} after snapshot", failures)
        initial_manifest = {name: blob.sha256 for name, blob in artifact_blobs.items()}
        for name, blob in sorted(artifact_blobs.items()):
            if name.endswith(".whl"):
                wheels.append(blob)
            elif name.endswith(".tar.gz"):
                sdists.append(blob)
            else:
                failures.append(f"dist: unexpected extra artifact: {name}")
        if len(wheels) != 1:
            failures.append(f"dist: requires exactly one wheel; found {len(wheels)}")
        if len(sdists) != 1:
            failures.append(f"dist: requires exactly one sdist; found {len(sdists)}")
        archive_failure_start = len(failures)
        for wheel in wheels:
            if artifact_blob_integrity(wheel, f"wheel {wheel.name} before inspection", failures):
                try:
                    inspect_wheel(wheel, project_name, project_version, package_names, failures)
                except Exception as exc:
                    failures.append(f"wheel {wheel.name}: inspection aborted fail-closed: {exc}")
                artifact_blob_integrity(wheel, f"wheel {wheel.name} after inspection", failures)
        for sdist in sdists:
            if artifact_blob_integrity(sdist, f"sdist {sdist.name} before inspection", failures):
                try:
                    inspect_sdist(sdist, project_name, project_version, package_names, failures)
                except Exception as exc:
                    failures.append(f"sdist {sdist.name}: inspection aborted fail-closed: {exc}")
                artifact_blob_integrity(sdist, f"sdist {sdist.name} after inspection", failures)
        if (
            len(failures) == archive_failure_start
            and len(wheels) == 1
            and len(sdists) == 1
            and project_name
            and project_version
        ):
            parity_inputs_valid = artifact_blob_integrity(
                wheels[0], f"wheel {wheels[0].name} immediately before parity", failures
            ) and artifact_blob_integrity(
                sdists[0], f"sdist {sdists[0].name} immediately before parity", failures
            )
            if parity_inputs_valid:
                try:
                    verify_source_artifact_parity(
                        source_rows, wheels[0], sdists[0], project_name, project_version, failures
                    )
                except Exception as exc:
                    failures.append(f"source/artifact parity aborted fail-closed: {exc}")
                artifact_blob_integrity(wheels[0], f"wheel {wheels[0].name} after parity", failures)
                artifact_blob_integrity(sdists[0], f"sdist {sdists[0].name} after parity", failures)
        if closed_dist_manifest(dist, root) != initial_manifest:
            failures.append("dist: final concurrent manifest drift detected after inspection")
    except (OSError, ValueError) as exc:
        failures.append(str(exc))

    if pyproject_snapshot_valid:
        try:
            if stable_bytes(pyproject, root, "pyproject.toml final recheck") != pyproject_payload:
                failures.append("pyproject.toml: final byte snapshot drift detected after inspection")
        except (OSError, ValueError) as exc:
            failures.append(f"pyproject.toml: final recheck failed: {exc}")
    if source_snapshot_valid:
        final_source_failures: list[str] = []
        final_source_rows = source_inventory(src, root, final_source_failures)
        if final_source_failures:
            failures.extend(f"src final recheck: {failure}" for failure in final_source_failures)
        elif final_source_rows != source_rows:
            failures.append("src: final closed byte inventory drift detected after inspection")
    if tests_snapshot_valid:
        final_test_failures: list[str] = []
        final_test_rows = test_inventory(tests, root, final_test_failures)
        if final_test_failures:
            failures.extend(f"tests final recheck: {failure}" for failure in final_test_failures)
        elif final_test_rows != test_rows:
            failures.append("tests: final closed byte inventory drift detected after inspection")

    for name, blob in artifact_blobs.items():
        artifact_blob_integrity(blob, f"dist/{name} before JSON diagnostic", failures)

    if failures:
        print(json.dumps({
            "archive_member_policy": "closed_minimal_python_payload",
            "authority_decision_attempted": False,
            "authority_integration": "absent",
            "build_equivalence": "not_evaluated",
            "candidate_code_executed": False,
            "diagnostic_status": "static_checks_failed",
            "failures": failures,
            "format": "candidate-release-static-diagnostic.v3",
            "python_source_payload_parity": "not_established",
            "release_authorized": False,
            "source_artifact_parity": "not_evaluated",
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps({
        "archive_member_policy": "closed_minimal_python_payload",
        "artifacts": initial_manifest,
        "authority_decision_attempted": False,
        "authority_integration": "absent",
        "build_equivalence": "not_evaluated",
        "candidate_code_executed": False,
        "diagnostic_status": "static_checks_passed",
        "format": "candidate-release-static-diagnostic.v3",
        "package_tests": real_package_tests,
        "packages": sorted(package_names),
        "project": project_name,
        "python_source_payload_parity": "observed_on_revalidated_non_atomic_local_snapshots",
        "release_authorized": False,
        "source_artifact_parity": "not_evaluated",
        "version": project_version,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
