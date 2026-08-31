from __future__ import annotations

import base64
import copy
import csv
import gzip
import hashlib
import io
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from scripts.portability_artifact_inventory import (
    CANONICAL_GZIP_HEADER,
    CANONICAL_WHEEL_DATE_TIME,
    CANONICAL_WHEEL_EXTERNAL_ATTRIBUTES,
    CANONICAL_WHEEL_FLAGS,
    CANONICAL_WHEEL_INTERNAL_ATTRIBUTES,
    CANONICAL_WHEEL_METHOD,
    CANONICAL_WHEEL_VERSION_MADE_BY,
    CANONICAL_WHEEL_VERSION_NEEDED,
    DEFLATE_STORED_BLOCK_MAX,
    DIST_INFO,
    EXPECTED_PACKAGE_FILES,
    EXPECTED_RAW_SDIST_MEMBERS,
    EXPECTED_SDIST_DIRECTORIES,
    EXPECTED_SDIST_FILES,
    EXPECTED_WHEEL_FILES,
    MAX_MEMBER_BYTES,
    METADATA_POLICY,
    SDIST_ARCHIVE_POLICY,
    SDIST_EGG_INFO_FILES,
    SDIST_ROOT,
    TAR_BLOCK_SIZE,
    TAR_RECORD_SIZE,
    _canonical_gzip_stored,
    _canonical_ustar_header,
    _canonical_ustar_payload,
    _validate_setuptools_pax_stream,
    canonicalize_sdist,
    canonicalize_wheel,
    inspect_package_artifacts,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CURRENT_CANONICAL_WHEEL_SHA256 = "da7a0161c8d6e752e644f9811de221f99f5794ad152588de63b66b9c4c02d106"
CURRENT_CANONICAL_SDIST_SHA256 = "9edd73cc3205d13510147c0831f834c8d7009cd1f15b9e202f567594e5d697f3"


def _run(command: list[str], *, cwd: Path) -> None:
    environment = dict(os.environ)
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        timeout=120,
    )


def _candidate(root: Path) -> Path:
    candidate = root / "candidate"
    candidate.mkdir(parents=True)
    for relative in ("LICENSE", "README.md", "pyproject.toml"):
        target = candidate / relative
        shutil.copy2(REPOSITORY_ROOT / relative, target)
    package = candidate / "src" / "financial_planning_sdk_br"
    package.mkdir(parents=True)
    for name in EXPECTED_PACKAGE_FILES:
        relative = Path(name).relative_to("financial_planning_sdk_br")
        target = package / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPOSITORY_ROOT / "src" / name, target)
    return candidate


def _build(candidate: Path, root: Path) -> tuple[Path, Path, Path, Path]:
    raw_direct = root / "direct-backend-raw"
    direct = root / "direct"
    raw = root / "raw"
    raw_rebuilt = root / "rebuilt-backend-raw"
    rebuilt = root / "rebuilt"
    for directory in (raw_direct, raw, raw_rebuilt):
        directory.mkdir(parents=True)
    _run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", os.fspath(raw_direct)],
        cwd=candidate,
    )
    _run([sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", os.fspath(raw)], cwd=candidate)
    raw_direct_wheel = next(raw_direct.glob("*.whl"))
    direct_wheel = canonicalize_wheel(
        raw_direct_wheel,
        direct / raw_direct_wheel.name,
        source_root=candidate,
    )
    raw_sdist = next(raw.glob("*.tar.gz"))
    sdist = canonicalize_sdist(raw_sdist, root / "canonical" / raw_sdist.name)
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--no-cache-dir",
            "--disable-pip-version-check",
            "--wheel-dir",
            os.fspath(raw_rebuilt),
            os.fspath(sdist),
        ],
        cwd=root,
    )
    raw_rebuilt_wheel = next(raw_rebuilt.glob("*.whl"))
    rebuilt_wheel = canonicalize_wheel(
        raw_rebuilt_wheel,
        rebuilt / raw_rebuilt_wheel.name,
        source_root=candidate,
    )
    return direct_wheel, raw_sdist, sdist, rebuilt_wheel


def _rewrite_sdist(source_path: Path, target_path: Path, replacements: dict[str, bytes]) -> None:
    stream = io.BytesIO()
    with (
        tarfile.open(source_path, mode="r:gz") as source,
        tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as target,
    ):
        for member in source.getmembers():
            copied = copy.copy(member)
            copied.pax_headers = {}
            if member.isdir():
                target.addfile(copied)
                continue
            extracted = source.extractfile(member)
            if extracted is None:
                raise AssertionError("test fixture lost a regular sdist member")
            payload = replacements.get(member.name, extracted.read())
            copied.size = len(payload)
            target.addfile(copied, io.BytesIO(payload))
    target_path.write_bytes(_canonical_gzip_stored(stream.getvalue()))


def _rewrite_backend_sdist_payloads(source_path: Path, target_path: Path, replacements: dict[str, bytes]) -> None:
    stream = io.BytesIO()
    with (
        tarfile.open(source_path, mode="r:gz") as source,
        tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as target,
    ):
        for member in source.getmembers():
            copied = copy.copy(member)
            if member.isdir():
                target.addfile(copied)
                continue
            extracted = source.extractfile(member)
            if extracted is None:
                raise AssertionError("test fixture lost a regular backend sdist member")
            payload = replacements.get(member.name, extracted.read())
            copied.size = len(payload)
            target.addfile(copied, io.BytesIO(payload))
    target_path.write_bytes(
        _gzip_with_raw_deflate(
            stream.getvalue(),
            level=9,
            filename=f"{SDIST_ROOT}.tar".encode("ascii"),
            xfl=2,
        )
    )


def _gzip_with_raw_deflate(
    payload: bytes,
    *,
    level: int,
    filename: bytes | None = None,
    xfl: int = 0,
) -> bytes:
    flags = 0x08 if filename is not None else 0
    header = b"\x1f\x8b\x08" + bytes((flags,)) + b"\x00\x00\x00\x00" + bytes((xfl, 255))
    compressor = zlib.compressobj(level=level, wbits=-zlib.MAX_WBITS)
    compressed = compressor.compress(payload) + compressor.flush()
    name = filename + b"\x00" if filename is not None else b""
    trailer = struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload) & 0xFFFFFFFF)
    return header + name + compressed + trailer


def _gzip_with_stored_blocks(payload: bytes, *, block_size: int, final_empty: bool = False) -> bytes:
    blocks = bytearray()
    for offset in range(0, len(payload), block_size):
        chunk = payload[offset : offset + block_size]
        blocks.append(1 if offset + len(chunk) == len(payload) and not final_empty else 0)
        blocks.extend(struct.pack("<HH", len(chunk), len(chunk) ^ 0xFFFF))
        blocks.extend(chunk)
    if final_empty:
        blocks.extend(b"\x01\x00\x00\xff\xff")
    trailer = struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload) & 0xFFFFFFFF)
    return CANONICAL_GZIP_HEADER + bytes(blocks) + trailer


def _tar_member_spans(payload: bytes) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    cursor = 0
    while payload[cursor : cursor + TAR_BLOCK_SIZE] != b"\x00" * TAR_BLOCK_SIZE:
        header = payload[cursor : cursor + TAR_BLOCK_SIZE]
        size = int(header[124:136].strip(b" \x00") or b"0", 8)
        end = cursor + TAR_BLOCK_SIZE + ((size + TAR_BLOCK_SIZE - 1) // TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE
        spans.append((cursor, end))
        cursor = end
    return spans


def _replace_tar_header(
    payload: bytes,
    index: int,
    mutator: Callable[[bytearray], None],
    *,
    canonical_checksum: bool = True,
) -> bytes:
    mutated = bytearray(payload)
    offset = _tar_member_spans(payload)[index][0]
    header = bytearray(mutated[offset : offset + TAR_BLOCK_SIZE])
    mutator(header)
    if canonical_checksum:
        header[148:156] = b"        "
        checksum = sum(header)
        header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    mutated[offset : offset + TAR_BLOCK_SIZE] = header
    return bytes(mutated)


def _replace_tar_field(
    payload: bytes,
    index: int,
    start: int,
    end: int,
    replacement: bytes,
    *,
    canonical_checksum: bool = True,
) -> bytes:
    if len(replacement) != end - start:
        raise AssertionError("test TAR field replacement has the wrong width")

    def replace(header: bytearray) -> None:
        header[start:end] = replacement

    return _replace_tar_header(payload, index, replace, canonical_checksum=canonical_checksum)


def _tar_base256(value: int, width: int) -> bytes:
    if value < 0:
        return value.to_bytes(width, "big", signed=True)
    encoded = bytearray(value.to_bytes(width, "big"))
    encoded[0] = 0x80
    return bytes(encoded)


def _raw_backend_gzip(tar_payload: bytes) -> bytes:
    return _gzip_with_raw_deflate(
        tar_payload,
        level=9,
        filename=f"{SDIST_ROOT}.tar".encode("ascii"),
        xfl=2,
    )


def _raw_tar_from_segments(segments: list[bytes]) -> bytes:
    payload = bytearray().join(segments) + b"\x00" * (2 * TAR_BLOCK_SIZE)
    remainder = len(payload) % TAR_RECORD_SIZE
    if remainder:
        payload += b"\x00" * (TAR_RECORD_SIZE - remainder)
    return bytes(payload)


def _replace_pax_payload(payload: bytes, index: int, replacement: bytes) -> bytes:
    start, end = _tar_member_spans(payload)[index]
    if len(replacement) > TAR_BLOCK_SIZE or end - start != 2 * TAR_BLOCK_SIZE:
        raise AssertionError("test PAX replacement exceeded its one-block fixture")
    header = bytearray(payload[start : start + TAR_BLOCK_SIZE])
    header[124:136] = f"{len(replacement):011o}\0".encode("ascii")
    header[148:156] = b"        "
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    mutated = bytearray(payload)
    mutated[start:end] = bytes(header) + replacement.ljust(TAR_BLOCK_SIZE, b"\x00")
    return bytes(mutated)


def _canonical_sdist_file_payloads(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, mode="r:gz") as archive:
        result: dict[str, bytes] = {}
        for member in archive.getmembers():
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise AssertionError("test fixture lost a regular canonical sdist member")
            result[member.name] = stream.read()
    return result


def _write_canonical_sdist_files(source_path: Path, target_path: Path, replacements: dict[str, bytes]) -> None:
    files = _canonical_sdist_file_payloads(source_path)
    files.update(replacements)
    target_path.write_bytes(_canonical_gzip_stored(_canonical_ustar_payload(files)))


def _rewrite_backend_wheel_payloads(
    source_path: Path,
    target_path: Path,
    replacements: dict[str, bytes],
    *,
    source_root: Path,
) -> None:
    with zipfile.ZipFile(source_path) as source:
        infos = source.infolist()
        payloads = {info.filename: source.read(info) for info in infos}
    record_name = "finplanbr-0.1.0.dev0.dist-info/RECORD"
    payloads.update(replacements)
    rows: list[list[str]] = []
    for info in infos:
        name = info.filename
        if name == record_name:
            rows.append([name, "", ""])
            continue
        payload = payloads[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        rows.append([name, "sha256=" + digest, str(len(payload))])
    record = io.StringIO(newline="")
    csv.writer(record, lineterminator="\r\n").writerows(rows)
    payloads[record_name] = record.getvalue().encode("utf-8")
    backend_path = target_path.with_name("backend-" + target_path.name)
    with zipfile.ZipFile(backend_path, mode="w") as target:
        for info in infos:
            target.writestr(copy.copy(info), payloads[info.filename])
    canonicalize_wheel(backend_path, target_path, source_root=source_root)


_ZIP_LOCAL_HEADER = struct.Struct("<4s5H3I2H")
_ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3I5H2I")
_ZIP_EOCD = struct.Struct("<4s4H2IH")


def _mutate_header_fields(
    source_path: Path,
    target_path: Path,
    *,
    local_mutator: Callable[[int, list[object]], None],
    central_mutator: Callable[[int, list[object]], None],
) -> None:
    payload = bytearray(source_path.read_bytes())
    eocd_offset = len(payload) - _ZIP_EOCD.size
    eocd = _ZIP_EOCD.unpack_from(payload, eocd_offset)
    central_offset = eocd[6]
    total_entries = eocd[4]
    cursor = 0
    index = 0
    while cursor < central_offset:
        values = list(_ZIP_LOCAL_HEADER.unpack_from(payload, cursor))
        local_mutator(index, values)
        _ZIP_LOCAL_HEADER.pack_into(payload, cursor, *values)
        cursor += _ZIP_LOCAL_HEADER.size + values[9] + values[10] + values[7]
        index += 1
    cursor = central_offset
    for index in range(total_entries):
        values = list(_ZIP_CENTRAL_HEADER.unpack_from(payload, cursor))
        central_mutator(index, values)
        _ZIP_CENTRAL_HEADER.pack_into(payload, cursor, *values)
        cursor += _ZIP_CENTRAL_HEADER.size + values[10] + values[11] + values[12]
    target_path.write_bytes(payload)


def _rewrite_wheel_archive(
    source_path: Path,
    target_path: Path,
    *,
    order: tuple[str, ...] = EXPECTED_WHEEL_FILES,
    compression: int = zipfile.ZIP_STORED,
    compresslevel: int | None = None,
    record_payload: bytes | None = None,
) -> None:
    with zipfile.ZipFile(source_path) as source:
        infos = {info.filename: info for info in source.infolist()}
        payloads = {name: source.read(name) for name in infos}
    if record_payload is not None:
        payloads[EXPECTED_WHEEL_FILES[-1]] = record_payload
    with zipfile.ZipFile(target_path, mode="w") as target:
        for name in order:
            copied = copy.copy(infos[name])
            copied.compress_type = compression
            copied._compresslevel = compresslevel
            target.writestr(copied, payloads[name])


class PortabilityArtifactInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="finplanbr-artifact-binding-")
        cls.root = Path(cls.temporary.name)
        cls.candidate = _candidate(cls.root / "clean")
        cls.direct_wheel, cls.raw_sdist, cls.sdist, cls.rebuilt_wheel = _build(cls.candidate, cls.root / "clean-build")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_clean_direct_and_sdist_wheels_bind_exact_inventory_and_content(self) -> None:
        binding = inspect_package_artifacts(
            source_root=self.candidate,
            direct_wheel=self.direct_wheel,
            sdist=self.sdist,
            rebuilt_wheel=self.rebuilt_wheel,
        )
        self.assertEqual(binding["package_member_count"], 18)
        self.assertEqual(binding["wheel_member_count"], 24)
        self.assertEqual(binding["sdist_member_count"], 33)
        self.assertTrue(binding["source_wheel_sdist_package_identical"])
        self.assertTrue(binding["direct_sdist_wheel_logical_identical"])
        self.assertTrue(binding["direct_sdist_wheel_archive_identical"])
        self.assertEqual(binding["sdist_archive_policy"], SDIST_ARCHIVE_POLICY)
        self.assertEqual(binding["wheel_archive_sha256"], hashlib.sha256(self.direct_wheel.read_bytes()).hexdigest())
        self.assertEqual(binding["sdist_archive_sha256"], hashlib.sha256(self.sdist.read_bytes()).hexdigest())
        self.assertEqual(binding["wheel_archive_sha256"], CURRENT_CANONICAL_WHEEL_SHA256)
        self.assertEqual(binding["sdist_archive_sha256"], CURRENT_CANONICAL_SDIST_SHA256)
        self.assertEqual(self.direct_wheel.read_bytes(), self.rebuilt_wheel.read_bytes())
        with tarfile.open(self.sdist, mode="r:gz") as archive:
            generated_names = (
                f"{SDIST_ROOT}/PKG-INFO",
                f"{SDIST_ROOT}/setup.cfg",
                *(f"{SDIST_ROOT}/src/finplanbr.egg-info/{name}" for name in SDIST_EGG_INFO_FILES),
            )
            for name in generated_names:
                extracted = archive.extractfile(name)
                self.assertIsNotNone(extracted)
                assert extracted is not None
                self.assertNotIn(b"\r", extracted.read())
            authored_bindings = (
                (f"{SDIST_ROOT}/LICENSE", self.candidate / "LICENSE"),
                (f"{SDIST_ROOT}/README.md", self.candidate / "README.md"),
                (f"{SDIST_ROOT}/pyproject.toml", self.candidate / "pyproject.toml"),
                *(
                    (f"{SDIST_ROOT}/src/{name}", self.candidate / "src" / name)
                    for name in EXPECTED_PACKAGE_FILES
                ),
            )
            for name, source in authored_bindings:
                extracted = archive.extractfile(name)
                self.assertIsNotNone(extracted)
                assert extracted is not None
                self.assertEqual(extracted.read(), source.read_bytes())
        with zipfile.ZipFile(self.direct_wheel) as archive:
            self.assertEqual(tuple(archive.namelist()), EXPECTED_WHEEL_FILES)
            self.assertEqual(archive.comment, b"")
            for info in archive.infolist():
                with self.subTest(member=info.filename):
                    self.assertEqual(info.date_time, CANONICAL_WHEEL_DATE_TIME)
                    self.assertEqual(info.compress_type, CANONICAL_WHEEL_METHOD)
                    self.assertEqual(info.flag_bits, CANONICAL_WHEEL_FLAGS)
                    self.assertEqual((info.create_system << 8) | info.create_version, CANONICAL_WHEEL_VERSION_MADE_BY)
                    self.assertEqual(info.extract_version, CANONICAL_WHEEL_VERSION_NEEDED)
                    self.assertEqual(info.internal_attr, CANONICAL_WHEEL_INTERNAL_ATTRIBUTES)
                    self.assertEqual(info.external_attr, CANONICAL_WHEEL_EXTERNAL_ATTRIBUTES)
                    self.assertEqual(info.extra, b"")
                    self.assertEqual(info.comment, b"")

    def test_raw_backend_tar_matches_one_coordinate_bound_pax_profile(self) -> None:
        tar_payload = gzip.decompress(self.raw_sdist.read_bytes())
        raw_members = _validate_setuptools_pax_stream(tar_payload)
        self.assertEqual(tuple(member.name for member in raw_members), EXPECTED_RAW_SDIST_MEMBERS)
        self.assertEqual(len(_tar_member_spans(tar_payload)), 2 * len(EXPECTED_RAW_SDIST_MEMBERS))
        self.assertEqual(len(tar_payload) % TAR_RECORD_SIZE, 0)

        if os.name == "nt":
            expected = (0o777, 0o666, 0, 0)
        elif sys.platform.startswith("linux"):
            expected = (0o755, 0o644, 65532, 65532)
        else:  # pragma: no cover - the portability matrix supports only these coordinates
            self.fail("test executed outside the closed Windows/Linux backend profile")
        for member in raw_members:
            with self.subTest(member=member.name):
                self.assertEqual(member.mode, expected[0] if member.directory else expected[1])
                self.assertEqual((member.uid, member.gid), expected[2:])
                self.assertEqual(member.raw_mtime, round(float(member.pax_mtime)))

        spans = _tar_member_spans(tar_payload)
        for index in range(0, len(spans), 2):
            pax = tar_payload[spans[index][0] : spans[index][0] + TAR_BLOCK_SIZE]
            logical = tar_payload[spans[index + 1][0] : spans[index + 1][0] + TAR_BLOCK_SIZE]
            with self.subTest(pair=index // 2):
                self.assertEqual(pax[0:100], b"././@PaxHeader".ljust(100, b"\x00"))
                self.assertEqual(pax[100:124], b"0000000\0" * 3)
                self.assertEqual(pax[136:148], b"00000000000\0")
                self.assertEqual(pax[148:156][-2:], b"\x00 ")
                self.assertEqual(pax[156:157], tarfile.XHDTYPE)
                self.assertFalse(any(pax[157:257]))
                self.assertFalse(any(pax[265:500]))
                self.assertFalse(any(pax[500:512]))
                self.assertEqual(logical[148:156][-2:], b"\x00 ")
                self.assertFalse(any(logical[157:257]))
                self.assertFalse(any(logical[265:512]))

    def test_raw_sdist_rejects_critic_numeric_and_owner_laundering(self) -> None:
        mutation_root = self.root / "raw-critic-fields"
        mutation_root.mkdir()
        tar_payload = gzip.decompress(self.raw_sdist.read_bytes())
        spans = _tar_member_spans(tar_payload)
        logical_index = 1
        logical_header = tar_payload[spans[logical_index][0] : spans[logical_index][0] + TAR_BLOCK_SIZE]
        mode = int(logical_header[100:107], 8)
        uid = int(logical_header[108:115], 8)
        gid = int(logical_header[116:123], 8)
        mtime = int(logical_header[136:147], 8)

        def hidden_octal(value: int, width: int, tail: int = ord("7")) -> bytes:
            digits = f"{value:o}".encode("ascii")
            return digits + b"\x00" + bytes((tail,)) * (width - len(digits) - 1)

        cases = {
            "mode-base256": _replace_tar_field(tar_payload, logical_index, 100, 108, _tar_base256(mode, 8)),
            "uid-base256": _replace_tar_field(tar_payload, logical_index, 108, 116, _tar_base256(uid, 8)),
            "gid-base256": _replace_tar_field(tar_payload, logical_index, 116, 124, _tar_base256(gid, 8)),
            "mtime-base256": _replace_tar_field(tar_payload, logical_index, 136, 148, _tar_base256(mtime, 12)),
            "mtime-negative-base256": _replace_tar_field(
                tar_payload, logical_index, 136, 148, _tar_base256(-1, 12)
            ),
            "mode-nul-tail": _replace_tar_field(
                tar_payload, logical_index, 100, 108, hidden_octal(mode, 8)
            ),
            "uid-nul-tail": _replace_tar_field(tar_payload, logical_index, 108, 116, hidden_octal(uid, 8)),
            "gid-nul-tail": _replace_tar_field(tar_payload, logical_index, 116, 124, hidden_octal(gid, 8)),
            "mtime-nul-tail": _replace_tar_field(
                tar_payload, logical_index, 136, 148, hidden_octal(0, 12)
            ),
            "uname-arbitrary": _replace_tar_field(
                tar_payload, logical_index, 265, 297, b"builder".ljust(32, b"\x00")
            ),
            "uname-nul-tail": _replace_tar_field(
                tar_payload, logical_index, 265, 297, b"\x00builder".ljust(32, b"\x00")
            ),
            "gname-arbitrary": _replace_tar_field(
                tar_payload, logical_index, 297, 329, b"builders".ljust(32, b"\x00")
            ),
            "gname-nul-tail": _replace_tar_field(
                tar_payload, logical_index, 297, 329, b"\x00builders".ljust(32, b"\x00")
            ),
        }
        for label, mutated_tar in cases.items():
            with self.subTest(label=label):
                with tarfile.open(fileobj=io.BytesIO(mutated_tar), mode="r:") as archive:
                    self.assertEqual(len(archive.getmembers()), len(EXPECTED_RAW_SDIST_MEMBERS))
                raw = mutation_root / f"{label}.tar.gz"
                target = mutation_root / f"canonical-{label}" / self.raw_sdist.name
                raw.write_bytes(_raw_backend_gzip(mutated_tar))
                with self.assertRaises(RuntimeError):
                    canonicalize_sdist(raw, target)
                self.assertFalse(target.exists())

    def test_raw_sdist_rejects_every_non_mtime_header_and_layout_channel(self) -> None:
        mutation_root = self.root / "raw-all-fields"
        mutation_root.mkdir()
        tar_payload = gzip.decompress(self.raw_sdist.read_bytes())
        spans = _tar_member_spans(tar_payload)
        segments = [tar_payload[start:end] for start, end in spans]
        pax_index = 0
        directory_index = 1
        file_index = 3
        directory_header = tar_payload[
            spans[directory_index][0] : spans[directory_index][0] + TAR_BLOCK_SIZE
        ]
        raw_mtime = int(directory_header[136:147], 8)

        def pax_name_prefix(header: bytearray) -> None:
            header[0:100] = b"@PaxHeader".ljust(100, b"\x00")
            header[345:500] = b"./.".ljust(155, b"\x00")

        def logical_name_prefix(header: bytearray) -> None:
            header[0:100] = b"PKG-INFO".ljust(100, b"\x00")
            header[345:500] = SDIST_ROOT.encode("ascii").ljust(155, b"\x00")

        def foreign_profile(header: bytearray) -> None:
            directory = header[156:157] == tarfile.DIRTYPE
            if os.name == "nt":
                mode, owner = (0o755 if directory else 0o644), 65532
            else:
                mode, owner = (0o777 if directory else 0o666), 0
            header[100:108] = f"{mode:07o}\0".encode("ascii")
            header[108:116] = f"{owner:07o}\0".encode("ascii")
            header[116:124] = f"{owner:07o}\0".encode("ascii")

        foreign_tar = tar_payload
        for index in range(1, len(spans), 2):
            foreign_tar = _replace_tar_header(foreign_tar, index, foreign_profile)

        pax_start, pax_end = spans[pax_index]
        pax_header = tar_payload[pax_start : pax_start + TAR_BLOCK_SIZE]
        pax_size = int(pax_header[124:135], 8)
        pax_payload = tar_payload[pax_start + TAR_BLOCK_SIZE : pax_start + TAR_BLOCK_SIZE + pax_size]
        pax_value = pax_payload.split(b"mtime=", 1)[1][:-1]
        noncanonical_pax_body = b"mtime=" + pax_value + b"0\n"
        noncanonical_pax_length = len(noncanonical_pax_body) + 3
        noncanonical_pax = f"{noncanonical_pax_length} ".encode("ascii") + noncanonical_pax_body
        self.assertEqual(len(noncanonical_pax), noncanonical_pax_length)
        leading_zero_body = f"mtime={raw_mtime}.1\n".encode("ascii")
        leading_zero_length = len(leading_zero_body) + 3
        while True:
            leading_zero_pax = (
                b"0" + str(leading_zero_length).encode("ascii") + b" " + leading_zero_body
            )
            if len(leading_zero_pax) == leading_zero_length:
                break
            leading_zero_length = len(leading_zero_pax)
        self.assertEqual(int(leading_zero_pax.split(b" ", 1)[0]), len(leading_zero_pax))

        bad_padding = bytearray(tar_payload)
        bad_padding[pax_start + TAR_BLOCK_SIZE + pax_size] = 1
        alternate_checksum = directory_header[148:154] + b"  "
        cases = {
            "pax-mode": _replace_tar_field(tar_payload, pax_index, 100, 108, b"0000001\0"),
            "pax-uid": _replace_tar_field(tar_payload, pax_index, 108, 116, b"0000001\0"),
            "pax-gid": _replace_tar_field(tar_payload, pax_index, 116, 124, b"0000001\0"),
            "pax-raw-mtime": _replace_tar_field(
                tar_payload, pax_index, 136, 148, b"00000000001\0"
            ),
            "pax-linkname": _replace_tar_field(
                tar_payload, pax_index, 157, 257, b"opaque".ljust(100, b"\x00")
            ),
            "pax-uname": _replace_tar_field(
                tar_payload, pax_index, 265, 297, b"builder".ljust(32, b"\x00")
            ),
            "pax-gname": _replace_tar_field(
                tar_payload, pax_index, 297, 329, b"builders".ljust(32, b"\x00")
            ),
            "pax-devmajor-zero-octal": _replace_tar_field(
                tar_payload, pax_index, 329, 337, b"0000000\0"
            ),
            "pax-devminor-zero-octal": _replace_tar_field(
                tar_payload, pax_index, 337, 345, b"0000000\0"
            ),
            "pax-name-prefix": _replace_tar_header(tar_payload, pax_index, pax_name_prefix),
            "pax-noncanonical-mtime": _replace_pax_payload(
                tar_payload, pax_index, noncanonical_pax
            ),
            "pax-leading-zero-length": _replace_pax_payload(
                tar_payload, pax_index, leading_zero_pax
            ),
            "member-mode-foreign": _replace_tar_field(
                tar_payload,
                directory_index,
                100,
                108,
                b"0000755\0" if os.name == "nt" else b"0000777\0",
            ),
            "member-uid-foreign": _replace_tar_field(
                tar_payload,
                directory_index,
                108,
                116,
                b"0177774\0" if os.name == "nt" else b"0000000\0",
            ),
            "member-gid-foreign": _replace_tar_field(
                tar_payload,
                directory_index,
                116,
                124,
                b"0177774\0" if os.name == "nt" else b"0000000\0",
            ),
            "foreign-coherent-profile": foreign_tar,
            "member-size-spaced": _replace_tar_field(
                tar_payload, directory_index, 124, 136, b"          0\0"
            ),
            "member-size-base256": _replace_tar_field(
                tar_payload, directory_index, 124, 136, _tar_base256(0, 12)
            ),
            "member-mtime-pax-mismatch": _replace_tar_field(
                tar_payload, directory_index, 136, 148, f"{raw_mtime + 1:011o}\0".encode("ascii")
            ),
            "member-checksum-encoding": _replace_tar_field(
                tar_payload,
                directory_index,
                148,
                156,
                alternate_checksum,
                canonical_checksum=False,
            ),
            "member-areg": _replace_tar_field(tar_payload, file_index, 156, 157, tarfile.AREGTYPE),
            "member-linkname-nul-tail": _replace_tar_field(
                tar_payload, directory_index, 157, 257, b"\x00opaque".ljust(100, b"\x00")
            ),
            "member-devmajor-zero-octal": _replace_tar_field(
                tar_payload, directory_index, 329, 337, b"0000000\0"
            ),
            "member-devminor-zero-octal": _replace_tar_field(
                tar_payload, directory_index, 337, 345, b"0000000\0"
            ),
            "member-name-prefix": _replace_tar_header(tar_payload, file_index, logical_name_prefix),
            "directory-name-without-slash": _replace_tar_field(
                tar_payload,
                directory_index,
                0,
                100,
                SDIST_ROOT.encode("ascii").ljust(100, b"\x00"),
            ),
            "member-magic": _replace_tar_field(tar_payload, directory_index, 257, 263, b"ustar "),
            "member-version": _replace_tar_field(tar_payload, directory_index, 263, 265, b" \x00"),
            "member-reserved": _replace_tar_field(
                tar_payload, directory_index, 500, 512, b"opaque".ljust(12, b"\x00")
            ),
            "member-padding": bytes(bad_padding),
            "missing-pax": _raw_tar_from_segments(segments[1:]),
            "reordered-pairs": _raw_tar_from_segments(
                [*segments[2:4], *segments[0:2], *segments[4:]]
            ),
            "minimum-eof": b"".join(segments) + b"\x00" * (2 * TAR_BLOCK_SIZE),
            "extra-eof": tar_payload + b"\x00" * TAR_BLOCK_SIZE,
        }
        for label, mutated_tar in cases.items():
            with self.subTest(label=label):
                raw = mutation_root / f"{label}.tar.gz"
                target = mutation_root / f"canonical-{label}" / self.raw_sdist.name
                raw.write_bytes(_raw_backend_gzip(mutated_tar))
                with self.assertRaises(RuntimeError):
                    canonicalize_sdist(raw, target)
                self.assertFalse(target.exists())

    def test_tarfile_second_guard_reconciles_raw_member_attributes(self) -> None:
        mutation_root = self.root / "raw-second-guard"
        mutation_root.mkdir()
        tar_payload = gzip.decompress(self.raw_sdist.read_bytes())
        raw_members = _validate_setuptools_pax_stream(tar_payload)
        spans = _tar_member_spans(tar_payload)
        header = tar_payload[spans[1][0] : spans[1][0] + TAR_BLOCK_SIZE]
        mode = int(header[100:107], 8)
        mutated_tar = _replace_tar_field(
            tar_payload,
            1,
            100,
            108,
            f"{(mode ^ 0o111):07o}\0".encode("ascii"),
        )
        raw = mutation_root / self.raw_sdist.name
        target = mutation_root / "canonical" / raw.name
        raw.write_bytes(_raw_backend_gzip(mutated_tar))
        with (
            mock.patch(
                "scripts.portability_artifact_inventory._validate_setuptools_pax_stream",
                return_value=raw_members,
            ),
            self.assertRaisesRegex(RuntimeError, "exposes attributes"),
        ):
            canonicalize_sdist(raw, target)
        self.assertFalse(target.exists())

    def test_canonical_sdist_converges_across_alternate_zlib_outputs_without_using_zlib_encoder(self) -> None:
        mutation_root = self.root / "zlib-independent-sdist"
        mutation_root.mkdir()
        tar_payload = gzip.decompress(self.raw_sdist.read_bytes())
        outputs: list[bytes] = []
        for level in (1, 6, 9):
            with self.subTest(level=level):
                raw = mutation_root / f"raw-{level}.tar.gz"
                raw.write_bytes(
                    _gzip_with_raw_deflate(
                        tar_payload,
                        level=level,
                        filename=f"{SDIST_ROOT}.tar".encode("ascii"),
                        xfl=2,
                    )
                )
                target = mutation_root / f"canonical-{level}" / self.raw_sdist.name
                with mock.patch(
                    "scripts.portability_artifact_inventory.zlib.compress",
                    side_effect=AssertionError("canonical writer delegated bytes to zlib.compress"),
                ):
                    canonicalize_sdist(raw, target)
                outputs.append(target.read_bytes())
        self.assertTrue(all(payload == self.sdist.read_bytes() for payload in outputs))
        self.assertEqual(hashlib.sha256(outputs[0]).hexdigest(), CURRENT_CANONICAL_SDIST_SHA256)

    def test_manual_ustar_writer_matches_r5_golden_and_closes_field_boundaries(self) -> None:
        files = _canonical_sdist_file_payloads(self.sdist)
        tar_payload = _canonical_ustar_payload(files)
        self.assertEqual(tar_payload, gzip.decompress(self.sdist.read_bytes()))
        self.assertEqual(len(tar_payload) % TAR_RECORD_SIZE, 0)
        self.assertEqual(
            hashlib.sha256(_canonical_gzip_stored(tar_payload)).hexdigest(),
            CURRENT_CANONICAL_SDIST_SHA256,
        )

        mutation_root = self.root / "manual-ustar-writer"
        mutation_root.mkdir()
        target = mutation_root / self.raw_sdist.name
        with mock.patch.object(
            tarfile.TarFile,
            "addfile",
            side_effect=AssertionError("canonical writer delegated TAR bytes to tarfile"),
        ):
            canonicalize_sdist(self.raw_sdist, target)
        self.assertEqual(target.read_bytes(), self.sdist.read_bytes())

        missing = dict(files)
        missing.pop(EXPECTED_SDIST_FILES[-1])
        with self.assertRaisesRegex(RuntimeError, "inventory"):
            _canonical_ustar_payload(missing)
        not_exact_bytes = dict(files)
        not_exact_bytes[EXPECTED_SDIST_FILES[-1]] = bytearray(not_exact_bytes[EXPECTED_SDIST_FILES[-1]])  # type: ignore[assignment]
        with self.assertRaisesRegex(RuntimeError, "exact bytes"):
            _canonical_ustar_payload(not_exact_bytes)
        oversized = dict(files)
        oversized[EXPECTED_SDIST_FILES[-1]] = b"x" * (MAX_MEMBER_BYTES + 1)
        with self.assertRaisesRegex(RuntimeError, "byte budget"):
            _canonical_ustar_payload(oversized)
        self.assertEqual(len(_canonical_ustar_header("a" * 100, directory=False, size=0)), TAR_BLOCK_SIZE)
        with self.assertRaisesRegex(RuntimeError, "name.*field"):
            _canonical_ustar_header("a" * 101, directory=False, size=0)
        with self.assertRaisesRegex(RuntimeError, "size.*octal"):
            _canonical_ustar_header("bounded", directory=False, size=8**11)

    def test_crlf_backend_generated_sdist_files_converge_without_normalizing_authored_bytes(self) -> None:
        mutation_root = self.root / "crlf-generated-sdist"
        mutation_root.mkdir()
        prefix = f"{SDIST_ROOT}/"
        generated_names = (
            prefix + "PKG-INFO",
            prefix + "setup.cfg",
            *(prefix + f"src/finplanbr.egg-info/{name}" for name in SDIST_EGG_INFO_FILES),
        )
        with tarfile.open(self.raw_sdist, mode="r:gz") as archive:
            replacements = {}
            for name in generated_names:
                extracted = archive.extractfile(name)
                self.assertIsNotNone(extracted)
                assert extracted is not None
                normalized = extracted.read().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                replacements[name] = normalized.replace(b"\n", b"\r\n")
        raw = mutation_root / self.raw_sdist.name
        _rewrite_backend_sdist_payloads(self.raw_sdist, raw, replacements)
        target = mutation_root / "canonical" / raw.name
        canonicalize_sdist(raw, target)
        self.assertEqual(target.read_bytes(), self.sdist.read_bytes())
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), CURRENT_CANONICAL_SDIST_SHA256)

    def test_final_canonical_sdist_requires_exact_lf_generated_metadata(self) -> None:
        mutation_root = self.root / "final-generated-metadata"
        mutation_root.mkdir()
        files = _canonical_sdist_file_payloads(self.sdist)
        prefix = f"{SDIST_ROOT}/"
        generated_names = (
            prefix + "PKG-INFO",
            prefix + "setup.cfg",
            *(prefix + f"src/finplanbr.egg-info/{name}" for name in SDIST_EGG_INFO_FILES),
        )
        self.assertEqual(len(generated_names), 8)
        for index, name in enumerate(generated_names):
            with self.subTest(member=name):
                self.assertIn(b"\n", files[name])
                mutated = mutation_root / f"crlf-{index}.tar.gz"
                replacement = files[name].replace(b"\n", b"\r\n")
                _write_canonical_sdist_files(self.sdist, mutated, {name: replacement})
                with self.assertRaisesRegex(RuntimeError, "sdist .*metadata|sdist SOURCES|sdist .*METADATA"):
                    inspect_package_artifacts(
                        source_root=self.candidate,
                        direct_wheel=self.direct_wheel,
                        sdist=mutated,
                        rebuilt_wheel=self.rebuilt_wheel,
                    )

        sources_name = prefix + "src/finplanbr.egg-info/SOURCES.txt"
        trailing_lf = mutation_root / "sources-trailing-lf.tar.gz"
        _write_canonical_sdist_files(self.sdist, trailing_lf, {sources_name: files[sources_name] + b"\n"})
        with self.assertRaisesRegex(RuntimeError, "sdist SOURCES.txt"):
            inspect_package_artifacts(
                source_root=self.candidate,
                direct_wheel=self.direct_wheel,
                sdist=trailing_lf,
                rebuilt_wheel=self.rebuilt_wheel,
            )

    def test_canonical_sdist_rejects_header_deflate_and_block_boundary_channels(self) -> None:
        mutation_root = self.root / "canonical-sdist-channels"
        mutation_root.mkdir()
        canonical = self.sdist.read_bytes()
        tar_payload = gzip.decompress(canonical)
        self.assertGreater(len(tar_payload), DEFLATE_STORED_BLOCK_MAX)

        header_mtime = bytearray(canonical)
        header_mtime[4] = 1
        header_xfl = bytearray(canonical)
        header_xfl[8] = 2
        header_os = bytearray(canonical)
        header_os[9] = 3
        padding = bytearray(canonical)
        padding[len(CANONICAL_GZIP_HEADER)] |= 0x08
        cases = {
            "mtime": bytes(header_mtime),
            "xfl": bytes(header_xfl),
            "os": bytes(header_os),
            "stored-padding": bytes(padding),
            "alternate-deflate": _gzip_with_raw_deflate(tar_payload, level=9),
            "alternate-stored-boundary": _gzip_with_stored_blocks(tar_payload, block_size=32768),
            "redundant-final-empty": _gzip_with_stored_blocks(
                tar_payload,
                block_size=DEFLATE_STORED_BLOCK_MAX,
                final_empty=True,
            ),
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                self.assertEqual(gzip.decompress(payload), tar_payload)
                mutated = mutation_root / f"{label}.tar.gz"
                mutated.write_bytes(payload)
                with self.assertRaisesRegex(RuntimeError, "gzip header|DEFLATE"):
                    inspect_package_artifacts(
                        source_root=self.candidate,
                        direct_wheel=self.direct_wheel,
                        sdist=mutated,
                        rebuilt_wheel=self.rebuilt_wheel,
                    )

        invalid_nlen = bytearray(canonical)
        invalid_nlen[len(CANONICAL_GZIP_HEADER) + 3] ^= 1
        invalid_trailer = bytearray(canonical)
        invalid_trailer[-8] ^= 1
        for label, payload in {
            "invalid-nlen": bytes(invalid_nlen),
            "invalid-trailer": bytes(invalid_trailer),
        }.items():
            with self.subTest(label=label):
                mutated = mutation_root / f"{label}.tar.gz"
                mutated.write_bytes(payload)
                with self.assertRaisesRegex(RuntimeError, "LEN/NLEN|trailer"):
                    inspect_package_artifacts(
                        source_root=self.candidate,
                        direct_wheel=self.direct_wheel,
                        sdist=mutated,
                        rebuilt_wheel=self.rebuilt_wheel,
                    )

    def test_canonical_sdist_rejects_semantically_equal_ustar_byte_channels(self) -> None:
        mutation_root = self.root / "canonical-ustar-channels"
        mutation_root.mkdir()
        canonical_tar = gzip.decompress(self.sdist.read_bytes())
        spans = _tar_member_spans(canonical_tar)
        self.assertEqual(len(spans), len(EXPECTED_SDIST_DIRECTORIES) + len(EXPECTED_SDIST_FILES))
        eof_offset = spans[-1][1]

        segments = [canonical_tar[start:end] for start, end in spans]
        reordered = b"".join((segments[1], segments[0], *segments[2:])) + canonical_tar[eof_offset:]

        def spaced_octal(header: bytearray) -> None:
            header[100:108] = b"   0755 "

        def alternate_name_prefix(header: bytearray) -> None:
            header[0:100] = b"src/".ljust(100, b"\x00")
            header[345:500] = SDIST_ROOT.encode("ascii").ljust(155, b"\x00")

        octal_spacing = _replace_tar_header(canonical_tar, 0, spaced_octal)
        name_prefix = _replace_tar_header(canonical_tar, 1, alternate_name_prefix)
        checksum_encoding = bytearray(canonical_tar)
        checksum_offset = spans[0][0] + 148
        canonical_checksum = checksum_encoding[checksum_offset : checksum_offset + 8]
        self.assertEqual(canonical_checksum[-2:], b"\x00 ")
        checksum_encoding[checksum_offset : checksum_offset + 8] = canonical_checksum[:6] + b"  "

        minimum_eof = canonical_tar[:eof_offset] + b"\x00" * (2 * TAR_BLOCK_SIZE)
        cases = {
            "member-order": reordered,
            "extra-eof-block": canonical_tar + b"\x00" * TAR_BLOCK_SIZE,
            "octal-spacing": octal_spacing,
            "checksum-encoding": bytes(checksum_encoding),
            "alternate-name-prefix": name_prefix,
        }
        if minimum_eof == canonical_tar:
            self.assertEqual(len(canonical_tar) - eof_offset, 2 * TAR_BLOCK_SIZE)
        else:
            cases["minimum-two-eof-blocks"] = minimum_eof
        for label, tar_payload in cases.items():
            with self.subTest(label=label):
                self.assertNotEqual(tar_payload, canonical_tar)
                mutated = mutation_root / f"{label}.tar.gz"
                mutated.write_bytes(_canonical_gzip_stored(tar_payload))
                with tarfile.open(mutated, mode="r:gz") as archive:
                    self.assertEqual(len(archive.getmembers()), len(spans))
                with self.assertRaisesRegex(RuntimeError, "canonical USTAR"):
                    inspect_package_artifacts(
                        source_root=self.candidate,
                        direct_wheel=self.direct_wheel,
                        sdist=mutated,
                        rebuilt_wheel=self.rebuilt_wheel,
                    )

    def test_canonical_gzip_stored_block_edges_have_one_closed_segmentation(self) -> None:
        for size, expected_lengths in (
            (0, [0]),
            (DEFLATE_STORED_BLOCK_MAX, [DEFLATE_STORED_BLOCK_MAX]),
            (DEFLATE_STORED_BLOCK_MAX + 1, [DEFLATE_STORED_BLOCK_MAX, 1]),
            (DEFLATE_STORED_BLOCK_MAX * 2, [DEFLATE_STORED_BLOCK_MAX, DEFLATE_STORED_BLOCK_MAX]),
        ):
            with self.subTest(size=size):
                source = bytes(index % 251 for index in range(size))
                encoded = _canonical_gzip_stored(source)
                self.assertEqual(gzip.decompress(encoded), source)
                cursor = len(CANONICAL_GZIP_HEADER)
                observed: list[tuple[int, int]] = []
                while True:
                    header = encoded[cursor]
                    length, complement = struct.unpack_from("<HH", encoded, cursor + 1)
                    self.assertEqual(complement, length ^ 0xFFFF)
                    observed.append((header, length))
                    cursor += 5 + length
                    if header == 1:
                        break
                self.assertEqual([length for _, length in observed], expected_lengths)
                self.assertEqual([header for header, _ in observed[:-1]], [0] * (len(observed) - 1))
                self.assertEqual(observed[-1][0], 1)
                self.assertEqual(cursor + 8, len(encoded))

    def test_crlf_backend_generated_files_converge_to_linux_canonical_wheel(self) -> None:
        mutation_root = self.root / "crlf-generated-metadata"
        mutation_root.mkdir()
        with zipfile.ZipFile(self.direct_wheel) as archive:
            replacements = {
                f"{DIST_INFO}/{name}": archive.read(f"{DIST_INFO}/{name}").replace(b"\n", b"\r\n")
                for name in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt")
            }
        canonical = mutation_root / self.direct_wheel.name
        _rewrite_backend_wheel_payloads(
            self.direct_wheel,
            canonical,
            replacements,
            source_root=self.candidate,
        )
        self.assertEqual(canonical.read_bytes(), self.direct_wheel.read_bytes())
        self.assertEqual(hashlib.sha256(canonical.read_bytes()).hexdigest(), CURRENT_CANONICAL_WHEEL_SHA256)
        with zipfile.ZipFile(canonical) as archive:
            for name in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD"):
                with self.subTest(member=name):
                    self.assertNotIn(b"\r", archive.read(f"{DIST_INFO}/{name}"))
            self.assertTrue(archive.read(f"{DIST_INFO}/METADATA").endswith(self.candidate.joinpath("README.md").read_bytes()))

        wrong_source = _candidate(mutation_root / "wrong-source")
        wrong_source.joinpath("README.md").write_bytes(
            wrong_source.joinpath("README.md").read_bytes() + b"\nsource-binding-negative-control\n"
        )
        backend = canonical.with_name("backend-" + canonical.name)
        with self.assertRaisesRegex(RuntimeError, "closed source policy"):
            canonicalize_wheel(
                backend,
                mutation_root / "wrong-source-canonical" / canonical.name,
                source_root=wrong_source,
            )

    def test_canonicalizer_does_not_normalize_authored_package_files(self) -> None:
        mutation_root = self.root / "authored-package-newlines"
        mutation_root.mkdir()
        package_name = "financial_planning_sdk_br/__init__.py"
        with zipfile.ZipFile(self.direct_wheel) as archive:
            original = archive.read(package_name)
        mutated = original.replace(b"\n", b"\r\n")
        self.assertNotEqual(mutated, original)
        canonical = mutation_root / self.direct_wheel.name
        _rewrite_backend_wheel_payloads(
            self.direct_wheel,
            canonical,
            {package_name: mutated},
            source_root=self.candidate,
        )
        with zipfile.ZipFile(canonical) as archive:
            self.assertEqual(archive.read(package_name), mutated)
        with self.assertRaisesRegex(RuntimeError, "source/wheel/sdist package content differs"):
            inspect_package_artifacts(
                source_root=self.candidate,
                direct_wheel=canonical,
                sdist=self.sdist,
                rebuilt_wheel=self.rebuilt_wheel,
            )

    def test_sdist_canonicalizer_preserves_authored_bytes_and_binding_rejects_drift(self) -> None:
        mutation_root = self.root / "authored-sdist-bytes"
        mutation_root.mkdir()
        archive_name = f"{SDIST_ROOT}/src/financial_planning_sdk_br/__init__.py"
        source_name = self.candidate / "src/financial_planning_sdk_br/__init__.py"
        original = source_name.read_bytes()
        replacement = original.replace(b"\n", b"\r\n")
        self.assertNotEqual(replacement, original)
        raw = mutation_root / self.raw_sdist.name
        _rewrite_backend_sdist_payloads(self.raw_sdist, raw, {archive_name: replacement})
        canonical = mutation_root / "canonical" / raw.name
        canonicalize_sdist(raw, canonical)
        with tarfile.open(canonical, mode="r:gz") as archive:
            stream = archive.extractfile(archive_name)
            self.assertIsNotNone(stream)
            assert stream is not None
            self.assertEqual(stream.read(), replacement)
        with self.assertRaisesRegex(RuntimeError, "source/wheel/sdist package content differs"):
            inspect_package_artifacts(
                source_root=self.candidate,
                direct_wheel=self.direct_wheel,
                sdist=canonical,
                rebuilt_wheel=self.rebuilt_wheel,
            )

    def test_full_inspector_rejects_header_channels_and_canonicalizer_erases_them(self) -> None:
        mutation_root = self.root / "header-channel"
        mutation_root.mkdir()

        def unchanged(_index: int, _values: list[object]) -> None:
            return

        def timestamp_local(_index: int, values: list[object]) -> None:
            values[4] = 1

        def timestamp_central(_index: int, values: list[object]) -> None:
            values[5] = 1

        def utf8_local(_index: int, values: list[object]) -> None:
            values[2] = int(values[2]) | 0x0800

        def utf8_central(_index: int, values: list[object]) -> None:
            values[3] = int(values[3]) | 0x0800

        def version_local(_index: int, values: list[object]) -> None:
            values[1] = 10

        def version_central(_index: int, values: list[object]) -> None:
            values[2] = 10

        def attributes_central(_index: int, values: list[object]) -> None:
            values[1] = 20
            values[15] = CANONICAL_WHEEL_EXTERNAL_ATTRIBUTES | (0o022 << 16)

        mutations = {
            "timestamp": (timestamp_local, timestamp_central),
            "utf8-flag": (utf8_local, utf8_central),
            "version-needed": (version_local, version_central),
            "creator-and-mode": (unchanged, attributes_central),
        }
        for label, (local_mutator, central_mutator) in mutations.items():
            with self.subTest(label=label):
                mutated = mutation_root / label / self.direct_wheel.name
                mutated.parent.mkdir()
                _mutate_header_fields(
                    self.direct_wheel,
                    mutated,
                    local_mutator=local_mutator,
                    central_mutator=central_mutator,
                )
                self.assertNotEqual(mutated.read_bytes(), self.direct_wheel.read_bytes())
                with self.assertRaisesRegex(RuntimeError, "canonical stored ZIP32"):
                    inspect_package_artifacts(
                        source_root=self.candidate,
                        direct_wheel=mutated,
                        sdist=self.sdist,
                        rebuilt_wheel=self.rebuilt_wheel,
                    )
                normalized = canonicalize_wheel(
                    mutated,
                    mutation_root / label / "canonical" / mutated.name,
                    source_root=self.candidate,
                )
                self.assertEqual(normalized.read_bytes(), self.direct_wheel.read_bytes())

    def test_member_order_record_order_and_compression_channels_are_closed(self) -> None:
        mutation_root = self.root / "layout-channel"
        mutation_root.mkdir()
        cases: dict[str, Path] = {}

        reordered = mutation_root / "reordered" / self.direct_wheel.name
        reordered.parent.mkdir()
        _rewrite_wheel_archive(
            self.direct_wheel,
            reordered,
            order=tuple(reversed(EXPECTED_WHEEL_FILES)),
        )
        cases["member-order"] = reordered

        with zipfile.ZipFile(self.direct_wheel) as archive:
            record = archive.read(EXPECTED_WHEEL_FILES[-1])
        lines = record.splitlines()
        record_reordered = b"\n".join((lines[1], lines[0], *lines[2:])) + b"\n"
        record_mutated = mutation_root / "record-reordered" / self.direct_wheel.name
        record_mutated.parent.mkdir()
        _rewrite_wheel_archive(self.direct_wheel, record_mutated, record_payload=record_reordered)
        cases["record-order"] = record_mutated

        for level in (1, 9):
            recompressed = mutation_root / f"deflate-{level}" / self.direct_wheel.name
            recompressed.parent.mkdir()
            _rewrite_wheel_archive(
                self.direct_wheel,
                recompressed,
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=level,
            )
            cases[f"deflate-{level}"] = recompressed

        for label, mutated in cases.items():
            with self.subTest(label=label):
                self.assertNotEqual(mutated.read_bytes(), self.direct_wheel.read_bytes())
                with self.assertRaisesRegex(RuntimeError, "canonical stored ZIP32"):
                    inspect_package_artifacts(
                        source_root=self.candidate,
                        direct_wheel=mutated,
                        sdist=self.sdist,
                        rebuilt_wheel=self.rebuilt_wheel,
                    )
                normalized = canonicalize_wheel(
                    mutated,
                    mutation_root / label / "canonical" / mutated.name,
                    source_root=self.candidate,
                )
                self.assertEqual(normalized.read_bytes(), self.direct_wheel.read_bytes())

    def test_backend_canary_and_secret_that_ship_are_rejected(self) -> None:
        mutation_root = self.root / "mutation"
        candidate = _candidate(mutation_root)
        package = candidate / "src" / "financial_planning_sdk_br"
        package.joinpath("unexpected_payload.py").write_bytes(b"CANARY = True\n")
        package.joinpath("secret.schema.json").write_bytes(b'{"secret":"must-not-ship"}\n')
        direct = mutation_root / "direct"
        raw = mutation_root / "raw"
        direct.mkdir()
        raw.mkdir()
        _run(
            [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", os.fspath(direct)],
            cwd=candidate,
        )
        _run(
            [sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", os.fspath(raw)],
            cwd=candidate,
        )
        wheel = next(direct.glob("*.whl"))
        raw_sdist = next(raw.glob("*.tar.gz"))
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
        with tarfile.open(raw_sdist, mode="r:gz") as archive:
            tar_names = {member.name for member in archive.getmembers()}
        self.assertIn("financial_planning_sdk_br/unexpected_payload.py", names)
        self.assertIn("financial_planning_sdk_br/secret.schema.json", names)
        self.assertIn(f"{SDIST_ROOT}/src/financial_planning_sdk_br/unexpected_payload.py", tar_names)
        self.assertIn(f"{SDIST_ROOT}/src/financial_planning_sdk_br/secret.schema.json", tar_names)
        with self.assertRaisesRegex(RuntimeError, "inventory"):
            canonicalize_sdist(raw_sdist, mutation_root / "canonical" / raw_sdist.name)
        with self.assertRaisesRegex(RuntimeError, "inventory"):
            inspect_package_artifacts(
                source_root=candidate,
                direct_wheel=wheel,
                sdist=self.sdist,
                rebuilt_wheel=self.rebuilt_wheel,
            )

    def test_zip_comment_extra_field_and_gzip_tail_are_rejected(self) -> None:
        mutation_root = self.root / "archive-channel"
        mutation_root.mkdir()
        commented = mutation_root / self.direct_wheel.name
        shutil.copy2(self.direct_wheel, commented)
        with zipfile.ZipFile(commented, mode="a") as archive:
            archive.comment = b"opaque-channel"
        with self.assertRaises(RuntimeError):
            inspect_package_artifacts(
                source_root=self.candidate,
                direct_wheel=commented,
                sdist=self.sdist,
                rebuilt_wheel=self.rebuilt_wheel,
            )

        extra = mutation_root / ("extra-" + self.direct_wheel.name)
        with zipfile.ZipFile(self.direct_wheel) as source, zipfile.ZipFile(extra, mode="w") as target:
            for index, info in enumerate(source.infolist()):
                copied = copy.copy(info)
                if index == 0:
                    copied.extra = b"\x99\x99\x00\x00"
                target.writestr(copied, source.read(info))
        with self.assertRaises(RuntimeError):
            inspect_package_artifacts(
                source_root=self.candidate,
                direct_wheel=extra,
                sdist=self.sdist,
                rebuilt_wheel=self.rebuilt_wheel,
            )

        tailed = mutation_root / ("tailed-" + self.sdist.name)
        tailed.write_bytes(self.sdist.read_bytes() + b"\x00")
        with self.assertRaisesRegex(RuntimeError, "trailing bytes"):
            inspect_package_artifacts(
                source_root=self.candidate,
                direct_wheel=self.direct_wheel,
                sdist=tailed,
                rebuilt_wheel=self.rebuilt_wheel,
            )

    def test_unknown_pax_record_is_rejected_before_canonicalization(self) -> None:
        mutation_root = self.root / "pax-channel"
        mutation_root.mkdir()
        tar_bytes = io.BytesIO()
        with (
            tarfile.open(self.sdist, mode="r:gz") as source,
            tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.PAX_FORMAT) as target,
        ):
            for index, member in enumerate(source.getmembers()):
                copied = copy.copy(member)
                copied.pax_headers = {"comment": "opaque"} if index == 0 else {}
                stream = source.extractfile(member) if member.isfile() else None
                target.addfile(copied, stream)
        gzip_bytes = io.BytesIO()
        with gzip.GzipFile(
            filename=f"{SDIST_ROOT}.tar",
            mode="wb",
            compresslevel=9,
            fileobj=gzip_bytes,
            mtime=0,
        ) as archive:
            archive.write(tar_bytes.getvalue())
        mutated = mutation_root / self.raw_sdist.name
        mutated.write_bytes(gzip_bytes.getvalue())
        with self.assertRaisesRegex(RuntimeError, "PAX"):
            canonicalize_sdist(mutated, mutation_root / "canonical" / mutated.name)

    def test_sdist_license_readme_and_pyproject_bytes_must_match_frozen_source(self) -> None:
        mutation_root = self.root / "source-binding"
        mutation_root.mkdir()
        cases = {
            f"{SDIST_ROOT}/LICENSE": b"substituted license\n",
            f"{SDIST_ROOT}/README.md": b"# substituted readme\n",
            f"{SDIST_ROOT}/pyproject.toml": self.candidate.joinpath("pyproject.toml").read_bytes() + b"\n",
        }
        for index, (name, payload) in enumerate(cases.items()):
            with self.subTest(name=name):
                mutated = mutation_root / f"mutated-{index}.tar.gz"
                _rewrite_sdist(self.sdist, mutated, {name: payload})
                with self.assertRaisesRegex(RuntimeError, r"LICENSE|README\.md|pyproject\.toml"):
                    inspect_package_artifacts(
                        source_root=self.candidate,
                        direct_wheel=self.direct_wheel,
                        sdist=mutated,
                        rebuilt_wheel=self.rebuilt_wheel,
                    )

    def test_unexpected_optional_dependency_metadata_is_rejected(self) -> None:
        mutation_root = self.root / "dependency-binding"
        mutation_root.mkdir()
        with zipfile.ZipFile(self.direct_wheel) as archive:
            metadata = archive.read("finplanbr-0.1.0.dev0.dist-info/METADATA")
        separator = b"\n\n"
        self.assertIn(separator, metadata)
        metadata = metadata.replace(
            separator,
            b'\nProvides-Extra: hidden\nRequires-Dist: requests==99; extra == "hidden"' + separator,
            1,
        )
        mutated = mutation_root / self.direct_wheel.name
        with self.assertRaisesRegex(RuntimeError, "dependency roster"):
            _rewrite_backend_wheel_payloads(
                self.direct_wheel,
                mutated,
                {f"{DIST_INFO}/METADATA": metadata},
                source_root=self.candidate,
            )

    def test_pyproject_build_urls_license_and_classifiers_are_closed_by_metadata_v5(self) -> None:
        self.assertEqual(METADATA_POLICY, "finplanbr-setuptools-84.0.0-metadata.v5")
        cases = (
            ("build-pin", "setuptools==84.0.0", "setuptools>=83"),
            (
                "issues-url",
                "https://github.com/arthur0211/financial-planning-sdk-br/issues",
                "https://example.invalid/issues",
            ),
            (
                "development-status",
                "Development Status :: 2 - Pre-Alpha",
                "Development Status :: 5 - Production/Stable",
            ),
            ("license-expression", 'license = "Apache-2.0"', 'license = "MIT"'),
        )
        for label, original, replacement in cases:
            with self.subTest(label=label):
                candidate = self.root / "metadata-v5" / label
                shutil.copytree(self.candidate, candidate)
                pyproject = candidate / "pyproject.toml"
                source = pyproject.read_text(encoding="utf-8")
                mutated = source.replace(original, replacement, 1)
                self.assertNotEqual(mutated, source)
                pyproject.write_text(mutated, encoding="utf-8", newline="\n")
                with self.assertRaisesRegex(RuntimeError, "packaging/dependency metadata"):
                    canonicalize_wheel(
                        self.direct_wheel,
                        self.root / "metadata-v5-output" / label / self.direct_wheel.name,
                        source_root=candidate,
                    )


if __name__ == "__main__":
    unittest.main()
