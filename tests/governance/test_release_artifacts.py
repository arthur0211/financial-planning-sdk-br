"""Adversarial Release01 archive and build probes using synthetic temporary packages."""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import importlib.util
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_validator", ROOT / "scripts" / "validate_release_artifacts.py")
assert SPEC and SPEC.loader
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


PROJECT = "financial-planning-sdk-br"
PACKAGE = "financial_planning_sdk_br"
VERSION = "0.1.0"


def metadata() -> bytes:
    return f"Metadata-Version: 2.1\nName: {PROJECT}\nVersion: {VERSION}\n\n".encode()


def artifact_blob(path: Path):
    return release.ArtifactBlob(path.name, path.read_bytes())


def wheel_payloads(
    *,
    tag: str = "py3-none-any",
    include_init: bool = True,
    executable: bool = False,
    data_backdoor: str | None = None,
    data_root: str | None = None,
    shadow_dist_info: bool = False,
    dist_info_extra: str | None = None,
    core_payload: bytes = b"VALUE = 1\n",
) -> dict[str, bytes]:
    dist_info = f"{PACKAGE}-{VERSION}.dist-info"
    payloads = {
        f"{PACKAGE}/core.py": core_payload,
        f"{dist_info}/METADATA": metadata(),
        f"{dist_info}/WHEEL": f"Wheel-Version: 1.0\nGenerator: synthetic-test\nRoot-Is-Purelib: true\nTag: {tag}\n\n".encode(),
    }
    if include_init:
        payloads[f"{PACKAGE}/__init__.py"] = b"from .core import VALUE\n"
    if executable:
        payloads[f"{PACKAGE}/malware.exe"] = b"MZ" + b"0" * 32
    if data_backdoor is not None:
        payloads[f"{data_root or f'{PACKAGE}-{VERSION}.data'}/{data_backdoor}/{PACKAGE}/backdoor.py"] = b"VALUE = 999\n"
    if shadow_dist_info:
        payloads[f"{PACKAGE}/shadow.dist-info/payload.py"] = b"VALUE = 31337\n"
    if dist_info_extra is not None:
        payloads[f"{dist_info}/{dist_info_extra}"] = b"[console_scripts]\nprobe = package:main\n"
    return payloads


def write_wheel(
    path: Path,
    *,
    tag: str = "py3-none-any",
    include_record: bool = True,
    include_init: bool = True,
    executable: bool = False,
    bomb: bool = False,
    data_backdoor: str | None = None,
    data_root: str | None = None,
    shadow_dist_info: bool = False,
    dist_info_extra: str | None = None,
    core_payload: bytes = b"VALUE = 1\n",
    record_extra_names: tuple[str, ...] = (),
    compression: int = zipfile.ZIP_DEFLATED,
    creator_system: int = 3,
    directory_payloads: dict[str, bytes] | None = None,
) -> None:
    payloads = wheel_payloads(
        tag=tag,
        include_init=include_init,
        executable=executable,
        data_backdoor=data_backdoor,
        data_root=data_root,
        shadow_dist_info=shadow_dist_info,
        dist_info_extra=dist_info_extra,
        core_payload=core_payload,
    )
    directories = dict(directory_payloads or {})
    if any(not name.endswith("/") for name in directories):
        raise AssertionError("synthetic directory members must use trailing-slash names")
    if set(payloads) & set(directories):
        raise AssertionError("synthetic file/directory names must be disjoint")
    if bomb:
        payloads[f"{PACKAGE}/bomb.txt"] = b"0" * (release.MAX_MEMBER_BYTES + 1)
    dist_info = f"{PACKAGE}-{VERSION}.dist-info"
    record_name = f"{dist_info}/RECORD"
    if include_record:
        rows = []
        for name, payload in (*payloads.items(), *directories.items()):
            digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
            rows.append([name, f"sha256={digest}", str(len(payload))])
        rows.extend([name, "", ""] for name in record_extra_names)
        rows.append([record_name, "", ""])
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(rows)
        payloads[record_name] = output.getvalue().encode()
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, payload in payloads.items():
            info = zipfile.ZipInfo(name)
            info.create_system = creator_system
            info.external_attr = 0o100644 << 16
            info.compress_type = compression
            archive.writestr(info, payload)
        for name, payload in directories.items():
            info = zipfile.ZipInfo(name)
            info.create_system = creator_system
            info.external_attr = (0o040755 << 16) | release.ZIP_DOS_DIRECTORY_ATTRIBUTE
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)


def raw_deflate(payload: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    return compressor.compress(payload) + compressor.flush()


def gzip_member(
    payload: bytes,
    *,
    extra: bytes | None = None,
    filename: bytes | None = None,
    comment: bytes | None = None,
    fhcrc: bool = False,
    corrupt_fhcrc: bool = False,
    reserved_flags: int = 0,
) -> bytes:
    flags = reserved_flags
    if extra is not None:
        flags |= release.GZIP_FLAG_FEXTRA
    if filename is not None:
        flags |= release.GZIP_FLAG_FNAME
    if comment is not None:
        flags |= release.GZIP_FLAG_FCOMMENT
    if fhcrc:
        flags |= release.GZIP_FLAG_FHCRC
    header = bytearray(struct.pack("<BBBBIBB", 0x1F, 0x8B, 8, flags, 0, 2, 255))
    if extra is not None:
        if len(extra) > 0xFFFF:
            raise AssertionError("synthetic gzip FEXTRA exceeds XLEN")
        header.extend(struct.pack("<H", len(extra)))
        header.extend(extra)
    if filename is not None:
        header.extend(filename)
        header.append(0)
    if comment is not None:
        header.extend(comment)
        header.append(0)
    if fhcrc:
        header_crc = zlib.crc32(header) & 0xFFFF
        if corrupt_fhcrc:
            header_crc ^= 1
        header.extend(struct.pack("<H", header_crc))
    trailer = struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload) & 0xFFFFFFFF)
    return bytes(header) + raw_deflate(payload) + trailer


def rewrite_last_zip_member(
    path: Path,
    member_name: str,
    *,
    compressed_suffix: bytes = b"",
    file_size_delta: int = 0,
    corrupt_crc: bool = False,
) -> bytes:
    """Mutate the final local member while keeping local/central metadata coherent."""

    original = path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(original)) as archive:
        info = archive.getinfo(member_name)
        decoded = archive.read(info)
    raw = bytearray(original)
    eocd_offset = len(raw) - release.ZIP_END_OF_CENTRAL_DIRECTORY.size
    eocd = release.ZIP_END_OF_CENTRAL_DIRECTORY.unpack_from(raw, eocd_offset)
    central_offset = eocd[6]
    local = release.ZIP_LOCAL_HEADER.unpack_from(raw, info.header_offset)
    data_start = info.header_offset + release.ZIP_LOCAL_HEADER.size + local[9] + local[10]
    data_end = data_start + local[7]
    if data_end != central_offset:
        raise AssertionError("test mutation requires the target to be the final local ZIP member")

    replacement = bytes(raw[data_start:data_end]) + compressed_suffix
    delta = len(replacement) - local[7]
    raw = raw[:data_start] + bytearray(replacement) + raw[data_end:]
    new_central_offset = central_offset + delta
    new_eocd_offset = eocd_offset + delta
    struct.pack_into("<I", raw, new_eocd_offset + 16, new_central_offset)

    declared_crc = local[6] ^ (1 if corrupt_crc else 0)
    declared_file_size = local[8] + file_size_delta
    struct.pack_into("<I", raw, info.header_offset + 14, declared_crc)
    struct.pack_into("<I", raw, info.header_offset + 18, len(replacement))
    struct.pack_into("<I", raw, info.header_offset + 22, declared_file_size)

    cursor = new_central_offset
    target_found = False
    while cursor < new_eocd_offset:
        central = release.ZIP_CENTRAL_HEADER.unpack_from(raw, cursor)
        if central[16] == info.header_offset:
            struct.pack_into("<I", raw, cursor + 16, declared_crc)
            struct.pack_into("<I", raw, cursor + 20, len(replacement))
            struct.pack_into("<I", raw, cursor + 24, declared_file_size)
            target_found = True
        cursor += release.ZIP_CENTRAL_HEADER.size + central[10] + central[11] + central[12]
    if cursor != new_eocd_offset or not target_found:
        raise AssertionError("test mutation could not reconcile the target central entry")
    path.write_bytes(raw)
    return decoded


def rewrite_zip_member_headers(
    path: Path,
    member_name: str,
    *,
    version_needed: int | None = None,
    version_made_by: int | None = None,
    internal_attributes: int | None = None,
    external_attributes: int | None = None,
) -> None:
    raw = bytearray(path.read_bytes())
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = archive.getinfo(member_name)
    if version_needed is not None:
        struct.pack_into("<H", raw, info.header_offset + 4, version_needed)

    eocd_offset = len(raw) - release.ZIP_END_OF_CENTRAL_DIRECTORY.size
    eocd = release.ZIP_END_OF_CENTRAL_DIRECTORY.unpack_from(raw, eocd_offset)
    cursor = eocd[6]
    target_found = False
    while cursor < eocd_offset:
        central = release.ZIP_CENTRAL_HEADER.unpack_from(raw, cursor)
        if central[16] == info.header_offset:
            if version_made_by is not None:
                struct.pack_into("<H", raw, cursor + 4, version_made_by)
            if version_needed is not None:
                struct.pack_into("<H", raw, cursor + 6, version_needed)
            if internal_attributes is not None:
                struct.pack_into("<H", raw, cursor + 36, internal_attributes)
            if external_attributes is not None:
                struct.pack_into("<I", raw, cursor + 38, external_attributes)
            target_found = True
        cursor += release.ZIP_CENTRAL_HEADER.size + central[10] + central[11] + central[12]
    if cursor != eocd_offset or not target_found:
        raise AssertionError("test mutation could not locate the target central entry")
    path.write_bytes(raw)


def pyproject_text(*, packages: str = f'["{PACKAGE}"]') -> str:
    return f"""[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "{PROJECT}"
version = "{VERSION}"

[tool.setuptools]
package-dir = {{"" = "src"}}
packages = {packages}
"""


def write_sdist(
    path: Path,
    *,
    embedded_pyproject: bytes | None = None,
    executable: bool = False,
    bomb: bool = False,
    traversal: bool = False,
    include_init: bool = True,
    setup_py: bool = False,
    extra_files: dict[str, bytes] | None = None,
    extra_directories: tuple[str, ...] = (),
) -> None:
    top = f"{PACKAGE}-{VERSION}"
    payloads = {
        f"{top}/PKG-INFO": metadata(),
        f"{top}/pyproject.toml": embedded_pyproject if embedded_pyproject is not None else pyproject_text().encode(),
        f"{top}/src/{PACKAGE}/core.py": b"VALUE = 1\n",
    }
    if include_init:
        payloads[f"{top}/src/{PACKAGE}/__init__.py"] = b"from .core import VALUE\n"
    if executable:
        payloads[f"{top}/malware.exe"] = b"MZ" + b"0" * 32
    if bomb:
        payloads[f"{top}/bomb.txt"] = b"0" * (release.MAX_MEMBER_BYTES + 1)
    if traversal:
        payloads[f"{top}/../escape.py"] = b"VALUE = 3\n"
    if setup_py:
        payloads[f"{top}/setup.py"] = b"raise SystemExit('unmodeled build script')\n"
    payloads.update(extra_files or {})
    with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT, encoding="utf-8", errors="strict") as archive:
        for name, payload in payloads.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
        for name in extra_directories:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)


class ReleaseArtifactAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="finplanbr-release-")
        self.root = Path(self.temp.name)
        (self.root / "src" / PACKAGE).mkdir(parents=True)
        (self.root / "src" / PACKAGE / "__init__.py").write_bytes(b"from .core import VALUE\n")
        (self.root / "src" / PACKAGE / "core.py").write_bytes(b"VALUE = 1\n")
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_core.py").write_text(f"import {PACKAGE}\n\ndef test_value():\n    assert {PACKAGE}.VALUE == 1\n", encoding="utf-8")
        (self.root / "pyproject.toml").write_text(pyproject_text(), encoding="utf-8")
        (self.root / "dist").mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def inspect_wheel(self, name: str | None = None, **kwargs) -> list[str]:
        wheel = self.root / "dist" / (name or f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        write_wheel(wheel, **kwargs)
        failures: list[str] = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        return failures

    def inspect_sdist(self, name: str | None = None, **kwargs) -> list[str]:
        sdist = self.root / "dist" / (name or f"{PACKAGE}-{VERSION}.tar.gz")
        write_sdist(sdist, **kwargs)
        failures: list[str] = []
        release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, failures)
        return failures

    def run_main(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "validate_release_artifacts.py"),
                "--root",
                str(self.root),
                *arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def assert_full_main_fails_closed(self, marker: str) -> dict[str, object]:
        completed = self.run_main()
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["diagnostic_status"], "static_checks_failed")
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")
        self.assertEqual(payload["build_equivalence"], "not_evaluated")
        self.assertEqual(payload["authority_integration"], "absent")
        self.assertFalse(payload["authority_decision_attempted"])
        self.assertFalse(payload["release_authorized"])
        self.assertFalse(payload["candidate_code_executed"])
        self.assertTrue(any(marker in failure for failure in payload["failures"]), payload)
        return payload

    def test_valid_synthetic_archives_pass_structural_inspection(self) -> None:
        self.assertEqual(self.inspect_wheel(), [])
        self.assertEqual(self.inspect_sdist(), [])
        completed = self.run_main()
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(
            set(payload),
            {
                "archive_member_policy",
                "artifacts",
                "authority_decision_attempted",
                "authority_integration",
                "build_equivalence",
                "candidate_code_executed",
                "diagnostic_status",
                "format",
                "package_tests",
                "packages",
                "project",
                "python_source_payload_parity",
                "release_authorized",
                "source_artifact_parity",
                "version",
            },
        )
        self.assertEqual(payload["format"], "candidate-release-static-diagnostic.v3")
        self.assertEqual(payload["diagnostic_status"], "static_checks_passed")
        self.assertEqual(payload["archive_member_policy"], "closed_minimal_python_payload")
        self.assertEqual(payload["python_source_payload_parity"], "observed_on_revalidated_non_atomic_local_snapshots")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")
        self.assertEqual(payload["build_equivalence"], "not_evaluated")
        self.assertEqual(payload["authority_integration"], "absent")
        self.assertFalse(payload["authority_decision_attempted"])
        self.assertFalse(payload["release_authorized"])
        self.assertFalse(payload["candidate_code_executed"])
        self.assertEqual(payload["project"], PROJECT)
        self.assertEqual(payload["version"], VERSION)
        self.assertEqual(payload["packages"], [PACKAGE])
        self.assertEqual(payload["package_tests"], 1)
        self.assertEqual(len(payload["artifacts"]), 2)
        self.assertNotIn("status", payload)
        self.assertNotIn("claim", payload)

        source = (ROOT / "scripts" / "validate_release_artifacts.py").read_text(encoding="utf-8")
        for forbidden in (
            "--external-attestation-sha256",
            "attestation",
            "content_equivalent",
            "release-static-result",
            '"status": "passed"',
            '"claim"',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

        legacy = self.run_main("--external-attestation-sha256", "1" * 64)
        self.assertEqual(legacy.returncode, 2, legacy.stdout + legacy.stderr)
        self.assertEqual(legacy.stdout, "")
        self.assertIn("unrecognized arguments", legacy.stderr)

    def test_declared_namespace_package_does_not_require_init(self) -> None:
        (self.root / "src" / PACKAGE / "__init__.py").unlink()
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        write_wheel(wheel, include_init=False)
        write_sdist(sdist, include_init=False)
        failures: list[str] = []
        rows = release.source_inventory(self.root / "src", self.root, failures)
        wheel_blob = artifact_blob(wheel)
        sdist_blob = artifact_blob(sdist)
        release.inspect_wheel(wheel_blob, PROJECT, VERSION, {PACKAGE}, failures)
        release.inspect_sdist(sdist_blob, PROJECT, VERSION, {PACKAGE}, failures)
        release.verify_source_artifact_parity(rows, wheel_blob, sdist_blob, PROJECT, VERSION, failures)
        self.assertEqual(failures, [])

    def test_wheel_requires_record_and_package_init(self) -> None:
        failures = self.inspect_wheel(include_record=False, include_init=False)
        self.assertTrue(any("RECORD" in failure for failure in failures), failures)

    def test_wheel_rejects_filename_metadata_and_platform_tag_mismatch(self) -> None:
        failures = self.inspect_wheel(name="other-9.9.9-py3-none-win_amd64.whl", tag="py3-none-any")
        self.assertTrue(any("filename project/version" in failure for failure in failures), failures)
        self.assertTrue(any("Tag headers" in failure for failure in failures), failures)
        self.assertTrue(any("Root-Is-Purelib" in failure for failure in failures), failures)

    def test_wheel_rejects_record_corruption(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        with zipfile.ZipFile(wheel, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{PACKAGE}/extra.py", b"VALUE = 2\n")
        failures: list[str] = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("RECORD inventory" in failure for failure in failures), failures)

    def test_archives_reject_member_path_traversal(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        with zipfile.ZipFile(wheel, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("../escape.py", b"VALUE = 3\n")
        wheel_failures: list[str] = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, wheel_failures)
        self.assertTrue(any("unsafe member paths" in failure for failure in wheel_failures), wheel_failures)
        sdist_failures = self.inspect_sdist(traversal=True)
        self.assertTrue(any("unsafe member paths" in failure for failure in sdist_failures), sdist_failures)

    def test_main_rejects_wheel_file_directory_same_path_collision(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        with zipfile.ZipFile(wheel, "a") as archive:
            info = zipfile.ZipInfo(f"{PACKAGE}/core.py/")
            info.create_system = 3
            info.external_attr = (0o40755 << 16) | release.ZIP_DOS_DIRECTORY_ATTRIBUTE
            archive.writestr(info, b"")
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        result = self.run_main()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(any("file/directory same-path collision" in failure for failure in payload["failures"]), payload)
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertFalse(payload["release_authorized"])

    def test_main_rejects_sdist_file_directory_same_path_collision(self) -> None:
        write_wheel(self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        top = f"{PACKAGE}-{VERSION}"
        write_sdist(
            self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz",
            extra_directories=(f"{top}/src/{PACKAGE}/core.py/",),
        )
        result = self.run_main()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(any("file/directory same-path collision" in failure for failure in payload["failures"]), payload)
        self.assertEqual(payload["archive_member_policy"], "closed_minimal_python_payload")
        self.assertFalse(payload["release_authorized"])

    def test_zip_and_tar_reject_case_and_unicode_normalized_name_collisions(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        for first, second in (
            (f"{PACKAGE}/core.py", f"{PACKAGE}/CORE.py"),
            (f"{PACKAGE}/caf\u00e9.py", f"{PACKAGE}/cafe\u0301.py"),
        ):
            with self.subTest(archive="zip", second=second):
                write_wheel(wheel)
                with zipfile.ZipFile(wheel, "a", compression=zipfile.ZIP_DEFLATED) as archive:
                    if first != f"{PACKAGE}/core.py":
                        archive.writestr(first, b"VALUE = 1\n")
                    archive.writestr(second, b"VALUE = 2\n")
                failures: list[str] = []
                release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
                self.assertTrue(any("normalized path collision" in failure for failure in failures), failures)

        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        top = f"{PACKAGE}-{VERSION}"
        for first, second in (
            (f"{top}/src/{PACKAGE}/core.py", f"{top}/src/{PACKAGE}/CORE.py"),
            (f"{top}/src/{PACKAGE}/caf\u00e9.py", f"{top}/src/{PACKAGE}/cafe\u0301.py"),
        ):
            with self.subTest(archive="tar", second=second):
                extras = {second: b"VALUE = 2\n"}
                if first != f"{top}/src/{PACKAGE}/core.py":
                    extras[first] = b"VALUE = 1\n"
                write_sdist(sdist, extra_files=extras)
                failures = []
                release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, failures)
                self.assertTrue(any("normalized path collision" in failure for failure in failures), failures)

    def test_zip_and_tar_reject_file_ancestor_paths(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        with zipfile.ZipFile(wheel, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{PACKAGE}/core.py/payload.py", b"VALUE = 2\n")
        wheel_failures: list[str] = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, wheel_failures)
        self.assertTrue(any("is an ancestor" in failure for failure in wheel_failures), wheel_failures)

        top = f"{PACKAGE}-{VERSION}"
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        write_sdist(
            sdist,
            extra_files={f"{top}/src/{PACKAGE}/core.py/payload.py": b"VALUE = 2\n"},
        )
        sdist_failures: list[str] = []
        release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, sdist_failures)
        self.assertTrue(any("is an ancestor" in failure for failure in sdist_failures), sdist_failures)

    def test_record_rejects_normalized_and_file_directory_collisions(self) -> None:
        for extra_name, expected in (
            (f"{PACKAGE}/CORE.py", "normalized path collision"),
            (f"{PACKAGE}/core.py/", "file/directory same-path collision"),
        ):
            with self.subTest(extra_name=extra_name):
                failures = self.inspect_wheel(record_extra_names=(extra_name,))
                self.assertTrue(any("RECORD" in failure and expected in failure for failure in failures), failures)

    def test_sdist_requires_valid_embedded_toml_and_nonempty_packages(self) -> None:
        failures = self.inspect_sdist(embedded_pyproject=b"this is not TOML [")
        self.assertTrue(any("invalid TOML" in failure for failure in failures), failures)
        failures = self.inspect_sdist(embedded_pyproject=pyproject_text(packages="[]").encode())
        self.assertTrue(any("packages declaration cannot be empty" in failure for failure in failures), failures)
        failures = self.inspect_sdist(name="other-9.9.9.tar.gz")
        self.assertTrue(any("filename project/version" in failure for failure in failures), failures)

    def test_archives_reject_zip_bomb_and_executables(self) -> None:
        wheel_failures = self.inspect_wheel(bomb=True)
        self.assertTrue(any("size budget" in failure or "compression-ratio" in failure for failure in wheel_failures), wheel_failures)
        wheel_failures = self.inspect_wheel(executable=True)
        self.assertTrue(any("executable payload" in failure for failure in wheel_failures), wheel_failures)
        sdist_failures = self.inspect_sdist(bomb=True)
        self.assertTrue(any("size budget" in failure or "compression-ratio" in failure for failure in sdist_failures), sdist_failures)
        sdist_failures = self.inspect_sdist(executable=True)
        self.assertTrue(any("executable payload" in failure for failure in sdist_failures), sdist_failures)

    def test_main_rejects_closed_inventory_extras_and_nested_archives(self) -> None:
        write_wheel(self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        (self.root / "dist" / "extra.txt").write_text("extra", encoding="utf-8")
        nested = self.root / "dist" / "nested"
        nested.mkdir()
        (nested / "invalid.whl").write_text("not a wheel", encoding="utf-8")
        result = self.run_main()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nested directories", result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(
            set(payload),
            {
                "archive_member_policy",
                "authority_decision_attempted",
                "authority_integration",
                "build_equivalence",
                "candidate_code_executed",
                "diagnostic_status",
                "failures",
                "format",
                "python_source_payload_parity",
                "release_authorized",
                "source_artifact_parity",
            },
        )
        self.assertEqual(payload["format"], "candidate-release-static-diagnostic.v3")
        self.assertEqual(payload["diagnostic_status"], "static_checks_failed")
        self.assertEqual(payload["archive_member_policy"], "closed_minimal_python_payload")
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")
        self.assertEqual(payload["build_equivalence"], "not_evaluated")
        self.assertEqual(payload["authority_integration"], "absent")
        self.assertFalse(payload["authority_decision_attempted"])
        self.assertFalse(payload["release_authorized"])
        self.assertFalse(payload["candidate_code_executed"])
        for path in nested.iterdir():
            path.unlink()
        nested.rmdir()
        result = self.run_main()
        self.assertIn("unexpected extra artifact", result.stdout)

    def test_root_pyproject_rejects_empty_packages_without_importing_source(self) -> None:
        (self.root / "pyproject.toml").write_text(pyproject_text(packages="[]"), encoding="utf-8")
        marker = self.root / "imported.txt"
        (self.root / "src" / PACKAGE / "__init__.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n", encoding="utf-8")
        result = self.run_main()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("packages declaration cannot be empty", result.stdout)
        self.assertFalse(marker.exists(), "static inspection executed source import side effects")

    def test_static_inspection_never_runs_build_import_or_network_side_effects(self) -> None:
        marker = self.root / "candidate-side-effect.txt"
        (self.root / "build.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n", encoding="utf-8")
        (self.root / "src" / PACKAGE / "__init__.py").write_text("import socket\nsocket.create_connection(('example.invalid', 443))\n", encoding="utf-8")
        write_wheel(self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        result = self.run_main()
        self.assertFalse(marker.exists(), result.stdout + result.stderr)
        self.assertNotIn("create_connection", result.stderr)

    def test_wheel_rejects_unix_symlink_member_type(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        with zipfile.ZipFile(wheel, "a") as archive:
            info = zipfile.ZipInfo(f"{PACKAGE}/link.py")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, b"core.py")
        failures: list[str] = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("Unix regular-file type" in failure for failure in failures), failures)

    def test_dist_hardlink_is_rejected(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        hardlink = self.root / "wheel-copy.whl"
        try:
            os.link(wheel, hardlink)
        except OSError as exc:
            self.skipTest(f"hardlinks unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "nlink=1"):
            release.snapshot_dist(self.root / "dist", self.root)

    def test_source_wheel_sdist_parity_is_exact(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        write_wheel(wheel)
        write_sdist(sdist)
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr(f"{PACKAGE}/core.py", b"VALUE = 999\n")
        failures: list[str] = []
        rows = release.source_inventory(self.root / "src", self.root, failures)
        release.verify_source_artifact_parity(rows, artifact_blob(wheel), artifact_blob(sdist), PROJECT, VERSION, failures)
        self.assertTrue(any("source/wheel parity mismatch" in failure for failure in failures), failures)

    def test_wheel_data_purelib_and_platlib_cannot_hide_backdoors(self) -> None:
        for scheme in ("purelib", "platlib"):
            with self.subTest(scheme=scheme):
                wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
                sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
                write_wheel(wheel, data_backdoor=scheme)
                write_sdist(sdist)
                failures: list[str] = []
                rows = release.source_inventory(self.root / "src", self.root, failures)
                release.verify_source_artifact_parity(rows, artifact_blob(wheel), artifact_blob(sdist), PROJECT, VERSION, failures)
                self.assertTrue(any("source/wheel parity mismatch" in failure for failure in failures), failures)

        failures = self.inspect_wheel(data_backdoor="purelib", data_root="shadow.data")
        self.assertTrue(any("non-canonical or unmodeled .data" in failure for failure in failures), failures)

    def test_main_rejects_record_covered_nested_shadow_dist_info(self) -> None:
        write_wheel(
            self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl",
            shadow_dist_info=True,
        )
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        result = self.run_main()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["diagnostic_status"], "static_checks_failed")
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")
        self.assertTrue(
            any("non-canonical .dist-info" in failure for failure in payload["failures"]),
            payload,
        )
        self.assertEqual(payload["build_equivalence"], "not_evaluated")
        self.assertEqual(payload["authority_integration"], "absent")
        self.assertFalse(payload["release_authorized"])

    def test_main_rechecks_pyproject_and_source_snapshots(self) -> None:
        write_wheel(self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        original = release.verify_source_artifact_parity

        def mutate_after_parity(*args, **kwargs) -> None:
            original(*args, **kwargs)
            (self.root / "pyproject.toml").write_text(pyproject_text() + "\n# late drift\n", encoding="utf-8")
            (self.root / "src" / PACKAGE / "core.py").write_bytes(b"VALUE = 999\n")

        output = io.StringIO()
        with mock.patch.object(release, "verify_source_artifact_parity", side_effect=mutate_after_parity):
            with mock.patch.object(sys, "argv", ["validator", "--root", str(self.root)]):
                with mock.patch.object(sys, "stdout", output):
                    self.assertEqual(release.main(), 1)
        payload = json.loads(output.getvalue())
        self.assertTrue(any("pyproject.toml: final byte snapshot drift" in failure for failure in payload["failures"]), payload)
        self.assertTrue(any("src: final closed byte inventory drift" in failure for failure in payload["failures"]), payload)
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")

    def test_main_rechecks_test_bytes_before_reporting_package_test_count(self) -> None:
        write_wheel(self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        original = release.verify_source_artifact_parity

        def mutate_test_after_parity(*args, **kwargs) -> None:
            original(*args, **kwargs)
            (self.root / "tests" / "test_core.py").write_bytes(b"# no behavioral test remains\n")

        output = io.StringIO()
        with mock.patch.object(release, "verify_source_artifact_parity", side_effect=mutate_test_after_parity):
            with mock.patch.object(sys, "argv", ["validator", "--root", str(self.root)]):
                with mock.patch.object(sys, "stdout", output):
                    self.assertEqual(release.main(), 1)
        payload = json.loads(output.getvalue())
        self.assertTrue(any("tests: final closed byte inventory drift" in failure for failure in payload["failures"]), payload)
        self.assertNotIn("package_tests", payload)
        self.assertEqual(payload["python_source_payload_parity"], "not_established")

    def test_main_uses_same_immutable_wheel_blob_for_hash_inspection_and_parity(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel, core_payload=b"VALUE = 999\n")
        wheel_a = wheel.read_bytes()
        alternate = self.root / "matching.whl"
        write_wheel(alternate)
        wheel_b = alternate.read_bytes()
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        original_inspect = release.inspect_wheel
        original_parity = release.verify_source_artifact_parity
        observed: dict[str, object] = {}

        def inspect_then_swap(candidate, *args, **kwargs) -> None:
            observed["inspection"] = candidate
            original_inspect(candidate, *args, **kwargs)
            if isinstance(candidate, Path):  # This branch reproduces the vulnerable R16 path flow.
                candidate.write_bytes(wheel_b)
            else:
                wheel.write_bytes(wheel_b)

        def parity_then_restore(source_rows, candidate, *args, **kwargs) -> None:
            observed["parity"] = candidate
            try:
                original_parity(source_rows, candidate, *args, **kwargs)
            finally:
                if isinstance(candidate, Path):
                    candidate.write_bytes(wheel_a)
                wheel.write_bytes(wheel_a)

        output = io.StringIO()
        with mock.patch.object(release, "inspect_wheel", side_effect=inspect_then_swap):
            with mock.patch.object(release, "verify_source_artifact_parity", side_effect=parity_then_restore):
                with mock.patch.object(sys, "argv", ["validator", "--root", str(self.root)]):
                    with mock.patch.object(sys, "stdout", output):
                        self.assertEqual(release.main(), 1)
        payload = json.loads(output.getvalue())
        self.assertIsInstance(observed["inspection"], release.ArtifactBlob)
        self.assertIs(observed["inspection"], observed["parity"])
        self.assertEqual(observed["inspection"].payload, wheel_a)
        self.assertEqual(observed["inspection"].sha256, hashlib.sha256(wheel_a).hexdigest())
        self.assertTrue(any("source/wheel parity mismatch" in failure for failure in payload["failures"]), payload)
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertFalse(payload["release_authorized"])

    def test_artifact_blob_is_c_level_immutable_and_mutation_attempt_fails_closed(self) -> None:
        blob = release.ArtifactBlob("probe.whl", b"original")
        for attribute in ("payload", "_payload", "sha256", "_sha256"):
            with self.subTest(attribute=attribute):
                with self.assertRaises((AttributeError, TypeError)):
                    object.__setattr__(blob, attribute, b"mutated")
        self.assertEqual(blob.payload, b"original")
        self.assertEqual(blob.sha256, hashlib.sha256(b"original").hexdigest())

        write_wheel(self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")

        def attempt_mutation(candidate, *args, **kwargs) -> None:
            object.__setattr__(candidate, "_payload", b"substituted")

        output = io.StringIO()
        with mock.patch.object(release, "inspect_wheel", side_effect=attempt_mutation):
            with mock.patch.object(sys, "argv", ["validator", "--root", str(self.root)]):
                with mock.patch.object(sys, "stdout", output):
                    self.assertEqual(release.main(), 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")
        self.assertFalse(payload["release_authorized"])
        self.assertTrue(any("inspection aborted fail-closed" in failure for failure in payload["failures"]), payload)

    def test_zip_tar_and_record_share_strict_win32_path_policy(self) -> None:
        top = f"{PACKAGE}-{VERSION}"
        unsafe_components = (
            "cafe\u0301.py",
            "control\x1f.py",
            "less<than.py",
            "quote\".py",
            "pipe|.py",
            "question?.py",
            "star*.py",
            "trailing.",
            "trailing ",
            "CON.py",
            "aux.txt",
            "COM1.module",
            "LPT9",
            "stream.py:payload",
        )
        for component in unsafe_components:
            archive_name = f"{PACKAGE}/{component}"
            with self.subTest(policy="direct", component=component):
                self.assertFalse(release.safe_archive_name(archive_name))
            with self.subTest(policy="zip", component=component):
                wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
                write_wheel(wheel)
                with zipfile.ZipFile(wheel, "a") as archive:
                    archive.writestr(archive_name, b"VALUE = 2\n")
                failures: list[str] = []
                release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
                self.assertTrue(any("unsafe member paths" in failure for failure in failures), failures)
            with self.subTest(policy="tar", component=component):
                failures = self.inspect_sdist(extra_files={f"{top}/src/{archive_name}": b"VALUE = 2\n"})
                self.assertTrue(any("unsafe member paths" in failure for failure in failures), failures)
            with self.subTest(policy="record", component=component):
                failures = self.inspect_wheel(record_extra_names=(archive_name,))
                self.assertTrue(any("RECORD" in failure and "unsafe" in failure for failure in failures), failures)
        completed = self.run_main()
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")
        self.assertFalse(payload["release_authorized"])

    def test_archives_reject_empty_explicit_directories(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr(f"{PACKAGE}/empty/", b"")
        failures: list[str] = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("empty explicit directory" in failure for failure in failures), failures)

        top = f"{PACKAGE}-{VERSION}"
        failures = self.inspect_sdist(extra_directories=(f"{top}/src/{PACKAGE}/empty",))
        self.assertTrue(any("empty explicit directory" in failure for failure in failures), failures)

    def test_archives_reject_unmodeled_nonempty_explicit_directories(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr("foreign/", b"")
            archive.writestr("foreign/payload.py", b"VALUE = 2\n")
        failures: list[str] = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("unmodeled explicit directories" in failure for failure in failures), failures)

        top = f"{PACKAGE}-{VERSION}"
        failures = self.inspect_sdist(
            extra_directories=(f"{top}/src/foreign",),
            extra_files={f"{top}/src/foreign/payload.py": b"VALUE = 2\n"},
        )
        self.assertTrue(any("unmodeled explicit directories" in failure for failure in failures), failures)

    def test_raw_zip_accepts_valid_stored_and_deflated_controls(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(compression=compression):
                write_wheel(wheel, compression=compression)
                failures: list[str] = []
                release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
                self.assertEqual(failures, [])
        write_wheel(wheel, compression=zipfile.ZIP_STORED)
        rewrite_zip_member_headers(wheel, f"{PACKAGE}/core.py", version_needed=10)
        failures = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertEqual(failures, [])

    def test_raw_zip_accepts_modeled_dos_and_unix_directory_controls(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        directory_name = f"{PACKAGE}/"
        for creator_system in (0, 3):
            with self.subTest(creator_system=creator_system):
                write_wheel(
                    wheel,
                    creator_system=creator_system,
                    directory_payloads={directory_name: b""},
                )
                write_sdist(sdist)
                failures: list[str] = []
                release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
                self.assertEqual(failures, [])
                completed = self.run_main()
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_raw_zip_rejects_hidden_directory_payload_full_main(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        directory_name = f"{PACKAGE}/"
        hidden_payload = b"R20 hidden directory payload"
        write_wheel(wheel, directory_payloads={directory_name: hidden_payload})
        write_sdist(sdist)
        self.assertTrue(zipfile.is_zipfile(wheel))
        with zipfile.ZipFile(wheel) as archive:
            info = archive.getinfo(directory_name)
            self.assertTrue(info.is_dir())
            self.assertEqual(archive.read(info), hidden_payload)
        self.assert_full_main_fails_closed("directory member")

    def test_raw_zip_rejects_r20_versions_and_attributes_full_main(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        target = f"{PACKAGE}/core.py"
        cases = (
            ("zero-version-needed", {"version_needed": 0}, "version-needed"),
            ("deflate-version-10", {"version_needed": 10}, "version-needed"),
            ("unsupported-creator-host", {"version_made_by": (42 << 8) | 20}, "version-made-by host"),
            ("internal-attributes", {"internal_attributes": 1}, "internal attributes"),
            (
                "dos-directory-attribute-on-file",
                {"external_attributes": (0o100644 << 16) | release.ZIP_DOS_DIRECTORY_ATTRIBUTE},
                "incoherent DOS attributes",
            ),
        )
        for case, mutation, marker in cases:
            with self.subTest(case=case):
                write_wheel(wheel)
                rewrite_zip_member_headers(wheel, target, **mutation)
                write_sdist(sdist)
                self.assertTrue(zipfile.is_zipfile(wheel))
                self.assert_full_main_fails_closed(marker)

    def test_raw_zip_rejects_invalid_crc_and_declared_size(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        record_name = f"{PACKAGE}-{VERSION}.dist-info/RECORD"
        cases = (
            ("stored-crc", zipfile.ZIP_STORED, {"corrupt_crc": True}, "CRC32"),
            ("deflated-crc", zipfile.ZIP_DEFLATED, {"corrupt_crc": True}, "CRC32"),
            ("stored-size", zipfile.ZIP_STORED, {"file_size_delta": 1}, "size"),
            ("deflated-size", zipfile.ZIP_DEFLATED, {"file_size_delta": 1}, "size"),
        )
        for case, compression, mutation, marker in cases:
            with self.subTest(case=case):
                write_wheel(wheel, compression=compression)
                rewrite_last_zip_member(wheel, record_name, **mutation)
                failures: list[str] = []
                release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
                self.assertTrue(
                    any("raw ZIP layout rejected" in failure and marker in failure for failure in failures),
                    failures,
                )

    def test_raw_zip_reconciles_decoded_bytes_before_record(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        original_read = zipfile.ZipFile.read

        def divergent_read(archive, member, pwd=None):
            decoded = original_read(archive, member, pwd=pwd)
            if isinstance(member, zipfile.ZipInfo) and member.filename == f"{PACKAGE}/core.py":
                return decoded + b"# divergent zipfile view\n"
            return decoded

        failures: list[str] = []
        with mock.patch.object(release.zipfile.ZipFile, "read", new=divergent_read):
            with mock.patch.object(release, "verify_record") as verify_record:
                release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        verify_record.assert_not_called()
        self.assertTrue(any("raw/zipfile decoded bytes disagree" in failure for failure in failures), failures)

    def test_raw_zip_rejects_r18_hidden_stored_tail_and_concatenated_deflate_full_main(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        record_name = f"{PACKAGE}-{VERSION}.dist-info/RECORD"
        cases = (
            ("stored-hidden-tail", zipfile.ZIP_STORED, b"hidden-stored-tail", "stored member"),
            (
                "concatenated-raw-deflate",
                zipfile.ZIP_DEFLATED,
                raw_deflate(b"hidden-second-stream"),
                "trailing or concatenated raw DEFLATE streams",
            ),
        )
        for case, compression, suffix, marker in cases:
            with self.subTest(case=case):
                write_wheel(wheel, compression=compression)
                expected = rewrite_last_zip_member(wheel, record_name, compressed_suffix=suffix)
                write_sdist(sdist)
                self.assertTrue(zipfile.is_zipfile(wheel))
                with zipfile.ZipFile(wheel) as archive:
                    self.assertEqual(archive.read(record_name), expected)

                completed = self.run_main()
                self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
                payload = json.loads(completed.stdout)
                self.assertEqual(payload["diagnostic_status"], "static_checks_failed")
                self.assertEqual(payload["python_source_payload_parity"], "not_established")
                self.assertEqual(payload["source_artifact_parity"], "not_evaluated")
                self.assertFalse(payload["release_authorized"])
                self.assertTrue(any(marker in failure for failure in payload["failures"]), payload)

    def test_raw_zip_rejects_prefix_orphan_and_full_main_fails_closed(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        write_wheel(wheel)
        orphan_name = b"orphan.py"
        orphan = struct.pack(
            "<4s5H3I2H",
            b"PK\x03\x04",
            20,
            0,
            zipfile.ZIP_STORED,
            0,
            0,
            0,
            0,
            0,
            len(orphan_name),
            0,
        ) + orphan_name
        wheel.write_bytes(orphan + wheel.read_bytes())
        self.assertTrue(zipfile.is_zipfile(wheel), "stdlib should reproduce the ignored-prefix ambiguity")
        failures: list[str] = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("raw ZIP layout rejected" in failure for failure in failures), failures)

        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        completed = self.run_main()
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")
        self.assertFalse(payload["release_authorized"])

    def test_raw_zip_rejects_trailing_records_descriptors_extras_comments_and_zip64(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"

        write_wheel(wheel)
        wheel.write_bytes(wheel.read_bytes() + b"trailing-record")
        failures: list[str] = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("final 22-byte record" in failure for failure in failures), failures)

        write_wheel(wheel)
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.comment = b"forbidden"
        failures = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("final 22-byte record" in failure for failure in failures), failures)

        write_wheel(wheel)
        with zipfile.ZipFile(wheel, "a") as archive:
            info = zipfile.ZipInfo(f"{PACKAGE}/extra-field.py")
            info.extra = b"\x99\x99\x00\x00"
            archive.writestr(info, b"")
        failures = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("forbidden extra field" in failure for failure in failures), failures)

        write_wheel(wheel)
        raw = bytearray(wheel.read_bytes())
        local_offset = raw.index(b"PK\x03\x04")
        central_offset = raw.index(b"PK\x01\x02")
        struct.pack_into("<H", raw, local_offset + 6, struct.unpack_from("<H", raw, local_offset + 6)[0] | 0x0008)
        struct.pack_into("<H", raw, central_offset + 8, struct.unpack_from("<H", raw, central_offset + 8)[0] | 0x0008)
        wheel.write_bytes(raw)
        failures = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("data descriptor" in failure for failure in failures), failures)

        write_wheel(wheel)
        raw = bytearray(wheel.read_bytes())
        eocd_offset = len(raw) - 22
        struct.pack_into("<H", raw, eocd_offset + 10, 0xFFFF)
        wheel.write_bytes(raw)
        failures = []
        release.inspect_wheel(artifact_blob(wheel), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("ZIP64" in failure for failure in failures), failures)

    def test_raw_gzip_rejects_concatenated_tar_and_full_main_fails_closed(self) -> None:
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        write_sdist(sdist)
        first_member = sdist.read_bytes()
        second = self.root / "second.tar.gz"
        write_sdist(second, extra_files={f"{PACKAGE}-{VERSION}/src/{PACKAGE}/second.py": b"VALUE = 2\n"})
        sdist.write_bytes(first_member + second.read_bytes())
        failures: list[str] = []
        release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("concatenated gzip members" in failure for failure in failures), failures)

        write_wheel(self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        completed = self.run_main()
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")
        self.assertFalse(payload["release_authorized"])

    def test_raw_gzip_accepts_bounded_optional_header_control(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        write_wheel(wheel)
        write_sdist(sdist)
        tar_payload = gzip.decompress(sdist.read_bytes())
        extra = b"AB" + struct.pack("<H", 3) + b"r20"
        sdist.write_bytes(
            gzip_member(
                tar_payload,
                extra=extra,
                filename=b"financial_planning_sdk_br-0.1.0.tar",
                comment=b"synthetic R20 control",
                fhcrc=True,
            )
        )
        failures: list[str] = []
        release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertEqual(failures, [])
        completed = self.run_main()
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_raw_gzip_rejects_unsafe_optional_headers_full_main(self) -> None:
        wheel = self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl"
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        write_wheel(wheel)
        write_sdist(sdist)
        tar_payload = gzip.decompress(sdist.read_bytes())
        cases = (
            ("reserved-flag", {"reserved_flags": 0x20}, "reserved flags"),
            ("malformed-fextra", {"extra": b"AB\x05\x00x"}, "FEXTRA subfield"),
            ("path-bearing-fname", {"filename": b"../unsafe.tar"}, "FNAME"),
            ("control-fcomment", {"comment": b"unsafe\x1fcomment"}, "FCOMMENT"),
            ("invalid-fhcrc", {"fhcrc": True, "corrupt_fhcrc": True}, "FHCRC"),
        )
        for case, options, marker in cases:
            with self.subTest(case=case):
                sdist.write_bytes(gzip_member(tar_payload, **options))
                failures: list[str] = []
                release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, failures)
                self.assertTrue(any(marker in failure for failure in failures), failures)
                self.assert_full_main_fails_closed(marker)

    def test_raw_tar_rejects_members_after_eof_and_gzip_trailing_nonzero(self) -> None:
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        write_sdist(sdist)
        first_member = sdist.read_bytes()
        raw_tar = gzip.decompress(first_member)
        second = self.root / "second.tar.gz"
        write_sdist(second)
        second_tar = gzip.decompress(second.read_bytes())
        sdist.write_bytes(gzip.compress(raw_tar + second_tar, mtime=0))
        failures: list[str] = []
        release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("after its first EOF" in failure for failure in failures), failures)

        sdist.write_bytes(first_member + b"nonzero-trailer")
        failures = []
        release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertTrue(any("trailing nonzero" in failure for failure in failures), failures)

        sdist.write_bytes(first_member + (b"\x00" * 16))
        failures = []
        release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, failures)
        self.assertEqual(failures, [])

    def test_raw_tar_rejects_pax_gnu_long_sparse_and_link_ambiguity(self) -> None:
        sdist = self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz"
        top = f"{PACKAGE}-{VERSION}"
        cases = (
            ("pax", tarfile.PAX_FORMAT, "p" * 120, tarfile.REGTYPE, ""),
            ("gnu-long", tarfile.GNU_FORMAT, "g" * 120, tarfile.REGTYPE, ""),
            ("sparse", tarfile.GNU_FORMAT, f"{top}/sparse", tarfile.GNUTYPE_SPARSE, ""),
            ("symlink", tarfile.USTAR_FORMAT, f"{top}/link", tarfile.SYMTYPE, "target"),
        )
        for label, archive_format, name, member_type, linkname in cases:
            with self.subTest(label=label):
                with tarfile.open(sdist, "w:gz", format=archive_format) as archive:
                    info = tarfile.TarInfo(name)
                    info.type = member_type
                    info.linkname = linkname
                    payload = b"x" if member_type == tarfile.REGTYPE else b""
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload) if payload else None)
                failures: list[str] = []
                release.inspect_sdist(artifact_blob(sdist), PROJECT, VERSION, {PACKAGE}, failures)
                self.assertTrue(any("raw gzip/TAR layout rejected" in failure for failure in failures), failures)

    def test_main_rejects_unmodeled_canonical_dist_info_entry_points(self) -> None:
        write_wheel(
            self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl",
            dist_info_extra="entry_points.txt",
        )
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        result = self.run_main()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(any("canonical .dist-info contains unmodeled members" in failure for failure in payload["failures"]), payload)
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")

    def test_main_rejects_unmodeled_sdist_setup_py(self) -> None:
        write_wheel(self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz", setup_py=True)
        result = self.run_main()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(any("contains unmodeled archive members" in failure for failure in payload["failures"]), payload)
        self.assertEqual(payload["python_source_payload_parity"], "not_established")
        self.assertEqual(payload["source_artifact_parity"], "not_evaluated")

    def test_final_concurrent_manifest_drift_is_detected(self) -> None:
        write_wheel(self.root / "dist" / f"{PACKAGE}-{VERSION}-py3-none-any.whl")
        write_sdist(self.root / "dist" / f"{PACKAGE}-{VERSION}.tar.gz")
        original = release.closed_dist_manifest
        def drifting(path: Path, boundary: Path | None = None):
            result = original(path, boundary)
            return {**result, "late.whl": "f" * 64}
        output = io.StringIO()
        with mock.patch.object(release, "closed_dist_manifest", side_effect=drifting):
            with mock.patch.object(sys, "argv", ["validator", "--root", str(self.root)]):
                with mock.patch.object(sys, "stdout", output):
                    self.assertEqual(release.main(), 1)
        payload = json.loads(output.getvalue())
        self.assertTrue(any("final concurrent manifest drift" in failure for failure in payload["failures"]), payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
