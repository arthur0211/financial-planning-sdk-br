#!/usr/bin/env python3
"""Emit a deterministic, non-authoritative source-freeze manifest."""

from __future__ import annotations

import os
import sys

# Python processes ambient startup hooks before loading a script, so this
# boundary cannot bootstrap its own isolation safely.  Supported CLI calls
# must begin with ``python -I``; repository launchers all do so explicitly.
if __name__ == "__main__" and not sys.flags.isolated:
    os.write(2, b"freeze_source_snapshot_requires_python_isolated_mode\n")
    raise SystemExit(2)

import argparse
import hashlib
import importlib.util
import json
import stat
from pathlib import Path, PurePosixPath
from typing import Any

if __package__:
    from .bounded_subprocess import run_bounded
else:
    boundary_path = Path(__file__).resolve().with_name("bounded_subprocess.py")
    boundary_spec = importlib.util.spec_from_file_location("_finplanbr_freeze_bounded_subprocess", boundary_path)
    if boundary_spec is None or boundary_spec.loader is None:
        raise RuntimeError("bounded subprocess helper could not be loaded")
    boundary_module = importlib.util.module_from_spec(boundary_spec)
    boundary_spec.loader.exec_module(boundary_module)
    run_bounded = boundary_module.run_bounded

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FORMAT = "finplanbr.source-freeze.v1"
INVENTORY_RECIPE = "git_ls_files_cached_others_exclude_standard_nul"
ORDERING_RECIPE = "relative_path_utf8_bytes_ascending"
DIGEST_RECIPE = "sha256_fpbr_c14n_1_manifest_without_trailing_newline"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _inventory(root: Path) -> tuple[str, ...]:
    completed = run_bounded(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        timeout_seconds=30,
        stdout_limit=16 * 1024 * 1024,
        stderr_limit=1024 * 1024,
    )
    if completed.returncode != 0:
        raise RuntimeError("git could not enumerate the source-freeze inventory")
    encoded_paths = [item for item in completed.stdout.split(b"\0") if item]
    if len(encoded_paths) != len(set(encoded_paths)):
        raise RuntimeError("source-freeze inventory contains a duplicate path")
    paths: list[str] = []
    for encoded in encoded_paths:
        path = encoded.decode("utf-8", errors="strict")
        pure = PurePosixPath(path)
        if (
            not path
            or "\\" in path
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in pure.parts)
            or pure.as_posix() != path
        ):
            raise RuntimeError("source-freeze inventory contains a non-canonical relative path")
        paths.append(path)
    return tuple(sorted(paths, key=lambda item: item.encode("utf-8")))


def _entry(root: Path, relative_path: str) -> dict[str, Any]:
    path = root.joinpath(*relative_path.split("/"))
    before = path.stat(follow_symlinks=False)
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise RuntimeError("source-freeze inventory contains a non-regular file")
    payload = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(payload) != before.st_size:
        raise RuntimeError("source-freeze file drifted while its bytes were read")
    return {
        "path": relative_path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def snapshot(root: Path) -> tuple[dict[str, Any], bytes, str]:
    entries = [_entry(root, path) for path in _inventory(root)]
    manifest: dict[str, Any] = {
        "format": FORMAT,
        "inventory": INVENTORY_RECIPE,
        "ordering": ORDERING_RECIPE,
        "digest_basis": DIGEST_RECIPE,
        "entries": entries,
    }
    payload = _canonical_json(manifest)
    return manifest, payload, hashlib.sha256(payload).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        action="store_true",
        help="emit only the recipe, entry count, canonical byte count, and manifest SHA-256",
    )
    arguments = parser.parse_args(argv)
    manifest, payload, digest = snapshot(REPOSITORY_ROOT)
    report: dict[str, Any]
    if arguments.summary:
        report = {
            "format": FORMAT,
            "inventory": INVENTORY_RECIPE,
            "ordering": ORDERING_RECIPE,
            "digest_basis": DIGEST_RECIPE,
            "entry_count": len(manifest["entries"]),
            "manifest_bytes": len(payload),
            "manifest_sha256": digest,
        }
    else:
        report = {"manifest": manifest, "manifest_sha256": digest}
    os.write(1, _canonical_json(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
