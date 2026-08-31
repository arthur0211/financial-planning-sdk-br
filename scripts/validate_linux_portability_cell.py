#!/usr/bin/env python3
"""Run one source/direct-wheel/sdist-wheel Linux portability cell."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import socket
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

if __package__:
    from .bounded_subprocess import run_bounded
    from .portability_artifact_inventory import canonicalize_sdist, canonicalize_wheel, inspect_package_artifacts
else:
    from bounded_subprocess import run_bounded  # type: ignore[no-redef]
    from portability_artifact_inventory import canonicalize_sdist, canonicalize_wheel, inspect_package_artifacts

FORMAT = "finplanbr.installed-portability-cell.v1"
_DOS_DEVICE = re.compile(r"(?i)^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$")
_INSTALL_FLAGS = (
    "--no-index",
    "--no-deps",
    "--no-cache-dir",
    "--no-compile",
    "--disable-pip-version-check",
)
CELL_OUTPUT_LIMIT = 32 * 1024 * 1024


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
    timeout: int = 240,
    expected_rc: int = 0,
) -> subprocess.CompletedProcess[bytes]:
    completed = run_bounded(
        command,
        cwd=cwd,
        env=environment,
        timeout_seconds=timeout,
        stdout_limit=CELL_OUTPUT_LIMIT,
        stderr_limit=CELL_OUTPUT_LIMIT,
    )
    if completed.returncode != expected_rc:
        digest = hashlib.sha256(completed.stderr + completed.stdout).hexdigest()
        raise RuntimeError(
            f"subprocess {Path(command[0]).name} returned {completed.returncode}, expected {expected_rc}; "
            f"output_sha256={digest}"
        )
    return completed


def _validate_relative_path(value: object) -> str:
    if type(value) is not str or not value or "\\" in value:
        raise RuntimeError("freeze contains a non-canonical path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or pure.as_posix() != value or any(part in {"", ".", ".."} for part in pure.parts):
        raise RuntimeError("freeze contains a non-canonical path")
    for part in pure.parts:
        if (
            part[-1:] in {" ", "."}
            or ":" in part
            or any(ord(character) < 32 for character in part)
            or _DOS_DEVICE.fullmatch(part)
        ):
            raise RuntimeError("freeze contains a Windows-reserved path")
    return value


def _load_and_verify_freeze(source: Path, freeze_path: Path) -> tuple[dict[str, Any], str]:
    outer = json.loads(freeze_path.read_bytes())
    if type(outer) is not dict or type(outer.get("manifest")) is not dict:
        raise RuntimeError("freeze report is not the full v1 manifest")
    manifest = outer["manifest"]
    digest = outer.get("manifest_sha256")
    if type(digest) is not str or hashlib.sha256(_canonical(manifest)).hexdigest() != digest:
        raise RuntimeError("freeze report digest does not bind its manifest")
    if manifest.get("format") != "finplanbr.source-freeze.v1" or type(manifest.get("entries")) is not list:
        raise RuntimeError("freeze report format is unsupported")
    seen: set[str] = set()
    for entry in manifest["entries"]:
        if type(entry) is not dict:
            raise RuntimeError("freeze entry is not an object")
        relative = _validate_relative_path(entry.get("path"))
        if relative in seen:
            raise RuntimeError("freeze repeats a path")
        seen.add(relative)
        candidate = source.joinpath(*relative.split("/"))
        status = candidate.stat(follow_symlinks=False)
        if candidate.is_symlink() or not stat.S_ISREG(status.st_mode):
            raise RuntimeError("freeze source contains a non-regular member")
        payload = candidate.read_bytes()
        if len(payload) != entry.get("size") or hashlib.sha256(payload).hexdigest() != entry.get("sha256"):
            raise RuntimeError("freeze source bytes drifted")
    return manifest, digest


def _copy_freeze(source: Path, target: Path, manifest: dict[str, Any]) -> None:
    target.mkdir(parents=True)
    for entry in manifest["entries"]:
        relative = entry["path"]
        origin = source.joinpath(*relative.split("/"))
        destination = target.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(origin.read_bytes())
        if _sha256(destination) != entry["sha256"]:
            raise RuntimeError("copied freeze member differs from source")


def _exactly_one(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one {pattern} artifact")
    return matches[0]


def _venv_python(root: Path) -> Path:
    return root / "bin" / "python"


def _purelib(interpreter: Path, cwd: Path) -> Path:
    completed = _run(
        [os.fspath(interpreter), "-P", "-s", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        cwd=cwd,
    )
    return Path(completed.stdout.decode("utf-8").strip()).resolve(strict=True)


def _isolated_origin(interpreter: Path, expected_root: Path, source: Path | None, cwd: Path) -> str:
    insertion = "" if source is None else f"sys.path.insert(0,{os.fspath(source)!r});"
    code = (
        "import pathlib,sys;"
        + insertion
        + "import financial_planning_sdk_br as p;"
        + "print(pathlib.Path(p.__file__).resolve())"
    )
    completed = _run([os.fspath(interpreter), "-I", "-c", code], cwd=cwd)
    origin = Path(completed.stdout.decode("utf-8").strip()).resolve(strict=True)
    origin.relative_to(expected_root.resolve(strict=True))
    return os.fspath(origin)


def _network_blocked() -> str:
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=3):
            pass
    except OSError as exc:
        return type(exc).__name__
    raise RuntimeError("Docker none boundary did not block the external network probe")


def _write_probe(interpreter: Path, target: Path, *, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    code = "from pathlib import Path; Path(__import__('sys').argv[1]).write_bytes(b'negative-control')"
    return run_bounded(
        [os.fspath(interpreter), "-P", "-s", "-c", code, os.fspath(target)],
        cwd=cwd,
        env={
            "HOME": os.environ["HOME"],
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ["PATH"],
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TZ": "UTC0",
        },
        timeout_seconds=15,
        stdout_limit=CELL_OUTPUT_LIMIT,
        stderr_limit=CELL_OUTPUT_LIMIT,
    )


def _make_read_only(root: Path) -> None:
    paths = sorted(root.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for path in paths:
        if path.is_symlink():
            continue
        mode = path.stat(follow_symlinks=False).st_mode
        if path.is_dir():
            path.chmod(0o555)
        elif stat.S_ISREG(mode):
            path.chmod(0o555 if mode & 0o111 else 0o444)
    root.chmod(0o555)


def _tree_fingerprint(roots: list[Path]) -> str:
    entries: list[dict[str, object]] = []
    for root in roots:
        for path in sorted((root, *root.rglob("*")), key=lambda item: os.fsencode(item)):
            relative = path.relative_to(root).as_posix() if path != root else "."
            status = path.stat(follow_symlinks=False)
            entry: dict[str, object] = {
                "root": root.name,
                "path": relative,
                "mode": stat.S_IMODE(status.st_mode),
                "size": status.st_size,
                "type": "directory" if stat.S_ISDIR(status.st_mode) else "file",
            }
            if stat.S_ISREG(status.st_mode):
                entry["sha256"] = _sha256(path)
            entries.append(entry)
    return hashlib.sha256(_canonical(entries)).hexdigest()


def _probe_environment(*, guard: Path, source: Path | None, variant: dict[str, str]) -> dict[str, str]:
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    if home is None:
        raise RuntimeError("portability cell has no explicit home directory")
    environment = {
        "FINPLANBR_PORTABILITY_CONTEXT": variant["context"],
        "FINPLANBR_PORTABILITY_GUARD": "1",
        "FINPLANBR_PORTABILITY_LOCALE": variant["locale"],
        "HOME": home,
        "LANG": variant["locale"],
        "LC_ALL": variant["locale"],
        "PATH": os.environ["PATH"],
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": variant["hash_seed"],
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": os.pathsep.join([os.fspath(guard), *([] if source is None else [os.fspath(source)])]),
        "TZ": variant["tz"],
    }
    for name in ("COMSPEC", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _run_product_probe(
    *,
    interpreter: Path,
    probe: Path,
    guard: Path,
    source: Path | None,
    expected_origin: Path,
    runtime: Path,
    variant: dict[str, str],
    console_script: Path | None = None,
) -> dict[str, Any]:
    command = [
        os.fspath(interpreter),
        "-P",
        "-s",
        os.fspath(probe),
        "--valid-input",
        os.fspath(runtime / "valid.json"),
        "--invalid-input",
        os.fspath(runtime / "invalid.json"),
        "--malformed-input",
        os.fspath(runtime / "malformed.json"),
        "--expected-origin-root",
        os.fspath(expected_origin),
    ]
    if console_script is not None:
        command.extend(("--console-script", os.fspath(console_script)))
    completed = _run(
        command,
        cwd=runtime,
        environment=_probe_environment(guard=guard, source=source, variant=variant),
        timeout=90,
    )
    if completed.stderr:
        raise RuntimeError("installed portability probe wrote unexpected stderr")
    report = json.loads(completed.stdout)
    if report.get("status") != "passed":
        raise RuntimeError("installed portability probe did not pass")
    return report


def _audit_negative(interpreter: Path, guard: Path, runtime: Path, *, network: bool) -> None:
    code = "import socket; socket.socket()" if network else "open('audit-negative-control', 'wb')"
    environment = _probe_environment(
        guard=guard,
        source=None,
        variant={"context": "baseline", "hash_seed": "0", "locale": "C", "tz": "UTC0"},
    )
    completed = run_bounded(
        [os.fspath(interpreter), "-P", "-s", "-c", code],
        cwd=runtime,
        env=environment,
        timeout_seconds=15,
        stdout_limit=CELL_OUTPUT_LIMIT,
        stderr_limit=CELL_OUTPUT_LIMIT,
    )
    marker = b"blocked network" if network else b"blocked write"
    if completed.returncode == 0 or marker not in completed.stderr:
        raise RuntimeError("secondary audit guard negative control did not trigger")


def _tool_version(module: str) -> str:
    completed = _run(
        [sys.executable, "-P", "-s", "-c", f"import {module}; print({module}.__version__)"],
        cwd=Path("/work"),
    )
    return completed.stdout.decode("ascii").strip()


def execute(arguments: argparse.Namespace) -> dict[str, object]:
    if platform.system() != "Linux" or os.geteuid() == 0:
        raise RuntimeError("Linux cell requires a non-root Linux process")
    expected_minor = tuple(int(part) for part in arguments.python_minor.split("."))
    if sys.version_info[:2] != expected_minor:
        raise RuntimeError("cell Python minor differs from the requested matrix coordinate")
    source = arguments.source_root.resolve(strict=True)
    work = arguments.work_root.resolve(strict=True)
    if source == work or source in work.parents or work in source.parents:
        raise RuntimeError("work root and source checkout must be disjoint")
    precontrol = json.loads(arguments.network_precontrol.read_bytes())
    if (
        precontrol.get("status") != "passed"
        or precontrol.get("expectation") != "reachable"
        or precontrol.get("connected") is not True
        or precontrol.get("nonce") != arguments.nonce
        or not str(precontrol.get("python", "")).startswith(arguments.python_minor + ".")
    ):
        raise RuntimeError("network precontrol is missing or does not match this cell")
    network_error = _network_blocked()
    root_write = _write_probe(Path(sys.executable), Path("/finplanbr-root-negative-control"), cwd=work)
    source_write = _write_probe(Path(sys.executable), source / f".finplanbr-negative-{arguments.nonce}", cwd=work)
    if root_write.returncode == 0 or source_write.returncode == 0:
        raise RuntimeError("read-only root/source boundary negative control did not trigger")

    manifest, freeze_digest = _load_and_verify_freeze(source, arguments.freeze_report)
    candidate = work / "candidate"
    _copy_freeze(source, candidate, manifest)
    artifacts = work / "artifacts"
    raw_direct_dir = artifacts / "direct-backend-raw"
    direct_dir = artifacts / "direct"
    raw_sdist_dir = artifacts / "sdist-backend-raw"
    sdist_dir = artifacts / "sdist"
    raw_rebuilt_dir = artifacts / "rebuilt-backend-raw"
    rebuilt_dir = artifacts / "rebuilt"
    for directory in (raw_direct_dir, raw_sdist_dir, raw_rebuilt_dir):
        directory.mkdir(parents=True)
    _run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", os.fspath(raw_direct_dir)],
        cwd=candidate,
    )
    _run(
        [sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", os.fspath(raw_sdist_dir)],
        cwd=candidate,
    )
    raw_direct_wheel = _exactly_one(raw_direct_dir, "*.whl")
    direct_wheel = canonicalize_wheel(
        raw_direct_wheel,
        direct_dir / raw_direct_wheel.name,
        source_root=candidate,
    )
    raw_sdist = _exactly_one(raw_sdist_dir, "*.tar.gz")
    sdist = canonicalize_sdist(raw_sdist, sdist_dir / raw_sdist.name)
    sdist_rebuild_input_sha256 = _sha256(sdist)
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
            os.fspath(raw_rebuilt_dir),
            os.fspath(sdist),
        ],
        cwd=work,
    )
    raw_rebuilt_wheel = _exactly_one(raw_rebuilt_dir, "*.whl")
    rebuilt_wheel = canonicalize_wheel(
        raw_rebuilt_wheel,
        rebuilt_dir / raw_rebuilt_wheel.name,
        source_root=candidate,
    )
    packaging = inspect_package_artifacts(
        source_root=candidate,
        direct_wheel=direct_wheel,
        sdist=sdist,
        rebuilt_wheel=rebuilt_wheel,
    )
    if packaging.get("sdist_archive_sha256") != sdist_rebuild_input_sha256:
        raise RuntimeError("canonical sdist rebuild input and packaging digests differ")

    direct_venv = work / "venv-direct"
    rebuilt_venv = work / "venv-sdist-wheel"
    for venv in (direct_venv, rebuilt_venv):
        _run([sys.executable, "-m", "venv", "--copies", os.fspath(venv)], cwd=work)
    direct_python = _venv_python(direct_venv)
    rebuilt_python = _venv_python(rebuilt_venv)
    direct_console = direct_venv / "bin" / "finplanbr"
    rebuilt_console = rebuilt_venv / "bin" / "finplanbr"
    for interpreter, wheel in ((direct_python, direct_wheel), (rebuilt_python, rebuilt_wheel)):
        _run(
            [
                os.fspath(interpreter),
                "-m",
                "pip",
                "install",
                *_INSTALL_FLAGS,
                os.fspath(wheel),
            ],
            cwd=work,
        )
        dependency_check = _run(
            [
                os.fspath(interpreter),
                "-P",
                "-s",
                "-c",
                (
                    "import importlib.metadata as m,json; "
                    "r=m.metadata('finplanbr').get_all('Requires-Dist') or []; "
                    "print(json.dumps([x for x in r if '; extra ==' not in x]))"
                ),
            ],
            cwd=work,
        )
        if dependency_check.stdout.strip() != b"[]":
            raise RuntimeError(
                "installed distribution gained a runtime dependency: "
                + dependency_check.stdout.decode("utf-8", errors="replace").strip()
            )

    runtime = work / "runtime"
    runtime.mkdir()
    runtime.joinpath("valid.json").write_bytes(
        candidate.joinpath("examples", "deterministic-cashflow-ledger.json").read_bytes()
    )
    runtime.joinpath("invalid.json").write_bytes(b"{}")
    runtime.joinpath("malformed.json").write_bytes(b"[[")
    pre_lock = runtime / "filesystem-precontrol"
    pre = _write_probe(direct_python, pre_lock, cwd=work)
    if pre.returncode != 0 or pre_lock.read_bytes() != b"negative-control":
        raise RuntimeError("filesystem precontrol did not demonstrate a writable target")
    pre_lock.unlink()

    source_runtime = candidate / "src"
    direct_purelib = _purelib(direct_python, work)
    rebuilt_purelib = _purelib(rebuilt_python, work)
    for locked in (source_runtime, direct_venv, rebuilt_venv, runtime):
        _make_read_only(locked)
    post_lock = _write_probe(direct_python, runtime / "filesystem-postcontrol", cwd=work)
    if post_lock.returncode == 0:
        raise RuntimeError("filesystem read-only postcontrol did not trigger")

    probe = source / "scripts" / "installed_portability_probe.py"
    guard = source / "tests" / "portability"
    for interpreter in (Path(sys.executable), direct_python, rebuilt_python):
        _audit_negative(interpreter, guard, runtime, network=False)
        _audit_negative(interpreter, guard, runtime, network=True)

    isolated_origins = {
        "source": _isolated_origin(Path(sys.executable), source_runtime, source_runtime, runtime),
        "direct_wheel": _isolated_origin(direct_python, direct_purelib, None, runtime),
        "sdist_wheel": _isolated_origin(rebuilt_python, rebuilt_purelib, None, runtime),
    }

    protected = [source_runtime, direct_purelib, rebuilt_purelib, runtime]
    before = _tree_fingerprint(protected)
    variants = (
        {"id": "baseline", "context": "baseline", "hash_seed": "0", "locale": "C", "tz": "UTC0"},
        {
            "id": "hostile",
            "context": "hostile",
            "hash_seed": "4294967295",
            "locale": "C.UTF-8",
            "tz": "GMT+12",
        },
    )
    surfaces = (
        ("source", Path(sys.executable), source_runtime, source_runtime, None),
        ("direct_wheel", direct_python, None, direct_purelib, direct_console),
        ("sdist_wheel", rebuilt_python, None, rebuilt_purelib, rebuilt_console),
    )
    reports: list[tuple[str, str, dict[str, Any]]] = []
    for variant in variants:
        for label, interpreter, import_source, expected_origin, console_script in surfaces:
            reports.append(
                (
                    variant["id"],
                    label,
                    _run_product_probe(
                        interpreter=interpreter,
                        probe=probe,
                        guard=guard,
                        source=import_source,
                        expected_origin=expected_origin,
                        runtime=runtime,
                        variant=variant,
                        console_script=console_script,
                    ),
                )
            )
    after = _tree_fingerprint(protected)
    if before != after:
        raise RuntimeError("tested product routes changed a protected runtime tree")
    parity_bases = [report["parity_basis"] for _, _, report in reports]
    if any(item != parity_bases[0] for item in parity_bases[1:]):
        digests = {f"{variant_id}:{surface}": report["parity_sha256"] for variant_id, surface, report in reports}
        route_digests = {
            f"{variant_id}:{surface}": {
                "_reason_codes": report["parity_basis"]["reason_codes"]["sha256"],
                "_schemas": report["parity_basis"]["schemas"]["sha256"],
                **{
                    route: {
                        "rc": value["rc"],
                        "stdout": value["stdout"]["sha256"],
                        "stderr": value["stderr"]["sha256"],
                    }
                    for route, value in report["parity_basis"]["routes"].items()
                },
            }
            for variant_id, surface, report in reports
        }
        raise RuntimeError(
            "source/direct/sdist or hostile-context bytes diverged: "
            + json.dumps(digests, sort_keys=True, separators=(",", ":"))
            + " routes="
            + json.dumps(route_digests, sort_keys=True, separators=(",", ":"))
        )
    contexts = {f"{variant_id}:{surface}": report["runtime_context"] for variant_id, surface, report in reports}
    if contexts["baseline:source"]["hash_seed"] == contexts["hostile:source"]["hash_seed"]:
        raise RuntimeError("hash-seed negative variation did not reach the product process")
    if contexts["baseline:source"]["locale"] == contexts["hostile:source"]["locale"]:
        raise RuntimeError("locale negative variation did not reach the product process")
    if contexts["baseline:source"]["tz_epoch_local"] == contexts["hostile:source"]["tz_epoch_local"]:
        raise RuntimeError("timezone negative variation did not reach the product process")
    console_records = [report["console_entrypoint"] for _, surface, report in reports if surface != "source"]
    if len(console_records) != 4 or any(record != console_records[0] for record in console_records[1:]):
        raise RuntimeError("installed console scripts diverged across wheels or hostile contexts")
    if console_records[0].get("command_count") != 8:
        raise RuntimeError("installed console-script command roster is incomplete")
    _load_and_verify_freeze(source, arguments.freeze_report)
    sdist_artifact_sha256 = _sha256(sdist)
    if sdist_artifact_sha256 != sdist_rebuild_input_sha256:
        raise RuntimeError("canonical sdist artifact drifted after wheel rebuild")

    return {
        "format": FORMAT,
        "status": "passed",
        "cell": f"linux-py{arguments.python_minor}",
        "platform": {"system": "linux", "machine": platform.machine()},
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "source_freeze": {
            "entry_count": len(manifest["entries"]),
            "manifest_sha256": freeze_digest,
            "rechecked_after_execution": True,
        },
        "toolchain": {
            "build": _tool_version("build"),
            "pip": _run([sys.executable, "-m", "pip", "--version"], cwd=work).stdout.decode().split()[1],
            "setuptools": _tool_version("setuptools"),
            "container_image_id": arguments.image_id,
            "base_image_ref": arguments.base_image_ref,
            "acquisition_network": "enabled_before_cell_image_build",
        },
        "artifacts": {
            "direct_wheel": {"name": direct_wheel.name, "sha256": _sha256(direct_wheel)},
            "sdist": {"name": sdist.name, "sha256": sdist_artifact_sha256},
            "sdist_wheel": {"name": rebuilt_wheel.name, "sha256": _sha256(rebuilt_wheel)},
        },
        "packaging": packaging,
        "installation": {
            "direct_wheel_venv_outside_checkout": True,
            "sdist_wheel_venv_outside_checkout": True,
            "flags": list(_INSTALL_FLAGS),
            "network_boundary_active": True,
            "runtime_dependencies": 0,
        },
        "controls": {
            "network": {
                "mechanism": "docker_none",
                "precontrol_connected": True,
                "postcontrol_blocked": True,
                "postcontrol_error_type": network_error,
                "nonce": arguments.nonce,
            },
            "filesystem": {
                "mechanism": "docker_read_only_bind_plus_posix_modes",
                "root_write_blocked": True,
                "source_write_blocked": True,
                "writable_precontrol_triggered": True,
                "readonly_postcontrol_triggered": True,
                "protected_tree_unchanged": True,
            },
            "audit_hook": {
                "role": "secondary_observer_not_sandbox",
                "network_negative_triggered": True,
                "write_negative_triggered": True,
            },
        },
        "observations": {
            "surface_count": len(surfaces),
            "variant_count": len(variants),
            "probe_count": len(reports),
            "contexts": contexts,
            "isolated_import_origins": isolated_origins,
            "isolated_import_origin_count": len(isolated_origins),
            "parity_sha256": reports[0][2]["parity_sha256"],
            "source_direct_sdist_bytes_identical": True,
            "sdk_cli_bytes_and_rc_identical": True,
            "console_cli_bytes_and_rc_identical": True,
            "installed_console_entrypoint_count": len(console_records),
            "installed_console_commands_per_probe": console_records[0]["command_count"],
            "schema_count": reports[0][2]["schema_count"],
            "reason_code_count": reports[0][2]["reason_code_count"],
            "skip_count": 0,
            "xfail_count": 0,
        },
        "authority": "none",
        "release_authorized": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--freeze-report", type=Path, required=True)
    parser.add_argument("--network-precontrol", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--python-minor", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--base-image-ref", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        report = execute(_parser().parse_args(argv))
    except Exception as exc:
        report = {
            "format": FORMAT,
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "authority": "none",
            "release_authorized": False,
        }
        os.write(1, _canonical(report) + b"\n")
        return 1
    os.write(1, _canonical(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
