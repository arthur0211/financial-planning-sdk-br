#!/usr/bin/env python3
"""Prepare, exercise, and finalize one Windows installed-portability cell."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .bounded_subprocess import run_bounded
    from .portability_artifact_inventory import canonicalize_sdist, canonicalize_wheel, inspect_package_artifacts
    from .validate_linux_portability_cell import (
        _INSTALL_FLAGS,
        FORMAT,
        _audit_negative,
        _canonical,
        _copy_freeze,
        _exactly_one,
        _load_and_verify_freeze,
        _run,
        _run_product_probe,
        _sha256,
        _tree_fingerprint,
    )
else:
    from bounded_subprocess import run_bounded  # type: ignore[no-redef]
    from portability_artifact_inventory import (  # type: ignore[no-redef]
        canonicalize_sdist,
        canonicalize_wheel,
        inspect_package_artifacts,
    )
    from validate_linux_portability_cell import (  # type: ignore[no-redef]
        _INSTALL_FLAGS,
        FORMAT,
        _audit_negative,
        _canonical,
        _copy_freeze,
        _exactly_one,
        _load_and_verify_freeze,
        _run,
        _run_product_probe,
        _sha256,
        _tree_fingerprint,
    )

STATE_FORMAT = "finplanbr.windows-portability-state.v1"
BOUNDARY_FORMAT = "finplanbr.windows-portability-boundary.v1"
EXERCISE_FORMAT = "finplanbr.windows-portability-exercise.v1"
CLEANUP_FORMAT = "finplanbr.windows-portability-cleanup.v1"


def _under(path: Path, root: Path) -> Path:
    resolved = path.resolve(strict=True)
    resolved.relative_to(root.resolve(strict=True))
    return resolved


def _venv_python(root: Path) -> Path:
    return root / "Scripts" / "python.exe"


def _venv_console(root: Path) -> Path:
    return root / "Scripts" / "finplanbr.exe"


def _purelib(interpreter: Path, cwd: Path) -> Path:
    completed = _run(
        [os.fspath(interpreter), "-P", "-s", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        cwd=cwd,
    )
    return Path(completed.stdout.decode("utf-8").strip()).resolve(strict=True)


def _base_dependencies(interpreter: Path, cwd: Path) -> None:
    completed = _run(
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
        cwd=cwd,
    )
    if completed.stdout.strip() != b"[]":
        raise RuntimeError("installed distribution gained a base runtime dependency")


def _write_probe(interpreter: Path, target: Path, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    environment.pop("PYTHONPATH", None)
    code = "from pathlib import Path; Path(__import__('sys').argv[1]).write_bytes(b'negative-control')"
    return run_bounded(
        [os.fspath(interpreter), "-P", "-s", "-c", code, os.fspath(target)],
        cwd=cwd,
        env=environment,
        timeout_seconds=15,
        stdout_limit=32 * 1024 * 1024,
        stderr_limit=32 * 1024 * 1024,
    )


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


def _load_state(path: Path) -> dict[str, Any]:
    state = json.loads(path.read_bytes())
    if type(state) is not dict or state.get("format") != STATE_FORMAT:
        raise RuntimeError("Windows portability state format is invalid")
    return state


def prepare(arguments: argparse.Namespace) -> dict[str, object]:
    if platform.system() != "Windows":
        raise RuntimeError("Windows prepare requires Windows")
    expected_minor = tuple(int(part) for part in arguments.python_minor.split("."))
    if sys.version_info[:2] != expected_minor:
        raise RuntimeError("cell Python minor differs from the requested coordinate")
    source = arguments.source_root.resolve(strict=True)
    work = arguments.work_root.resolve(strict=True)
    if source == work or source in work.parents or work in source.parents:
        raise RuntimeError("work root and checkout must be disjoint")
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
    sdist_artifact_sha256 = _sha256(sdist)
    if (
        sdist_rebuild_input_sha256 != sdist_artifact_sha256
        or packaging.get("sdist_archive_sha256") != sdist_artifact_sha256
    ):
        raise RuntimeError("canonical sdist rebuild input, artifact, and packaging digests differ")

    direct_venv = work / "venv-direct"
    rebuilt_venv = work / "venv-sdist-wheel"
    for venv in (direct_venv, rebuilt_venv):
        _run([sys.executable, "-m", "venv", "--copies", os.fspath(venv)], cwd=work)
    direct_python = _venv_python(direct_venv)
    rebuilt_python = _venv_python(rebuilt_venv)
    for interpreter, wheel in ((direct_python, direct_wheel), (rebuilt_python, rebuilt_wheel)):
        _run(
            [os.fspath(interpreter), "-m", "pip", "install", *_INSTALL_FLAGS, os.fspath(wheel)],
            cwd=work,
        )
        _base_dependencies(interpreter, work)

    runtime = work / "runtime"
    runtime.mkdir()
    runtime.joinpath("valid.json").write_bytes(
        candidate.joinpath("examples", "deterministic-cashflow-ledger.json").read_bytes()
    )
    runtime.joinpath("invalid.json").write_bytes(b"{}")
    runtime.joinpath("malformed.json").write_bytes(b"[[")
    precontrol = runtime / "filesystem-precontrol"
    result = _write_probe(direct_python, precontrol, work)
    if result.returncode != 0 or precontrol.read_bytes() != b"negative-control":
        raise RuntimeError("filesystem writable precontrol did not trigger")
    precontrol.unlink()

    direct_purelib = _purelib(direct_python, work)
    rebuilt_purelib = _purelib(rebuilt_python, work)
    state: dict[str, object] = {
        "format": STATE_FORMAT,
        "nonce": arguments.nonce,
        "cell": f"windows-py{arguments.python_minor}",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "source_root": os.fspath(source),
        "freeze_report": os.fspath(arguments.freeze_report.resolve(strict=True)),
        "work_root": os.fspath(work),
        "candidate": os.fspath(candidate),
        "runtime": os.fspath(runtime),
        "source_runtime": os.fspath(candidate / "src"),
        "direct_venv": os.fspath(direct_venv),
        "rebuilt_venv": os.fspath(rebuilt_venv),
        "direct_python": os.fspath(direct_python),
        "rebuilt_python": os.fspath(rebuilt_python),
        "direct_console": os.fspath(_venv_console(direct_venv)),
        "rebuilt_console": os.fspath(_venv_console(rebuilt_venv)),
        "direct_purelib": os.fspath(direct_purelib),
        "rebuilt_purelib": os.fspath(rebuilt_purelib),
        "filesystem_roots": [os.fspath(path) for path in (candidate, direct_venv, rebuilt_venv, runtime)],
        "source_freeze": {
            "manifest_sha256": freeze_digest,
            "entry_count": len(manifest["entries"]),
        },
        "artifacts": {
            "direct_wheel": {
                "name": direct_wheel.name,
                "path": os.fspath(direct_wheel),
                "sha256": _sha256(direct_wheel),
            },
            "sdist": {"name": sdist.name, "path": os.fspath(sdist), "sha256": sdist_artifact_sha256},
            "sdist_wheel": {
                "name": rebuilt_wheel.name,
                "path": os.fspath(rebuilt_wheel),
                "sha256": _sha256(rebuilt_wheel),
            },
        },
        "packaging": packaging,
        "installation_flags": list(_INSTALL_FLAGS),
        "filesystem_writable_precontrol": True,
        "toolchain": {
            "build": _run([sys.executable, "-P", "-s", "-c", "import build; print(build.__version__)"], cwd=work)
            .stdout.decode("ascii")
            .strip(),
            "pip": _run([sys.executable, "-m", "pip", "--version"], cwd=work).stdout.decode().split()[1],
            "setuptools": _run(
                [sys.executable, "-P", "-s", "-c", "import setuptools; print(setuptools.__version__)"], cwd=work
            )
            .stdout.decode("ascii")
            .strip(),
            "acquisition_network": "enabled_before_firewall_boundary",
        },
    }
    _load_and_verify_freeze(source, arguments.freeze_report)
    arguments.state_out.write_bytes(_canonical(state) + b"\n")
    return {"format": STATE_FORMAT, "status": "prepared", "cell": state["cell"], "nonce": arguments.nonce}


def exercise(arguments: argparse.Namespace) -> dict[str, object]:
    if platform.system() != "Windows":
        raise RuntimeError("Windows exercise requires Windows")
    state = _load_state(arguments.state)
    boundary = json.loads(arguments.boundary_report.read_bytes())
    if (
        type(boundary) is not dict
        or boundary.get("format") != BOUNDARY_FORMAT
        or boundary.get("nonce") != state["nonce"]
        or boundary.get("status") != "active"
        or boundary.get("network", {}).get("mechanism") != "windows_firewall_exact_program"
        or boundary.get("network", {}).get("precontrol_connected") is not True
        or boundary.get("network", {}).get("postcontrol_blocked") is not True
    ):
        raise RuntimeError("Windows external boundary report is missing or inactive")
    work = Path(state["work_root"]).resolve(strict=True)
    source = Path(state["source_root"]).resolve(strict=True)
    runtime = _under(Path(state["runtime"]), work)
    candidate = _under(Path(state["candidate"]), work)
    source_runtime = _under(Path(state["source_runtime"]), work)
    direct_venv = _under(Path(state["direct_venv"]), work)
    rebuilt_venv = _under(Path(state["rebuilt_venv"]), work)
    direct_python = _under(Path(state["direct_python"]), work)
    rebuilt_python = _under(Path(state["rebuilt_python"]), work)
    direct_purelib = _under(Path(state["direct_purelib"]), work)
    rebuilt_purelib = _under(Path(state["rebuilt_purelib"]), work)
    for artifact in state["artifacts"].values():
        path = _under(Path(artifact["path"]), work)
        if _sha256(path) != artifact["sha256"]:
            raise RuntimeError("staged artifact drifted before exercise")
    post = _write_probe(direct_python, runtime / "filesystem-postcontrol", work)
    if post.returncode == 0:
        raise RuntimeError("NTFS read-only postcontrol did not trigger")

    probe = candidate / "scripts" / "installed_portability_probe.py"
    guard = candidate / "tests" / "portability"
    for interpreter in (Path(sys.executable), direct_python, rebuilt_python):
        _audit_negative(interpreter, guard, runtime, network=False)
        _audit_negative(interpreter, guard, runtime, network=True)
    isolated_origins = {
        "source": _isolated_origin(Path(sys.executable), source_runtime, source_runtime, runtime),
        "direct_wheel": _isolated_origin(direct_python, direct_purelib, None, runtime),
        "sdist_wheel": _isolated_origin(rebuilt_python, rebuilt_purelib, None, runtime),
    }
    protected = [candidate, direct_venv, rebuilt_venv, runtime]
    before = _tree_fingerprint(protected)
    variants = (
        {"id": "baseline", "context": "baseline", "hash_seed": "0", "locale": "C", "tz": "UTC0"},
        {
            "id": "hostile",
            "context": "hostile",
            "hash_seed": "4294967295",
            "locale": "Portuguese_Brazil.1252",
            "tz": "GMT+12",
        },
    )
    surfaces = (
        ("source", Path(sys.executable), source_runtime, source_runtime, None),
        (
            "direct_wheel",
            direct_python,
            None,
            direct_purelib,
            _under(Path(state["direct_console"]), work),
        ),
        (
            "sdist_wheel",
            rebuilt_python,
            None,
            rebuilt_purelib,
            _under(Path(state["rebuilt_console"]), work),
        ),
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
        raise RuntimeError("tested product routes changed a protected Windows runtime tree")
    parity_bases = [report["parity_basis"] for _, _, report in reports]
    if any(item != parity_bases[0] for item in parity_bases[1:]):
        raise RuntimeError("Windows source/direct/sdist or hostile-context bytes diverged")
    contexts = {f"{variant_id}:{surface}": report["runtime_context"] for variant_id, surface, report in reports}
    if contexts["baseline:source"]["hash_seed"] == contexts["hostile:source"]["hash_seed"]:
        raise RuntimeError("hash-seed variation did not reach Windows product process")
    if contexts["baseline:source"]["locale"] == contexts["hostile:source"]["locale"]:
        raise RuntimeError("locale variation did not reach Windows product process")
    if contexts["baseline:source"]["tz_epoch_local"] == contexts["hostile:source"]["tz_epoch_local"]:
        raise RuntimeError("timezone variation did not reach Windows product process")
    console_records = [report["console_entrypoint"] for _, surface, report in reports if surface != "source"]
    if len(console_records) != 4 or any(record != console_records[0] for record in console_records[1:]):
        raise RuntimeError("Windows console scripts diverged across wheels or hostile contexts")
    if console_records[0].get("command_count") != 8:
        raise RuntimeError("Windows console-script command roster is incomplete")
    manifest, digest = _load_and_verify_freeze(source, Path(state["freeze_report"]))
    if digest != state["source_freeze"]["manifest_sha256"]:
        raise RuntimeError("source freeze drifted between Windows phases")
    for artifact in state["artifacts"].values():
        path = _under(Path(artifact["path"]), work)
        if _sha256(path) != artifact["sha256"]:
            raise RuntimeError("staged artifact drifted during exercise")
    result: dict[str, object] = {
        "format": EXERCISE_FORMAT,
        "status": "exercised",
        "cell": state["cell"],
        "nonce": state["nonce"],
        "platform": {"system": "windows", "machine": platform.machine()},
        "python": state["python"],
        "source_freeze": {
            "manifest_sha256": digest,
            "entry_count": len(manifest["entries"]),
            "rechecked_after_execution": True,
        },
        "artifacts": {
            label: {"name": artifact["name"], "sha256": artifact["sha256"]}
            for label, artifact in state["artifacts"].items()
        },
        "packaging": state["packaging"],
        "installation": {
            "direct_wheel_venv_outside_checkout": True,
            "sdist_wheel_venv_outside_checkout": True,
            "flags": state["installation_flags"],
            "network_boundary_active": True,
            "runtime_dependencies": 0,
        },
        "controls": {
            "network": boundary["network"],
            "filesystem": {
                "mechanism": "ntfs_acl_readonly_tested_trees",
                "writable_precontrol_triggered": state["filesystem_writable_precontrol"],
                "readonly_postcontrol_triggered": True,
                "protected_tree_unchanged": True,
                "target_count": boundary["filesystem"]["target_count"],
                "targets_absolute": boundary["filesystem"]["targets_absolute"],
                "prior_sddl_snapshot_count": boundary["filesystem"]["prior_sddl_snapshot_count"],
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
        "toolchain": state["toolchain"],
        "authority": "none",
        "release_authorized": False,
    }
    arguments.exercise_out.write_bytes(_canonical(result) + b"\n")
    return {"format": EXERCISE_FORMAT, "status": "exercised", "cell": state["cell"]}


def finalize(arguments: argparse.Namespace) -> dict[str, object]:
    exercise_report = json.loads(arguments.exercise_report.read_bytes())
    cleanup = json.loads(arguments.cleanup_report.read_bytes())
    if type(exercise_report) is not dict or exercise_report.get("format") != EXERCISE_FORMAT:
        raise RuntimeError("Windows exercise report is invalid")
    if (
        type(cleanup) is not dict
        or cleanup.get("format") != CLEANUP_FORMAT
        or cleanup.get("nonce") != exercise_report.get("nonce")
        or cleanup.get("firewall_rules_absent") is not True
        or cleanup.get("acl_restored") is not True
    ):
        raise RuntimeError("Windows cleanup was not verified")
    report = dict(exercise_report)
    report["format"] = FORMAT
    report["status"] = "passed"
    del report["nonce"]
    report["controls"]["network"]["cleanup_verified"] = True
    report["controls"]["filesystem"]["cleanup_verified"] = True
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="phase", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--source-root", type=Path, required=True)
    prepare_parser.add_argument("--freeze-report", type=Path, required=True)
    prepare_parser.add_argument("--work-root", type=Path, required=True)
    prepare_parser.add_argument("--python-minor", required=True)
    prepare_parser.add_argument("--nonce", required=True)
    prepare_parser.add_argument("--state-out", type=Path, required=True)
    exercise_parser = commands.add_parser("exercise")
    exercise_parser.add_argument("--state", type=Path, required=True)
    exercise_parser.add_argument("--boundary-report", type=Path, required=True)
    exercise_parser.add_argument("--exercise-out", type=Path, required=True)
    finalize_parser = commands.add_parser("finalize")
    finalize_parser.add_argument("--exercise-report", type=Path, required=True)
    finalize_parser.add_argument("--cleanup-report", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.phase == "prepare":
            report = prepare(arguments)
        elif arguments.phase == "exercise":
            report = exercise(arguments)
        else:
            report = finalize(arguments)
    except Exception as exc:
        report = {
            "format": "finplanbr.windows-portability-phase.v1",
            "status": "failed",
            "phase": arguments.phase,
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
