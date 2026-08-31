#!/usr/bin/env python3
"""Observe the installed SDK and CLI without writing during product routes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import locale
import os
import subprocess
import sys
import time
from decimal import getcontext
from pathlib import Path
from typing import Any

if __package__:
    from .bounded_subprocess import run_bounded
else:
    boundary_path = Path(__file__).resolve().with_name("bounded_subprocess.py")
    boundary_spec = importlib.util.spec_from_file_location("_finplanbr_bounded_subprocess", boundary_path)
    if boundary_spec is None or boundary_spec.loader is None:
        raise RuntimeError("bounded subprocess helper could not be loaded")
    boundary_module = importlib.util.module_from_spec(boundary_spec)
    boundary_spec.loader.exec_module(boundary_module)
    run_bounded = boundary_module.run_bounded

FORMAT = "finplanbr.installed-portability-probe.v1"
PROBE_OUTPUT_LIMIT = 1024 * 1024


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _encoded(payload: bytes) -> dict[str, object]:
    return {
        "base64": base64.b64encode(payload).decode("ascii"),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _run_cli(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
    ):
        environment.pop(name, None)
    return run_bounded(
        [sys.executable, "-P", "-s", "-m", "financial_planning_sdk_br", *arguments],
        cwd=Path.cwd(),
        env=environment,
        timeout_seconds=30,
        stdout_limit=PROBE_OUTPUT_LIMIT,
        stderr_limit=PROBE_OUTPUT_LIMIT,
    )


def _run_console(executable: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    return run_bounded(
        [os.fspath(executable), *arguments],
        cwd=Path.cwd(),
        env=environment,
        timeout_seconds=30,
        stdout_limit=PROBE_OUTPUT_LIMIT,
        stderr_limit=PROBE_OUTPUT_LIMIT,
    )


def _assert_cli(
    *,
    label: str,
    arguments: list[str],
    expected_rc: int,
    expected_stdout: bytes,
    expected_stderr: bytes = b"",
) -> dict[str, object]:
    completed = _run_cli(arguments)
    if completed.returncode != expected_rc:
        raise RuntimeError(f"{label} returned RC {completed.returncode}, expected {expected_rc}")
    if completed.stdout != expected_stdout or completed.stderr != expected_stderr:
        raise RuntimeError(f"{label} SDK/CLI bytes differ")
    return {
        "rc": completed.returncode,
        "stdout": _encoded(completed.stdout),
        "stderr": _encoded(completed.stderr),
    }


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if type(value) is not dict:
        raise RuntimeError("probe fixture root must be an exact JSON object")
    return value


def _relative_origin(module_file: str, expected_root: Path) -> str:
    origin = Path(module_file).resolve(strict=True)
    root = expected_root.resolve(strict=True)
    try:
        return origin.relative_to(root).as_posix()
    except ValueError as exc:
        raise RuntimeError("package import origin escaped the expected surface") from exc


def observe(arguments: argparse.Namespace) -> dict[str, object]:
    if os.environ.get("FINPLANBR_PORTABILITY_GUARD_ACTIVE") != "1":
        raise RuntimeError("secondary portability guard did not load")

    import financial_planning_sdk_br as sdk

    valid = _read_json_object(arguments.valid_input)
    invalid = _read_json_object(arguments.invalid_input)
    origin = _relative_origin(sdk.__file__, arguments.expected_origin_root)

    valid_report = sdk.validate_deterministic_request(valid)
    valid_bytes = valid_report.to_json_bytes() + b"\n"
    valid_cli = _assert_cli(
        label="validate-valid",
        arguments=["validate", os.fspath(arguments.valid_input)],
        expected_rc=0,
        expected_stdout=valid_bytes,
    )

    result = sdk.compute_deterministic(valid)
    result_bytes = result.to_json_bytes() + b"\n"
    compute_cli = _assert_cli(
        label="compute-valid",
        arguments=["compute", "deterministic", os.fspath(arguments.valid_input)],
        expected_rc=0,
        expected_stdout=result_bytes,
    )

    invalid_report = sdk.validate_deterministic_request(invalid)
    invalid_bytes = invalid_report.to_json_bytes() + b"\n"
    invalid_validate_cli = _assert_cli(
        label="validate-invalid",
        arguments=["validate", os.fspath(arguments.invalid_input)],
        expected_rc=2,
        expected_stdout=invalid_bytes,
    )
    try:
        sdk.compute_deterministic(invalid)
    except sdk.InputValidationError as exc:
        invalid_compute_bytes = exc.report.to_json_bytes() + b"\n"
    else:
        raise RuntimeError("invalid SDK compute did not fail closed")
    invalid_compute_cli = _assert_cli(
        label="compute-invalid",
        arguments=["compute", "deterministic", os.fspath(arguments.invalid_input)],
        expected_rc=2,
        expected_stdout=b"",
        expected_stderr=invalid_compute_bytes,
    )

    reference_bytes = sdk.run_reference_acceptance_pack().to_json_bytes() + b"\n"
    reference_cli = _assert_cli(
        label="reference",
        arguments=["reference", "run"],
        expected_rc=0,
        expected_stdout=reference_bytes,
    )

    malformed_validate = _run_cli(["validate", os.fspath(arguments.malformed_input)])
    malformed_compute = _run_cli(["compute", "deterministic", os.fspath(arguments.malformed_input)])
    if malformed_validate.returncode != 2 or malformed_compute.returncode != 2:
        raise RuntimeError("malformed JSON routes did not return RC2")
    if (
        malformed_validate.stdout
        or malformed_compute.stdout
        or malformed_validate.stderr != malformed_compute.stderr
        or b"DCL_JSON_INPUT" not in malformed_validate.stderr
        or b"Traceback" in malformed_validate.stderr
    ):
        raise RuntimeError("malformed JSON routes lost canonical redacted parity")

    schema_documents = {
        "deterministic-request.schema.json": sdk.deterministic_request_schema(),
        "deterministic-result.schema.json": sdk.deterministic_result_schema(),
        "reference-acceptance-report.schema.json": sdk.reference_acceptance_report_schema(),
        "validation-report.schema.json": sdk.validation_report_schema(),
    }
    schema_bytes = _canonical(schema_documents)
    reason_code_bytes = _canonical(sorted(sdk.DETERMINISTIC_REASON_CODES))
    invalid_codes = {issue.code for issue in invalid_report.issues}
    if not invalid_codes or not invalid_codes.issubset(set(sdk.DETERMINISTIC_REASON_CODES)):
        raise RuntimeError("invalid route emitted a reason code outside the public roster")

    console_entrypoint: dict[str, object] | None = None
    if arguments.console_script is not None:
        module_version = _run_cli(["--version"])
        console_commands = (
            ("version", ["--version"], module_version),
            (
                "validate_valid",
                ["validate", os.fspath(arguments.valid_input)],
                _run_cli(["validate", os.fspath(arguments.valid_input)]),
            ),
            (
                "compute_valid",
                ["compute", "deterministic", os.fspath(arguments.valid_input)],
                _run_cli(["compute", "deterministic", os.fspath(arguments.valid_input)]),
            ),
            (
                "validate_invalid",
                ["validate", os.fspath(arguments.invalid_input)],
                _run_cli(["validate", os.fspath(arguments.invalid_input)]),
            ),
            (
                "compute_invalid",
                ["compute", "deterministic", os.fspath(arguments.invalid_input)],
                _run_cli(["compute", "deterministic", os.fspath(arguments.invalid_input)]),
            ),
            ("reference", ["reference", "run"], _run_cli(["reference", "run"])),
            (
                "validate_malformed",
                ["validate", os.fspath(arguments.malformed_input)],
                malformed_validate,
            ),
            (
                "compute_malformed",
                ["compute", "deterministic", os.fspath(arguments.malformed_input)],
                malformed_compute,
            ),
        )
        console_routes: dict[str, object] = {}
        for label, command, module_result in console_commands:
            installed_result = _run_console(arguments.console_script, command)
            if (
                installed_result.returncode != module_result.returncode
                or installed_result.stdout != module_result.stdout
                or installed_result.stderr != module_result.stderr
            ):
                raise RuntimeError(f"installed console script differs from module CLI for {label}")
            console_routes[label] = {
                "rc": installed_result.returncode,
                "stdout": _encoded(installed_result.stdout),
                "stderr": _encoded(installed_result.stderr),
            }
        console_entrypoint = {
            "command_count": len(console_commands),
            "routes": console_routes,
        }

    routes = {
        "compute_invalid": invalid_compute_cli,
        "compute_valid": compute_cli,
        "reference": reference_cli,
        "validate_invalid": invalid_validate_cli,
        "validate_valid": valid_cli,
        "malformed_json": {
            "rc": 2,
            "stderr": _encoded(malformed_validate.stderr),
            "stdout": _encoded(b""),
        },
    }
    parity_basis = {
        "routes": routes,
        "schemas": _encoded(schema_bytes),
        "reason_codes": _encoded(reason_code_bytes),
    }
    return {
        "format": FORMAT,
        "status": "passed",
        "package_version": sdk.__version__,
        "package_origin": origin,
        "python": {
            "implementation": sys.implementation.name,
            "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
        "runtime_context": {
            "decimal_Emax": getcontext().Emax,
            "decimal_Emin": getcontext().Emin,
            "decimal_precision": getcontext().prec,
            "decimal_rounding": getcontext().rounding,
            "hash_seed": os.environ.get("PYTHONHASHSEED"),
            "locale": locale.setlocale(locale.LC_ALL),
            "tz": os.environ.get("TZ"),
            "tz_epoch_local": list(time.localtime(0)[:6]),
        },
        "reason_code_count": len(sdk.DETERMINISTIC_REASON_CODES),
        "schema_count": len(schema_documents),
        "sdk_cli_bytes_identical": True,
        "console_entrypoint": console_entrypoint,
        "parity_basis": parity_basis,
        "parity_sha256": hashlib.sha256(_canonical(parity_basis)).hexdigest(),
        "authority": "none",
        "release_authorized": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--valid-input", type=Path, required=True)
    parser.add_argument("--invalid-input", type=Path, required=True)
    parser.add_argument("--malformed-input", type=Path, required=True)
    parser.add_argument("--expected-origin-root", type=Path, required=True)
    parser.add_argument("--console-script", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        report = observe(_parser().parse_args(argv))
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
