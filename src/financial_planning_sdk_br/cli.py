"""Command-line interface for the local deterministic slice."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal, cast

from . import __version__
from .deterministic import compute_deterministic, validate_deterministic_request
from .errors import InputValidationError, ValidationIssue, ValidationReport
from .jsonio import (
    MAX_DETERMINISTIC_REQUEST_NODES,
    JsonContractError,
    JsonObject,
    read_json_file,
    write_atomic,
)
from .reference import run_reference_acceptance_pack

_REFERENCE_FAILURE = b"reference report could not be produced safely\n"
_VALIDATION_REPORT_FALLBACK = (
    b'{"authority":"none","contract_version":"0.1.0-draft.1",'
    b'"deployment_eligibility":"not_authorized",'
    b'"issues":[{"code":"DCL_OUTPUT_WRITE","message":'
    b'"validation report could not be serialized under the closed output contract",'
    b'"pointer":""}],"report_format":"finplanbr.validation-report.v2",'
    b'"truncation":{"status":"complete"},"valid":false}\n'
)
_ReportWrite = Literal["report", "fallback", "failed"]


class _DeterministicArgumentParser(argparse.ArgumentParser):
    """Keep help and parser construction independent of terminal color support."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if sys.version_info >= (3, 14):
            kwargs["color"] = False
        super().__init__(*args, **kwargs)


def _parser() -> argparse.ArgumentParser:
    parser = _DeterministicArgumentParser(
        prog="finplanbr",
        description="Local deterministic financial-planning arithmetic; no advice or regulatory authority.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate one deterministic JSON request")
    validate.add_argument("input", type=Path)

    compute = commands.add_parser("compute", help="run a bounded local computation")
    compute_commands = compute.add_subparsers(dest="calculation", required=True)
    deterministic = compute_commands.add_parser(
        "deterministic", help="compute present value and replay a deterministic cash-flow ledger"
    )
    deterministic.add_argument("input", type=Path)
    deterministic.add_argument("--output", type=Path)
    deterministic.add_argument("--force", action="store_true", help="replace an existing explicit output path")

    reference = commands.add_parser("reference", help="run the bundled synthetic local acceptance pack")
    reference_commands = reference.add_subparsers(dest="reference_action", required=True)
    reference_commands.add_parser(
        "run",
        help="emit a canonical machine-readable local acceptance report",
        description=(
            "Run the three bundled synthetic cases.\n"
            "Report format: finplanbr.reference-acceptance-report.v2."
        ),
        epilog=(
            "Exit 0: local technical reproduction passed.\n"
            "Exit 1: a case or bundled pack failed.\n"
            "Inspect: diagnostics[].code, location, scope, remediation_id.\n"
            "Remediation IDs:\n"
            "  reinstall_distribution\n"
            "  verify_installed_versions\n"
            "  inspect_bundled_pack_drift\n"
            "  inspect_case_output_mismatch\n"
            "This command provides no release, regulatory, or professional authority."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    return parser


def _json_error(code: str, message: str) -> ValidationReport:
    return ValidationReport(
        valid=False,
        issues=(ValidationIssue(code=code, pointer="", message=message),),
    )


def _write_once(payload: bytes, *, stream: Any) -> bool:
    try:
        written = stream.buffer.write(payload)
        if written != len(payload):
            return False
        stream.flush()
    except (OSError, ValueError):
        return False
    return True


def _emit_report(report: ValidationReport, *, stream: Any) -> _ReportWrite:
    try:
        payload = report.to_json_bytes() + b"\n"
    except Exception:  # fixed redacted fallback is independent of candidate report state
        return "fallback" if _write_once(_VALIDATION_REPORT_FALLBACK, stream=stream) else "failed"
    return "report" if _write_once(payload, stream=stream) else "failed"


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "reference":
        try:
            reference_report = run_reference_acceptance_pack()
            output = reference_report.to_json_bytes() + b"\n"
        except Exception:  # fail before stdout and never expose pack/runtime values
            try:
                sys.stderr.buffer.write(_REFERENCE_FAILURE)
                sys.stderr.flush()
            except OSError:
                pass
            return 1
        try:
            written = sys.stdout.buffer.write(output)
            if written != len(output):
                return 1
            sys.stdout.flush()
        except OSError:
            return 1
        return 0 if reference_report.status == "local_technical_acceptance_passed" else 1

    try:
        document = read_json_file(arguments.input, max_nodes=MAX_DETERMINISTIC_REQUEST_NODES)
    except (OSError, JsonContractError):
        report = _json_error("DCL_JSON_INPUT", "input could not be acquired as one stable strict JSON file")
        return 2 if _emit_report(report, stream=sys.stderr) == "report" else 1

    request = cast(JsonObject, document)

    if arguments.command == "validate":
        report = validate_deterministic_request(request)
        if _emit_report(report, stream=sys.stdout) != "report":
            return 1
        return 0 if report.valid else 2

    try:
        result = compute_deterministic(request)
    except InputValidationError as exc:
        return 2 if _emit_report(exc.report, stream=sys.stderr) == "report" else 1
    payload = result.to_json_bytes() + b"\n"
    if arguments.output is None:
        return 0 if _write_once(payload, stream=sys.stdout) else 1
    try:
        write_atomic(arguments.output, payload, overwrite=arguments.force)
    except (OSError, FileExistsError):
        report = _json_error("DCL_OUTPUT_WRITE", "output could not be written atomically under the requested policy")
        _emit_report(report, stream=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
