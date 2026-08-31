#!/usr/bin/env python3
"""Build and install the local package entirely inside a disposable directory."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import site
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import zipfile
from pathlib import Path

from jsonschema import Draft202012Validator

if __package__:
    from .bounded_subprocess import (
        BoundedProcessCleanupError,
        BoundedProcessOutputLimit,
        BoundedProcessStartError,
        BoundedProcessTimeout,
        run_bounded,
    )
else:
    from bounded_subprocess import (  # type: ignore[no-redef]
        BoundedProcessCleanupError,
        BoundedProcessOutputLimit,
        BoundedProcessStartError,
        BoundedProcessTimeout,
        run_bounded,
    )

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PACKAGE_FILES = {
    "financial_planning_sdk_br/__init__.py",
    "financial_planning_sdk_br/__main__.py",
    "financial_planning_sdk_br/_schema_validation.py",
    "financial_planning_sdk_br/_value_object.py",
    "financial_planning_sdk_br/cli.py",
    "financial_planning_sdk_br/contracts.py",
    "financial_planning_sdk_br/deterministic.py",
    "financial_planning_sdk_br/deterministic-request.schema.json",
    "financial_planning_sdk_br/deterministic-result.schema.json",
    "financial_planning_sdk_br/errors.py",
    "financial_planning_sdk_br/jsonio.py",
    "financial_planning_sdk_br/numeric.py",
    "financial_planning_sdk_br/py.typed",
    "financial_planning_sdk_br/reference.py",
    "financial_planning_sdk_br/reference-acceptance-pack.v1.json",
    "financial_planning_sdk_br/reference-acceptance-pack.v2.json",
    "financial_planning_sdk_br/reference-acceptance-report.schema.json",
    "financial_planning_sdk_br/validation-report.schema.json",
}
SMOKE_OUTPUT_LIMIT = 16 * 1024 * 1024
_TOOL_BOOTSTRAP = r"""
import importlib.machinery
import json
import os
import runpy
import sys

module = sys.argv[1]
try:
    roots = json.loads(sys.argv[2])
except (IndexError, json.JSONDecodeError):
    raise SystemExit(120)
arguments = sys.argv[3:]
if module not in {"build", "pip"}:
    raise SystemExit(121)
if type(roots) is not list or not roots or any(type(root) is not str or not os.path.isabs(root) for root in roots):
    raise SystemExit(125)
if len(roots) != len(set(roots)):
    raise SystemExit(126)
spec = importlib.machinery.PathFinder.find_spec(module, roots)
if spec is None or spec.origin is None or spec.submodule_search_locations is None:
    raise SystemExit(122)
origin = os.path.realpath(spec.origin)
locations = [os.path.realpath(item) for item in spec.submodule_search_locations]
if len(locations) != 1 or not any(os.path.commonpath((origin, root)) == root for root in map(os.path.realpath, roots)):
    raise SystemExit(123)
sys.path[:0] = roots
resolved = importlib.machinery.PathFinder.find_spec(module, roots)
if resolved is None or os.path.realpath(resolved.origin or "") != origin:
    raise SystemExit(124)
sys.argv = [module, *arguments]
runpy.run_module(module, run_name="__main__", alter_sys=True)
"""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    command: list[str], *, cwd: Path, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    completed = _run_bounded(command, cwd=cwd, environment=environment, timeout_seconds=180)
    if completed.returncode != 0:
        raise RuntimeError(f"package smoke subprocess failed with code {completed.returncode}: {command[1:3]}")
    return completed


def run_bytes(
    command: list[str], *, cwd: Path, environment: dict[str, str]
) -> subprocess.CompletedProcess[bytes]:
    completed = _run_bounded(command, cwd=cwd, environment=environment, timeout_seconds=60)
    if completed.returncode != 0:
        raise RuntimeError(f"package runtime subprocess failed with code {completed.returncode}: {command[1:3]}")
    return completed


def tool_environment(temporary_root: Path) -> dict[str, str]:
    """Return a minimal environment for origin-bound build and pip tools."""

    allowed = (
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "LANG",
        "LC_ALL",
    )
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment.update(
        {
            "HOME": os.fspath(temporary_root),
            "USERPROFILE": os.fspath(temporary_root),
            "TEMP": os.fspath(temporary_root),
            "TMP": os.fspath(temporary_root),
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PIP_NO_INDEX": "1",
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
    )
    return environment


def tool_import_roots() -> list[str]:
    """Resolve tool roots before ``-S`` can hide a Python <=3.13 venv."""

    candidates = [sysconfig.get_path("purelib"), sysconfig.get_path("platlib")]
    if sys.prefix == sys.base_prefix:
        candidates.append(site.getusersitepackages())
    roots: list[str] = []
    for candidate in candidates:
        if type(candidate) is not str or not candidate:
            continue
        resolved = os.path.realpath(candidate)
        if resolved not in roots:
            roots.append(resolved)
    if not roots:
        raise RuntimeError("package smoke could not resolve any closed tool import root")
    return roots


def run_tool(module: str, arguments: list[str], *, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    if module not in {"build", "pip"}:
        raise ValueError("package smoke tool module is outside the closed roster")
    return run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            _TOOL_BOOTSTRAP,
            module,
            json.dumps(tool_import_roots(), ensure_ascii=True, separators=(",", ":")),
            *arguments,
        ],
        cwd=cwd,
        environment=tool_environment(cwd),
    )


def _run_bounded(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return run_bounded(
            command,
            cwd=cwd,
            env=environment,
            timeout_seconds=timeout_seconds,
            stdout_limit=SMOKE_OUTPUT_LIMIT,
            stderr_limit=SMOKE_OUTPUT_LIMIT,
        )
    except BoundedProcessTimeout as exc:
        raise RuntimeError("package smoke subprocess exceeded its time budget") from exc
    except BoundedProcessOutputLimit as exc:
        raise RuntimeError(f"package smoke subprocess exceeded its {exc.stream} byte budget") from exc
    except (BoundedProcessStartError, BoundedProcessCleanupError) as exc:
        raise RuntimeError("package smoke subprocess boundary failed") from exc


def runtime_environment(package_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.fspath(package_root)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONNOUSERSITE"] = "1"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "PYTHONSTARTUP", "PYTHONINSPECT"):
        environment.pop(name, None)
    return environment


def reference_surface_bytes(*, label: str, cwd: Path, environment: dict[str, str]) -> bytes:
    command = [sys.executable, "-P", "-s", "-m", "financial_planning_sdk_br", "reference", "run"]
    first = run_bytes(command, cwd=cwd, environment=environment)
    second = run_bytes(command, cwd=cwd, environment=environment)
    sdk = run_bytes(
        [
            sys.executable,
            "-P",
            "-s",
            "-c",
            (
                "import sys; from financial_planning_sdk_br import run_reference_acceptance_pack; "
                "sys.stdout.buffer.write(run_reference_acceptance_pack().to_json_bytes() + b'\\n')"
            ),
        ],
        cwd=cwd,
        environment=environment,
    )
    if first.stderr or second.stderr or sdk.stderr:
        raise RuntimeError(f"{label} reference surface wrote unexpected stderr")
    if first.stdout != second.stdout or first.stdout != sdk.stdout:
        raise RuntimeError(f"{label} SDK and CLI reference reports are not byte-identical")
    if len(first.stdout) > 65_536:
        raise RuntimeError(f"{label} reference report exceeds the closed output budget")
    report = json.loads(first.stdout)
    if (
        report.get("status") != "local_technical_acceptance_passed"
        or report.get("case_count") != 3
        or report.get("passed_count") != 3
        or report.get("failed_count") != 0
        or report.get("provenance") != "repository_local_untrusted"
        or report.get("reference_independence") != "not_claimed"
        or report.get("authority") != "none"
        or report.get("release_authorized") is not False
    ):
        raise RuntimeError(f"{label} reference report lost its closed local draft boundary")
    return first.stdout


def precision_bound_request() -> dict[str, object]:
    def money(value: str) -> dict[str, str]:
        return {"currency": "BRL", "value": value}

    request: dict[str, object] = {
        "contract_version": "0.1.0-draft.1",
        "calculation_id": "installed_precision_bound",
        "valuation_date": "2026-01-01",
        "base_currency": "BRL",
        "use_context": {
            "purpose": "software_testing",
            "client_specific": False,
            "recommendation_enabled": False,
            "execution_enabled": False,
        },
        "discount_factors": [
            {"date": "2026-01-02", "factor": "0.000000000000000001"},
            {"date": "2026-01-03", "factor": "99999999999999999999999999999999999999"},
            {"date": "2026-01-04", "factor": "99999999999999999999999999999999999999"},
        ],
        "accounts": [],
        "events": [],
    }
    request["cashflows"] = [
        {
            "cashflow_id": f"a_tiny_{index:04d}",
            "claim_id": f"a_tiny_claim_{index:04d}",
            "event_date": "2026-01-02",
            "amount": money("0.01"),
        }
        for index in range(2)
    ] + [
        {
            "cashflow_id": f"b_positive_{index:04d}",
            "claim_id": f"b_positive_claim_{index:04d}",
            "event_date": "2026-01-03",
            "amount": money("999999999999999999999999999999999999.99"),
        }
        for index in range(2047)
    ] + [
        {
            "cashflow_id": f"c_negative_{index:04d}",
            "claim_id": f"c_negative_claim_{index:04d}",
            "event_date": "2026-01-04",
            "amount": money("-999999999999999999999999999999999999.99"),
        }
        for index in range(2047)
    ]
    return request


def precision_bound_surface_bytes(
    *, label: str, cwd: Path, environment: dict[str, str], request_path: Path
) -> bytes:
    cli = run_bytes(
        [
            sys.executable,
            "-P",
            "-s",
            "-m",
            "financial_planning_sdk_br",
            "compute",
            "deterministic",
            os.fspath(request_path),
        ],
        cwd=cwd,
        environment=environment,
    )
    sdk_program = "\n".join(
        (
            "import json, sys",
            "from decimal import ROUND_FLOOR, Context, localcontext",
            "from pathlib import Path",
            "from financial_planning_sdk_br import compute_deterministic",
            "request = json.loads(Path(sys.argv[1]).read_bytes())",
            "baseline = compute_deterministic(request).to_json_bytes()",
            "hostile = Context(prec=1, rounding=ROUND_FLOOR, Emin=-1, Emax=1, capitals=0, clamp=1)",
            "signals = tuple(sorted(hostile.flags, key=lambda signal: signal.__name__))",
            "for index, signal in enumerate(signals):",
            "    hostile.flags[signal] = index % 2 == 0",
            "    hostile.traps[signal] = False",
            "def snapshot(context):",
            "    return (context.prec, context.rounding, context.Emin, context.Emax, context.capitals, "
            "context.clamp, tuple((signal.__name__, context.flags[signal], context.traps[signal]) "
            "for signal in signals))",
            "with localcontext(hostile) as caller:",
            "    before = snapshot(caller)",
            "    observed = compute_deterministic(request).to_json_bytes()",
            "    after = snapshot(caller)",
            "if observed != baseline or after != before:",
            "    raise RuntimeError('installed hostile Decimal context changed result or caller')",
            "sys.stdout.buffer.write(baseline + b'\\n')",
        )
    )
    sdk = run_bytes(
        [sys.executable, "-P", "-s", "-c", sdk_program, os.fspath(request_path)],
        cwd=cwd,
        environment=environment,
    )
    if cli.stderr or sdk.stderr:
        raise RuntimeError(f"{label} precision-bound surface wrote unexpected stderr")
    if cli.stdout != sdk.stdout:
        raise RuntimeError(f"{label} Mapping SDK and JSON CLI precision-bound bytes differ")
    result = json.loads(cli.stdout)
    if (
        result.get("valuation", {}).get("present_value_exact") != "0.00000000000000000002"
        or len(result.get("valuation", {}).get("cashflows", [])) != 4096
    ):
        raise RuntimeError(f"{label} precision-bound result differs from the closed expectation")
    return cli.stdout


def invalid_event_budget_request() -> dict[str, object]:
    return {
        "contract_version": "0.1.0-draft.1",
        "calculation_id": "installed_error_budget",
        "valuation_date": "2026-01-01",
        "base_currency": "BRL",
        "use_context": {
            "purpose": "software_testing",
            "client_specific": False,
            "recommendation_enabled": False,
            "execution_enabled": False,
        },
        "discount_factors": [],
        "cashflows": [],
        "accounts": [],
        "events": [{"event_type": "posting"} for _ in range(4096)],
    }


def schema_surface_bytes(*, label: str, cwd: Path, environment: dict[str, str]) -> bytes:
    program = "\n".join(
        (
            "import json, sys",
            "from financial_planning_sdk_br import (deterministic_request_schema, "
            "deterministic_result_schema, reference_acceptance_report_schema, validation_report_schema)",
            "schemas = {",
            "    'deterministic-request.schema.json': deterministic_request_schema(),",
            "    'deterministic-result.schema.json': deterministic_result_schema(),",
            "    'reference-acceptance-report.schema.json': reference_acceptance_report_schema(),",
            "    'validation-report.schema.json': validation_report_schema(),",
            "}",
            "sys.stdout.buffer.write(json.dumps(schemas, ensure_ascii=False, allow_nan=False, "
            "sort_keys=True, separators=(',', ':')).encode('utf-8'))",
        )
    )
    completed = run_bytes(
        [sys.executable, "-P", "-s", "-c", program],
        cwd=cwd,
        environment=environment,
    )
    if completed.stderr:
        raise RuntimeError(f"{label} schema accessors wrote unexpected stderr")
    return completed.stdout


def closed_schema_surface_bytes(*, label: str, cwd: Path, environment: dict[str, str]) -> bytes:
    program = "\n".join(
        (
            "import json, sys",
            "from financial_planning_sdk_br._schema_validation import (ClosedSchemaError, "
            "assert_schema_instance, assert_supported_schema)",
            "draft = 'https://json-schema.org/draft/2020-12/schema'",
            "expected_id = 'urn:finplanbr:smoke:closed-schema'",
            "def root(**changes):",
            "    schema = {'$schema': draft, '$id': expected_id, '$defs': {'target': {'type': 'string'}}, "
            "'$ref': '#/$defs/target'}",
            "    schema.update(changes)",
            "    return schema",
            "attacks = {",
            "    'nested_id': root(**{'$defs': {'target': {'$id': 'urn:finplanbr:smoke:nested'}}}),",
            "    'nested_schema': root(**{'$defs': {'target': {'$schema': draft}}}),",
            "    'percent_slash_upper': root(**{'$defs': {'a%2Fb': True}, '$ref': '#/$defs/a%2Fb'}),",
            "    'percent_slash_lower': root(**{'$defs': {'a%2fb': True}, '$ref': '#/$defs/a%2fb'}),",
            "    'percent_tilde': root(**{'$defs': {'a%7Eb': True}, '$ref': '#/$defs/a%7Eb'}),",
            "    'percent_percent': root(**{'$defs': {'a%25b': True}, '$ref': '#/$defs/a%25b'}),",
            "    'escaped_tilde_literal': root(**{'$defs': {'a~1b': True}, '$ref': '#/$defs/a~1b'}),",
            "    'deep_ref': root(**{'$ref': '#/$defs/target/deeper'}),",
            "    'unresolved_ref': root(**{'$ref': '#/$defs/missing'}),",
            "    'vocabulary': root(**{'$vocabulary': {'urn:finplanbr:smoke:vocab': True}}),",
            "    'unknown_keyword': root(**{'unknownKeyword': True}),",
            "    'unsupported_format': root(**{'format': 'uri'}),",
            "    'unsupported_pattern': root(**{'pattern': '.*'}),",
            "    'direct_cycle': root(**{'$defs': {'loop': {'$ref': '#/$defs/loop'}}, "
            "'$ref': '#/$defs/loop'}),",
            "    'indirect_cycle': root(**{'$defs': {'left': {'$ref': '#/$defs/right'}, "
            "'right': {'$ref': '#/$defs/left'}}, '$ref': '#/$defs/left'}),",
            "}",
            "recursive_node = {}",
            "recursive_node['not'] = recursive_node",
            "attacks['python_object_cycle'] = root(**{'$defs': {'loop': recursive_node}, '$ref': '#/$defs/loop'})",
            "for attack, schema in attacks.items():",
            "    for operation in (lambda: assert_supported_schema(schema, expected_id=expected_id), "
            "lambda: assert_schema_instance(schema, None)):",
            "        try:",
            "            operation()",
            "        except ClosedSchemaError:",
            "            pass",
            "        except RecursionError as exc:",
            "            raise RuntimeError(f'{attack} leaked RecursionError') from exc",
            "        else:",
            "            raise RuntimeError(f'{attack} escaped closed schema admission')",
            "sys.stdout.buffer.write(json.dumps({'closed_schema_attacks': len(attacks), 'status': 'passed'}, "
            "sort_keys=True, separators=(',', ':')).encode('utf-8'))",
        )
    )
    completed = run_bytes(
        [sys.executable, "-P", "-s", "-c", program],
        cwd=cwd,
        environment=environment,
    )
    if completed.stderr:
        raise RuntimeError(f"{label} closed-schema probe wrote unexpected stderr")
    return completed.stdout


def value_object_hardening_surface_bytes(
    *,
    label: str,
    cwd: Path,
    environment: dict[str, str],
    request_path: Path,
) -> bytes:
    program = "\n".join(
        (
            "import copy, json, pickle, sys",
            "from pathlib import Path",
            "from financial_planning_sdk_br import (DeterministicResult, ReferenceAcceptanceReport, "
            "ValidationIssue, ValidationReport, compute_deterministic, run_reference_acceptance_pack)",
            "request = json.loads(Path(sys.argv[1]).read_bytes())",
            "issue = ValidationIssue('DCL_REQUIRED_FIELD', '/events', 'required field is missing')",
            "values = (issue, ValidationReport(valid=False, issues=(issue,)), "
            "compute_deterministic(request), run_reference_acceptance_pack())",
            "for value in values:",
            "    cls = type(value)",
            "    try:",
            "        tuple.__new__(cls, tuple(value))",
            "    except TypeError:",
            "        pass",
            "    else:",
            "        raise RuntimeError(f'{cls.__name__} admitted tuple base construction')",
            "    shell = object.__new__(cls)",
            "    for operation in (lambda: len(shell), lambda: tuple(shell), lambda: repr(shell)):",
            "        try:",
            "            operation()",
            "        except (AttributeError, TypeError, ValueError):",
            "            pass",
            "        else:",
            "            raise RuntimeError(f'{cls.__name__} exposed an object base shell')",
            "    for target in (value, shell):",
            "        try:",
            "            object.__setattr__(target, 'forged', b'{}')",
            "        except (AttributeError, TypeError):",
            "            pass",
            "        else:",
            "            raise RuntimeError(f'{cls.__name__} admitted object setattr state')",
            "    if copy.copy(value) is not value or copy.deepcopy(value) is not value:",
            "        raise RuntimeError(f'{cls.__name__} copy lost immutable identity')",
            "    try:",
            "        pickle.dumps(value)",
            "    except TypeError:",
            "        pass",
            "    else:",
            "        raise RuntimeError(f'{cls.__name__} admitted pickle serialization')",
            "baseline_issue = ValidationIssue.to_dict(issue)",
            "try:",
            "    object.__setattr__(issue, '__class__', ValidationReport)",
            "except TypeError:",
            "    pass",
            "else:",
            "    try:",
            "        class_swap_operations = (",
            "            lambda: ValidationIssue.to_dict(issue),",
            "            lambda: ValidationIssue.code.__get__(issue, ValidationIssue),",
            "            lambda: ValidationReport.to_dict(issue),",
            "            lambda: ValidationReport.valid.__get__(issue, ValidationReport),",
            "            lambda: len(issue),",
            "            lambda: copy.copy(issue),",
            "            lambda: copy.deepcopy(issue),",
            "            lambda: pickle.dumps(issue),",
            "        )",
            "        for operation in class_swap_operations:",
            "            try:",
            "                operation()",
            "            except (AttributeError, TypeError, ValueError):",
            "                pass",
            "            else:",
            "                raise RuntimeError('class reassignment escaped exact-type binding')",
            "    finally:",
            "        object.__setattr__(issue, '__class__', ValidationIssue)",
            "    if ValidationIssue.to_dict(issue) != baseline_issue:",
            "        raise RuntimeError('class reassignment changed registered value-object state')",
            "class SilentMixin:",
            "    def __init_subclass__(cls, **kwargs):",
            "        pass",
            "class ReorderingMeta(type):",
            "    def mro(cls):",
            "        default = super().mro()",
            "        return [cls, SilentMixin, *[entry for entry in default[1:] if entry is not SilentMixin]]",
            "def poisoned(*args, **kwargs):",
            "    raise RuntimeError('private virtual dispatch ran before exact-type rejection')",
            "for value in values:",
            "    cls = type(value)",
            "    namespace = {'_validated_sequence': poisoned}",
            "    if cls in (ValidationIssue, ValidationReport):",
            "        namespace['_document'] = poisoned",
            "    if cls is ValidationReport:",
            "        namespace['_issues_from_document'] = staticmethod(poisoned)",
            "        namespace['_omitted_from_document'] = staticmethod(poisoned)",
            "    if cls is DeterministicResult:",
            "        namespace['_validated_document'] = poisoned",
            "    if cls is ReferenceAcceptanceReport:",
            "        namespace['_validated_pair'] = poisoned",
            "    forged_types = (",
            "        type(f'ForgedLeftMro{cls.__name__}', (SilentMixin, cls), namespace),",
            "        ReorderingMeta(f'ForgedCustomMeta{cls.__name__}', (cls, SilentMixin), namespace),",
            "    )",
            "    library_base = next(base for base in cls.__mro__ if base.__name__ == '_OpaqueValueObject')",
            "    for forged_type in forged_types:",
            "        forged = object.__new__(forged_type)",
            "        operations = [",
            "            lambda: library_base.__len__(forged),",
            "            lambda: library_base.__iter__(forged),",
            "            lambda: library_base.__getitem__(forged, 0),",
            "            lambda: library_base.__contains__(forged, None),",
            "            lambda: library_base.count(forged, None),",
            "            lambda: library_base.index(forged, None),",
            "            lambda: library_base.__repr__(forged),",
            "            lambda: library_base.__eq__(forged, ()),",
            "            lambda: library_base.__lt__(forged, ()),",
            "            lambda: library_base.__hash__(forged),",
            "            lambda: library_base.__copy__(forged),",
            "            lambda: library_base.__deepcopy__(forged, {}),",
            "            lambda: pickle.dumps(forged),",
            "        ]",
            "        if cls is ValidationIssue:",
            "            operations += [lambda: ValidationIssue.to_dict(forged),",
            "                           lambda: ValidationIssue.code.__get__(forged, forged_type)]",
            "        elif cls is ValidationReport:",
            "            operations += [lambda: ValidationReport.to_dict(forged),",
            "                           lambda: ValidationReport.to_json_bytes(forged),",
            "                           lambda: ValidationReport.valid.__get__(forged, forged_type)]",
            "        elif cls is DeterministicResult:",
            "            operations += [lambda: DeterministicResult.to_dict(forged),",
            "                           lambda: DeterministicResult.to_json_bytes(forged)]",
            "        else:",
            "            operations += [lambda: ReferenceAcceptanceReport.to_dict(forged),",
            "                           lambda: ReferenceAcceptanceReport.to_json_bytes(forged),",
            "                           lambda: ReferenceAcceptanceReport.status.__get__(forged, forged_type)]",
            "        for operation in operations:",
            "            try:",
            "                operation()",
            "            except (AttributeError, TypeError, ValueError):",
            "                pass",
            "            else:",
            "                raise RuntimeError(f'{forged_type.__name__} inherited operation emitted forged state')",
            "        try:",
            "            if cls is ValidationIssue:",
            "                forged_type('DCL_REQUIRED_FIELD', '/events', 'required field is missing')",
            "            elif cls is ValidationReport:",
            "                forged_type(valid=False, issues=(issue,))",
            "            elif cls is DeterministicResult:",
            "                forged_type._from_canonical_payload(value.to_json_bytes())",
            "            else:",
            "                forged_type._from_canonical_payload(value.to_json_bytes(), value.status)",
            "        except TypeError:",
            "            pass",
            "        else:",
            "            raise RuntimeError(f'{forged_type.__name__} inherited factory registered a subclass')",
            "for terminator in ('\\n', '\\r', '\\u0085', '\\u2028', '\\u2029'):",
            "    try:",
            "        ValidationIssue('DCL_REQUIRED_FIELD', '/events' + terminator, 'required field is missing')",
            "    except ValueError:",
            "        pass",
            "    else:",
            "        raise RuntimeError('ValidationIssue admitted a line terminator')",
            "minimal_result = (b'{\"artifact_status\":\"draft\",\"authority\":\"none\",'",
            "                  b'\"computational_status\":\"computed\",\"contract_version\":'",
            "                  b'\"0.1.0-draft.1\",\"deployment_eligibility\":\"not_authorized\",'",
            "                  b'\"engine_version\":\"0.1.0.dev0\",\"result_format\":'",
            "                  b'\"finplanbr.deterministic-cashflow-ledger-result.v1\"}')",
            "try:",
            "    DeterministicResult._from_canonical_payload(minimal_result)",
            "except ValueError:",
            "    pass",
            "else:",
            "    raise RuntimeError('DeterministicResult admitted a schema-invalid minimum')",
            "minimal_reference = (b'{\"report_format\":\"finplanbr.reference-acceptance-report.v2\",'",
            "                     b'\"status\":\"local_technical_acceptance_passed\"}')",
            "try:",
            "    ReferenceAcceptanceReport._from_canonical_payload(",
            "        minimal_reference, 'local_technical_acceptance_passed')",
            "except ValueError:",
            "    pass",
            "else:",
            "    raise RuntimeError('ReferenceAcceptanceReport admitted a schema-invalid minimum')",
            "sys.stdout.buffer.write(b'{\"status\":\"passed\",\"value_objects\":4}')",
        )
    )
    completed = run_bytes(
        [sys.executable, "-P", "-s", "-c", program, os.fspath(request_path)],
        cwd=cwd,
        environment=environment,
    )
    if completed.stderr:
        raise RuntimeError(f"{label} value-object hardening probe wrote unexpected stderr")
    return completed.stdout


def invalid_event_surface_bytes(
    *,
    label: str,
    cwd: Path,
    environment: dict[str, str],
    request_path: Path,
    validator: Draft202012Validator,
) -> tuple[bytes, bytes]:
    payloads: list[bytes] = []
    routes = (
        ("validate", os.fspath(request_path)),
        ("compute", "deterministic", os.fspath(request_path)),
    )
    for index, route in enumerate(routes):
        completed = _run_bounded(
            [sys.executable, "-P", "-s", "-m", "financial_planning_sdk_br", *route],
            cwd=cwd,
            environment=environment,
            timeout_seconds=60,
        )
        if completed.returncode != 2:
            raise RuntimeError(f"{label} invalid-event route did not return RC2")
        if b"Traceback" in completed.stdout or b"Traceback" in completed.stderr:
            raise RuntimeError(f"{label} invalid-event route exposed a traceback")
        payload = completed.stdout if index == 0 else completed.stderr
        other = completed.stderr if index == 0 else completed.stdout
        if other:
            raise RuntimeError(f"{label} invalid-event route wrote to the wrong stream")
        report = json.loads(payload)
        if list(validator.iter_errors(report)):
            raise RuntimeError(f"{label} invalid-event report is not schema-valid")
        if (
            report.get("report_format") != "finplanbr.validation-report.v2"
            or len(report.get("issues", [])) != 128
            or "issue_count" in report
            or report.get("truncation")
            != {"status": "truncated", "omitted_issue_count": 81_790}
        ):
            raise RuntimeError(f"{label} invalid-event report lost its bounded truncation semantics")
        payloads.append(payload)
    return payloads[0], payloads[1]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="finplanbr-package-smoke-") as directory:
        root = Path(directory)
        candidate = root / "candidate"
        candidate.mkdir()
        shutil.copy2(REPOSITORY_ROOT / "pyproject.toml", candidate / "pyproject.toml")
        shutil.copy2(REPOSITORY_ROOT / "README.md", candidate / "README.md")
        shutil.copy2(REPOSITORY_ROOT / "LICENSE", candidate / "LICENSE")
        shutil.copytree(
            REPOSITORY_ROOT / "src", candidate / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
        )
        output = root / "dist"
        run_tool(
            "build",
            [
                "--wheel",
                "--no-isolation",
                "--outdir",
                os.fspath(output),
            ],
            cwd=candidate,
        )
        run_tool(
            "build",
            [
                "--sdist",
                "--no-isolation",
                "--outdir",
                os.fspath(output),
            ],
            cwd=candidate,
        )
        wheels = sorted(output.glob("*.whl"))
        sdists = sorted(output.glob("*.tar.gz"))
        if len(wheels) != 1 or len(sdists) != 1:
            raise RuntimeError("explicit source builds did not produce exactly one direct wheel and one sdist")

        with zipfile.ZipFile(wheels[0]) as archive:
            wheel_payload = {
                name
                for name in archive.namelist()
                if name.startswith("financial_planning_sdk_br/") and not name.endswith("/")
            }
        if wheel_payload != EXPECTED_PACKAGE_FILES:
            missing = sorted(EXPECTED_PACKAGE_FILES - wheel_payload)
            extra = sorted(wheel_payload - EXPECTED_PACKAGE_FILES)
            raise RuntimeError(f"wheel package payload differs from the closed local inventory: {missing=}; {extra=}")

        with tarfile.open(sdists[0], mode="r:gz") as archive:
            sdist_names = {member.name for member in archive.getmembers() if member.isfile()}
        for relative in EXPECTED_PACKAGE_FILES:
            suffix = f"/src/{relative}"
            if not any(name.endswith(suffix) for name in sdist_names):
                raise RuntimeError("sdist omits a required package file")

        source_reference = reference_surface_bytes(
            label="source",
            cwd=root,
            environment=runtime_environment(candidate / "src"),
        )
        hardening_request_path = REPOSITORY_ROOT / "examples" / "deterministic-cashflow-ledger.json"
        source_hardening = value_object_hardening_surface_bytes(
            label="source",
            cwd=root,
            environment=runtime_environment(candidate / "src"),
            request_path=hardening_request_path,
        )
        schema_names = (
            "deterministic-request.schema.json",
            "deterministic-result.schema.json",
            "reference-acceptance-report.schema.json",
            "validation-report.schema.json",
        )
        schema_documents = {
            name: json.loads((candidate / "src" / "financial_planning_sdk_br" / name).read_bytes())
            for name in schema_names
        }
        for schema in schema_documents.values():
            Draft202012Validator.check_schema(schema)
        expected_schema_surface = json.dumps(
            schema_documents,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        validation_validator = Draft202012Validator(schema_documents["validation-report.schema.json"])
        source_schema_surface = schema_surface_bytes(
            label="source",
            cwd=root,
            environment=runtime_environment(candidate / "src"),
        )
        if source_schema_surface != expected_schema_surface:
            raise RuntimeError("source schema accessors differ from the four packaged schema files")
        source_closed_schema = closed_schema_surface_bytes(
            label="source",
            cwd=root,
            environment=runtime_environment(candidate / "src"),
        )
        error_request_path = root / "invalid-event-budget-request.json"
        error_request_path.write_bytes(
            json.dumps(
                invalid_event_budget_request(),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        source_error_reports = invalid_event_surface_bytes(
            label="source",
            cwd=root,
            environment=runtime_environment(candidate / "src"),
            request_path=error_request_path,
            validator=validation_validator,
        )
        precision_request_path = root / "precision-bound-request.json"
        precision_request_path.write_bytes(
            json.dumps(
                precision_bound_request(),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        source_precision = precision_bound_surface_bytes(
            label="source",
            cwd=root,
            environment=runtime_environment(candidate / "src"),
            request_path=precision_request_path,
        )

        target = root / "installed-wheel"
        run_tool(
            "pip",
            ["install", "--no-deps", "--target", os.fspath(target), os.fspath(wheels[0])],
            cwd=root,
        )
        environment = runtime_environment(target)
        completed = run(
            [
                sys.executable,
                "-m",
                "financial_planning_sdk_br",
                "compute",
                "deterministic",
                os.fspath(REPOSITORY_ROOT / "examples" / "deterministic-cashflow-ledger.json"),
            ],
            cwd=root,
            environment=environment,
        )
        result = json.loads(completed.stdout)
        if result.get("authority") != "none" or result.get("deployment_eligibility") != "not_authorized":
            raise RuntimeError("installed-wheel smoke result lost its authority boundary")
        if result.get("valuation", {}).get("present_value") != "-1.60":
            raise RuntimeError("installed-wheel smoke result differs from the golden calculation")

        wheel_reference = reference_surface_bytes(
            label="installed wheel",
            cwd=root,
            environment=environment,
        )
        wheel_hardening = value_object_hardening_surface_bytes(
            label="installed wheel",
            cwd=root,
            environment=environment,
            request_path=hardening_request_path,
        )
        wheel_schema_surface = schema_surface_bytes(
            label="installed wheel",
            cwd=root,
            environment=environment,
        )
        wheel_closed_schema = closed_schema_surface_bytes(
            label="installed wheel",
            cwd=root,
            environment=environment,
        )
        wheel_error_reports = invalid_event_surface_bytes(
            label="installed wheel",
            cwd=root,
            environment=environment,
            request_path=error_request_path,
            validator=validation_validator,
        )
        wheel_precision = precision_bound_surface_bytes(
            label="installed wheel",
            cwd=root,
            environment=environment,
            request_path=precision_request_path,
        )

        rebuilt_output = root / "sdist-wheel"
        rebuilt_output.mkdir()
        run_tool(
            "pip",
            [
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--no-cache-dir",
                "--no-index",
                "--wheel-dir",
                os.fspath(rebuilt_output),
                os.fspath(sdists[0]),
            ],
            cwd=root,
        )
        rebuilt_wheels = sorted(rebuilt_output.glob("*.whl"))
        if len(rebuilt_wheels) != 1:
            raise RuntimeError("sdist did not build exactly one wheel")
        with zipfile.ZipFile(rebuilt_wheels[0]) as archive:
            rebuilt_payload = {
                name
                for name in archive.namelist()
                if name.startswith("financial_planning_sdk_br/") and not name.endswith("/")
            }
        if rebuilt_payload != EXPECTED_PACKAGE_FILES:
            raise RuntimeError("wheel built from sdist differs from the closed local package inventory")

        sdist_target = root / "installed-sdist-wheel"
        run_tool(
            "pip",
            [
                "install",
                "--no-deps",
                "--target",
                os.fspath(sdist_target),
                os.fspath(rebuilt_wheels[0]),
            ],
            cwd=root,
        )
        sdist_reference = reference_surface_bytes(
            label="installed wheel built from sdist",
            cwd=root,
            environment=runtime_environment(sdist_target),
        )
        sdist_environment = runtime_environment(sdist_target)
        sdist_hardening = value_object_hardening_surface_bytes(
            label="installed wheel built from sdist",
            cwd=root,
            environment=sdist_environment,
            request_path=hardening_request_path,
        )
        sdist_schema_surface = schema_surface_bytes(
            label="installed wheel built from sdist",
            cwd=root,
            environment=sdist_environment,
        )
        sdist_closed_schema = closed_schema_surface_bytes(
            label="installed wheel built from sdist",
            cwd=root,
            environment=sdist_environment,
        )
        sdist_error_reports = invalid_event_surface_bytes(
            label="installed wheel built from sdist",
            cwd=root,
            environment=sdist_environment,
            request_path=error_request_path,
            validator=validation_validator,
        )
        sdist_precision = precision_bound_surface_bytes(
            label="installed wheel built from sdist",
            cwd=root,
            environment=sdist_environment,
            request_path=precision_request_path,
        )
        if source_reference != wheel_reference or source_reference != sdist_reference:
            raise RuntimeError("source, wheel, and sdist-built-wheel reference reports are not byte-identical")
        if source_hardening != wheel_hardening or source_hardening != sdist_hardening:
            raise RuntimeError("source, wheel, and sdist-built-wheel hardening probes are not byte-identical")
        if source_precision != wheel_precision or source_precision != sdist_precision:
            raise RuntimeError("source, wheel, and sdist-built-wheel precision-bound results are not byte-identical")
        if source_schema_surface != wheel_schema_surface or source_schema_surface != sdist_schema_surface:
            raise RuntimeError("source, wheel, and sdist-built-wheel four-schema accessors are not byte-identical")
        if source_closed_schema != wheel_closed_schema or source_closed_schema != sdist_closed_schema:
            raise RuntimeError("source, wheel, and sdist-built-wheel closed-schema probes are not byte-identical")
        if source_error_reports != wheel_error_reports or source_error_reports != sdist_error_reports:
            raise RuntimeError("source, wheel, and sdist-built-wheel bounded error reports are not byte-identical")

        print(
            json.dumps(
                {
                    "format": "finplanbr.local-package-smoke.v1",
                    "status": "passed",
                    "wheel": {"name": wheels[0].name, "sha256": digest(wheels[0])},
                    "sdist": {"name": sdists[0].name, "sha256": digest(sdists[0])},
                    "sdist_built_wheel": {
                        "name": rebuilt_wheels[0].name,
                        "sha256": digest(rebuilt_wheels[0]),
                    },
                    "installed_cli_present_value": "-1.60",
                    "installed_reference_cases": 3,
                    "installed_precision_bound_cashflows": 4096,
                    "installed_precision_bound_exact": "0.00000000000000000002",
                    "installed_invalid_event_issue_count": 81_918,
                    "installed_invalid_event_reported_issues": 128,
                    "installed_public_schema_accessors": 4,
                    "installed_closed_schema_attacks": 16,
                    "installed_public_value_objects_hardened": 4,
                    "sdk_cli_reference_bytes_identical": True,
                    "source_wheel_sdist_reference_bytes_identical": True,
                    "source_wheel_sdist_value_object_hardening_identical": True,
                    "source_wheel_sdist_precision_bytes_identical": True,
                    "source_wheel_sdist_four_schema_accessors_identical": True,
                    "source_wheel_sdist_closed_schema_boundary_identical": True,
                    "source_wheel_sdist_bounded_error_bytes_identical": True,
                    "authority": "none",
                    "release_authorized": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
