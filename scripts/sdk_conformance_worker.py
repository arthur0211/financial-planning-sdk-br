"""Fixed subprocess worker for the local SDK conformance diagnostic.

The parent process owns corpus checks, expectations and time limits.  This
worker only loads the explicit source tree and executes the public SDK or the
closed vector adapter.  It deliberately uses no third-party dependency.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import json
import sys
from decimal import ROUND_FLOOR, Context, localcontext
from pathlib import Path
from typing import Any

BATCH_PROTOCOL = "finplanbr.local-sdk-conformance-batch.v1"
RESPONSE_PROTOCOL = "finplanbr.local-sdk-conformance-batch-response.v1"


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _closed_path(path: Path, required_child: str) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_dir() or not (resolved / required_child).is_file():
        raise ValueError("worker source root does not contain the required entrypoint")
    return resolved


def _context_snapshot(context: Context) -> dict[str, Any]:
    signals = tuple(sorted(context.flags, key=lambda signal: signal.__name__))
    return {
        "prec": context.prec,
        "rounding": context.rounding,
        "Emin": context.Emin,
        "Emax": context.Emax,
        "capitals": context.capitals,
        "clamp": context.clamp,
        "signals": [
            {
                "name": signal.__name__,
                "flag": context.flags[signal],
                "trap": context.traps[signal],
            }
            for signal in signals
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    args = parser.parse_args(argv)

    source_root = _closed_path(args.source_root, "financial_planning_sdk_br/__init__.py")
    repository_root = _closed_path(args.repository_root, "tests/sdk/vector_adapter.py")
    sys.path[:0] = [str(source_root), str(repository_root)]

    document = json.loads(
        sys.stdin.buffer.read().decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_constant,
    )
    if not isinstance(document, dict) or set(document) != {"protocol", "cases"}:
        raise ValueError("batch request must contain exactly protocol and cases")
    if document.get("protocol") != BATCH_PROTOCOL:
        raise ValueError("unsupported batch protocol")
    cases = document.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 256:
        raise ValueError("batch must contain between 1 and 256 cases")

    sdk = importlib.import_module("financial_planning_sdk_br")
    vector_adapter = importlib.import_module("tests.sdk.vector_adapter")
    responses: list[dict[str, Any]] = []
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"case_id", "operation", "payload"}:
            raise ValueError("case must use the closed worker envelope")
        case_id = case.get("case_id")
        operation = case.get("operation")
        payload = case.get("payload")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise ValueError("case_id must be a unique non-empty string")
        if not isinstance(payload, dict):
            raise ValueError("case payload must be an object")
        seen.add(case_id)
        try:
            if operation == "vector":
                output = vector_adapter.compute(payload)
            elif operation == "compute":
                output = sdk.compute_deterministic(payload).to_dict()
            elif operation == "validate":
                output = sdk.validate_deterministic_request(payload).to_dict()
            elif operation == "reference":
                if payload:
                    raise ValueError("reference operation payload must be empty")
                output = sdk.run_reference_acceptance_pack().to_dict()
            elif operation in {"compute_hostile_context", "compute_pv_hostile_context"}:
                hostile = Context(prec=1, rounding=ROUND_FLOOR, Emin=-9, Emax=9, capitals=0, clamp=1)
                for signal_index, signal in enumerate(sorted(hostile.flags, key=lambda item: item.__name__)):
                    hostile.flags[signal] = signal_index % 2 == 0
                    hostile.traps[signal] = False
                with localcontext(hostile) as caller:
                    before = _context_snapshot(caller)
                    result = sdk.compute_deterministic(payload).to_dict()
                    after = _context_snapshot(caller)
                if operation == "compute_hostile_context":
                    output = {"context_preserved": before == after, "result": result}
                else:
                    output = {
                        "context_preserved": before == after,
                        "valuation": {
                            "present_value_exact": result["valuation"]["present_value_exact"],
                            "present_value": result["valuation"]["present_value"],
                        },
                    }
            elif operation in {"compute_parsed_object", "compute_replaced_object"}:
                deterministic = importlib.import_module("financial_planning_sdk_br.deterministic")
                request = deterministic._parse_deterministic_request(payload)
                if operation == "compute_replaced_object":
                    request = dataclasses.replace(
                        request,
                        base_currency="USD",
                        recommendation_enabled=True,
                        execution_enabled=True,
                    )
                output = sdk.compute_deterministic(request).to_dict()
            else:
                raise ValueError("unsupported worker operation")
        except sdk.InputValidationError as exc:
            output = {"raised_validation_error": exc.report.to_dict()}
        responses.append({"case_id": case_id, "output": output})

    json.dump(
        {
            "protocol": RESPONSE_PROTOCOL,
            "responses": responses,
            "subject": {
                "distribution": "finplanbr",
                "module": "financial_planning_sdk_br",
                "version": sdk.__version__,
            },
        },
        sys.stdout,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
