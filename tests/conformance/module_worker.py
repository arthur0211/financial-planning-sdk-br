"""Isolated child-process bridge for a Python module SUT.

The parent runner owns time/output/process-tree limits.  This bridge deliberately
does not catch implementation exceptions: they become a non-zero child exit and
are classified as a crash by the harness.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result: raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True)
    parser.add_argument("--module-root", type=Path, required=True)
    args = parser.parse_args()
    module_name, separator, callable_name = args.module.partition(":")
    sys.path.insert(0, str(args.module_root.resolve(strict=True)))
    function = getattr(importlib.import_module(module_name), callable_name if separator else "compute")
    request = json.loads(sys.stdin.read(), object_pairs_hook=reject_duplicates)
    response = function(request)
    json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__": raise SystemExit(main())
