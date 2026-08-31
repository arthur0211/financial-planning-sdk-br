"""Run the dedicated fail-closed governance mutation suite."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    return subprocess.call(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(root / "tests" / "governance"),
            "-p",
            "test_*.py",
            "-v",
        ],
        cwd=root,
    )


if __name__ == "__main__":
    raise SystemExit(main())
