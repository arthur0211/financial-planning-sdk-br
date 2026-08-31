#!/usr/bin/env python3
"""Emit one explicit reachability control for the portability launcher."""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect", choices=("reachable", "blocked"), required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--host", default="1.1.1.1")
    parser.add_argument("--port", type=int, default=443)
    arguments = parser.parse_args(argv)
    connected = False
    error_type: str | None = None
    try:
        with socket.create_connection((arguments.host, arguments.port), timeout=5):
            connected = True
    except OSError as exc:
        error_type = type(exc).__name__
    passed = connected is (arguments.expect == "reachable")
    report = {
        "format": "finplanbr.portability-network-control.v1",
        "status": "passed" if passed else "failed",
        "expectation": arguments.expect,
        "connected": connected,
        "error_type": error_type,
        "endpoint": f"{arguments.host}:{arguments.port}",
        "nonce": arguments.nonce,
        "platform": platform.system().lower(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }
    os.write(1, _canonical(report) + b"\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
