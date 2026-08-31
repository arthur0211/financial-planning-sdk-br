"""Secondary runtime guard for installed-portability probes.

This audit hook is deliberately not presented as an operating-system sandbox.
The portability launcher must establish and prove the external network and
filesystem boundaries before evidence can pass.
"""

from __future__ import annotations

import decimal
import locale
import os
import time

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
if hasattr(os, "O_EXCL"):
    _WRITE_FLAGS |= os.O_EXCL


def _is_write_open(arguments: tuple[object, ...]) -> bool:
    target = arguments[0] if arguments else None
    # Wrapping an already-created pipe descriptor is process I/O, not a
    # filesystem open. The launcher supplies no inherited writable file.
    if isinstance(target, int):
        return False
    mode = arguments[1] if len(arguments) > 1 else None
    flags = arguments[2] if len(arguments) > 2 else 0
    if isinstance(mode, str) and any(marker in mode for marker in ("w", "a", "x", "+")):
        return True
    return isinstance(flags, int) and bool(flags & _WRITE_FLAGS)


def _guard(event: str, arguments: tuple[object, ...]) -> None:
    if event == "open" and _is_write_open(arguments):
        detail = f": {arguments[:3]!r}" if os.environ.get("FINPLANBR_PORTABILITY_GUARD_DEBUG") == "1" else ""
        raise RuntimeError(f"finplanbr portability guard blocked write{detail}")
    if event.startswith("socket."):
        raise RuntimeError("finplanbr portability guard blocked network")


if os.environ.get("FINPLANBR_PORTABILITY_GUARD") == "1":
    variant = os.environ.get("FINPLANBR_PORTABILITY_CONTEXT", "baseline")
    if variant == "hostile":
        context = decimal.getcontext()
        context.prec = 7
        context.rounding = decimal.ROUND_FLOOR
        context.Emin = -7
        context.Emax = 7
        context.traps[decimal.Inexact] = True
        context.traps[decimal.Rounded] = True
    requested_locale = os.environ.get("FINPLANBR_PORTABILITY_LOCALE", "C")
    locale.setlocale(locale.LC_ALL, requested_locale)
    if hasattr(time, "tzset"):
        time.tzset()
    elif os.name == "nt":
        import ctypes

        ctypes.CDLL("ucrtbase")._tzset()
    os.environ["FINPLANBR_PORTABILITY_GUARD_ACTIVE"] = "1"
    import sys

    sys.addaudithook(_guard)
