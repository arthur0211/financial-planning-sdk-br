"""Bounded subprocess execution for local diagnostic harnesses.

The boundary is deliberately operational rather than authoritative.  On
Windows, a fixed Python bootstrap waits for a one-byte parent gate; the parent
assigns that harmless bootstrap to a kill-on-close Job Object before allowing
it to replace itself with the requested command.  On POSIX, the command starts
in a new session and cleanup targets its process group.  A POSIX descendant
can still escape with ``setsid``/``setpgid``; callers must report that limit
instead of presenting this helper as a sandbox.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any

_START_GATE = b"\x00"
_GATE_BOOTSTRAP = (
    "import os,subprocess,sys\n"
    "if os.read(0,1) != b'\\x00': raise SystemExit(120)\n"
    "argv = sys.argv[1:]\n"
    "if not argv: raise SystemExit(121)\n"
    "raise SystemExit(subprocess.run(argv,check=False).returncode)\n"
)
ENVELOPE_FORMAT = "finplanbr.bounded-subprocess-envelope.v1"


class BoundedProcessError(RuntimeError):
    """Base class for failures produced by the subprocess boundary."""


class BoundedProcessStartError(BoundedProcessError):
    """The process boundary could not be created before candidate execution."""


class BoundedProcessTimeout(BoundedProcessError):
    """The command exceeded its monotonic wall-clock budget."""


class BoundedProcessOutputLimit(BoundedProcessError):
    """One captured output stream exceeded its in-flight byte budget."""

    def __init__(self, stream: str, limit: int) -> None:
        super().__init__(f"subprocess {stream} exceeded its {limit} byte limit")
        self.stream = stream
        self.limit = limit


class BoundedProcessCleanupError(BoundedProcessError):
    """The process or its communication threads did not close deterministically."""


class _LaunchOwnership:
    """Retain the bootstrap object before its constructor can create a child."""

    def __init__(self) -> None:
        self.process: subprocess.Popen[bytes] | None = None

    def publish(self, process: subprocess.Popen[bytes]) -> None:
        if self.process is not None:
            raise BoundedProcessStartError("subprocess bootstrap ownership was published twice")
        self.process = process


class _OwnedBootstrapProcess(subprocess.Popen):  # type: ignore[type-arg]
    """A Popen whose identity is owned before ``Popen.__init__`` can spawn."""

    def __new__(
        cls,
        *args: Any,
        ownership: _LaunchOwnership,
        **kwargs: Any,
    ) -> _OwnedBootstrapProcess:
        del args, kwargs
        instance = super().__new__(cls)
        # Popen.__del__ is allowed to observe an object whose initialization
        # failed before a child existed.
        instance.returncode = 0
        instance._child_created = False
        ownership.publish(instance)
        return instance

    def __init__(
        self,
        *args: Any,
        ownership: _LaunchOwnership,
        **kwargs: Any,
    ) -> None:
        del ownership
        self._initialize(*args, **kwargs)

    def _initialize(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class WindowsJob:
    """Own a kill-on-close Windows Job Object."""

    def __init__(self) -> None:
        self.handle: int | None = None
        if os.name != "nt":
            return

        import ctypes
        from ctypes import wintypes

        class IoCounters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_ulonglong)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise BoundedProcessStartError(f"CreateJobObjectW failed with Win32 {ctypes.get_last_error()}")
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            raise BoundedProcessStartError(f"SetInformationJobObject failed with Win32 {error}")
        self._ctypes = ctypes
        self._kernel32 = kernel32
        self.handle = int(handle)

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        if self.handle is None:
            return
        if not self._kernel32.AssignProcessToJobObject(self.handle, int(process._handle)):  # type: ignore[attr-defined]
            raise BoundedProcessStartError(
                f"AssignProcessToJobObject failed with Win32 {self._ctypes.get_last_error()}"
            )

    def terminate(self) -> None:
        if self.handle is None:
            return
        if not self._kernel32.TerminateJobObject(self.handle, 1):
            raise BoundedProcessCleanupError(
                f"TerminateJobObject failed with Win32 {self._ctypes.get_last_error()}"
            )

    def close(self) -> None:
        if self.handle is not None:
            self._kernel32.CloseHandle(self.handle)
            self.handle = None


def _terminate_tree(process: subprocess.Popen[bytes], windows_job: WindowsJob) -> None:
    cleanup_error: BaseException | None = None
    if os.name == "nt":
        try:
            windows_job.terminate()
        except BoundedProcessCleanupError as exc:
            cleanup_error = exc
    else:
        try:
            # The original group can outlive its leader.  Detached descendants
            # remain outside this best-effort POSIX cleanup boundary.
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            cleanup_error = exc
    if cleanup_error is not None:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as final_exc:
            raise BoundedProcessCleanupError("subprocess leader did not terminate") from final_exc
        cleanup_error = cleanup_error or exc
    if cleanup_error is not None:
        raise BoundedProcessCleanupError("subprocess tree cleanup was not verified") from cleanup_error


def _terminate_unassigned_bootstrap(process: subprocess.Popen[bytes]) -> None:
    """Stop a gated bootstrap that was never admitted to its process boundary."""

    try:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BoundedProcessCleanupError("unassigned subprocess bootstrap did not terminate") from exc


def _published_bootstrap_started(process: subprocess.Popen[bytes] | None) -> bool:
    if process is None:
        return False
    return bool(getattr(process, "_child_created", False)) or type(getattr(process, "pid", None)) is int


def _join_started_thread(thread: threading.Thread | None, *, timeout: float) -> None:
    if thread is not None and thread.ident is not None:
        thread.join(timeout=timeout)


def _started_thread_is_alive(thread: threading.Thread | None) -> bool:
    return thread is not None and thread.ident is not None and thread.is_alive()


def _read_limited(
    stream: Any,
    limit: int,
    chunks: list[bytes],
    overflow: threading.Event,
    errors: list[BaseException],
) -> None:
    total = 0
    try:
        while True:
            remaining = limit - total
            read_size = min(8192, remaining + 1)
            reader = getattr(stream, "read1", stream.read)
            chunk = reader(read_size)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                overflow.set()
                break
            chunks.append(chunk)
    except (OSError, ValueError) as exc:
        errors.append(exc)
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _write_input(stream: Any, payload: bytes, errors: list[BaseException]) -> None:
    try:
        stream.write(payload)
        stream.flush()
    except BrokenPipeError:
        pass
    except (OSError, ValueError) as exc:
        errors.append(exc)
    finally:
        try:
            stream.close()
        except OSError:
            pass


def run_bounded(
    command: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    input_bytes: bytes = b"",
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run one command with bounded capture and deterministic tree cleanup."""

    argv = list(command)
    if not argv or any(type(item) is not str or not item for item in argv):
        raise ValueError("bounded subprocess command must be a non-empty exact-string argv")
    if type(input_bytes) is not bytes:
        raise TypeError("bounded subprocess input must be exact bytes")
    if type(timeout_seconds) not in (int, float):
        raise TypeError("bounded subprocess timeout must be a finite number")
    if type(stdout_limit) is not int:
        raise TypeError("bounded subprocess stdout limit must be an exact integer")
    if type(stderr_limit) is not int:
        raise TypeError("bounded subprocess stderr limit must be an exact integer")
    try:
        timeout_value = float(timeout_seconds)
    except OverflowError as exc:
        raise ValueError("bounded subprocess limits are invalid") from exc
    if not math.isfinite(timeout_value) or timeout_value <= 0 or stdout_limit < 0 or stderr_limit < 0:
        raise ValueError("bounded subprocess limits are invalid")

    # Every platform starts a harmless fixed bootstrap.  Candidate execution
    # is admitted only after the parent owns the process boundary and has
    # rechecked its monotonic deadline.  This also makes asynchronous
    # cancellation during Popen a fail-closed pre-execution event.
    launched = [sys.executable, "-I", "-S", "-B", "-c", _GATE_BOOTSTRAP, *argv]
    payload = _START_GATE + input_bytes
    creationflags = 0
    start_new_session = os.name != "nt"
    windows_job = WindowsJob()
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

    ownership = _LaunchOwnership()
    process: subprocess.Popen[bytes] | None = None
    job_assigned = False
    readers: tuple[threading.Thread, ...] = ()
    writer: threading.Thread | None = None
    deadline = time.monotonic() + timeout_value
    try:
        try:
            process = _OwnedBootstrapProcess(
                launched,
                ownership=ownership,
                cwd=cwd,
                env=None if env is None else dict(env),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
                start_new_session=start_new_session,
                shell=False,
            )
        except OSError as exc:
            raise BoundedProcessStartError("subprocess leader could not start") from exc
        windows_job.assign(process)
        job_assigned = True

        if time.monotonic() >= deadline:
            raise BoundedProcessTimeout(f"subprocess timed out after {timeout_value:g}s before gate release")

        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_overflow = threading.Event()
        stderr_overflow = threading.Event()
        stream_errors: list[BaseException] = []
        readers = (
            threading.Thread(
                target=_read_limited,
                args=(process.stdout, stdout_limit, stdout_chunks, stdout_overflow, stream_errors),
                daemon=True,
                name="finplanbr-bounded-stdout",
            ),
            threading.Thread(
                target=_read_limited,
                args=(process.stderr, stderr_limit, stderr_chunks, stderr_overflow, stream_errors),
                daemon=True,
                name="finplanbr-bounded-stderr",
            ),
        )
        for reader in readers:
            reader.start()
        writer_errors: list[BaseException] = []
        writer = threading.Thread(
            target=_write_input,
            args=(process.stdin, payload, writer_errors),
            daemon=True,
            name="finplanbr-bounded-stdin",
        )
        writer.start()

        timed_out = False
        while process.poll() is None:
            if stdout_overflow.is_set() or stderr_overflow.is_set():
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.005)
        leader_returncode = process.poll()
        _terminate_tree(process, windows_job)
        windows_job.close()
        _join_started_thread(writer, timeout=2)
        for reader in readers:
            _join_started_thread(reader, timeout=2)
        if _started_thread_is_alive(writer) or any(_started_thread_is_alive(reader) for reader in readers):
            raise BoundedProcessCleanupError("subprocess communication streams did not close")
        if stdout_overflow.is_set():
            raise BoundedProcessOutputLimit("stdout", stdout_limit)
        if stderr_overflow.is_set():
            raise BoundedProcessOutputLimit("stderr", stderr_limit)
        if timed_out:
            raise BoundedProcessTimeout(f"subprocess timed out after {timeout_value:g}s")
        if writer_errors or stream_errors:
            raise BoundedProcessCleanupError("subprocess pipe I/O failed") from (writer_errors + stream_errors)[0]
        return subprocess.CompletedProcess(
            argv,
            process.returncode if leader_returncode is None else leader_returncode,
            b"".join(stdout_chunks),
            b"".join(stderr_chunks),
        )
    except BaseException as primary_error:
        cleanup_error: BoundedProcessCleanupError | None = None
        owned_process = process if process is not None else ownership.process
        if _published_bootstrap_started(owned_process):
            try:
                if process is None or (os.name == "nt" and not job_assigned):
                    _terminate_unassigned_bootstrap(owned_process)
                else:
                    _terminate_tree(owned_process, windows_job)
            except BoundedProcessCleanupError as exc:
                cleanup_error = exc
            windows_job.close()
            for stream in (
                getattr(owned_process, "stdin", None),
                getattr(owned_process, "stdout", None),
                getattr(owned_process, "stderr", None),
            ):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        _join_started_thread(writer, timeout=2)
        for reader in readers:
            _join_started_thread(reader, timeout=2)
        if _started_thread_is_alive(writer) or any(_started_thread_is_alive(reader) for reader in readers):
            communication_error = BoundedProcessCleanupError(
                "subprocess communication threads did not close after failure"
            )
            if cleanup_error is None:
                cleanup_error = communication_error
        if not _published_bootstrap_started(owned_process):
            windows_job.close()
        if cleanup_error is not None:
            if hasattr(primary_error, "add_note"):
                primary_error.add_note(f"subprocess cleanup also failed: {cleanup_error}")
            raise primary_error from cleanup_error
        raise


def process_tree_claim() -> str:
    """Return the exact claim supported by this platform boundary."""

    if os.name == "nt":
        return "windows_job_kill_on_close_with_preassignment_gate"
    return "best_effort_same_process_group_daemon_escape_possible"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def command_envelope(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
) -> dict[str, object]:
    """Return a closed public envelope without exposing candidate stderr."""

    try:
        completed = run_bounded(
            command,
            timeout_seconds=timeout_seconds,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )
    except BoundedProcessTimeout:
        return {"format": ENVELOPE_FORMAT, "status": "failed", "failure_class": "timeout"}
    except BoundedProcessOutputLimit as exc:
        return {
            "format": ENVELOPE_FORMAT,
            "status": "failed",
            "failure_class": "output_limit",
            "stream": exc.stream,
        }
    except BoundedProcessStartError:
        return {"format": ENVELOPE_FORMAT, "status": "failed", "failure_class": "start_failure"}
    except BoundedProcessCleanupError:
        return {"format": ENVELOPE_FORMAT, "status": "failed", "failure_class": "cleanup_failure"}
    except (TypeError, ValueError):
        return {"format": ENVELOPE_FORMAT, "status": "failed", "failure_class": "invalid_configuration"}
    return {
        "format": ENVELOPE_FORMAT,
        "status": "completed",
        "returncode": completed.returncode,
        "stdout_base64": base64.b64encode(completed.stdout).decode("ascii"),
        "stdout_bytes": len(completed.stdout),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one command behind the bounded subprocess boundary.")
    parser.add_argument("--json-envelope", action="store_true", required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--stdout-limit", type=int, required=True)
    parser.add_argument("--stderr-limit", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = list(arguments.command)
    if command[:1] == ["--"]:
        command = command[1:]
    envelope = command_envelope(
        command,
        timeout_seconds=arguments.timeout_seconds,
        stdout_limit=arguments.stdout_limit,
        stderr_limit=arguments.stderr_limit,
    )
    os.write(1, _canonical_json(envelope) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
