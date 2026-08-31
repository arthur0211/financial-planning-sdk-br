#!/usr/bin/env python3
"""CPython 3.13 child used by the local Windows AppContainer boundary probe.

The parent helper supplies a closed JSON request from a read-only source copy.
This program records raw observations only.  It never decides whether the
boundary passed.  Network attempts are limited to the parent-declared endpoint.
"""

from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import json
import os
import select
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final

REQUEST_FORMAT: Final = "finplanbr.windows-appcontainer-child-request.v3"
REPORT_FORMAT: Final = "finplanbr.windows-appcontainer-child-observations.v4"
ROLES: Final = frozenset(
    {"root", "child", "grandchild", "breakaway-control", "network-arm", "positive-control"}
)
REQUEST_KEYS: Final = frozenset(
    {
        "appcontainer_sid",
        "decoy_canary_sha256",
        "decoy_handle",
        "format",
        "lan_host",
        "lan_port",
        "loopback_host",
        "loopback_port",
        "nonce",
        "permitted_canary_sha256",
        "permitted_handle",
        "probe_source",
        "protected_root",
        "request_path",
        "runtime_root",
        "scratch_root",
        "source_root",
    }
)
SHA256_HEX_LENGTH: Final = 64
ERROR_ACCESS_DENIED: Final = 5
CREATE_BREAKAWAY_FROM_JOB: Final = 0x01000000
FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
SE_FILE_OBJECT: Final = 1
OWNER_SECURITY_INFORMATION: Final = 0x00000001
DACL_SECURITY_INFORMATION: Final = 0x00000004
MAX_REQUEST_BYTES: Final = 32_768
MAX_REPORT_BYTES: Final = 1_048_576
MAX_WAIT_SECONDS: Final = 30.0


class ProbeFailure(RuntimeError):
    """Closed failure raised before a trustworthy observation can be emitted."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ProbeFailure("request_duplicate_key")
        value[key] = item
    return value


def _reject_constant(_value: str) -> object:
    raise ProbeFailure("request_non_finite_number")


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_path(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(value)))


def _path_utf8_sha256(value: str | os.PathLike[str]) -> str:
    return _sha256(_canonical_path(value).encode("utf-8"))


def _runtime_relative_path(value: str | os.PathLike[str], runtime_root: str) -> str:
    candidate = _canonical_path(value)
    root = _canonical_path(runtime_root)
    try:
        if os.path.commonpath((candidate, root)) != root:
            raise ProbeFailure("runtime_path_outside_declared_root")
        relative = os.path.relpath(candidate, root)
    except ValueError as error:
        raise ProbeFailure("runtime_path_outside_declared_root") from error
    if relative in {"", "."} or os.path.isabs(relative) or relative.startswith(".."):
        raise ProbeFailure("runtime_relative_path_invalid")
    return relative.replace("/", "\\")


def _read_request(path: Path) -> dict[str, object]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ProbeFailure(f"request_payload_read_oserror_{_winerror(error)}") from error
    if not (1 <= len(payload) <= MAX_REQUEST_BYTES) or not payload.endswith(b"\n"):
        raise ProbeFailure("request_framing_invalid")
    if payload.count(b"\n") != 1 or b"\r" in payload or b"\x00" in payload:
        raise ProbeFailure("request_framing_invalid")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ProbeFailure) as error:
        raise ProbeFailure("request_json_invalid") from error
    if type(value) is not dict or frozenset(value) != REQUEST_KEYS:
        raise ProbeFailure("request_shape_invalid")
    if _canonical_json(value) != payload:
        raise ProbeFailure("request_not_canonical")
    if value["format"] != REQUEST_FORMAT:
        raise ProbeFailure("request_format_invalid")
    for key in REQUEST_KEYS - {"lan_port", "loopback_port"}:
        if type(value[key]) is not str or not value[key]:
            raise ProbeFailure("request_value_invalid")
    for key in ("lan_port", "loopback_port"):
        if type(value[key]) is not int or not (1 <= value[key] <= 65_535):
            raise ProbeFailure("request_value_invalid")
    try:
        lan_host = ipaddress.IPv4Address(value["lan_host"])
        loopback_host = ipaddress.IPv4Address(value["loopback_host"])
    except ipaddress.AddressValueError as error:
        raise ProbeFailure("request_network_target_invalid") from error
    if (
        str(lan_host) != value["lan_host"]
        or lan_host.is_loopback
        or str(loopback_host) != value["loopback_host"]
        or value["loopback_host"] != "127.0.0.1"
    ):
        raise ProbeFailure("request_network_target_invalid")
    nonce = value["nonce"]
    if len(nonce) not in {32, 64} or any(character not in "0123456789abcdef" for character in nonce):
        raise ProbeFailure("request_nonce_invalid")
    for key in ("decoy_canary_sha256", "permitted_canary_sha256"):
        digest = value[key]
        if len(digest) != SHA256_HEX_LENGTH or any(character not in "0123456789abcdef" for character in digest):
            raise ProbeFailure("request_value_invalid")
    for key in ("decoy_handle", "permitted_handle"):
        handle_text = value[key]
        if not handle_text.isascii() or not handle_text.isdecimal() or int(handle_text) <= 0:
            raise ProbeFailure("request_value_invalid")
    for key in (
        "probe_source",
        "protected_root",
        "request_path",
        "runtime_root",
        "scratch_root",
        "source_root",
    ):
        candidate = Path(value[key])
        if not candidate.is_absolute() or "\x00" in os.fspath(candidate):
            raise ProbeFailure("request_path_invalid")
    declared_request = os.path.normcase(os.path.abspath(os.fspath(value["request_path"])))
    observed_request = os.path.normcase(os.path.abspath(os.fspath(path)))
    if declared_request != observed_request:
        raise ProbeFailure("request_path_mismatch")
    return value


def _winerror(error: BaseException) -> int | None:
    observed = getattr(error, "winerror", None)
    if type(observed) is int:
        return observed
    observed = getattr(error, "errno", None)
    if isinstance(error, PermissionError) and observed == 13:
        return ERROR_ACCESS_DENIED
    return observed if type(observed) is int else None


def _attempt(operation: Callable[[], object]) -> dict[str, object]:
    try:
        result = operation()
    except OSError as error:
        return {
            "observation": type(error).__name__,
            "status": "error",
            "winerror": _winerror(error),
        }
    return {"observation": result, "status": "success", "winerror": None}


def _read_file(path: Path) -> str:
    return _sha256(path.read_bytes())


def _write_file(path: Path, payload: bytes) -> str:
    path.write_bytes(payload)
    return _sha256(path.read_bytes())


def _delete_file(path: Path) -> bool:
    path.unlink()
    return not path.exists()


def _rename_file(source: Path, target: Path) -> bool:
    source.rename(target)
    return not source.exists() and target.is_file()


def _write_ads(path: Path, payload: bytes) -> str:
    stream = Path(os.fspath(path) + ":fpbr-boundary")
    stream.write_bytes(payload)
    digest = _sha256(stream.read_bytes())
    stream.unlink()
    return digest


def _hardlink(source: Path, target: Path) -> bool:
    os.link(source, target)
    source_stat = source.stat()
    target_stat = target.stat()
    return source_stat.st_ino == target_stat.st_ino and target_stat.st_nlink >= 2


def _is_reparse(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def _file_symlink(source: Path, target: Path) -> bool:
    os.symlink(source, target, target_is_directory=False)
    return target.is_symlink() and _is_reparse(target)


def _directory_reparse(source: Path, target: Path) -> bool:
    os.symlink(source, target, target_is_directory=True)
    return target.is_symlink() and _is_reparse(target)


def _repeat_security_descriptor(path: Path, security_information: int) -> int:
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    get_security = advapi32.GetNamedSecurityInfoW
    get_security.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_security.restype = ctypes.c_uint32
    set_security = advapi32.SetNamedSecurityInfoW
    set_security.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    set_security.restype = ctypes.c_uint32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = int(
        get_security(
            os.fspath(path),
            SE_FILE_OBJECT,
            security_information,
            ctypes.byref(owner),
            ctypes.byref(group),
            ctypes.byref(dacl),
            ctypes.byref(sacl),
            ctypes.byref(descriptor),
        )
    )
    if result != 0:
        raise OSError(result, "GetNamedSecurityInfoW", os.fspath(path), result)
    try:
        result = int(
            set_security(
                os.fspath(path),
                SE_FILE_OBJECT,
                security_information,
                owner if security_information == OWNER_SECURITY_INFORMATION else None,
                None,
                dacl if security_information == DACL_SECURITY_INFORMATION else None,
                None,
            )
        )
        if result != 0:
            raise OSError(result, "SetNamedSecurityInfoW", os.fspath(path), result)
        return result
    finally:
        if descriptor.value:
            kernel32.LocalFree(descriptor)


def _filesystem_observations(
    request: dict[str, object], *, positive_control: bool
) -> dict[str, object]:
    scratch = Path(request["scratch_root"])
    protected = Path(request["protected_root"])
    positive = scratch / "filesystem-positive"
    if positive_control:
        try:
            positive.mkdir()
            (positive / "directory-target").mkdir()
        except OSError as error:
            raise ProbeFailure(f"filesystem_positive_setup_oserror_{_winerror(error)}") from error
    payload = ("fpbr-positive-" + request["nonce"]).encode("ascii")

    positive_seed_names = (
        "delete.txt",
        "hardlink-source.txt",
        "overwrite.txt",
        "rename.txt",
        "rights.txt",
        "stream.txt",
        "symlink-source.txt",
    )
    if positive_control:
        for name in positive_seed_names:
            try:
                (positive / name).write_bytes(payload)
            except OSError as error:
                raise ProbeFailure(f"filesystem_positive_seed_oserror_{_winerror(error)}") from error

    operations: dict[str, dict[str, dict[str, object]]] = {}

    def pair(
        name: str,
        positive_operation: Callable[[], object],
        negative_operation: Callable[[], object],
    ) -> None:
        operations[name] = {
            "negative": None if positive_control else _attempt(negative_operation),
            "positive": _attempt(positive_operation) if positive_control else None,
        }

    pair(
        "read",
        lambda: _read_file(Path(request["probe_source"])),
        lambda: _read_file(protected / "denied-read.txt"),
    )
    pair(
        "create",
        lambda: _write_file(positive / "created.txt", payload),
        lambda: _write_file(protected / "created.txt", payload),
    )
    pair(
        "overwrite",
        lambda: _write_file(positive / "overwrite.txt", payload + b"-overwrite"),
        lambda: _write_file(protected / "overwrite.txt", payload + b"-overwrite"),
    )
    pair(
        "delete",
        lambda: _delete_file(positive / "delete.txt"),
        lambda: _delete_file(protected / "delete.txt"),
    )
    pair(
        "rename",
        lambda: _rename_file(positive / "rename.txt", positive / "renamed.txt"),
        lambda: _rename_file(protected / "rename.txt", protected / "renamed.txt"),
    )
    pair(
        "ads",
        lambda: _write_ads(positive / "stream.txt", payload),
        lambda: _write_ads(protected / "stream.txt", payload),
    )
    pair(
        "hardlink",
        lambda: _hardlink(positive / "hardlink-source.txt", positive / "hardlink-created.txt"),
        lambda: _hardlink(protected / "hardlink-source.txt", protected / "hardlink-created.txt"),
    )
    pair(
        "symlink",
        lambda: _file_symlink(positive / "symlink-source.txt", positive / "symlink-created.txt"),
        lambda: _file_symlink(protected / "symlink-source.txt", protected / "symlink-created.txt"),
    )
    pair(
        "reparse",
        lambda: _directory_reparse(positive / "directory-target", positive / "directory-created"),
        lambda: _directory_reparse(protected / "directory-target", protected / "directory-created"),
    )
    pair(
        "write_dac",
        lambda: _repeat_security_descriptor(positive / "rights.txt", DACL_SECURITY_INFORMATION),
        lambda: _repeat_security_descriptor(protected / "rights.txt", DACL_SECURITY_INFORMATION),
    )
    pair(
        "write_owner",
        lambda: _repeat_security_descriptor(positive / "rights.txt", OWNER_SECURITY_INFORMATION),
        lambda: _repeat_security_descriptor(protected / "rights.txt", OWNER_SECURITY_INFORMATION),
    )
    return {"operations": operations}


def _network_attempt(host: str, port: int, nonce: str) -> dict[str, object]:
    observed_error: int | None = None
    connected = False
    echo = b""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(2.0)
    try:
        connect_result = client.connect_ex((host, port))
        if connect_result == 10_035:
            _, writable, exceptional = select.select([], [client], [client], 2.0)
            if writable or exceptional:
                connect_result = int(client.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR))
            else:
                connect_result = 10_060
        connected = connect_result == 0
        observed_error = None if connected else connect_result
        if connected:
            payload = nonce.encode("ascii")
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            observed_length = 0
            while observed_length <= len(payload):
                chunk = client.recv(min(4096, len(payload) + 1 - observed_length))
                if not chunk:
                    break
                chunks.append(chunk)
                observed_length += len(chunk)
            echo = b"".join(chunks)
    finally:
        client.close()

    diagnosis_result: int | None = None
    diagnosis_type: int | None = None
    if not connected:
        try:
            firewall_api = ctypes.WinDLL("Firewallapi.dll", use_last_error=True)
            diagnose = firewall_api.NetworkIsolationDiagnoseConnectFailureAndGetInfo
            diagnose.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
            diagnose.restype = ctypes.c_uint32
            diagnosis = ctypes.c_int(-1)
            diagnosis_target = "localhost" if host == "127.0.0.1" else host
            diagnosis_result = int(diagnose(diagnosis_target, ctypes.byref(diagnosis)))
            diagnosis_type = int(diagnosis.value)
        except (AttributeError, OSError):
            diagnosis_result = None
            diagnosis_type = None
    payload = nonce.encode("ascii")
    return {
        "connected": connected,
        "diagnosis_result": diagnosis_result,
        "diagnosis_type": diagnosis_type,
        "echo_matches": connected and echo == payload,
        "echo_nonce_sha256": _sha256(echo) if echo else None,
        "host": host,
        "nonce_sha256": _sha256(payload),
        "port": port,
        "winerror": observed_error,
    }


def _read_handle_canary(handle: int) -> dict[str, object]:
    try:
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    except OSError as error:
        raise ProbeFailure(f"kernel32_load_oserror_{_winerror(error)}") from error
    kernel32.GetHandleInformation.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.GetHandleInformation.restype = ctypes.c_int
    kernel32.ReadFile.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    kernel32.ReadFile.restype = ctypes.c_int
    flags = ctypes.c_uint32()
    try:
        valid = bool(kernel32.GetHandleInformation(ctypes.c_void_p(handle), ctypes.byref(flags)))
    except OSError:
        valid = False
    if not valid:
        return {
            "canary_sha256": None,
            "get_handle_information_error": 6,
            "read_error": None,
            "valid": False,
        }
    buffer = ctypes.create_string_buffer(64)
    count = ctypes.c_uint32()
    try:
        read_succeeded = bool(
            kernel32.ReadFile(
                ctypes.c_void_p(handle),
                buffer,
                len(buffer),
                ctypes.byref(count),
                None,
            )
        )
    except OSError as error:
        return {
            "canary_sha256": None,
            "get_handle_information_error": 0,
            "read_error": _winerror(error),
            "valid": True,
        }
    return {
        "canary_sha256": _sha256(buffer.raw[: count.value]) if read_succeeded else None,
        "get_handle_information_error": 0,
        "read_error": 0 if read_succeeded else ctypes.get_last_error(),
        "valid": True,
    }


def _runtime_observations(request: dict[str, object]) -> dict[str, object]:
    runtime_root = str(request["runtime_root"])
    source_root = str(request["source_root"])
    origins: dict[str, dict[str, str]] = {}
    for name in ("ctypes", "hashlib", "json", "os", "select", "socket", "subprocess"):
        module = sys.modules[name]
        origin = getattr(module, "__file__", None)
        if type(origin) is not str:
            raise ProbeFailure("runtime_module_origin_missing")
        origin_path = Path(origin)
        try:
            blob_sha256 = _sha256(origin_path.read_bytes())
        except OSError as error:
            raise ProbeFailure(f"runtime_module_origin_read_oserror_{_winerror(error)}") from error
        origins[name] = {
            "blob_sha256": blob_sha256,
            "path_utf8_sha256": _path_utf8_sha256(origin),
            "relative_to_runtime": _runtime_relative_path(origin, runtime_root),
        }
    sys_path = [
        {
            "path_utf8_sha256": _path_utf8_sha256(item),
            "relative_to_runtime": _runtime_relative_path(item, runtime_root),
        }
        for item in sys.path
    ]
    return {
        "base_exec_prefix_path_utf8_sha256": _path_utf8_sha256(sys.base_exec_prefix),
        "base_prefix_path_utf8_sha256": _path_utf8_sha256(sys.base_prefix),
        "dont_write_bytecode": bool(sys.flags.dont_write_bytecode),
        "executable_leaf": "python.exe",
        "executable_path_utf8_sha256": _path_utf8_sha256(sys.executable),
        "exec_prefix_path_utf8_sha256": _path_utf8_sha256(sys.exec_prefix),
        "expected_runtime_root_path_utf8_sha256": _path_utf8_sha256(runtime_root),
        "expected_source_root_path_utf8_sha256": _path_utf8_sha256(source_root),
        "ignore_environment": bool(sys.flags.ignore_environment),
        "implementation": sys.implementation.name,
        "isolated": bool(sys.flags.isolated),
        "module_origins": origins,
        "no_user_site": bool(sys.flags.no_user_site),
        "prefix_path_utf8_sha256": _path_utf8_sha256(sys.prefix),
        "probe_source_leaf": "windows_appcontainer_child_probe.py",
        "probe_source_path_utf8_sha256": _path_utf8_sha256(__file__),
        "runtime_root_role": "external_rx_runtime_copy",
        "safe_path": bool(sys.flags.safe_path),
        "source_root_role": "protected_probe_source_copy",
        "sys_path": sys_path,
        "version": [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
        "version_text_sha256": _sha256(sys.version.encode("utf-8")),
    }


def _write_report(path: Path, value: dict[str, object]) -> None:
    payload = _canonical_json(value)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _wait_for(path: Path, expected_role: str) -> dict[str, object]:
    deadline = time.monotonic() + MAX_WAIT_SECONDS
    while time.monotonic() < deadline:
        if path.is_file():
            payload = path.read_bytes()
            if (
                not (1 <= len(payload) <= MAX_REPORT_BYTES)
                or not payload.endswith(b"\n")
                or payload.count(b"\n") != 1
                or b"\r" in payload
                or b"\x00" in payload
            ):
                raise ProbeFailure("lineage_report_framing_invalid")
            value = json.loads(
                payload,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
            if (
                type(value) is dict
                and _canonical_json(value) == payload
                and value.get("format") == REPORT_FORMAT
                and value.get("role") == expected_role
            ):
                return value
            raise ProbeFailure("lineage_report_protocol_invalid")
        time.sleep(0.02)
    raise ProbeFailure("lineage_report_timeout")


def _linger() -> None:
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        time.sleep(0.1)
    raise ProbeFailure("job_close_did_not_terminate_process")


def _python_command(request: dict[str, object], role: str) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-B",
        request["probe_source"],
        request["request_path"],
        role,
    ]


def _run_grandchild(request: dict[str, object]) -> None:
    report = {
        "format": REPORT_FORMAT,
        "parent_pid": os.getppid(),
        "pid": os.getpid(),
        "role": "grandchild",
        "runtime": _runtime_observations(request),
    }
    _write_report(Path(request["scratch_root"]) / "grandchild.json", report)
    _linger()


def _run_positive_control(request: dict[str, object]) -> None:
    report = {
        "filesystem": _filesystem_observations(request, positive_control=True),
        "format": REPORT_FORMAT,
        "parent_pid": os.getppid(),
        "pid": os.getpid(),
        "role": "positive-control",
        "runtime": _runtime_observations(request),
    }
    _write_report(Path(request["scratch_root"]) / "positive-control.json", report)


def _run_network_arm(request: dict[str, object]) -> None:
    report = {
        "format": REPORT_FORMAT,
        "network": _network_attempt(
            str(request["lan_host"]), int(request["lan_port"]), str(request["nonce"])
        ),
        "parent_pid": os.getppid(),
        "pid": os.getpid(),
        "request_sha256": _sha256(_canonical_json(request)),
        "role": "network-arm",
        "runtime": _runtime_observations(request),
    }
    _write_report(Path(request["scratch_root"]) / "network-arm.json", report)


def _run_child(request: dict[str, object]) -> None:
    try:
        grandchild = subprocess.Popen(
            _python_command(request, "grandchild"),
            close_fds=True,
            cwd=request["scratch_root"],
        )
    except OSError as error:
        raise ProbeFailure(f"grandchild_spawn_oserror_{_winerror(error)}") from error
    grandchild_report = _wait_for(
        Path(request["scratch_root"]) / "grandchild.json", "grandchild"
    )
    report = {
        "format": REPORT_FORMAT,
        "grandchild_pid": grandchild.pid,
        "grandchild_reported_pid": grandchild_report["pid"],
        "parent_pid": os.getppid(),
        "pid": os.getpid(),
        "role": "child",
        "runtime": _runtime_observations(request),
    }
    _write_report(Path(request["scratch_root"]) / "child.json", report)
    _linger()


def _breakaway_observation(request: dict[str, object]) -> dict[str, object]:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            _python_command(request, "breakaway-control"),
            close_fds=True,
            creationflags=CREATE_BREAKAWAY_FROM_JOB,
            cwd=request["scratch_root"],
        )
    except OSError as error:
        return {"created": False, "exit_code": None, "winerror": _winerror(error)}
    try:
        return {"created": True, "exit_code": process.wait(timeout=5), "winerror": None}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def _run_root(request: dict[str, object]) -> None:
    breakaway = _breakaway_observation(request)
    try:
        child = subprocess.Popen(
            _python_command(request, "child"),
            close_fds=True,
            cwd=request["scratch_root"],
        )
    except OSError as error:
        raise ProbeFailure(f"child_spawn_oserror_{_winerror(error)}") from error
    try:
        child_report = _wait_for(Path(request["scratch_root"]) / "child.json", "child")
    except OSError as error:
        raise ProbeFailure(f"child_report_wait_oserror_{_winerror(error)}") from error
    try:
        grandchild_report = _wait_for(
            Path(request["scratch_root"]) / "grandchild.json", "grandchild"
        )
    except OSError as error:
        raise ProbeFailure(f"grandchild_report_wait_oserror_{_winerror(error)}") from error
    try:
        filesystem = _filesystem_observations(request, positive_control=False)
    except OSError as error:
        raise ProbeFailure(f"filesystem_probe_oserror_{_winerror(error)}") from error
    try:
        decoy_handle = _read_handle_canary(int(request["decoy_handle"]))
    except OSError as error:
        raise ProbeFailure(f"decoy_handle_probe_oserror_{_winerror(error)}") from error
    try:
        permitted_handle = _read_handle_canary(int(request["permitted_handle"]))
    except OSError as error:
        raise ProbeFailure(f"permitted_handle_probe_oserror_{_winerror(error)}") from error
    handles = {"decoy": decoy_handle, "permitted": permitted_handle}
    try:
        network = {
            "loopback": _network_attempt(
                request["loopback_host"], request["loopback_port"], request["nonce"]
            ),
        }
    except OSError as error:
        raise ProbeFailure(f"network_probe_oserror_{_winerror(error)}") from error
    report = {
        "breakaway": breakaway,
        "child_pid": child.pid,
        "child_reported_pid": child_report["pid"],
        "filesystem": filesystem,
        "format": REPORT_FORMAT,
        "grandchild_pid": child_report["grandchild_pid"],
        "grandchild_reported_pid": grandchild_report["pid"],
        "handles": handles,
        "network": network,
        "parent_pid": os.getppid(),
        "pid": os.getpid(),
        "role": "root",
        "runtime": _runtime_observations(request),
    }
    try:
        _write_report(Path(request["scratch_root"]) / "root.json", report)
    except OSError as error:
        raise ProbeFailure(f"root_report_write_oserror_{_winerror(error)}") from error
    _linger()


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if os.name != "nt" or len(arguments) != 2 or arguments[1] not in ROLES:
        return 2
    try:
        try:
            request = _read_request(Path(arguments[0]))
        except OSError as error:
            raise ProbeFailure(f"request_read_oserror_{_winerror(error)}") from error
        role = arguments[1]
        if role == "root":
            _run_root(request)
        elif role == "child":
            _run_child(request)
        elif role == "grandchild":
            _run_grandchild(request)
        elif role == "positive-control":
            _run_positive_control(request)
            return 0
        elif role == "network-arm":
            _run_network_arm(request)
            return 0
        else:
            return 0
        return 1
    except BaseException as error:
        if isinstance(error, ProbeFailure):
            reason = str(error)
        elif isinstance(error, OSError):
            reason = f"oserror_{_winerror(error)}"
        else:
            reason = type(error).__name__
        try:
            _write_report(
                Path.cwd() / "failure.json",
                {
                    "format": "finplanbr.windows-appcontainer-child-failure.v2",
                    "reason": reason,
                    "role": arguments[1],
                },
            )
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
