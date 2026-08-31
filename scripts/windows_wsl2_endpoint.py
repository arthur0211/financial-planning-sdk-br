"""Bounded WSL2 NAT echo endpoint for the AppContainer boundary diagnostic.

The lease uses only an already-running ``docker-desktop`` WSL2 namespace.  It
does not create Docker objects, change Windows/WSL networking policy, restart a
distro, or write guest files.  A CSPRNG instance marker and high port bind one
``nc`` process to an exact PID.  The listener has its own 120-second timeout,
and wrapper cleanup targets only that marker-bound PID.
"""

from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import os
import queue
import re
import secrets
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path
from typing import Final

try:
    from .windows_appcontainer_boundary_report import (
        ENDPOINT_RECEIPT_FORMAT,
        NETWORK_DISTRO_NAME,
        NETWORK_ENDPOINT_CLASS,
        NETWORK_LISTENER_TIMEOUT_SECONDS,
    )
except ImportError:
    from windows_appcontainer_boundary_report import (  # type: ignore[no-redef]
        ENDPOINT_RECEIPT_FORMAT,
        NETWORK_DISTRO_NAME,
        NETWORK_ENDPOINT_CLASS,
        NETWORK_LISTENER_TIMEOUT_SECONDS,
    )

WSL_VERSION: Final = 2
GUEST_INTERFACE: Final = "eth0"
LISTENER_TIMEOUT_SECONDS: Final = NETWORK_LISTENER_TIMEOUT_SECONDS
MIN_LISTENER_PORT: Final = 49_152
MAX_LISTENER_PORT: Final = 65_535
BOOT_ID_PATTERN: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.ASCII,
)
NETNS_PATTERN: Final = re.compile(r"net:\[[0-9]+\]\Z", re.ASCII)
MARKER_PATTERN: Final = re.compile(r"FPBR_BOUNDARY_LISTENER_NONCE=[0-9a-f]{32}\Z", re.ASCII)

CommandRunner = Callable[..., subprocess.CompletedProcess[bytes]]
ProcessFactory = Callable[..., subprocess.Popen[bytes]]
PortFactory = Callable[[], int]
NonceFactory = Callable[[int], bytes]
IPv4Reader = Callable[[], set[str]]
HostCreationTimeReader = Callable[[subprocess.Popen[bytes]], int]


class WslEndpointFailure(RuntimeError):
    """The external endpoint could not establish its closed lifecycle."""


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]


class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


_IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
]


class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
]


class _SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ("sin_family", wintypes.USHORT),
        ("sin_port", wintypes.USHORT),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


class _FILETIME(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


def host_process_creation_time_100ns(process: subprocess.Popen[bytes]) -> int:
    """Read creation time from the retained Windows process handle."""

    if os.name != "nt":
        raise WslEndpointFailure("windows_required")
    raw_handle = getattr(process, "_handle", None)
    if raw_handle is None:
        raise WslEndpointFailure("host_launcher_handle_unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_times = kernel32.GetProcessTimes
    get_times.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
    ]
    get_times.restype = wintypes.BOOL
    creation = _FILETIME()
    exit_time = _FILETIME()
    kernel = _FILETIME()
    user = _FILETIME()
    if not get_times(
        wintypes.HANDLE(int(raw_handle)),
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise WslEndpointFailure("host_launcher_creation_time_failed")
    value = (int(creation.high) << 32) | int(creation.low)
    if value < 1:
        raise WslEndpointFailure("host_launcher_creation_time_invalid")
    return value


def windows_ipv4_addresses() -> set[str]:
    """Enumerate every configured Windows IPv4 unicast interface address."""

    if os.name != "nt":
        raise WslEndpointFailure("windows_required")
    get_adapters = ctypes.WinDLL("iphlpapi", use_last_error=True).GetAdaptersAddresses
    get_adapters.argtypes = [
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        ctypes.POINTER(_IP_ADAPTER_ADDRESSES),
        ctypes.POINTER(wintypes.ULONG),
    ]
    get_adapters.restype = wintypes.ULONG
    size = wintypes.ULONG(15_000)
    for _attempt in range(3):
        buffer = ctypes.create_string_buffer(size.value)
        first = ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
        result = int(get_adapters(socket.AF_INET, 0x000E, None, first, ctypes.byref(size)))
        if result == 111:  # ERROR_BUFFER_OVERFLOW
            continue
        if result != 0:
            raise WslEndpointFailure(f"windows_interface_enumeration_failed_{result}")
        addresses: set[str] = set()
        adapter = first
        adapter_count = 0
        while adapter:
            adapter_count += 1
            if adapter_count > 4096:
                raise WslEndpointFailure("windows_interface_roster_unbounded")
            unicast = adapter.contents.FirstUnicastAddress
            unicast_count = 0
            while unicast:
                unicast_count += 1
                if unicast_count > 4096:
                    raise WslEndpointFailure("windows_unicast_roster_unbounded")
                address = unicast.contents.Address
                if address.lpSockaddr and address.iSockaddrLength >= ctypes.sizeof(_SOCKADDR_IN):
                    sockaddr = ctypes.cast(
                        address.lpSockaddr, ctypes.POINTER(_SOCKADDR_IN)
                    ).contents
                    if sockaddr.sin_family == socket.AF_INET:
                        addresses.add(socket.inet_ntoa(bytes(sockaddr.sin_addr)))
                unicast = unicast.contents.Next
            adapter = adapter.contents.Next
        return addresses
    raise WslEndpointFailure("windows_interface_enumeration_unstable")


def _system_wsl_path() -> Path:
    if os.name != "nt":
        raise WslEndpointFailure("windows_required")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_system_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(get_system_directory(buffer, len(buffer)))
    if length == 0 or length >= len(buffer):
        raise WslEndpointFailure("system_directory_resolution_failed")
    path = Path(buffer.value) / "wsl.exe"
    if not path.is_absolute() or not path.is_file():
        raise WslEndpointFailure("system_wsl_missing")
    return path


def _decode_wsl_output(payload: bytes, name: str) -> str:
    if len(payload) > 1_048_576:
        raise WslEndpointFailure(f"{name}_output_oversize")
    try:
        if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = payload.decode("utf-16")
        elif b"\x00" in payload:
            text = payload.decode("utf-16-le")
        else:
            text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WslEndpointFailure(f"{name}_output_encoding_invalid") from exc
    if "\x00" in text:
        raise WslEndpointFailure(f"{name}_output_nul_invalid")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _default_port() -> int:
    return MIN_LISTENER_PORT + secrets.randbelow(MAX_LISTENER_PORT - MIN_LISTENER_PORT + 1)


class Wsl2EndpointLease:
    """Own one externally observable WSL2 NAT listener and its exact cleanup."""

    _SNAPSHOT_SCRIPT: Final = r"""
set -eu
boot_id=$(/bin/busybox cat /proc/sys/kernel/random/boot_id)
set -- $(/bin/busybox ip -4 -o addr show dev eth0 scope global | /bin/busybox awk '{print $4}')
[ "$#" -eq 1 ]
ipv4_prefix=$1
netns=$(/bin/busybox readlink /proc/self/ns/net)
printf 'boot_id=%s\nipv4_prefix=%s\nnetns=%s\n' "$boot_id" "$ipv4_prefix" "$netns"
""".strip()
    _MARKER_SCAN_SCRIPT: Final = r"""
set -eu
needle=$1
for path in /proc/[0-9]*/environ; do
    [ -r "$path" ] || continue
    if /bin/busybox tr '\000' '\n' < "$path" | /bin/busybox grep -F -x -- "$needle" >/dev/null 2>&1; then
        pid=${path#/proc/}
        pid=${pid%/environ}
        printf '%s\n' "$pid"
    fi
done
""".strip()
    _STARTUP_SCRIPT: Final = r"""
set -eu
[ "$#" -eq 4 ] || exit 64
ip=$1
port=$2
ttl=$3
nonce=$4
case "$ip" in ''|*[!0-9.]*) exit 64;; esac
case "$port" in ''|*[!0-9]*) exit 64;; esac
case "$ttl" in ''|*[!0-9]*) exit 64;; esac
case "$nonce" in ''|*[!0-9a-f]*) exit 64;; esac
[ "${#nonce}" -eq 32 ] || exit 64
[ "$port" -ge 49152 ] && [ "$port" -le 65535 ] || exit 64
[ "$ttl" -ge 30 ] && [ "$ttl" -le 600 ] || exit 64
listener=$$
listener_start=$(/bin/busybox awk '{print $22}' "/proc/$listener/stat")
(
    elapsed=0
    while [ "$elapsed" -lt "$ttl" ]; do
        [ -r "/proc/$listener/stat" ] || exit 0
        current=$(/bin/busybox awk '{print $22}' "/proc/$listener/stat") || exit 0
        [ "$current" = "$listener_start" ] || exit 0
        /bin/busybox sleep 1
        elapsed=$((elapsed + 1))
    done
    [ -r "/proc/$listener/stat" ] || exit 0
    current=$(/bin/busybox awk '{print $22}' "/proc/$listener/stat") || exit 0
    [ "$current" = "$listener_start" ] || exit 0
    /bin/busybox kill -TERM "$listener" || exit 0
    /bin/busybox sleep 2
    [ -r "/proc/$listener/stat" ] || exit 0
    current=$(/bin/busybox awk '{print $22}' "/proc/$listener/stat") || exit 0
    [ "$current" = "$listener_start" ] || exit 0
    /bin/busybox kill -KILL "$listener" || :
) >/dev/null 2>&1 &
watchdog=$!
watchdog_start=$(/bin/busybox awk '{print $22}' "/proc/$watchdog/stat")
printf 'FPBR_WSL2_ENDPOINT_V1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$nonce" "$listener" "$listener_start" "$watchdog" "$watchdog_start" "$ip" "$port"
export FPBR_BOUNDARY_LISTENER_NONCE="$nonce"
exec /bin/busybox nc -n -lk -s "$ip" -p "$port" -e /bin/cat
""".strip()
    _EXACT_SIGNAL_SCRIPT: Final = r"""
set -eu
[ "$#" -eq 10 ] || exit 64
signal=$1
pid=$2
start=$3
marker=$4
cmd_sha=$5
netns=$6
inode=$7
local_hex=$8
port_hex=$9
label=${10}
[ "$label" = "fpbr-exact-listener-cleanup-v2" ] || exit 64
case "$signal" in TERM|KILL) :;; *) exit 64;; esac
case "$pid:$start:$inode" in *[!0-9:]*) exit 64;; esac
case "$cmd_sha" in *[!0-9a-f]*) exit 64;; esac
[ "${#cmd_sha}" -eq 64 ] || exit 64
case "$local_hex:$port_hex" in *[!0-9A-F:]*) exit 64;; esac
[ "${#local_hex}" -eq 8 ] && [ "${#port_hex}" -eq 4 ] || exit 64

read_identity() {
    if [ ! -e "/proc/$pid" ]; then
        observed_state=absent
        return 0
    fi
    [ -r "/proc/$pid/stat" ] || exit 70
    if ! stat=$(/bin/busybox cat "/proc/$pid/stat"); then
        if [ ! -e "/proc/$pid" ]; then
            observed_state=absent
            return 0
        fi
        exit 70
    fi
    stat_pid=${stat%% *}
    [ "$stat_pid" = "$pid" ] || exit 70
    tail=${stat##*) }
    [ "$tail" != "$stat" ] || exit 70
    set -- $tail
    [ "$#" -ge 20 ] || exit 70
    shift 19
    observed_state=$1
}

read_identity
if [ "$observed_state" = absent ]; then
    printf 'ABSENT\n'
    exit 0
fi
if [ "$observed_state" != "$start" ]; then
    printf 'ABSENT_REUSED\n'
    exit 0
fi
[ -r "/proc/$pid/environ" ] || exit 70
/bin/busybox tr '\000' '\n' < "/proc/$pid/environ" \
    | /bin/busybox grep -F -x -- "$marker" >/dev/null || exit 70
observed_cmd_sha=$(/bin/busybox sha256sum "/proc/$pid/cmdline" | /bin/busybox awk '{print $1}')
[ "$observed_cmd_sha" = "$cmd_sha" ] || exit 70
[ "$(/bin/busybox readlink "/proc/$pid/ns/net")" = "$netns" ] || exit 70
owned=0
for path in "/proc/$pid/fd"/*; do
    [ -L "$path" ] || continue
    [ "$(/bin/busybox readlink "$path")" = "socket:[$inode]" ] && owned=$((owned + 1))
done
[ "$owned" -ge 1 ] || exit 70
rows=$(/bin/busybox awk -v local="$local_hex:$port_hex" -v inode="$inode" \
    'NR > 1 && $2 == local && $4 == "0A" && $10 == inode { count++ } END { print count + 0 }' \
    "/proc/$pid/net/tcp")
[ "$rows" -eq 1 ] || exit 70
read_identity
[ "$observed_state" = "$start" ] || exit 70
/bin/busybox kill "-$signal" "$pid"
printf 'SIGNALED\n'
""".strip()

    def __init__(
        self,
        *,
        wsl_path: Path | None = None,
        runner: CommandRunner = subprocess.run,
        process_factory: ProcessFactory = subprocess.Popen,
        port_factory: PortFactory = _default_port,
        nonce_factory: NonceFactory = secrets.token_bytes,
        ipv4_reader: IPv4Reader = windows_ipv4_addresses,
        host_creation_time_reader: HostCreationTimeReader = host_process_creation_time_100ns,
        lease_seconds: int = NETWORK_LISTENER_TIMEOUT_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._wsl_path = _system_wsl_path() if wsl_path is None else wsl_path
        self._runner = runner
        self._process_factory = process_factory
        self._port_factory = port_factory
        self._nonce_factory = nonce_factory
        self._ipv4_reader = ipv4_reader
        self._host_creation_time_reader = host_creation_time_reader
        if type(lease_seconds) is not int or not 30 <= lease_seconds <= 600:
            raise WslEndpointFailure("listener_lease_seconds_invalid")
        self._lease_seconds = lease_seconds
        self._monotonic = monotonic
        self._sleeper = sleeper
        self._host_process: subprocess.Popen[bytes] | None = None
        self._listener_pid: int | None = None
        self._listener_port: int | None = None
        self._marker: str | None = None
        self._listener_command_sha256: str | None = None
        self._listener_socket_inode: int | None = None
        self._listener_starttime_ticks: int | None = None
        self._host_launcher_pid: int | None = None
        self._host_launcher_creation_time_100ns: int | None = None
        self._watchdog_pid: int | None = None
        self._watchdog_starttime_ticks: int | None = None
        self._busybox_sha256: str | None = None
        self._snapshot_before: dict[str, object] | None = None
        self._snapshot_after: dict[str, object] | None = None
        self._prelaunch: dict[str, object] | None = None
        self._receipt: dict[str, object] | None = None
        self._closed = False

    def _run(self, arguments: list[str], *, timeout: int = 15) -> bytes:
        try:
            completed = self._runner(
                [os.fspath(self._wsl_path), *arguments],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WslEndpointFailure("wsl_command_execution_failed") from exc
        if type(completed.returncode) is not int or completed.returncode != 0:
            raise WslEndpointFailure("wsl_command_failed")
        if type(completed.stdout) is not bytes or type(completed.stderr) is not bytes:
            raise WslEndpointFailure("wsl_command_output_type_invalid")
        if completed.stderr:
            raise WslEndpointFailure("wsl_stderr_present")
        return completed.stdout

    def _run_guest(self, arguments: list[str], *, timeout: int = 15) -> bytes:
        return self._run(
            ["--distribution", NETWORK_DISTRO_NAME, "--exec", *arguments], timeout=timeout
        )

    def _roster(self, arguments: list[str], name: str) -> tuple[str, ...]:
        text = _decode_wsl_output(self._run(arguments), name)
        roster = tuple(line.strip().lstrip("*").strip() for line in text.splitlines() if line.strip())
        if len(roster) != len(set(roster)):
            raise WslEndpointFailure(f"{name}_roster_duplicate")
        return roster

    def _distro_running_v2(self) -> bool:
        installed = self._roster(["--list", "--quiet"], "wsl_installed")
        running = self._roster(["--list", "--running", "--quiet"], "wsl_running")
        if NETWORK_DISTRO_NAME not in installed:
            return False
        verbose = _decode_wsl_output(self._run(["--list", "--verbose"]), "wsl_verbose")
        version: int | None = None
        for line in verbose.splitlines():
            fields = line.strip().lstrip("*").split()
            if fields and fields[0] == NETWORK_DISTRO_NAME:
                if version is not None or not fields[-1].isdigit():
                    raise WslEndpointFailure("wsl_verbose_roster_invalid")
                version = int(fields[-1])
        if version != WSL_VERSION:
            return False
        return NETWORK_DISTRO_NAME in running

    def _snapshot(self) -> dict[str, object]:
        output = _decode_wsl_output(
            self._run_guest(["/bin/sh", "-c", self._SNAPSHOT_SCRIPT]), "guest_snapshot"
        )
        pairs: dict[str, str] = {}
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in pairs:
                raise WslEndpointFailure("guest_snapshot_shape_invalid")
            pairs[key] = value
        if set(pairs) != {"boot_id", "ipv4_prefix", "netns"}:
            raise WslEndpointFailure("guest_snapshot_shape_invalid")
        address_text, separator, prefix_text = pairs["ipv4_prefix"].partition("/")
        if not separator or not prefix_text.isdigit():
            raise WslEndpointFailure("guest_address_invalid")
        try:
            address = ipaddress.IPv4Address(address_text)
        except ipaddress.AddressValueError as exc:
            raise WslEndpointFailure("guest_address_invalid") from exc
        prefix = int(prefix_text)
        network = ipaddress.IPv4Network((address, prefix), strict=False)
        if (
            str(address) != address_text
            or not 1 <= prefix <= 32
            or address.is_unspecified
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address in {network.network_address, network.broadcast_address}
        ):
            raise WslEndpointFailure("guest_address_invalid")
        if BOOT_ID_PATTERN.fullmatch(pairs["boot_id"]) is None:
            raise WslEndpointFailure("guest_boot_id_invalid")
        if NETNS_PATTERN.fullmatch(pairs["netns"]) is None:
            raise WslEndpointFailure("guest_netns_invalid")
        return {
            "boot_id": pairs["boot_id"],
            "ipv4": address_text,
            "netns": pairs["netns"],
            "prefix_length": prefix,
        }

    def _busybox_digest(self) -> str:
        output = _decode_wsl_output(
            self._run_guest(["/bin/busybox", "sha256sum", "/bin/busybox"]),
            "guest_busybox_digest",
        )
        fields = output.strip().split()
        if (
            len(fields) != 2
            or fields[1] != "/bin/busybox"
            or re.fullmatch(r"[0-9a-f]{64}", fields[0]) is None
        ):
            raise WslEndpointFailure("guest_busybox_digest_invalid")
        return fields[0]

    def _read_ready(self, process: subprocess.Popen[bytes]) -> tuple[int, int, int, int]:
        stdout = process.stdout
        if stdout is None:
            raise WslEndpointFailure("host_launcher_stdout_unavailable")
        result_queue: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=1)

        def read_line() -> None:
            try:
                result_queue.put(stdout.readline(257))
            except BaseException as exc:  # pragma: no cover - platform pipe failure
                result_queue.put(exc)

        threading.Thread(target=read_line, daemon=True).start()
        try:
            result = result_queue.get(timeout=5)
        except queue.Empty as exc:
            raise WslEndpointFailure("guest_listener_ready_timeout") from exc
        if isinstance(result, BaseException):
            raise WslEndpointFailure("guest_listener_ready_read_failed") from result
        if len(result) > 256 or not result.endswith(b"\n") or b"\r" in result or b"\x00" in result:
            raise WslEndpointFailure("guest_listener_ready_frame_invalid")
        try:
            text = result[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise WslEndpointFailure("guest_listener_ready_frame_invalid") from exc
        fields = text.split("\t")
        if len(fields) != 8 or fields[0] != "FPBR_WSL2_ENDPOINT_V1":
            raise WslEndpointFailure("guest_listener_ready_frame_invalid")
        nonce = fields[1]
        if self._marker != "FPBR_BOUNDARY_LISTENER_NONCE=" + nonce:
            raise WslEndpointFailure("guest_listener_ready_nonce_mismatch")
        numbers: list[int] = []
        for item in fields[2:6]:
            if not item.isdigit() or item.startswith("0"):
                raise WslEndpointFailure("guest_listener_ready_identity_invalid")
            numbers.append(int(item))
        if any(value < 2 for value in (numbers[0], numbers[2])) or any(
            value < 1 for value in (numbers[1], numbers[3])
        ):
            raise WslEndpointFailure("guest_listener_ready_identity_invalid")
        if self._snapshot_before is None or fields[6] != self._snapshot_before["ipv4"]:
            raise WslEndpointFailure("guest_listener_ready_address_mismatch")
        if self._listener_port is None or fields[7] != str(self._listener_port):
            raise WslEndpointFailure("guest_listener_ready_port_mismatch")
        return numbers[0], numbers[1], numbers[2], numbers[3]

    def _listening_socket_rows(self, port: int) -> tuple[tuple[int, str, int], ...]:
        if type(port) is not int or not 1 <= port <= 65_535:
            raise WslEndpointFailure("guest_listener_port_invalid")
        rows: list[tuple[int, str, int]] = []
        for family, path, width in (
            (socket.AF_INET, "/proc/net/tcp", 8),
            (socket.AF_INET6, "/proc/net/tcp6", 32),
        ):
            output = _decode_wsl_output(
                self._run_guest(["/bin/busybox", "cat", path]),
                "guest_tcp_roster_v4" if family == socket.AF_INET else "guest_tcp_roster_v6",
            )
            lines = output.splitlines()
            if not lines or "local_address" not in lines[0]:
                raise WslEndpointFailure("guest_tcp_roster_invalid")
            for line in lines[1:]:
                fields = line.split()
                if len(fields) < 10 or ":" not in fields[1]:
                    raise WslEndpointFailure("guest_tcp_roster_invalid")
                host_hex, port_hex = fields[1].rsplit(":", 1)
                if (
                    len(host_hex) != width
                    or re.fullmatch(rf"[0-9A-F]{{{width}}}", host_hex) is None
                    or re.fullmatch(r"[0-9A-F]{4}", port_hex) is None
                    or re.fullmatch(r"[0-9A-F]{2}", fields[3]) is None
                ):
                    raise WslEndpointFailure("guest_tcp_roster_invalid")
                try:
                    parsed_port = int(port_hex, 16)
                except ValueError as exc:  # defensive after the closed grammar
                    raise WslEndpointFailure("guest_tcp_roster_invalid") from exc
                if parsed_port != port or fields[3] != "0A":
                    continue
                if not fields[9].isdigit() or int(fields[9]) < 1:
                    raise WslEndpointFailure("guest_listener_socket_inode_invalid")
                rows.append((family, host_hex, int(fields[9])))
        if len(rows) != len(set(rows)):
            raise WslEndpointFailure("guest_listener_port_duplicate")
        return tuple(sorted(rows))

    def _port_socket_inode(self, port: int, expected_ipv4: str | None = None) -> int | None:
        rows = self._listening_socket_rows(port)
        if not rows:
            return None
        if expected_ipv4 is None:
            if len(rows) != 1:
                raise WslEndpointFailure("guest_listener_port_ambiguous")
            return rows[0][2]
        try:
            packed = ipaddress.IPv4Address(expected_ipv4).packed
        except ipaddress.AddressValueError as exc:
            raise WslEndpointFailure("guest_listener_address_invalid") from exc
        expected_host = packed[::-1].hex().upper()
        if len(rows) != 1 or rows[0][:2] != (socket.AF_INET, expected_host):
            raise WslEndpointFailure("guest_listener_address_binding_mismatch")
        return rows[0][2]

    def _marker_pids(self, marker: str) -> tuple[int, ...]:
        if MARKER_PATTERN.fullmatch(marker) is None:
            raise WslEndpointFailure("listener_marker_invalid")
        output = _decode_wsl_output(
            self._run_guest(
                [
                    "/bin/busybox",
                    "sh",
                    "-c",
                    self._MARKER_SCAN_SCRIPT,
                    "finplanbr-marker-scan",
                    marker,
                ]
            ),
            "guest_marker_roster",
        )
        values: list[int] = []
        for line in output.splitlines():
            if not line.isascii() or not line.isdigit():
                raise WslEndpointFailure("guest_marker_roster_invalid")
            value = int(line)
            if value < 2:
                raise WslEndpointFailure("guest_marker_pid_invalid")
            values.append(value)
        if values != sorted(set(values)):
            raise WslEndpointFailure("guest_marker_roster_invalid")
        return tuple(values)

    def _pid_cmdline(self, pid: int) -> bytes:
        output = _decode_wsl_output(
            self._run_guest(
                ["/bin/busybox", "od", "-An", "-tx1", "-v", f"/proc/{pid}/cmdline"]
            ),
            "guest_listener_cmdline",
        )
        compact = "".join(output.split())
        if not compact or len(compact) % 2 or re.fullmatch(r"[0-9a-f]+", compact) is None:
            raise WslEndpointFailure("guest_listener_cmdline_invalid")
        return bytes.fromhex(compact)

    def _pid_netns(self, pid: int) -> str:
        output = _decode_wsl_output(
            self._run_guest(["/bin/busybox", "readlink", f"/proc/{pid}/ns/net"]),
            "guest_listener_netns",
        ).strip()
        if NETNS_PATTERN.fullmatch(output) is None:
            raise WslEndpointFailure("guest_listener_netns_invalid")
        return output

    def _pid_starttime_ticks(self, pid: int) -> int:
        output = _decode_wsl_output(
            self._run_guest(["/bin/busybox", "cat", f"/proc/{pid}/stat"]),
            "guest_listener_stat",
        ).strip()
        return self._parse_proc_stat_starttime(output, pid, "guest_listener_stat")

    @staticmethod
    def _parse_proc_stat_starttime(output: str, pid: int, name: str) -> int:
        first_space = output.find(" ")
        close_parenthesis = output.rfind(")")
        if (
            first_space < 1
            or output[:first_space] != str(pid)
            or first_space + 1 >= len(output)
            or output[first_space + 1] != "("
            or close_parenthesis <= first_space + 1
        ):
            raise WslEndpointFailure(f"{name}_invalid")
        fields_from_state = output[close_parenthesis + 1 :].split()
        if len(fields_from_state) < 20 or not fields_from_state[19].isdigit():
            raise WslEndpointFailure(f"{name}_invalid")
        starttime = int(fields_from_state[19])
        if starttime < 1:
            raise WslEndpointFailure(f"{name}_invalid")
        return starttime

    def _pid_starttime_or_none(self, pid: int) -> int | None:
        script = r"""
set -eu
pid=$1
if [ ! -e "/proc/$pid" ]; then
    printf 'ABSENT\n'
    exit 0
fi
[ -r "/proc/$pid/stat" ] || exit 70
if ! /bin/busybox cat "/proc/$pid/stat"; then
    [ ! -e "/proc/$pid" ] && printf 'ABSENT\n' && exit 0
    exit 70
fi
""".strip()
        output = _decode_wsl_output(
            self._run_guest(
                ["/bin/busybox", "sh", "-c", script, "finplanbr-stat", str(pid)]
            ),
            "guest_optional_stat",
        ).strip()
        if output == "ABSENT":
            return None
        if not output:
            raise WslEndpointFailure("guest_optional_stat_empty")
        return self._parse_proc_stat_starttime(output, pid, "guest_optional_stat")

    def _pid_owns_socket(self, pid: int, inode: int) -> bool:
        script = r"""
set -eu
pid=$1
inode=$2
count=0
for path in "/proc/$pid/fd"/*; do
    [ -L "$path" ] || continue
    target=$(/bin/busybox readlink "$path")
    if [ "$target" = "socket:[$inode]" ]; then
        count=$((count + 1))
    fi
done
printf '%s\n' "$count"
""".strip()
        output = _decode_wsl_output(
            self._run_guest(
                [
                    "/bin/busybox",
                    "sh",
                    "-c",
                    script,
                    "finplanbr-socket-owner",
                    str(pid),
                    str(inode),
                ]
            ),
            "guest_listener_socket_owner",
        ).strip()
        if not output.isdigit():
            raise WslEndpointFailure("guest_listener_socket_owner_invalid")
        return int(output) >= 1

    def _wait_started(self, marker: str, port: int, expected_cmdline: bytes) -> int:
        if (
            self._listener_pid is None
            or self._listener_starttime_ticks is None
            or self._watchdog_pid is None
            or self._watchdog_starttime_ticks is None
        ):
            raise WslEndpointFailure("guest_listener_ready_identity_missing")
        deadline = self._monotonic() + 8.0
        while self._monotonic() < deadline:
            if self._host_process is not None and self._host_process.poll() is not None:
                raise WslEndpointFailure("guest_listener_exited_early")
            pids = self._marker_pids(marker)
            if len(pids) > 1:
                raise WslEndpointFailure("guest_listener_marker_ambiguous")
            expected_ipv4 = (
                str(self._snapshot_before["ipv4"]) if self._snapshot_before is not None else ""
            )
            socket_inode = self._port_socket_inode(port, expected_ipv4)
            if len(pids) == 1 and socket_inode is not None:
                pid = pids[0]
                if pid != self._listener_pid:
                    raise WslEndpointFailure("guest_listener_marker_pid_mismatch")
                cmdline = self._pid_cmdline(pid)
                if cmdline != expected_cmdline:
                    raise WslEndpointFailure("guest_listener_cmdline_mismatch")
                if self._snapshot_before is None or self._pid_netns(pid) != self._snapshot_before["netns"]:
                    raise WslEndpointFailure("guest_listener_netns_mismatch")
                starttime_ticks = self._pid_starttime_ticks(pid)
                if starttime_ticks != self._listener_starttime_ticks:
                    raise WslEndpointFailure("guest_listener_starttime_mismatch")
                if (
                    self._pid_starttime_or_none(self._watchdog_pid)
                    != self._watchdog_starttime_ticks
                ):
                    raise WslEndpointFailure("guest_watchdog_identity_mismatch")
                if not self._pid_owns_socket(pid, socket_inode):
                    raise WslEndpointFailure("guest_listener_socket_owner_mismatch")
                self._listener_command_sha256 = _sha256(cmdline)
                self._listener_socket_inode = socket_inode
                return pid
            self._sleeper(0.05)
        raise WslEndpointFailure("guest_listener_start_timeout")

    def start(self) -> Wsl2EndpointLease:
        if self._prelaunch is not None or self._closed:
            raise WslEndpointFailure("endpoint_lease_state_invalid")
        if not self._distro_running_v2():
            raise WslEndpointFailure("existing_running_wsl2_distro_unavailable")
        self._snapshot_before = self._snapshot()
        guest_ip = str(self._snapshot_before["ipv4"])
        windows_ips = self._ipv4_reader()
        windows_ip_absent = guest_ip not in windows_ips
        if not windows_ip_absent:
            raise WslEndpointFailure("guest_ip_present_on_windows_interface")
        startup_nonce = self._nonce_factory(16).hex()
        marker = "FPBR_BOUNDARY_LISTENER_NONCE=" + startup_nonce
        if MARKER_PATTERN.fullmatch(marker) is None:
            raise WslEndpointFailure("listener_nonce_factory_invalid")
        if self._marker_pids(marker):
            raise WslEndpointFailure("listener_marker_preexisting")
        port = 0
        for _attempt in range(32):
            candidate = self._port_factory()
            if type(candidate) is not int or not MIN_LISTENER_PORT <= candidate <= MAX_LISTENER_PORT:
                raise WslEndpointFailure("listener_port_factory_invalid")
            if self._port_socket_inode(candidate) is None:
                port = candidate
                break
        if port == 0:
            raise WslEndpointFailure("listener_port_unavailable")
        guest_argv = (
            "/bin/busybox",
            "nc",
            "-n",
            "-lk",
            "-s",
            guest_ip,
            "-p",
            str(port),
            "-e",
            "/bin/cat",
        )
        expected_cmdline = b"\0".join(item.encode("ascii") for item in guest_argv) + b"\0"
        self._busybox_sha256 = self._busybox_digest()
        self._marker = marker
        self._listener_port = port
        command = [
            os.fspath(self._wsl_path),
            "--distribution",
            NETWORK_DISTRO_NAME,
            "--exec",
            "/bin/busybox",
            "sh",
            "-c",
            self._STARTUP_SCRIPT,
            "fpbr-wsl2-endpoint-v1",
            guest_ip,
            str(port),
            str(self._lease_seconds),
            startup_nonce,
        ]
        creationflags = 0x08000000 if os.name == "nt" else 0
        try:
            self._host_process = self._process_factory(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WslEndpointFailure("host_launcher_start_failed") from exc
        try:
            host_launcher_pid = getattr(self._host_process, "pid", None)
            if type(host_launcher_pid) is not int or host_launcher_pid < 2:
                raise WslEndpointFailure("host_launcher_pid_invalid")
            self._host_launcher_pid = host_launcher_pid
            self._host_launcher_creation_time_100ns = self._host_creation_time_reader(
                self._host_process
            )
            (
                self._listener_pid,
                self._listener_starttime_ticks,
                self._watchdog_pid,
                self._watchdog_starttime_ticks,
            ) = self._read_ready(self._host_process)
            self._wait_started(marker, port, expected_cmdline)
        except Exception:
            self.close()
            raise
        self._prelaunch = {
            "distro_name": NETWORK_DISTRO_NAME,
            "distro_running_before": True,
            "endpoint_class": NETWORK_ENDPOINT_CLASS,
            "guest_boot_id": self._snapshot_before["boot_id"],
            "guest_interface": GUEST_INTERFACE,
            "guest_ipv4": guest_ip,
            "guest_prefix_length": self._snapshot_before["prefix_length"],
            "host_launcher_pid": self._host_launcher_pid,
            "host_launcher_creation_time_100ns": self._host_launcher_creation_time_100ns,
            "busybox_sha256": self._busybox_sha256,
            "listener_command_sha256": self._listener_command_sha256,
            "listener_pid": self._listener_pid,
            "listener_port": port,
            "listener_port_absent_before_start": True,
            "listener_port_observed_before": True,
            "listener_process_absent_before_start": True,
            "listener_process_observed_before": True,
            "listener_socket_inode": self._listener_socket_inode,
            "listener_starttime_ticks": self._listener_starttime_ticks,
            "listener_watchdog_timeout_seconds": self._lease_seconds,
            "startup_nonce_sha256": _sha256(startup_nonce.encode("ascii")),
            "startup_script_sha256": _sha256(self._STARTUP_SCRIPT.encode("ascii")),
            "netns_inode": self._snapshot_before["netns"],
            "windows_interface_ip_absent_before": windows_ip_absent,
            "watchdog_pid": self._watchdog_pid,
            "watchdog_starttime_ticks": self._watchdog_starttime_ticks,
            "wsl_version": WSL_VERSION,
        }
        return self

    @property
    def prelaunch_observation(self) -> dict[str, object]:
        if self._prelaunch is None or self._closed:
            raise WslEndpointFailure("endpoint_prelaunch_unavailable")
        return dict(self._prelaunch)

    def _signal_exact_listener(self, signal_name: str) -> bool:
        if self._listener_pid is None:
            return True
        if (
            signal_name not in {"TERM", "KILL"}
            or self._marker is None
            or self._listener_starttime_ticks is None
            or self._listener_socket_inode is None
            or self._listener_command_sha256 is None
            or self._listener_port is None
            or self._snapshot_before is None
        ):
            return False
        address = ipaddress.IPv4Address(str(self._snapshot_before["ipv4"]))
        local_hex = address.packed[::-1].hex().upper()
        port_hex = f"{self._listener_port:04X}"
        output = _decode_wsl_output(
            self._run_guest(
                [
                    "/bin/busybox",
                    "sh",
                    "-c",
                    self._EXACT_SIGNAL_SCRIPT,
                    "fpbr-exact-listener-cleanup-v2",
                    signal_name,
                    str(self._listener_pid),
                    str(self._listener_starttime_ticks),
                    self._marker,
                    self._listener_command_sha256,
                    str(self._snapshot_before["netns"]),
                    str(self._listener_socket_inode),
                    local_hex,
                    port_hex,
                    "fpbr-exact-listener-cleanup-v2",
                ]
            ),
            "guest_exact_listener_cleanup",
        ).strip()
        return output in {"ABSENT", "ABSENT_REUSED", "SIGNALED"}

    def _listener_cleanup_state(self) -> tuple[bool, bool, bool]:
        identity_absent = self._listener_pid is None
        if self._listener_pid is not None and self._listener_starttime_ticks is not None:
            identity_absent = (
                self._pid_starttime_or_none(self._listener_pid)
                != self._listener_starttime_ticks
            )
        elif self._listener_pid is not None:
            identity_absent = False
        marker_absent = self._marker is None or not self._marker_pids(self._marker)
        port_absent = self._listener_port is None or not self._listening_socket_rows(
            self._listener_port
        )
        return identity_absent and marker_absent, marker_absent, port_absent

    def _wait_listener_absent(self, seconds: float) -> tuple[bool, bool, bool]:
        deadline = self._monotonic() + seconds
        state = self._listener_cleanup_state()
        while self._monotonic() < deadline and not all(state):
            self._sleeper(0.05)
            state = self._listener_cleanup_state()
        return state

    def _wait_watchdog_absent(self, seconds: float) -> bool:
        if self._watchdog_pid is None:
            return True
        if self._watchdog_starttime_ticks is None:
            return False
        deadline = self._monotonic() + seconds
        absent = False
        while self._monotonic() < deadline:
            absent = (
                self._pid_starttime_or_none(self._watchdog_pid)
                != self._watchdog_starttime_ticks
            )
            if absent:
                break
            self._sleeper(0.05)
        return absent

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        process_absent = self._listener_pid is None
        marker_absent = self._marker is None
        watchdog_absent = self._watchdog_pid is None
        port_absent = self._listener_port is None
        distro_running_after = False
        windows_ip_absent_after = False
        host_absent = self._host_process is None
        cleanup_exact = True
        snapshot_after = self._snapshot_before

        try:
            distro_running_after = self._distro_running_v2()
            if distro_running_after and self._listener_pid is not None:
                cleanup_exact = self._signal_exact_listener("TERM")
                process_absent, marker_absent, port_absent = self._wait_listener_absent(5.0)
                if not (process_absent and marker_absent and port_absent):
                    cleanup_exact = self._signal_exact_listener("KILL") and cleanup_exact
                    process_absent, marker_absent, port_absent = self._wait_listener_absent(4.0)
                watchdog_absent = self._wait_watchdog_absent(4.0)
        except (OSError, subprocess.SubprocessError, WslEndpointFailure):
            cleanup_exact = False

        try:
            if self._host_process is not None:
                try:
                    self._host_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._host_process.terminate()
                    try:
                        self._host_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self._host_process.kill()
                        self._host_process.wait(timeout=5)
                    cleanup_exact = False
                host_absent = self._host_process.poll() is not None
        except (OSError, subprocess.SubprocessError):
            cleanup_exact = False
            host_absent = False
        finally:
            if self._host_process is not None and self._host_process.stdout is not None:
                try:
                    self._host_process.stdout.close()
                except OSError:
                    cleanup_exact = False

        try:
            distro_running_after = self._distro_running_v2()
            if distro_running_after:
                process_absent, marker_absent, port_absent = self._listener_cleanup_state()
                watchdog_absent = self._wait_watchdog_absent(2.0)
                snapshot_after = self._snapshot()
                windows_ip_absent_after = (
                    str(snapshot_after["ipv4"]) not in self._ipv4_reader()
                )
            else:
                cleanup_exact = False
        except (OSError, subprocess.SubprocessError, WslEndpointFailure):
            cleanup_exact = False

        if self._snapshot_before is None or snapshot_after is None:
            return
        self._snapshot_after = snapshot_after
        startup_nonce = (
            self._marker.partition("=")[2] if self._marker is not None else "missing"
        )
        windows_ip_absent_before = bool(
            self._prelaunch is not None
            and self._prelaunch.get("windows_interface_ip_absent_before") is True
        )
        self._receipt = {
            "busybox_sha256": self._busybox_sha256 or "0" * 64,
            "cleanup_exact_listener_pid_only": cleanup_exact,
            "distro_name": NETWORK_DISTRO_NAME,
            "distro_running_after": distro_running_after,
            "distro_running_before": True,
            "endpoint_class": NETWORK_ENDPOINT_CLASS,
            "format": ENDPOINT_RECEIPT_FORMAT,
            "guest_boot_id_after": snapshot_after["boot_id"],
            "guest_boot_id_before": self._snapshot_before["boot_id"],
            "guest_interface": GUEST_INTERFACE,
            "guest_ipv4_after": snapshot_after["ipv4"],
            "guest_ipv4_before": self._snapshot_before["ipv4"],
            "guest_prefix_length_after": snapshot_after["prefix_length"],
            "guest_prefix_length_before": self._snapshot_before["prefix_length"],
            "guest_residual_absent_after": (
                process_absent and marker_absent and port_absent and watchdog_absent
            ),
            "host_launcher_process_absent_after": host_absent,
            "host_launcher_pid": self._host_launcher_pid or 2,
            "host_launcher_creation_time_100ns": (
                self._host_launcher_creation_time_100ns or 1
            ),
            "listener_command_sha256": self._listener_command_sha256 or "0" * 64,
            "listener_pid": self._listener_pid or 2,
            "listener_port": self._listener_port or MIN_LISTENER_PORT,
            "listener_port_absent_after": port_absent,
            "listener_port_absent_before_start": True,
            "listener_port_observed_before": self._prelaunch is not None,
            "listener_process_absent_after": process_absent,
            "listener_process_absent_before_start": True,
            "listener_process_observed_before": self._prelaunch is not None,
            "listener_socket_inode": self._listener_socket_inode or 1,
            "listener_starttime_ticks": self._listener_starttime_ticks or 1,
            "listener_watchdog_timeout_seconds": self._lease_seconds,
            "netns_inode_after": snapshot_after["netns"],
            "netns_inode_before": self._snapshot_before["netns"],
            "startup_nonce_sha256": _sha256(startup_nonce.encode("ascii")),
            "startup_script_sha256": _sha256(self._STARTUP_SCRIPT.encode("ascii")),
            "windows_interface_ip_absent_after": windows_ip_absent_after,
            "windows_interface_ip_absent_before": windows_ip_absent_before,
            "wsl_version": WSL_VERSION,
            "watchdog_pid": self._watchdog_pid or 2,
            "watchdog_process_absent_after": watchdog_absent,
            "watchdog_starttime_ticks": self._watchdog_starttime_ticks or 1,
        }

    @property
    def receipt(self) -> dict[str, object]:
        if not self._closed or self._receipt is None:
            raise WslEndpointFailure("endpoint_receipt_unavailable")
        return dict(self._receipt)

    def __enter__(self) -> Wsl2EndpointLease:
        return self.start()

    def __exit__(self, *_args: object) -> None:
        self.close()


def acquire_wsl2_endpoint(timeout_seconds: int = 180) -> Wsl2EndpointLease:
    """Create an unstarted lease for the fixed, preregistered endpoint class."""

    if type(timeout_seconds) is not int or not 30 <= timeout_seconds <= 900:
        raise WslEndpointFailure("endpoint_timeout_invalid")
    return Wsl2EndpointLease(lease_seconds=min(timeout_seconds + 30, 600))
