from __future__ import annotations

import io
import subprocess
import unittest

from scripts import windows_appcontainer_boundary_report as boundary
from scripts import windows_wsl2_endpoint as endpoint


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        self.value += 0.05
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class _FakeProcess:
    def __init__(self, ready: bytes, owner: _DeterministicLease) -> None:
        self.pid = 654
        self.stdout = io.BytesIO(ready)
        self.returncode: int | None = None
        self._owner = owner

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None:
            return self.returncode
        if self._owner.listener_alive:
            raise subprocess.TimeoutExpired("fake-wsl", timeout)
        self.returncode = 0
        return 0

    def terminate(self) -> None:
        self.returncode = 1

    def kill(self) -> None:
        self.returncode = 1


class _DeterministicLease(endpoint.Wsl2EndpointLease):
    guest_ip = "172.29.60.71"
    port = 55_123
    listener_pid = 321
    listener_starttime = 12_345
    watchdog_pid = 322
    watchdog_starttime = 12_346
    socket_inode = 987_654
    netns = "net:[4026532896]"
    boot_id = "f596e7b8-c93b-4b3f-86b1-1faf403afc0a"

    def __init__(self) -> None:
        self.clock = _Clock()
        self.listener_alive = False
        self.marker_present = False
        self.socket_alive = False
        self.watchdog_alive = False
        self.current_listener_starttime = self.listener_starttime
        self.signals: list[tuple[str, int]] = []
        self.fail_guest_cleanup = False
        super().__init__(
            wsl_path=endpoint.Path(r"C:\Windows\System32\wsl.exe"),
            process_factory=self._make_process,  # type: ignore[arg-type]
            port_factory=lambda: self.port,
            nonce_factory=lambda byte_count: b"\xab" * byte_count,
            ipv4_reader=lambda: {"172.29.48.1", "127.0.0.1"},
            host_creation_time_reader=lambda _process: 133_800_000_000_000_000,
            lease_seconds=210,
            monotonic=self.clock.monotonic,
            sleeper=self.clock.sleep,
        )

    def _make_process(self, _command: list[str], **_kwargs: object) -> _FakeProcess:
        self.listener_alive = True
        self.marker_present = True
        self.socket_alive = True
        self.watchdog_alive = True
        nonce = "ab" * 16
        ready = (
            "FPBR_WSL2_ENDPOINT_V1\t"
            f"{nonce}\t{self.listener_pid}\t{self.listener_starttime}\t"
            f"{self.watchdog_pid}\t{self.watchdog_starttime}\t"
            f"{self.guest_ip}\t{self.port}\n"
        ).encode("ascii")
        return _FakeProcess(ready, self)

    def _distro_running_v2(self) -> bool:
        return True

    def _snapshot(self) -> dict[str, object]:
        return {
            "boot_id": self.boot_id,
            "ipv4": self.guest_ip,
            "netns": self.netns,
            "prefix_length": 20,
        }

    def _busybox_digest(self) -> str:
        return "0" * 64

    def _marker_pids(self, _marker: str) -> tuple[int, ...]:
        return (self.listener_pid,) if self.listener_alive and self.marker_present else ()

    def _port_socket_inode(
        self, _port: int, _expected_ipv4: str | None = None
    ) -> int | None:
        return self.socket_inode if self.socket_alive else None

    def _listening_socket_rows(self, _port: int) -> tuple[tuple[int, str, int], ...]:
        if not self.socket_alive:
            return ()
        ipv4_hex = bytes(reversed(bytes((172, 29, 60, 71)))).hex().upper()
        return ((endpoint.socket.AF_INET, ipv4_hex, self.socket_inode),)

    def _pid_cmdline(self, _pid: int) -> bytes:
        return b"\0".join(
            (
                b"/bin/busybox",
                b"nc",
                b"-n",
                b"-lk",
                b"-s",
                self.guest_ip.encode("ascii"),
                b"-p",
                str(self.port).encode("ascii"),
                b"-e",
                b"/bin/cat",
            )
        ) + b"\0"

    def _pid_netns(self, _pid: int) -> str:
        return self.netns

    def _pid_starttime_ticks(self, pid: int) -> int:
        if pid == self.listener_pid:
            return self.current_listener_starttime
        if pid == self.watchdog_pid and self.watchdog_alive:
            return self.watchdog_starttime
        raise endpoint.WslEndpointFailure("fake_process_absent")

    def _pid_starttime_or_none(self, pid: int) -> int | None:
        if pid == self.watchdog_pid:
            return self.watchdog_starttime if self.watchdog_alive else None
        if pid == self.listener_pid:
            return self.current_listener_starttime if self.listener_alive else None
        return None

    def _pid_owns_socket(self, _pid: int, _inode: int) -> bool:
        return self.listener_alive and self.socket_alive

    def _run_guest(self, arguments: list[str], *, timeout: int = 15) -> bytes:
        del timeout
        if "fpbr-exact-listener-cleanup-v2" in arguments:
            if self.fail_guest_cleanup:
                raise endpoint.WslEndpointFailure("fake_guest_cleanup_failure")
            self.assert_exact_cleanup_arguments(arguments)
            signal = arguments[-10]
            pid = int(arguments[-9])
            if self.current_listener_starttime != self.listener_starttime:
                return b"ABSENT_REUSED\n"
            if not self.listener_alive:
                return b"ABSENT\n"
            if not self.marker_present or not self.socket_alive:
                raise endpoint.WslEndpointFailure("fake_identity_refused")
            self.signals.append((signal, pid))
            self.listener_alive = False
            self.marker_present = False
            self.socket_alive = False
            self.watchdog_alive = False
            return b"SIGNALED\n"
        return b""

    def assert_exact_cleanup_arguments(self, arguments: list[str]) -> None:
        expected = (
            ["/bin/busybox", "sh", "-c"],
            "fpbr-exact-listener-cleanup-v2",
            str(self.listener_pid),
            str(self.listener_starttime),
            "FPBR_BOUNDARY_LISTENER_NONCE=" + "ab" * 16,
            self._listener_command_sha256,
            self.netns,
            str(self.socket_inode),
            "473C1DAC",
            f"{self.port:04X}",
            "fpbr-exact-listener-cleanup-v2",
        )
        observed = (
            arguments[:3],
            arguments[-11],
            arguments[-9],
            arguments[-8],
            arguments[-7],
            arguments[-6],
            arguments[-5],
            arguments[-4],
            arguments[-3],
            arguments[-2],
            arguments[-1],
        )
        if observed != expected or arguments[-10] not in {"TERM", "KILL"}:
            raise AssertionError("exact cleanup argv drift")


class WindowsWsl2EndpointTests(unittest.TestCase):
    def test_wsl_output_decoder_accepts_utf16le_and_utf8_but_rejects_nul(self) -> None:
        text = "docker-desktop\r\n"
        self.assertEqual(endpoint._decode_wsl_output(text.encode("utf-16-le"), "fixture"), "docker-desktop\n")
        self.assertEqual(endpoint._decode_wsl_output(b"ready\n", "fixture"), "ready\n")
        with self.assertRaises(endpoint.WslEndpointFailure):
            endpoint._decode_wsl_output(b"a\x00b", "fixture")

    def test_full_fake_lifecycle_binds_identity_and_exact_cleanup(self) -> None:
        lease = _DeterministicLease().start()
        prelaunch = lease.prelaunch_observation
        self.assertEqual(prelaunch["listener_pid"], lease.listener_pid)
        self.assertEqual(prelaunch["listener_starttime_ticks"], lease.listener_starttime)
        self.assertEqual(prelaunch["listener_socket_inode"], lease.socket_inode)
        self.assertEqual(prelaunch["watchdog_pid"], lease.watchdog_pid)
        self.assertEqual(prelaunch["listener_watchdog_timeout_seconds"], 210)

        lease.close()
        receipt = lease.receipt
        self.assertEqual(lease.signals, [("TERM", lease.listener_pid)])
        self.assertTrue(receipt["cleanup_exact_listener_pid_only"])
        self.assertTrue(receipt["watchdog_process_absent_after"])
        self.assertTrue(receipt["guest_residual_absent_after"])
        self.assertEqual(boundary._validate_endpoint_receipt(receipt), receipt)

    def test_starttime_drift_is_not_signaled_and_fails_closed(self) -> None:
        lease = _DeterministicLease().start()
        lease.current_listener_starttime += 1
        lease.close()

        receipt = lease.receipt
        self.assertEqual(lease.signals, [])
        self.assertFalse(receipt["cleanup_exact_listener_pid_only"])
        self.assertFalse(receipt["listener_process_absent_after"])
        self.assertFalse(receipt["guest_residual_absent_after"])

    def test_marker_loss_does_not_hide_live_original_pid(self) -> None:
        lease = _DeterministicLease().start()
        lease.marker_present = False
        lease.close()

        receipt = lease.receipt
        self.assertEqual(lease.signals, [])
        self.assertFalse(receipt["cleanup_exact_listener_pid_only"])
        self.assertFalse(receipt["listener_process_absent_after"])
        self.assertFalse(receipt["guest_residual_absent_after"])

    def test_guest_cleanup_failure_still_finalizes_retained_host_process(self) -> None:
        lease = _DeterministicLease().start()
        process = lease._host_process
        self.assertIsNotNone(process)
        lease.fail_guest_cleanup = True
        lease.close()

        self.assertIsNotNone(process)
        self.assertEqual(process.poll(), 1)  # type: ignore[union-attr]
        self.assertTrue(lease.receipt["host_launcher_process_absent_after"])
        self.assertFalse(lease.receipt["cleanup_exact_listener_pid_only"])

    def test_startup_script_has_bounded_exact_cleanup_only(self) -> None:
        script = endpoint.Wsl2EndpointLease._STARTUP_SCRIPT
        snapshot_script = endpoint.Wsl2EndpointLease._SNAPSHOT_SCRIPT
        cleanup_script = endpoint.Wsl2EndpointLease._EXACT_SIGNAL_SCRIPT
        self.assertIn('exec /bin/busybox nc -n -lk -s "$ip"', script)
        self.assertIn('/bin/busybox kill -TERM "$listener"', script)
        self.assertIn('[ "$#" -eq 1 ]', snapshot_script)
        for proof in ("cmd_sha", "netns", "inode", "local_hex", "read_identity"):
            self.assertIn(proof, cleanup_script)
        for forbidden in ("killall", "pkill", "fuser", "wsl --terminate", "docker "):
            self.assertNotIn(forbidden, script + cleanup_script)

    def test_socket_binding_requires_exact_ipv4_and_no_tcp6_listener(self) -> None:
        lease = _DeterministicLease()
        ipv4_hex = bytes(reversed(bytes((172, 29, 60, 71)))).hex().upper()
        lease._listening_socket_rows = lambda _port: (  # type: ignore[method-assign]
            (endpoint.socket.AF_INET, ipv4_hex, lease.socket_inode),
        )
        self.assertEqual(
            endpoint.Wsl2EndpointLease._port_socket_inode(
                lease, lease.port, lease.guest_ip
            ),
            lease.socket_inode,
        )

        lease._listening_socket_rows = lambda _port: (  # type: ignore[method-assign]
            (endpoint.socket.AF_INET6, "0" * 32, lease.socket_inode),
        )
        with self.assertRaisesRegex(
            endpoint.WslEndpointFailure, "guest_listener_address_binding_mismatch"
        ):
            endpoint.Wsl2EndpointLease._port_socket_inode(
                lease, lease.port, lease.guest_ip
            )

    def test_socket_roster_reads_ipv4_and_ipv6_before_exact_binding(self) -> None:
        lease = _DeterministicLease()
        port_hex = f"{lease.port:04X}"
        ipv4 = (
            "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt "
            "uid timeout inode\n"
            f"  0: 473C1DAC:{port_hex} 00000000:0000 0A 0:0 00:0 0 0 0 "
            f"{lease.socket_inode}\n"
        ).encode("ascii")
        tcp6_empty = (
            "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt "
            "uid timeout inode\n"
        ).encode("ascii")
        observed_paths: list[str] = []

        def roster_run(arguments: list[str], *, timeout: int = 15) -> bytes:
            del timeout
            observed_paths.append(arguments[-1])
            return ipv4 if arguments[-1] == "/proc/net/tcp" else tcp6_empty

        lease._run_guest = roster_run  # type: ignore[method-assign]
        rows = endpoint.Wsl2EndpointLease._listening_socket_rows(lease, lease.port)
        self.assertEqual(observed_paths, ["/proc/net/tcp", "/proc/net/tcp6"])
        self.assertEqual(
            rows,
            ((endpoint.socket.AF_INET, "473C1DAC", lease.socket_inode),),
        )


if __name__ == "__main__":
    unittest.main()
