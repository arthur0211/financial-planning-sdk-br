from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from scripts import bounded_subprocess as bounded


class BoundedSubprocessTests(unittest.TestCase):
    def run_python(
        self,
        code: str,
        *,
        input_bytes: bytes = b"",
        timeout_seconds: float = 5,
        stdout_limit: int = 65_536,
        stderr_limit: int = 65_536,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return bounded.run_bounded(
            [sys.executable, "-I", "-S", "-B", "-c", code],
            cwd=cwd,
            input_bytes=input_bytes,
            timeout_seconds=timeout_seconds,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )

    def test_exact_input_output_and_return_code_are_preserved(self) -> None:
        payload = b"bounded-input\x00\xff"
        code = (
            "import hashlib,sys;"
            "data=sys.stdin.buffer.read();"
            "sys.stdout.write(str(len(data))+'|'+hashlib.sha256(data).hexdigest());"
            "sys.stderr.write('diagnostic');"
            "raise SystemExit(7)"
        )
        completed = self.run_python(code, input_bytes=payload)
        self.assertEqual(completed.args, [sys.executable, "-I", "-S", "-B", "-c", code])
        self.assertEqual(completed.returncode, 7)
        self.assertEqual(completed.stdout, f"{len(payload)}|{hashlib.sha256(payload).hexdigest()}".encode())
        self.assertEqual(completed.stderr, b"diagnostic")

    def test_stdout_and_stderr_are_bounded_during_execution(self) -> None:
        for stream in ("stdout", "stderr"):
            target = "sys.stdout.buffer" if stream == "stdout" else "sys.stderr.buffer"
            code = f"import sys,time;{target}.write(b'x'*1048576);{target}.flush();time.sleep(30)"
            started = time.monotonic()
            with self.assertRaises(bounded.BoundedProcessOutputLimit) as captured:
                self.run_python(code, stdout_limit=1024, stderr_limit=1024)
            self.assertEqual(captured.exception.stream, stream)
            self.assertLess(time.monotonic() - started, 5)

    def test_limit_plus_one_is_output_limit_not_timeout(self) -> None:
        for stream in ("stdout", "stderr"):
            target = "sys.stdout.buffer" if stream == "stdout" else "sys.stderr.buffer"
            code = f"import sys,time;{target}.write(b'x'*1025);{target}.flush();time.sleep(30)"
            started = time.monotonic()
            with self.assertRaises(bounded.BoundedProcessOutputLimit) as captured:
                self.run_python(
                    code,
                    timeout_seconds=1,
                    stdout_limit=1024,
                    stderr_limit=1024,
                )
            self.assertEqual(captured.exception.stream, stream)
            self.assertLess(time.monotonic() - started, 1)

    def test_timeout_kills_descendants_before_temporary_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-bounded-timeout-") as directory:
            root = Path(directory)
            marker = root / "descendant-survived.txt"
            child = (
                "import pathlib,time;"
                "time.sleep(0.8);"
                f"pathlib.Path({str(marker)!r}).write_text('bad')"
            )
            parent = (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
                "time.sleep(30)"
            )
            with self.assertRaises(bounded.BoundedProcessTimeout):
                self.run_python(parent, timeout_seconds=0.2, cwd=root)
            time.sleep(1)
            self.assertFalse(marker.exists())

    def test_successful_leader_cannot_leave_a_descendant_holding_pipes(self) -> None:
        child = "import time;time.sleep(30)"
        parent = (
            "import subprocess,sys;"
            "sys.stdin.buffer.read();"
            f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
            "print('done',flush=True)"
        )
        started = time.monotonic()
        completed = self.run_python(parent)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout.replace(b"\r\n", b"\n"), b"done\n")
        self.assertLess(time.monotonic() - started, 5)

    def test_cancellation_still_kills_the_process_tree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-bounded-cancel-") as directory:
            root = Path(directory)
            marker = root / "cancelled-descendant-survived.txt"
            child = (
                "import pathlib,time;"
                "time.sleep(0.8);"
                f"pathlib.Path({str(marker)!r}).write_text('bad')"
            )
            parent = (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
                "time.sleep(30)"
            )
            real_sleep = time.sleep
            cancellation_injected = False

            def cancel_after_candidate_start(delay: float) -> None:
                nonlocal cancellation_injected
                if not cancellation_injected:
                    cancellation_injected = True
                    real_sleep(0.2)
                    raise KeyboardInterrupt
                real_sleep(delay)

            with mock.patch.object(bounded.time, "sleep", cancel_after_candidate_start):
                with self.assertRaises(KeyboardInterrupt):
                    self.run_python(parent, cwd=root)
            self.assertTrue(cancellation_injected)
            real_sleep(1)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "the pre-assignment gate is Windows-specific")
    def test_windows_assignment_failure_cannot_reach_candidate_command(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-bounded-assign-") as directory:
            marker = Path(directory) / "candidate-started.txt"
            code = f"from pathlib import Path;Path({str(marker)!r}).write_text('bad')"
            with mock.patch.object(
                bounded.WindowsJob,
                "assign",
                side_effect=bounded.BoundedProcessStartError("injected assignment failure"),
            ):
                with self.assertRaisesRegex(bounded.BoundedProcessStartError, "injected"):
                    self.run_python(code)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "the pre-assignment gate is Windows-specific")
    def test_windows_delayed_assignment_still_precedes_candidate_execution(self) -> None:
        observed: list[float] = []
        original = bounded.WindowsJob.assign

        def delayed(job: bounded.WindowsJob, process: subprocess.Popen[bytes]) -> None:
            time.sleep(0.2)
            original(job, process)
            observed.append(time.monotonic())

        code = "import json,time;print(json.dumps({'started':time.monotonic()}))"
        with mock.patch.object(bounded.WindowsJob, "assign", delayed):
            completed = self.run_python(code)
        started = json.loads(completed.stdout)["started"]
        self.assertEqual(len(observed), 1)
        self.assertGreaterEqual(started, observed[0])

    @unittest.skipUnless(os.name == "nt", "the pre-assignment gate is Windows-specific")
    def test_windows_deadline_expiry_never_releases_candidate_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-bounded-deadline-") as directory:
            marker = Path(directory) / "candidate-started.txt"
            original = bounded.WindowsJob.assign

            def delayed(job: bounded.WindowsJob, process: subprocess.Popen[bytes]) -> None:
                time.sleep(0.2)
                original(job, process)

            code = f"from pathlib import Path;Path({str(marker)!r}).write_text('bad')"
            with mock.patch.object(bounded.WindowsJob, "assign", delayed):
                with self.assertRaisesRegex(bounded.BoundedProcessTimeout, "before gate release"):
                    self.run_python(code, timeout_seconds=0.05)
            time.sleep(0.2)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "the pre-assignment gate is Windows-specific")
    def test_windows_assignment_cancellation_is_immediate_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-bounded-assign-cancel-") as directory:
            marker = Path(directory) / "candidate-started.txt"
            code = f"from pathlib import Path;Path({str(marker)!r}).write_text('bad')"
            started = time.monotonic()
            with mock.patch.object(bounded.WindowsJob, "assign", side_effect=KeyboardInterrupt("cancel")):
                with self.assertRaises(KeyboardInterrupt) as captured:
                    self.run_python(code)
            self.assertIsNone(captured.exception.__cause__)
            self.assertLess(time.monotonic() - started, 1)
            self.assertFalse(marker.exists())

    def test_platform_claim_is_explicitly_bounded(self) -> None:
        expected = (
            "windows_job_kill_on_close_with_preassignment_gate"
            if os.name == "nt"
            else "best_effort_same_process_group_daemon_escape_possible"
        )
        self.assertEqual(bounded.process_tree_claim(), expected)

    def test_process_start_failure_is_normalized(self) -> None:
        with mock.patch.object(
            bounded._OwnedBootstrapProcess,
            "_initialize",
            autospec=True,
            side_effect=OSError("injected start failure"),
        ):
            with self.assertRaisesRegex(bounded.BoundedProcessStartError, "leader could not start"):
                self.run_python("pass")

    def test_post_create_cancellation_retains_and_reaps_bootstrap_ownership(self) -> None:
        state = {"kill": 0, "wait": 0, "gate_writes": 0}

        class Gate:
            def write(self, _payload: bytes) -> None:
                state["gate_writes"] += 1

            def close(self) -> None:
                return None

        def post_create_cancel(process: Any, *_args: object, **_kwargs: object) -> None:
            process._child_created = True
            process.pid = 314159
            process.stdin = Gate()
            process.stdout = Gate()
            process.stderr = Gate()
            process.poll = lambda: None

            def kill() -> None:
                state["kill"] += 1

            def wait(*, timeout: float) -> int:
                self.assertEqual(timeout, 5)
                state["wait"] += 1
                process.returncode = -9
                return -9

            process.kill = kill
            process.wait = wait
            raise KeyboardInterrupt("post-create-pre-ownership-return")

        with mock.patch.object(
            bounded._OwnedBootstrapProcess,
            "_initialize",
            autospec=True,
            side_effect=post_create_cancel,
        ):
            with self.assertRaisesRegex(KeyboardInterrupt, "post-create-pre-ownership-return"):
                self.run_python("raise AssertionError('candidate must remain gated')")
        self.assertEqual(state, {"kill": 1, "wait": 1, "gate_writes": 0})
        self.assertFalse(
            [thread for thread in threading.enumerate() if thread.name == "finplanbr-bounded-launch"]
        )

    def test_cancellation_after_real_create_uses_preinitialized_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-bounded-post-create-") as directory:
            marker = Path(directory) / "candidate-started.txt"
            code = f"from pathlib import Path;Path({str(marker)!r}).write_text('bad')"
            original_initialize = bounded._OwnedBootstrapProcess._initialize

            def cancel_after_create(process: object, *args: object, **kwargs: object) -> None:
                original_initialize(process, *args, **kwargs)  # type: ignore[arg-type]
                raise KeyboardInterrupt("cancelled-after-real-create")

            with mock.patch.object(
                bounded._OwnedBootstrapProcess,
                "_initialize",
                autospec=True,
                side_effect=cancel_after_create,
            ):
                with self.assertRaisesRegex(KeyboardInterrupt, "cancelled-after-real-create"):
                    self.run_python(code)
            time.sleep(0.1)
            self.assertFalse(marker.exists())

    def test_reader_start_cancellation_does_not_join_an_unstarted_thread(self) -> None:
        original_start = bounded.threading.Thread.start
        reader_starts = 0

        def cancel_second_reader(thread: threading.Thread) -> None:
            nonlocal reader_starts
            if thread.name.startswith("finplanbr-bounded-std"):
                reader_starts += 1
                if reader_starts == 2:
                    raise KeyboardInterrupt("cancelled-before-reader-start")
            original_start(thread)

        with mock.patch.object(bounded.threading.Thread, "start", autospec=True, side_effect=cancel_second_reader):
            with self.assertRaisesRegex(KeyboardInterrupt, "cancelled-before-reader-start") as captured:
                self.run_python("pass")
        self.assertIsNone(captured.exception.__cause__)
        self.assertEqual(reader_starts, 2)
        self.assertFalse(
            [thread for thread in threading.enumerate() if thread.name.startswith("finplanbr-bounded-")]
        )

    def test_resource_limits_reject_nonfinite_and_nonexact_values(self) -> None:
        command = [sys.executable, "-I", "-S", "-B", "-c", "pass"]
        for timeout in (float("nan"), float("inf"), float("-inf"), -1.0):
            with self.assertRaises(ValueError):
                bounded.run_bounded(
                    command,
                    timeout_seconds=timeout,
                    stdout_limit=1,
                    stderr_limit=1,
                )
        with self.assertRaises(TypeError):
            bounded.run_bounded(command, timeout_seconds=True, stdout_limit=1, stderr_limit=1)
        with self.assertRaises(TypeError):
            bounded.run_bounded(command, timeout_seconds=1, stdout_limit=True, stderr_limit=1)
        with self.assertRaises(TypeError):
            bounded.run_bounded(command, timeout_seconds=1, stdout_limit=1, stderr_limit=False)

    @unittest.skipUnless(os.name == "nt", "the Job cleanup receipt is Windows-specific")
    def test_windows_cleanup_failure_is_not_masked_after_leader_exit(self) -> None:
        with mock.patch.object(
            bounded.WindowsJob,
            "terminate",
            side_effect=bounded.BoundedProcessCleanupError("injected cleanup failure"),
        ):
            with self.assertRaisesRegex(bounded.BoundedProcessCleanupError, "tree cleanup was not verified"):
                self.run_python("pass")

    def test_public_envelope_binds_but_never_exposes_candidate_stderr(self) -> None:
        secret = "private-candidate-detail"
        envelope = bounded.command_envelope(
            [sys.executable, "-I", "-S", "-B", "-c", f"import sys;sys.stderr.write({secret!r})"],
            timeout_seconds=5,
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertEqual(envelope["status"], "completed")
        self.assertEqual(envelope["stderr_bytes"], len(secret.encode()))
        self.assertEqual(envelope["stderr_sha256"], hashlib.sha256(secret.encode()).hexdigest())
        self.assertNotIn(secret, json.dumps(envelope))

    def test_public_envelope_uses_closed_failure_classes(self) -> None:
        envelope = bounded.command_envelope(
            [sys.executable, "-I", "-S", "-B", "-c", "import time;time.sleep(30)"],
            timeout_seconds=0.1,
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertEqual(
            envelope,
            {"format": bounded.ENVELOPE_FORMAT, "status": "failed", "failure_class": "timeout"},
        )
        output_envelope = bounded.command_envelope(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                "import sys,time;sys.stdout.buffer.write(b'x'*1025);sys.stdout.flush();time.sleep(30)",
            ],
            timeout_seconds=1,
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertEqual(
            output_envelope,
            {
                "format": bounded.ENVELOPE_FORMAT,
                "status": "failed",
                "failure_class": "output_limit",
                "stream": "stdout",
            },
        )
        invalid_envelope = bounded.command_envelope(
            [sys.executable, "-I", "-S", "-B", "-c", "pass"],
            timeout_seconds=float("nan"),
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertEqual(
            invalid_envelope,
            {
                "format": bounded.ENVELOPE_FORMAT,
                "status": "failed",
                "failure_class": "invalid_configuration",
            },
        )

    def test_cli_nonfinite_limit_is_closed_json_without_traceback(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                os.fspath(Path(bounded.__file__).resolve()),
                "--json-envelope",
                "--timeout-seconds",
                "nan",
                "--stdout-limit",
                "1",
                "--stderr-limit",
                "1",
                "--",
                sys.executable,
                "-c",
                "pass",
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "failure_class": "invalid_configuration",
                "format": bounded.ENVELOPE_FORMAT,
                "status": "failed",
            },
        )

    @unittest.skipUnless(os.name == "nt", "the injected Job cleanup failure is Windows-specific")
    def test_cancellation_type_is_preserved_when_cleanup_also_fails(self) -> None:
        real_sleep = time.sleep

        def cancel(_: float) -> None:
            real_sleep(0.05)
            raise KeyboardInterrupt

        with (
            mock.patch.object(bounded.time, "sleep", cancel),
            mock.patch.object(
                bounded.WindowsJob,
                "terminate",
                side_effect=bounded.BoundedProcessCleanupError("injected cleanup failure"),
            ),
        ):
            with self.assertRaises(KeyboardInterrupt) as captured:
                self.run_python("import time;time.sleep(30)")
        self.assertIsInstance(captured.exception.__cause__, bounded.BoundedProcessCleanupError)
        self.assertFalse(
            [thread for thread in threading.enumerate() if thread.name.startswith("finplanbr-bounded-")]
        )


if __name__ == "__main__":
    unittest.main()
