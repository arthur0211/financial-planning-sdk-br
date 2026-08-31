from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import run_linux_portability_cell as linux_runner
from scripts import smoke_local_package as package_smoke

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PYTHON_RUNNERS = (
    "freeze_source_snapshot.py",
    "installed_portability_probe.py",
    "run_linux_portability_cell.py",
    "smoke_local_package.py",
    "validate_linux_portability_cell.py",
    "validate_sdk_conformance.py",
    "validate_windows_portability_cell.py",
)


class BoundedRunnerAdoptionTests(unittest.TestCase):
    def test_candidate_runners_do_not_regress_to_buffered_subprocess_run(self) -> None:
        for name in PYTHON_RUNNERS:
            path = REPOSITORY_ROOT / "scripts" / name
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            calls = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr == "run"
            ]
            self.assertFalse(calls, f"{name} regressed to subprocess.run")
            self.assertIn("run_bounded", source, name)

    def test_windows_launcher_uses_closed_bounded_envelope(self) -> None:
        source = (REPOSITORY_ROOT / "scripts" / "run_windows_portability_cell.ps1").read_text(
            encoding="utf-8-sig"
        )
        for marker in (
            "finplanbr.bounded-subprocess-envelope.v1",
            "--stdout-limit 33554432 --stderr-limit 33554432",
            "stderr_sha256=",
            "[Convert]::FromBase64String",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("throw \"Python phase failed with RC $returnCode`: $text\"", source)

    def test_linux_host_errors_never_publish_raw_candidate_output(self) -> None:
        source = (REPOSITORY_ROOT / "scripts" / "run_linux_portability_cell.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("output_sha256=", source)
        self.assertNotIn("errors=\"replace\"", source)
        self.assertNotIn("[-24_000:]", source)

    def test_linux_cleanup_attempts_every_owned_object_before_failing(self) -> None:
        removed: list[tuple[str, ...]] = []
        inventories = iter(
            (
                (("first", "second"), ("sha256:" + "a" * 64,)),
                ((), ()),
            )
        )

        def remove(command: list[str], **_: object) -> object:
            removed.append(tuple(command))
            if command[1:4] == ["container", "rm", "--force"] and command[4] == "first":
                raise RuntimeError("injected first cleanup failure")
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        with (
            mock.patch.object(linux_runner, "_docker_owned_inventory", side_effect=lambda _: next(inventories)),
            mock.patch.object(linux_runner, "_run", side_effect=remove),
        ):
            with self.assertRaisesRegex(RuntimeError, "1 owned object"):
                linux_runner._cleanup_created_docker_objects(
                    nonce="nonce",
                    container_names=("first", "second"),
                    image_id="sha256:" + "a" * 64,
                    image_tag="finplanbr-portability-nonce:py311",
                )
        self.assertEqual(len(removed), 3)

    def test_linux_cleanup_treats_inventory_failure_as_unverified(self) -> None:
        removed: list[tuple[str, ...]] = []

        def remove(command: list[str], **_: object) -> object:
            removed.append(tuple(command))
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        with mock.patch.object(
            linux_runner,
            "_docker_owned_inventory",
            side_effect=RuntimeError("injected Docker daemon failure"),
        ), mock.patch.object(linux_runner, "_run", side_effect=remove):
            with self.assertRaisesRegex(RuntimeError, "2 owned object"):
                linux_runner._cleanup_created_docker_objects(
                    nonce="nonce",
                    container_names=("first", "second"),
                    image_id=None,
                    image_tag=None,
                )
        self.assertEqual(
            removed,
            [
                ("docker", "container", "rm", "--force", "first"),
                ("docker", "container", "rm", "--force", "second"),
            ],
        )

    def test_linux_cleanup_uses_nonce_tag_when_image_id_and_inventory_are_unavailable(self) -> None:
        removed: list[tuple[str, ...]] = []
        tag = "finplanbr-portability-nonce:py314"

        def remove(command: list[str], **_: object) -> object:
            removed.append(tuple(command))
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        with mock.patch.object(
            linux_runner,
            "_docker_owned_inventory",
            side_effect=RuntimeError("injected Docker daemon failure"),
        ), mock.patch.object(linux_runner, "_run", side_effect=remove):
            with self.assertRaisesRegex(RuntimeError, "2 owned object"):
                linux_runner._cleanup_created_docker_objects(
                    nonce="nonce",
                    container_names=(),
                    image_id=None,
                    image_tag=tag,
                )
        self.assertEqual(removed, [("docker", "image", "rm", tag)])

    def test_linux_successful_build_retains_tag_ownership_when_id_query_fails(self) -> None:
        cleanup_calls: list[dict[str, object]] = []

        def run(command: list[str], **_: object) -> object:
            if command[:2] == ["docker", "build"]:
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")
            if command[:3] == ["docker", "image", "inspect"]:
                raise RuntimeError("injected image-ID query failure")
            return mock.Mock(returncode=0, stdout=b"{}", stderr=b"")

        def cleanup(**kwargs: object) -> None:
            cleanup_calls.append(kwargs)

        with (
            mock.patch.object(linux_runner.secrets, "token_hex", return_value="nonce"),
            mock.patch.object(linux_runner, "_run", side_effect=run),
            mock.patch.object(linux_runner, "_cleanup_created_docker_objects", side_effect=cleanup),
        ):
            with self.assertRaisesRegex(RuntimeError, "image-ID query failure"):
                linux_runner.execute("3.14")
        self.assertEqual(len(cleanup_calls), 1)
        self.assertEqual(cleanup_calls[0]["image_id"], None)
        self.assertEqual(cleanup_calls[0]["image_tag"], "finplanbr-portability-nonce:py314")

    def test_supported_freeze_cli_starts_isolated_before_stdlib_imports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-freeze-origin-") as directory:
            root = Path(directory)
            attacker = root / "attacker"
            attacker.mkdir()
            marker = root / "attacker-ran.txt"
            (attacker / "hashlib.py").write_text(
                f"from pathlib import Path;Path({os.fspath(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            (attacker / "sitecustomize.py").write_text(
                f"from pathlib import Path;Path({os.fspath(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.fspath(attacker)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    os.fspath(REPOSITORY_ROOT / "scripts" / "freeze_source_snapshot.py"),
                    "--summary",
                ],
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=False,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
            report = json.loads(completed.stdout)
            self.assertEqual(report["format"], "finplanbr.source-freeze.v1")
            self.assertFalse(marker.exists())

    def test_sdk_conformance_cli_loads_its_sibling_boundary_under_isolation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-sdk-origin-") as directory:
            root = Path(directory)
            attacker = root / "attacker"
            attacker.mkdir()
            marker = root / "attacker-ran.txt"
            (attacker / "sitecustomize.py").write_text(
                f"from pathlib import Path;Path({os.fspath(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.fspath(attacker)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    os.fspath(REPOSITORY_ROOT / "scripts" / "validate_sdk_conformance.py"),
                    "--help",
                ],
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=False,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
            self.assertIn(b"--output-format", completed.stdout)
            self.assertFalse(marker.exists())

    def test_freeze_cli_rejects_nonisolated_interpreter(self) -> None:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONUSERBASE", None)
        completed = subprocess.run(
            [sys.executable, "-B", os.fspath(REPOSITORY_ROOT / "scripts" / "freeze_source_snapshot.py")],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=False,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"freeze_source_snapshot_requires_python_isolated_mode\n")

    def test_build_and_pip_tools_ignore_hostile_pythonpath(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-smoke-tool-origin-") as directory:
            root = Path(directory)
            attacker = root / "attacker"
            marker = root / "attacker-ran.txt"
            for module in ("build", "pip"):
                package = attacker / module
                package.mkdir(parents=True, exist_ok=True)
                (package / "__main__.py").write_text(
                    f"from pathlib import Path;Path({os.fspath(marker)!r}).write_text('bad')",
                    encoding="utf-8",
                )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.fspath(attacker)
            environment["PYTHONSTARTUP"] = os.fspath(attacker / "startup.py")
            with mock.patch.dict(os.environ, environment, clear=True):
                for module in ("build", "pip"):
                    completed = package_smoke.run_tool(module, ["--version"], cwd=root)
                    self.assertEqual(completed.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertNotIn("PYTHONPATH", package_smoke.tool_environment(root))
            self.assertNotIn("PYTHONSTARTUP", package_smoke.tool_environment(root))
            self.assertEqual(sys.executable, package_smoke.sys.executable)

    def test_smoke_maps_limit_plus_one_to_output_budget(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-smoke-cap-") as directory:
            root = Path(directory)
            for stream in ("stdout", "stderr"):
                target = "sys.stdout.buffer" if stream == "stdout" else "sys.stderr.buffer"
                command = [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    f"import sys,time;{target}.write(b'x'*1025);{target}.flush();time.sleep(30)",
                ]
                with mock.patch.object(package_smoke, "SMOKE_OUTPUT_LIMIT", 1024):
                    with self.assertRaisesRegex(RuntimeError, f"{stream} byte budget"):
                        package_smoke._run_bounded(
                            command,
                            cwd=root,
                            environment=package_smoke.tool_environment(root),
                            timeout_seconds=1,
                        )


if __name__ == "__main__":
    unittest.main()
