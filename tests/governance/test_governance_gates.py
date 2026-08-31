"""Mutation tests for diagnostic Structure and permanently closed release gates."""

from __future__ import annotations

import csv
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
POWERSHELL_HOSTS = tuple(
    dict.fromkeys(
        path
        for name in ("powershell", "pwsh")
        if (path := shutil.which(name)) is not None
    )
)
COPY_IGNORE = shutil.ignore_patterns(
    ".git",
    ".coverage",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "*.egg-info",
    "*.pyc",
    "__pycache__",
    "build",
    "coverage.xml",
    "dist",
    "htmlcov",
    "venv",
)


class GovernanceGateMutationTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="finplanbr-governance-r19-")
        canonical_temp_root = Path(self.temp.name).resolve(strict=True)
        self.root = canonical_temp_root / "candidate"
        shutil.copytree(
            REPO_ROOT,
            self.root,
            ignore=COPY_IGNORE,
        )
        (self.root / ".git").mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def output(completed: subprocess.CompletedProcess[str]) -> str:
        return completed.stdout + completed.stderr

    @staticmethod
    def fullwidth_ascii(value: str) -> str:
        return "".join(
            "\u3000"
            if character == " "
            else chr(ord(character) + 0xFEE0)
            if "!" <= character <= "~"
            else character
            for character in value
        )

    def run_gate(
        self,
        mode: str,
        *arguments: str,
        host: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        executable = host or (shutil.which("powershell") or shutil.which("pwsh"))
        self.assertIsNotNone(executable, "PowerShell is required")
        return subprocess.run(
            [
                str(executable),
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.root / "scripts" / "validate_docs.ps1"),
                "-Mode",
                mode,
                *arguments,
            ],
            cwd=self.root,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=60,
            env=environment,
        )

    def mutate_csv(self, relative: str, mutator) -> None:
        path = self.root / relative
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
            fields = reader.fieldnames
        self.assertIsNotNone(fields)
        mutator(rows)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def create_fake_human_files(self) -> None:
        (self.root / "LICENSE").write_text("Synthetic test-only license assertion.\n", encoding="utf-8")
        (self.root / "MAINTAINERS.md").write_text(
            "# Synthetic maintainers\n\nTest-only assertion.\n",
            encoding="utf-8",
        )

    def test_candidate_copy_policy_excludes_generated_artifacts(self) -> None:
        names = (
            ".git",
            ".coverage",
            ".mypy_cache",
            ".nox",
            ".pytest_cache",
            ".ruff_cache",
            ".tox",
            ".venv",
            "finplanbr.egg-info",
            "module.pyc",
            "__pycache__",
            "build",
            "coverage.xml",
            "dist",
            "docs",
            "htmlcov",
            "src",
            "venv",
        )
        ignored = set(COPY_IGNORE(str(REPO_ROOT), names))
        self.assertEqual(ignored, set(names) - {"docs", "src"})

    def test_onboarding_keeps_virtual_environment_outside_checkout(self) -> None:
        for relative in (
            "AGENTS.md",
            "CONTRIBUTING.md",
            "README.en.md",
            "README.md",
            "docs/runbook.md",
        ):
            content = (self.root / relative).read_text(encoding="utf-8-sig")
            with self.subTest(relative=relative):
                self.assertIn("$FinPlanBrVenv", content)
                self.assertNotIn("python -m venv .venv", content)
                self.assertNotIn(r".\.venv\Scripts", content)
    def assert_structure_rejected_on_every_host(self, expected: str) -> None:
        self.assertGreaterEqual(
            len(POWERSHELL_HOSTS),
            2,
            "both Windows PowerShell 5.1 and PowerShell 7.x are required",
        )
        for host in POWERSHELL_HOSTS:
            completed = self.run_gate("Structure", host=host)
            output = self.output(completed)
            with self.subTest(host=host):
                self.assertEqual(completed.returncode, 1, output)
                self.assertIn(expected, output)
                self.assertNotIn("Local consistency check passed", output)

    def create_directory_junction(self, link: Path, target: Path) -> None:
        if os.name == "nt":
            command = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            if command.returncode == 0:
                return
        try:
            os.symlink(target, link, target_is_directory=True)
        except OSError as exc:
            self.fail(f"directory reparse creation is required for this regression: {exc}")

    def mirror_pwsh_home_with_adulterated_management_module(self, host: str) -> tuple[Path, Path]:
        probe = subprocess.run(
            [
                host,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$PSHOME+'|'+$PSVersionTable.PSEdition",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(probe.returncode, 0, self.output(probe))
        source_home_text, edition = probe.stdout.strip().rsplit("|", 1)
        self.assertEqual(edition, "Core")
        source_home = Path(source_home_text)
        copied_home = self.root.parent / "copied-pwsh-home"
        copied_home.mkdir()
        management_manifest_relative = Path(
            "Modules/Microsoft.PowerShell.Management/Microsoft.PowerShell.Management.psd1"
        )

        for source in source_home.rglob("*"):
            relative = source.relative_to(source_home)
            destination = copied_home / relative
            if source.is_dir():
                destination.mkdir(exist_ok=True)
                continue
            if not source.is_file():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if relative in {Path("pwsh.exe"), management_manifest_relative}:
                shutil.copy2(source, destination)
            else:
                try:
                    os.link(source, destination)
                except OSError:
                    shutil.copy2(source, destination)

        marker = self.root.parent / "adulterated-management-module-loaded"
        manifest = copied_home / management_manifest_relative
        manifest.chmod(0o666)
        original_manifest = manifest.read_text(encoding="utf-8-sig")
        self.assertTrue(original_manifest.startswith("@{"))
        manifest.write_text(
            original_manifest.replace(
                "@{",
                "@{\nScriptsToProcess = @('R18HostileManagement.ps1')",
                1,
            ),
            encoding="utf-8",
        )
        (manifest.parent / "R18HostileManagement.ps1").write_text(
            "[System.IO.File]::WriteAllText($env:FINPLANBR_HOSTILE_MODULE_MARKER,'loaded')\n",
            encoding="utf-8",
        )
        return copied_home / "pwsh.exe", marker

    def test_structure_passes_on_windows_powershell_51_and_powershell_7(self) -> None:
        self.assertGreaterEqual(
            len(POWERSHELL_HOSTS),
            2,
            "both Windows PowerShell 5.1 and PowerShell 7.x are required",
        )
        editions: set[str] = set()
        outputs: list[str] = []
        expected_markdown_count = sum(1 for path in self.root.rglob("*.md") if path.is_file())
        for host in POWERSHELL_HOSTS:
            version = subprocess.run(
                [
                    host,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$PSVersionTable.PSVersion.ToString()+'|'+$PSVersionTable.PSEdition",
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(version.returncode, 0, self.output(version))
            editions.add(version.stdout.strip().split("|")[-1])
            completed = self.run_gate("Structure", host=host)
            self.assertEqual(completed.returncode, 0, self.output(completed))
            self.assertIn(
                f"{expected_markdown_count} Markdown files and 5 CSV contracts",
                completed.stdout,
            )
            outputs.append(completed.stdout)
        self.assertEqual(editions, {"Core", "Desktop"})
        self.assertEqual(len(set(outputs)), 1)

    def test_documented_relative_paths_pass_on_every_host(self) -> None:
        for host in POWERSHELL_HOSTS:
            for script_path in ("./scripts/validate_docs.ps1", ".\\scripts\\validate_docs.ps1"):
                completed = subprocess.run(
                    [
                        host,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        script_path,
                        "-Mode",
                        "Structure",
                    ],
                    cwd=self.root,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=60,
                )
                with self.subTest(host=host, script_path=script_path):
                    self.assertEqual(completed.returncode, 0, self.output(completed))
                    self.assertIn("Local consistency check passed in Structure mode", completed.stdout)

    def test_absolute_path_casing_is_intentionally_identity_based_on_windows(self) -> None:
        script = str(self.root / "scripts" / "validate_docs.ps1")
        case_variant = script.swapcase()
        self.assertNotEqual(case_variant, script)
        for host in POWERSHELL_HOSTS:
            completed = subprocess.run(
                [
                    host,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    case_variant,
                    "-Mode",
                    "Structure",
                ],
                cwd=self.root,
                text=True,
                capture_output=True,
                check=False,
                timeout=60,
            )
            with self.subTest(host=host):
                self.assertEqual(completed.returncode, 0, self.output(completed))
                self.assertIn("Local consistency check passed in Structure mode", completed.stdout)

    def test_switch_mode_and_relative_path_lexical_variants_are_rc2_on_every_host(self) -> None:
        script = str(self.root / "scripts" / "validate_docs.ps1")
        parent_path = str(self.root / "scripts" / ".." / "scripts" / "validate_docs.ps1")
        cases = {
            "lower_noprofile": ["-noprofile", "-File", script, "-Mode", "Structure"],
            "abbreviated_noprofile": ["-NoP", "-File", script, "-Mode", "Structure"],
            "lower_file": ["-NoProfile", "-file", script, "-Mode", "Structure"],
            "lower_mode_switch": ["-NoProfile", "-File", script, "-mode", "Structure"],
            "abbreviated_mode_switch": ["-NoProfile", "-File", script, "-M", "Structure"],
            "lower_mode_value": ["-NoProfile", "-File", script, "-Mode", "structure"],
            "parent_segment": ["-NoProfile", "-File", parent_path, "-Mode", "Structure"],
            "uncanonical_relative": [
                "-NoProfile",
                "-File",
                "scripts/validate_docs.ps1",
                "-Mode",
                "Structure",
            ],
            "relative_path_case_variant": [
                "-NoProfile",
                "-File",
                "./scripts/VALIDATE_DOCS.ps1",
                "-Mode",
                "Structure",
            ],
            "extra_argument": [
                "-NoProfile",
                "-File",
                script,
                "-Mode",
                "Structure",
                "-Unexpected",
            ],
        }
        for host in POWERSHELL_HOSTS:
            for name, arguments in cases.items():
                completed = subprocess.run(
                    [host, *arguments],
                    cwd=self.root,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                output = self.output(completed)
                with self.subTest(host=host, case=name):
                    self.assertEqual(completed.returncode, 2, output)
                    self.assertEqual(output.count("refused a non-canonical invocation"), 1, output)
                    self.assertNotIn("Local consistency check passed", output)
                    self.assertNotIn("Local consistency check failed", output)

    def test_direct_file_verbose_is_rc2_on_every_host(self) -> None:
        script = str(self.root / "scripts" / "validate_docs.ps1")
        for host in POWERSHELL_HOSTS:
            completed = subprocess.run(
                [host, "-NoProfile", "-File", script, "-Mode", "Structure", "-Verbose"],
                cwd=self.root,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            output = self.output(completed)
            with self.subTest(host=host):
                self.assertEqual(completed.returncode, 2, output)
                self.assertEqual(output.count("refused a non-canonical invocation"), 1, output)
                self.assertNotIn("Local consistency check passed", output)
                self.assertNotIn("Local consistency check failed", output)

    def test_hostile_psmodulepath_cannot_redirect_a_corrupted_candidate(self) -> None:
        clean_root = self.root.parent / "clean-decoy-root"
        shutil.copytree(self.root, clean_root)
        (self.root / "README.md").write_text("", encoding="utf-8")

        module_root = self.root.parent / "hostile-modules"
        module = module_root / "Microsoft.PowerShell.Management"
        module.mkdir(parents=True)
        (module / "Microsoft.PowerShell.Management.psd1").write_text(
            "@{\n"
            "  RootModule = 'Microsoft.PowerShell.Management.psm1'\n"
            "  ModuleVersion = '99.0.0'\n"
            "  GUID = '20c17b0c-7217-4d32-9e86-8b90a7f9c117'\n"
            "  FunctionsToExport = @('Split-Path','Invoke-R17Decoy')\n"
            "  CmdletsToExport = @()\n"
            "  VariablesToExport = @()\n"
            "  AliasesToExport = @()\n"
            "}\n",
            encoding="utf-8",
        )
        (module / "Microsoft.PowerShell.Management.psm1").write_text(
            "[System.IO.File]::WriteAllText($env:FINPLANBR_DECOY_MARKER,'loaded')\n"
            "function Split-Path {\n"
            "  [CmdletBinding()]\n"
            "  param([Parameter(Position=0)][string]$Path,[switch]$Parent)\n"
            "  return $env:FINPLANBR_DECOY_ROOT\n"
            "}\n"
            "function Invoke-R17Decoy { return $env:FINPLANBR_DECOY_ROOT }\n"
            "Export-ModuleMember -Function Split-Path,Invoke-R17Decoy\n",
            encoding="utf-8",
        )

        for host in POWERSHELL_HOSTS:
            marker = self.root.parent / f"decoy-loaded-{Path(host).stem}"
            environment = dict(os.environ)
            original_module_path = environment.get("PSModulePath", "")
            environment["PSModulePath"] = os.pathsep.join(
                part for part in (str(module_root), original_module_path) if part
            )
            environment["PSModuleAnalysisCachePath"] = str(
                self.root.parent / f"module-analysis-{Path(host).stem}.cache"
            )
            environment["FINPLANBR_DECOY_MARKER"] = str(marker)
            environment["FINPLANBR_DECOY_ROOT"] = str(clean_root)

            probe = subprocess.run(
                [
                    host,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$decoy=Invoke-R17Decoy; $redirect=Split-Path -Parent ignored; $decoy+'|'+$redirect",
                ],
                cwd=self.root,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
                env=environment,
            )
            with self.subTest(host=host, phase="decoy-probe"):
                self.assertEqual(probe.returncode, 0, self.output(probe))
                self.assertEqual(probe.stdout.strip(), f"{clean_root}|{clean_root}")
                self.assertTrue(marker.exists(), self.output(probe))
            if marker.exists():
                marker.unlink()

            completed = self.run_gate("Structure", host=host, environment=environment)
            output = self.output(completed)
            with self.subTest(host=host, phase="gate"):
                self.assertEqual(completed.returncode, 1, output)
                self.assertIn("README.md is empty", output)
                self.assertNotIn("Local consistency check passed", output)
                self.assertFalse(marker.exists(), output)

    def test_copied_pwsh_with_adulterated_pshome_module_is_rc2_before_import(self) -> None:
        core_hosts: list[str] = []
        for host in POWERSHELL_HOSTS:
            edition = subprocess.run(
                [host, "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSEdition"],
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(edition.returncode, 0, self.output(edition))
            if edition.stdout.strip() == "Core":
                core_hosts.append(host)
        self.assertEqual(len(core_hosts), 1, "exactly one PowerShell Core host is required")

        copied_host, marker = self.mirror_pwsh_home_with_adulterated_management_module(core_hosts[0])
        environment = dict(os.environ)
        environment["FINPLANBR_HOSTILE_MODULE_MARKER"] = str(marker)
        launch_probe = subprocess.run(
            [str(copied_host), "-NoProfile", "-NonInteractive", "-Command", "$PSHOME"],
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
            env=environment,
        )
        self.assertEqual(launch_probe.returncode, 0, self.output(launch_probe))
        self.assertEqual(Path(launch_probe.stdout.strip()), copied_host.parent)

        completed = self.run_gate("Structure", host=str(copied_host), environment=environment)
        output = self.output(completed)
        self.assertEqual(completed.returncode, 2, output)
        self.assertIn("could not establish its supported Windows PowerShell host trust boundary", output)
        self.assertIn("cannot authenticate a compromised administrator or PowerShell engine", output)
        self.assertNotIn("Local consistency check passed", output)
        self.assertNotIn("Local consistency check failed", output)
        self.assertFalse(marker.exists(), output)

    def test_docs_junction_is_rejected_without_traversing_external_docs_on_every_host(self) -> None:
        self.assertGreaterEqual(len(POWERSHELL_HOSTS), 2)
        candidate_docs = self.root / "docs"
        external_docs = self.root.parent / "external-docs"
        shutil.copytree(candidate_docs, external_docs)
        (external_docs / "outside-only.md").write_text(
            "# External probe\n\nStatus: TBD\n",
            encoding="utf-8",
        )
        external_probe_before = (external_docs / "outside-only.md").read_bytes()
        shutil.rmtree(candidate_docs)
        self.create_directory_junction(candidate_docs, external_docs)
        try:
            for host in POWERSHELL_HOSTS:
                completed = self.run_gate("Structure", host=host)
                output = self.output(completed)
                with self.subTest(host=host):
                    self.assertEqual(completed.returncode, 1, output)
                    self.assertIn(
                        "Structure repository tree contains a forbidden symlink/junction/reparse path: docs",
                        output,
                    )
                    self.assertNotIn("outside-only.md", output)
                    self.assertNotIn("Local consistency check passed", output)
                    self.assertEqual(
                        (external_docs / "outside-only.md").read_bytes(),
                        external_probe_before,
                    )
        finally:
            if candidate_docs.exists() or candidate_docs.is_symlink():
                os.rmdir(candidate_docs)

    def test_repository_root_junction_is_rejected_on_every_host(self) -> None:
        self.assertGreaterEqual(len(POWERSHELL_HOSTS), 2)
        real_root = self.root.parent / "candidate-real"
        self.root.rename(real_root)
        self.create_directory_junction(self.root, real_root)
        try:
            for host in POWERSHELL_HOSTS:
                completed = self.run_gate("Structure", host=host)
                output = self.output(completed)
                with self.subTest(host=host):
                    self.assertEqual(completed.returncode, 1, output)
                    self.assertIn("repository root or one of its ancestors", output)
                    self.assertNotIn("Local consistency check passed", output)
        finally:
            if self.root.exists() or self.root.is_symlink():
                os.rmdir(self.root)
            real_root.rename(self.root)

    def test_f0_local_human_decisions_never_open_external_authority(self) -> None:
        completed = self.run_gate("F0")
        output = self.output(completed)
        self.assertNotEqual(completed.returncode, 0, output)
        self.assertIn("External release authority is not implemented or integrated", output)
        self.assertIn("Local Apache-2.0 decision and LICENSE do not authenticate external F0", output)
        self.assertIn("Local maintainer roster does not authenticate an independent human reviewer", output)
        self.assertIn("Local governance does not authorize F0, package publication, or release", output)

    def test_fake_human_files_never_open_progressive_gates(self) -> None:
        self.create_fake_human_files()
        for mode in ("F0", "Release00", "Release01"):
            with self.subTest(mode=mode):
                completed = self.run_gate(mode)
                output = self.output(completed)
                self.assertNotEqual(completed.returncode, 0, output)
                self.assertIn("External release authority is not implemented or integrated", output)
                self.assertNotIn("Local consistency check passed", output)
                if mode in {"Release00", "Release01"}:
                    self.assertIn("external math-conformance authority is not implemented", output)
                if mode == "Release01":
                    self.assertIn("external closed artifact inspection", output)

    def test_every_removed_legacy_parameter_is_rejected_before_script_body(self) -> None:
        marker = self.root.parent / "LEGACY_RUNTIME_EXECUTED"
        runtime = self.root.parent / "attacker-runtime.cmd"
        runtime.write_text(
            f'@echo off\r\n>"{marker}" echo executed\r\nexit /b 0\r\n',
            encoding="ascii",
        )
        cases = (
            ("-BootstrapResultPath", str(self.root.parent / "result.json")),
            ("-BootstrapResultSha256", "a" * 64),
            ("-BootstrapResultPublicKeyPath", str(self.root.parent / "key.txt")),
            ("-BootstrapResultPublicKeyFingerprint", "sha256:" + "b" * 64),
            ("-PythonRuntimePath", str(runtime)),
            ("-EvaluationTime", "2026-08-09T12:00:00Z"),
        )
        for name, value in cases:
            with self.subTest(parameter=name):
                completed = self.run_gate("Structure", name, value)
                self.assertNotEqual(completed.returncode, 0, self.output(completed))
                self.assertNotIn("Local consistency check passed", self.output(completed))
        self.assertFalse(marker.exists())

    def test_canonical_progressive_gates_fail_directly_on_every_host(self) -> None:
        expected_counts = {"F0": 4, "Release00": 5, "Release01": 6}
        for host in POWERSHELL_HOSTS:
            for mode, count in expected_counts.items():
                with self.subTest(host=host, mode=mode):
                    completed = self.run_gate(mode, host=host)
                    output = self.output(completed)
                    self.assertEqual(completed.returncode, 1, output)
                    self.assertIn(f"Local consistency check failed in {mode} mode with {count} issue(s)", output)
                    self.assertIn("External release authority is not implemented or integrated", output)
                    self.assertNotIn("Local consistency check passed", output)

    def test_noncanonical_call_and_dot_source_terminate_host_despite_aliases_and_functions(self) -> None:
        script = self.root / "scripts" / "validate_docs.ps1"
        for host in POWERSHELL_HOSTS:
            for route in ("& $gate -Mode Structure", ". $gate -Mode Structure"):
                marker = self.root.parent / f"wrapper-continued-{Path(host).stem}-{len(route)}"
                environment = dict(os.environ)
                environment["FINPLANBR_DOCS_SCRIPT"] = str(script)
                environment["FINPLANBR_WRAPPER_MARKER"] = str(marker)
                command = (
                    "$gate=$env:FINPLANBR_DOCS_SCRIPT;"
                    "function Split-Path { throw 'shadowed Split-Path executed' };"
                    "function Add-Failure { param($Message) };"
                    "function Write-Host { param($Object) };"
                    "Set-Alias -Name Test-Path -Value Write-Output;"
                    f"{route};"
                    "[System.IO.File]::WriteAllText($env:FINPLANBR_WRAPPER_MARKER,'continued')"
                )
                completed = subprocess.run(
                    [host, "-NoProfile", "-NonInteractive", "-Command", command],
                    cwd=self.root,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                    env=environment,
                )
                output = self.output(completed)
                with self.subTest(host=host, route=route):
                    self.assertEqual(completed.returncode, 2, output)
                    self.assertEqual(output.count("refused a non-canonical invocation"), 1, output)
                    self.assertFalse(marker.exists(), output)
                    self.assertNotIn("Local consistency check passed", output)
                    self.assertNotIn("Local consistency check failed", output)
                    self.assertNotIn("External release authority is not implemented", output)

    def test_result_key_swap_probe_has_no_consumer_surface(self) -> None:
        result = self.root.parent / "result.json"
        key = self.root.parent / "key.txt"
        result.write_text('{"status":"passed"}', encoding="utf-8")
        key.write_text("attacker-key", encoding="utf-8")
        stop = threading.Event()

        def swap() -> None:
            counter = 0
            while not stop.is_set():
                result.write_text(f'{{"counter":{counter}}}', encoding="utf-8")
                key.write_text(str(counter), encoding="utf-8")
                counter += 1

        attacker = threading.Thread(target=swap, daemon=True)
        attacker.start()
        try:
            completed = self.run_gate(
                "F0",
                "-BootstrapResultPath",
                str(result),
                "-BootstrapResultPublicKeyPath",
                str(key),
            )
        finally:
            stop.set()
            attacker.join(timeout=5)
        self.assertNotEqual(completed.returncode, 0, self.output(completed))
        self.assertNotIn("Local consistency check passed", self.output(completed))

    def test_progressive_gates_never_execute_candidate_validators(self) -> None:
        self.create_fake_human_files()
        markers: list[Path] = []
        for name in (
            "validate_contracts.py",
            "validate_math_vectors.py",
            "validate_release_artifacts.py",
            "validate_release_trust.py",
        ):
            marker = self.root.parent / f"{name}.executed"
            markers.append(marker)
            (self.root / "scripts" / name).write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
        for mode in ("F0", "Release00", "Release01"):
            completed = self.run_gate(mode)
            self.assertNotEqual(completed.returncode, 0, self.output(completed))
        self.assertFalse([marker for marker in markers if marker.exists()])

    def test_gate_source_contains_no_candidate_authority_implementation(self) -> None:
        source = (self.root / "scripts" / "validate_docs.ps1").read_text(encoding="utf-8")
        guard = "validate_docs.ps1 refused a non-canonical invocation"
        progressive_blocker = "if (-not [System.String]::Equals($Mode, 'Structure'"
        host_boundary = "$hostTrustEstablished = $false"
        repository_preflight = "$repositoryPreflightFailures = [System.Collections.Generic.List[string]]::new()"
        module_isolation = "$PSModuleAutoLoadingPreference = 'None'"
        module_path_clear = "SetEnvironmentVariable('PSModulePath'"
        first_trusted_import = "Microsoft.PowerShell.Core\\Import-Module"
        self.assertIn(guard, source)
        self.assertIn(progressive_blocker, source)
        self.assertIn("[System.Environment]::Exit(2)", source)
        self.assertLess(source.index(guard), source.index(module_isolation))
        self.assertLess(source.index(progressive_blocker), source.index("function Add-Failure"))
        self.assertLess(source.index(progressive_blocker), source.index(host_boundary))
        self.assertLess(source.index(host_boundary), source.index(repository_preflight))
        self.assertLess(source.index(repository_preflight), source.index(module_isolation))
        self.assertLess(source.index(progressive_blocker), source.index(module_isolation))
        self.assertLess(source.index(module_isolation), source.index(module_path_clear))
        self.assertLess(source.index(module_path_clear), source.index(first_trusted_import))
        self.assertLess(source.index(first_trusted_import), source.index("$ErrorActionPreference"))
        self.assertIn("[System.Environment]::GetCommandLineArgs()", source)
        self.assertIn("[System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName", source)
        self.assertIn("[System.Environment]::GetFolderPath", source)
        self.assertIn("[System.IO.FileAttributes]::ReparsePoint", source)
        self.assertIn("[System.IO.Directory]::EnumerateFileSystemEntries", source)
        self.assertIn("cannot authenticate a compromised administrator or PowerShell engine", source)
        self.assertIn("[System.Console]::Error.WriteLine", source)
        self.assertIn("[System.IO.Directory]::GetParent", source)
        self.assertIn("[System.StringComparison]::OrdinalIgnoreCase", source)
        self.assertIn("function Get-LinePreservingNormalizedText", source)
        self.assertIn("[Text.NormalizationForm]::FormKC", source)
        self.assertIn("[regex]::Replace($text, '\\p{Cf}', '')", source)
        self.assertIn("$normalizedScanContent = Get-LinePreservingNormalizedText $content", source)
        self.assertEqual(source.count("[regex]::Matches($normalizedScanContent"), 2)
        self.assertIn("$normalizedScanContent,", source)
        self.assertIn("[System.StringComparison]::Ordinal", source)
        self.assertIn("$expectedHistoryH2Roster", source)
        self.assertNotIn("Split-Path", source)
        self.assertIn("$script:failures = [System.Collections.Generic.List[string]]::new()", source)
        self.assertNotIn("\n$failures =", source)
        self.assertNotIn("\n$modeRank =", source)
        self.assertNotIn("$script:modeRank", source)
        qualified_commands = {
            "Import-Module": "Microsoft.PowerShell.Core",
            "Join-Path": "Microsoft.PowerShell.Management",
            "Test-Path": "Microsoft.PowerShell.Management",
            "Get-Item": "Microsoft.PowerShell.Management",
            "Resolve-Path": "Microsoft.PowerShell.Management",
            "Get-ChildItem": "Microsoft.PowerShell.Management",
            "ConvertFrom-Csv": "Microsoft.PowerShell.Utility",
            "Group-Object": "Microsoft.PowerShell.Utility",
            "Where-Object": "Microsoft.PowerShell.Core",
            "Write-Host": "Microsoft.PowerShell.Utility",
        }
        for command, module_name in qualified_commands.items():
            with self.subTest(command=command):
                self.assertIn(f"{module_name}\\{command}", source)
                self.assertIsNone(
                    re.search(rf"(?<![\\\w.-]){re.escape(command)}\b", source),
                    f"unqualified command remains: {command}",
                )
        forbidden = (
            "Add-Type",
            "BootstrapResult",
            "Ed25519",
            "Initialize-SignedExternalTrust",
            "PythonRuntimePath",
            "Test-External",
            "trustedRepository",
            "validate_release_trust.py",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, source)
        self.assertNotIn("& $", source)

    def test_superseded_history_file_and_exact_frontmatter_are_required(self) -> None:
        history = self.root / "docs" / "history" / "trust-r2-r11-superseded.md"
        original = history.read_text(encoding="utf-8")
        mutations = {
            "status": original.replace("status: superseded", "status: active", 1),
            "executable": original.replace("executable: false", "executable: true", 1),
            "accepted_by_gate": original.replace("accepted_by_gate: false", "accepted_by_gate: true", 1),
            "authority": original.replace("authority: none", "authority: candidate", 1),
            "extra_key": original.replace("authority: none\n---", "authority: none\nlegacy: true\n---", 1),
        }
        for name, mutated in mutations.items():
            with self.subTest(mutation=name):
                history.write_text(mutated, encoding="utf-8")
                completed = self.run_gate("Structure")
                output = self.output(completed)
                self.assertEqual(completed.returncode, 1, output)
                self.assertIn("front matter must be exactly", output)
                self.assertNotIn("Local consistency check passed", output)
                history.write_text(original, encoding="utf-8")

        history.unlink()
        completed = self.run_gate("Structure")
        output = self.output(completed)
        self.assertEqual(completed.returncode, 1, output)
        self.assertIn("requires local path: docs/history/trust-r2-r11-superseded.md", output)
        self.assertNotIn("Local consistency check passed", output)

    def test_superseded_history_exact_h1_and_every_h2_are_required(self) -> None:
        history = self.root / "docs" / "history" / "trust-r2-r11-superseded.md"
        original = history.read_text(encoding="utf-8")

        history.write_text(
            original.replace(
                "# HISTÓRICO SUPERADO — NÃO EXECUTÁVEL",
                "# Histórico",
                1,
            ),
            encoding="utf-8",
        )
        completed = self.run_gate("Structure")
        output = self.output(completed)
        self.assertEqual(completed.returncode, 1, output)
        self.assertIn("exact superseded/non-executable H1", output)

        history.write_text(
            original.replace(
                "## HISTÓRICO SUPERADO — NÃO EXECUTÁVEL — R7",
                "## R7",
                1,
            ),
            encoding="utf-8",
        )
        completed = self.run_gate("Structure")
        output = self.output(completed)
        self.assertEqual(completed.returncode, 1, output)
        self.assertIn("H2 is not explicitly invalidated: R7", output)
        self.assertNotIn("Local consistency check passed", output)

    def test_superseded_history_h2_roster_is_closed_and_ordinal_on_every_host(self) -> None:
        history = self.root / "docs" / "history" / "trust-r2-r11-superseded.md"
        original = history.read_text(encoding="utf-8")
        headings = re.findall(r"^## (?!#)[^\r\n]+", original, flags=re.MULTILINE)
        self.assertEqual(len(headings), 7)
        invalidating_prefix = headings[0][3:].split("R2\u2013R3", 1)[0]
        swap_sentinel = "R19-HISTORY-HEADING-SWAP-SENTINEL"
        reordered = (
            original.replace(headings[2], swap_sentinel, 1)
            .replace(headings[3], headings[2], 1)
            .replace(swap_sentinel, headings[3], 1)
        )
        mutations = {
            "missing": original.replace(headings[1] + "\n", "", 1),
            "duplicate": original.replace(
                headings[2],
                headings[2].replace("R6", "R4", 1),
                1,
            ),
            "reordered": reordered,
            "extra": original
            + f"\n\n## {invalidating_prefix}R9 \u2014 synthetic extra history section\n",
            "r999": original.replace(
                headings[-1],
                headings[-1].replace("R11", "R999", 1),
                1,
            ),
        }
        try:
            for name, mutated in mutations.items():
                with self.subTest(mutation=name):
                    history.write_text(mutated, encoding="utf-8")
                    self.assert_structure_rejected_on_every_host(
                        "H2 roster must be exactly 7 entries in Ordinal order"
                    )
        finally:
            history.write_text(original, encoding="utf-8")

    def test_legacy_machine_protocol_id_is_rejected_outside_history(self) -> None:
        readme = self.root / "README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8")
            + "\n\nLegacy probe: `external-trust-bootstrap-result.v4`.\n",
            encoding="utf-8",
        )
        completed = self.run_gate("Structure")
        output = self.output(completed)
        self.assertEqual(completed.returncode, 1, output)
        self.assertIn(
            "README.md reintroduces legacy machine trust protocol id outside superseded history: "
            "external-trust-bootstrap-result.v4",
            output,
        )
        self.assertNotIn("Local consistency check passed", output)

    def test_current_changelog_cannot_reinsert_r2_r11_history_sections(self) -> None:
        changelog = self.root / "docs" / "changelog-codex.md"
        original = changelog.read_text(encoding="utf-8")
        cases = {
            "operational": (
                original + "\n\n## R7 — authority revived\n\nSynthetic reinsertion.\n",
                "reintroduces an R2-R11 operational heading",
            ),
            "copied_history": (
                original
                + "\n\n## HISTÓRICO SUPERADO — NÃO EXECUTÁVEL — R7 — copied section\n\nSynthetic reinsertion.\n",
                "reinserts a superseded history section into current operational documentation",
            ),
        }
        for name, (mutated, expected) in cases.items():
            with self.subTest(mutation=name):
                changelog.write_text(mutated, encoding="utf-8")
                completed = self.run_gate("Structure")
                output = self.output(completed)
                self.assertEqual(completed.returncode, 1, output)
                self.assertIn(expected, output)
                self.assertNotIn("Local consistency check passed", output)
                changelog.write_text(original, encoding="utf-8")

    def test_legacy_scans_normalize_nfkc_and_strip_format_controls_on_every_host(self) -> None:
        readme = self.root / "README.md"
        original = readme.read_text(encoding="utf-8")
        protocol = "external-trust-bootstrap-result.v4"
        operational_heading = "## R7 \u2014 revived authority"
        copied_history_heading = (
            "## HIST\u00d3RICO SUPERADO \u2014 N\u00c3O EXECUT\u00c1VEL \u2014 R7 \u2014 copied section"
        )
        cases = {
            "protocol_zero_width": (
                protocol.replace("bootstrap", "boot\u200bstrap", 1),
                "reintroduces legacy machine trust protocol id",
            ),
            "protocol_bidi": (
                protocol.replace("bootstrap", "boot\u202estrap", 1),
                "reintroduces legacy machine trust protocol id",
            ),
            "protocol_fullwidth": (
                self.fullwidth_ascii(protocol),
                "reintroduces legacy machine trust protocol id",
            ),
            "operational_zero_width": (
                operational_heading.replace("R7", "R\u200b7", 1),
                "reintroduces an R2-R11 operational heading",
            ),
            "operational_bidi": (
                operational_heading.replace("R7", "R\u202e7", 1),
                "reintroduces an R2-R11 operational heading",
            ),
            "operational_fullwidth": (
                self.fullwidth_ascii(operational_heading),
                "reintroduces an R2-R11 operational heading",
            ),
            "copied_history_zero_width": (
                copied_history_heading.replace("SUPERADO", "SUPE\u200bRADO", 1),
                "reinserts a superseded history section",
            ),
            "copied_history_bidi": (
                copied_history_heading.replace("SUPERADO", "SUPE\u202eRADO", 1),
                "reinserts a superseded history section",
            ),
            "copied_history_fullwidth": (
                self.fullwidth_ascii(copied_history_heading),
                "reinserts a superseded history section",
            ),
        }
        try:
            for name, (probe, expected) in cases.items():
                with self.subTest(mutation=name):
                    readme.write_text(original + "\n\n" + probe + "\n", encoding="utf-8")
                    self.assert_structure_rejected_on_every_host(expected)
        finally:
            readme.write_text(original, encoding="utf-8")

    def test_operational_history_links_require_no_fragment_and_invalidating_label(self) -> None:
        changelog = self.root / "docs" / "changelog-codex.md"
        original = changelog.read_text(encoding="utf-8")
        original_link = "[histórico invalidado e não executável](history/trust-r2-r11-superseded.md)"
        self.assertIn(original_link, original)
        cases = {
            "fragment": (
                "[histórico invalidado e não executável](history/trust-r2-r11-superseded.md#r7)",
                "operational link to superseded history must not contain a fragment",
            ),
            "label": (
                "[histórico R2-R11](history/trust-r2-r11-superseded.md)",
                "operational link to superseded history requires an explicitly invalidating label",
            ),
        }
        for name, (replacement, expected) in cases.items():
            with self.subTest(mutation=name):
                changelog.write_text(original.replace(original_link, replacement, 1), encoding="utf-8")
                completed = self.run_gate("Structure")
                output = self.output(completed)
                self.assertEqual(completed.returncode, 1, output)
                self.assertIn(expected, output)
                self.assertNotIn("Local consistency check passed", output)
                changelog.write_text(original, encoding="utf-8")

    def test_empty_markdown_is_reported_without_crash(self) -> None:
        (self.root / "README.md").write_text("", encoding="utf-8")
        completed = self.run_gate("Structure")
        self.assertNotEqual(completed.returncode, 0, self.output(completed))
        self.assertIn("README.md is empty", self.output(completed))

    def test_unicode_case_whitespace_marker_is_rejected(self) -> None:
        (self.root / "README.md").write_text(
            "# Probe\n\nStatus:  T\u200bBd  \n",
            encoding="utf-8",
        )
        completed = self.run_gate("Structure")
        self.assertNotEqual(completed.returncode, 0, self.output(completed))
        self.assertIn("unresolved marker", self.output(completed))

    def test_csv_marker_normalization_is_fail_closed(self) -> None:
        self.mutate_csv(
            "docs/governance/regulatory-authority-ledger.csv",
            lambda rows: rows[0].__setitem__("notes", "  tBd  "),
        )
        completed = self.run_gate("Structure")
        self.assertNotEqual(completed.returncode, 0, self.output(completed))
        self.assertIn("uses legacy marker", self.output(completed))

    def test_approved_record_rejects_zero_checksum_and_candidate_approval(self) -> None:
        def mutate(rows: list[dict[str, str]]) -> None:
            rows[0].update(
                artifact_status="approved",
                source_artifact_path="AGENTS.md",
                source_checksum="sha256:" + "0" * 64,
                reviewed_by="synthetic-reviewer",
                reviewed_on="2026-08-08",
                review_expires_at="2099-12-31",
            )

        self.mutate_csv("docs/governance/regulatory-authority-ledger.csv", mutate)
        completed = self.run_gate("Structure")
        output = self.output(completed)
        self.assertNotEqual(completed.returncode, 0, output)
        self.assertIn("forbidden all-zero sha256 sentinel", output)
        self.assertIn("candidate-side approval assertion", output)

    def test_approved_record_verifies_local_artifact_checksum(self) -> None:
        def mutate(rows: list[dict[str, str]]) -> None:
            rows[0].update(
                artifact_status="approved",
                source_artifact_path="AGENTS.md",
                source_checksum="sha256:" + hashlib.sha256(b"wrong").hexdigest(),
                reviewed_by="synthetic-reviewer",
                reviewed_on="2026-08-08",
                review_expires_at="2099-12-31",
            )

        self.mutate_csv("docs/governance/regulatory-authority-ledger.csv", mutate)
        completed = self.run_gate("Structure")
        self.assertNotEqual(completed.returncode, 0, self.output(completed))
        self.assertIn("checksum does not match source_artifact_path", self.output(completed))

    def test_court_clarification_cannot_suspend(self) -> None:
        def mutate(rows: list[dict[str, str]]) -> None:
            row = next(item for item in rows if item["event_id"] == "BR-IOF-2025-COURT-CLARIFY-GAP")
            row["suspends"] = "authority:BR-DEC-12499"

        self.mutate_csv("docs/governance/legal-event-ledger.csv", mutate)
        completed = self.run_gate("Structure")
        self.assertNotEqual(completed.returncode, 0, self.output(completed))
        self.assertIn("cannot set suspends", self.output(completed))

    def test_required_document_wrong_type_is_reported(self) -> None:
        (self.root / "README.md").unlink()
        (self.root / "README.md").mkdir()
        completed = self.run_gate("Structure")
        self.assertNotEqual(completed.returncode, 0, self.output(completed))
        self.assertIn("requires a regular file, not a directory: README.md", self.output(completed))


if __name__ == "__main__":
    unittest.main(verbosity=2)
