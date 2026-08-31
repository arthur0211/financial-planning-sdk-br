from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.validate_windows_portability_cell import CLEANUP_FORMAT, EXERCISE_FORMAT, finalize

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPOSITORY_ROOT / "scripts" / "run_windows_portability_cell.ps1"
VALIDATOR = REPOSITORY_ROOT / "scripts" / "validate_windows_portability_cell.py"


class WindowsPortabilityFailClosedTests(unittest.TestCase):
    def test_finalize_requires_firewall_and_acl_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-windows-finalize-") as directory:
            root = Path(directory)
            exercise = root / "exercise.json"
            cleanup = root / "cleanup.json"
            exercise.write_text(
                json.dumps(
                    {
                        "format": EXERCISE_FORMAT,
                        "status": "exercised",
                        "nonce": "test-nonce",
                        "controls": {"network": {}, "filesystem": {}},
                    }
                ),
                encoding="utf-8",
            )
            cleanup.write_text(
                json.dumps(
                    {
                        "format": CLEANUP_FORMAT,
                        "nonce": "test-nonce",
                        "firewall_rules_absent": True,
                        "acl_restored": False,
                    }
                ),
                encoding="utf-8",
            )
            arguments = argparse.Namespace(exercise_report=exercise, cleanup_report=cleanup)
            with self.assertRaisesRegex(RuntimeError, "cleanup was not verified"):
                finalize(arguments)
            cleanup.write_text(
                json.dumps(
                    {
                        "format": CLEANUP_FORMAT,
                        "nonce": "test-nonce",
                        "firewall_rules_absent": True,
                        "acl_restored": True,
                    }
                ),
                encoding="utf-8",
            )
            report = finalize(arguments)
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["controls"]["network"]["cleanup_verified"])
        self.assertTrue(report["controls"]["filesystem"]["cleanup_verified"])

    def test_launcher_has_no_audit_only_fallback_and_local_unprivileged_run_fails(self) -> None:
        source = LAUNCHER.read_text(encoding="utf-8-sig")
        for marker in (
            "windows_firewall_control_requires_elevated_runner",
            "audit_hook_fallback = $false",
            "New-NetFirewallRule -PolicyStore ActiveStore",
            "-Direction Outbound -Action Block -Program",
            "Remove-NetFirewallRule -PolicyStore ActiveStore -Name",
            "program_targets_absolute = $true",
            "$firewallSnapshot.Add",
            "$aclBackups.Add($target, $acl.Sddl)",
            "prior_sddl_snapshot_count = $aclBackups.Count",
            "finplanbr.bounded-subprocess-envelope.v1",
            "--stdout-limit 33554432 --stderr-limit 33554432",
            "stderr_sha256=",
            "@(Get-Command -Name $PythonExecutable -CommandType Application -ErrorAction Stop)[0]",
        ):
            self.assertIn(marker, source)
        self.assertIn("ntfs_acl_readonly_tested_trees", VALIDATOR.read_text(encoding="utf-8"))
        self.assertLess(source.index("$ruleNames.Add($ruleName)"), source.index("New-NetFirewallRule"))
        self.assertIn("Invoke-PythonJson -Arguments @('-I', '-B', $freezeScript)", source)
        if os.name != "nt" or shutil.which("pwsh") is None:
            return
        privilege = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-Command",
                (
                    "$p=[Security.Principal.WindowsPrincipal]::new("
                    "[Security.Principal.WindowsIdentity]::GetCurrent());"
                    "if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 0}else{exit 1}"
                ),
            ],
            capture_output=True,
            check=False,
            timeout=15,
        )
        if privilege.returncode == 0:
            return
        completed = subprocess.run(
            ["pwsh", "-NoProfile", "-File", os.fspath(LAUNCHER), "-PythonMinor", "3.11"],
            cwd=REPOSITORY_ROOT,
            input=b"",
            capture_output=True,
            check=False,
            timeout=30,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(report["status"], "not_observed")
        self.assertFalse(report["audit_hook_fallback"])


if __name__ == "__main__":
    unittest.main()
