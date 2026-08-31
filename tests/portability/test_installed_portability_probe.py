from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROBE = REPOSITORY_ROOT / "scripts" / "installed_portability_probe.py"
GUARD = Path(__file__).resolve().parent
SOURCE_ROOT = REPOSITORY_ROOT / "src"
VALID = REPOSITORY_ROOT / "examples" / "deterministic-cashflow-ledger.json"


class InstalledPortabilityProbeTests(unittest.TestCase):
    def test_source_probe_observes_sdk_cli_bytes_schemas_reason_codes_and_rcs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-portability-probe-") as directory:
            root = Path(directory)
            invalid = root / "invalid.json"
            malformed = root / "malformed.json"
            invalid.write_bytes(b"{}")
            malformed.write_bytes(b"[[")
            environment = os.environ.copy()
            hostile_locale = "Portuguese_Brazil.1252" if os.name == "nt" else "C.UTF-8"
            environment.update(
                {
                    "FINPLANBR_PORTABILITY_CONTEXT": "hostile",
                    "FINPLANBR_PORTABILITY_GUARD": "1",
                    "FINPLANBR_PORTABILITY_LOCALE": hostile_locale,
                    "LC_ALL": "C",
                    "LANG": "C",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONHASHSEED": "4294967295",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONPATH": os.pathsep.join((os.fspath(GUARD), os.fspath(SOURCE_ROOT))),
                    "TZ": "GMT+12",
                }
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-P",
                    "-s",
                    os.fspath(PROBE),
                    "--valid-input",
                    os.fspath(VALID),
                    "--invalid-input",
                    os.fspath(invalid),
                    "--malformed-input",
                    os.fspath(malformed),
                    "--expected-origin-root",
                    os.fspath(SOURCE_ROOT),
                ],
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=60,
            )
        report = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 0, report)
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["sdk_cli_bytes_identical"])
        self.assertEqual(report["schema_count"], 4)
        self.assertGreater(report["reason_code_count"], 0)
        self.assertEqual(report["runtime_context"]["hash_seed"], "4294967295")
        self.assertEqual(report["runtime_context"]["decimal_precision"], 7)
        self.assertNotEqual(report["runtime_context"]["locale"], "C")
        self.assertEqual(report["runtime_context"]["tz_epoch_local"], [1969, 12, 31, 12, 0, 0])
        self.assertFalse(completed.stderr)


if __name__ == "__main__":
    unittest.main()
