from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import scripts.validate_sdk_conformance as conformance
from scripts.validate_sdk_conformance import (
    DiagnosticConfigurationError,
    FileSnapshot,
    WorkerCrash,
    WorkerTimeout,
    evaluate_repository,
    load_bridge_bundle,
)
from tests.sdk.vector_adapter import MATH_SUT_PROTOCOL
from tests.sdk.vector_adapter import compute as compute_vector

REPO_ROOT = Path(__file__).resolve().parents[2]


def copy_diagnostic_repository(target: Path) -> None:
    shutil.copytree(REPO_ROOT / "src", target / "src")
    shutil.copytree(REPO_ROOT / "tests" / "vectors", target / "tests" / "vectors")
    (target / "tests" / "sdk").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "tests" / "__init__.py", target / "tests" / "__init__.py")
    shutil.copy2(REPO_ROOT / "tests" / "sdk" / "__init__.py", target / "tests" / "sdk" / "__init__.py")
    shutil.copy2(REPO_ROOT / "tests" / "sdk" / "vector_adapter.py", target / "tests" / "sdk" / "vector_adapter.py")
    (target / "scripts").mkdir()
    shutil.copy2(REPO_ROOT / "scripts" / "sdk_conformance_worker.py", target / "scripts" / "sdk_conformance_worker.py")


class LocalSdkConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report, cls.exit_code = evaluate_repository(REPO_ROOT)

    def test_canonical_diagnostic_executes_the_public_sdk_and_all_mutants_are_killed(self) -> None:
        self.assertEqual(self.exit_code, 0, self.report)
        self.assertEqual(self.report["status"], "local_sdk_conformance_passed")
        self.assertEqual(self.report["counts"]["vector_cases"], 7)
        self.assertEqual(self.report["counts"]["property_cases"], 71)
        self.assertEqual(self.report["counts"]["property_families"], 7)
        self.assertEqual(self.report["counts"]["reference_pack_cases"], 1)
        mutation = self.report["counts"]["mutation"]
        self.assertTrue(mutation["evaluated"])
        self.assertEqual(mutation["declared"], 23)
        self.assertEqual(mutation["semantic_kill"] + mutation["assertion_kill"], 23)
        self.assertEqual(mutation["compound_declared"], 3)
        self.assertEqual(mutation["compound_controlled_kill"], 3)
        self.assertEqual(
            mutation["compound_roster"],
            [
                "false_reconciliation_after_omitted_posting",
                "negative_money_rounding_half_down",
                "return_uses_opening_balance",
            ],
        )
        self.assertEqual(mutation["compound_controlled_kills"], mutation["compound_roster"])
        self.assertIn(
            "property::return::sequential_current_balance",
            mutation["required_kill_case_coverage"]["return_uses_opening_balance"],
        )
        self.assertIn(
            "gate::reference_pack::current_balance_return",
            mutation["required_kill_case_coverage"]["return_uses_opening_balance"],
        )
        self.assertEqual(mutation["crash"], 0)
        self.assertEqual(mutation["timeout"], 0)
        self.assertEqual(mutation["nonviable"], 0)
        self.assertEqual(mutation["survived"], 0)

    def test_report_keeps_release_and_full_sut_authority_closed(self) -> None:
        self.assertFalse(self.report["release_authorized"])
        self.assertEqual(self.report["authority"], "technical_validation_only_not_release_authority")
        self.assertEqual(self.report["official_21_vector_sut_conformance"], "not_evaluated")
        self.assertEqual(self.report["scope"]["corpus_vectors_total"], 21)
        self.assertEqual(self.report["scope"]["supported_vectors"], 7)
        self.assertEqual(self.report["scope"]["out_of_scope_vectors"], 14)
        encoded = json.dumps(self.report, sort_keys=True)
        self.assertNotIn('"release_authorized": true', encoded)

    def test_bridge_manifest_is_an_exact_corpus_partition(self) -> None:
        bundle = load_bridge_bundle(REPO_ROOT)
        supported = {vector.vector_id for vector in bundle.vectors}
        out_of_scope = set(bundle.out_of_scope_vector_ids)
        self.assertEqual(len(supported), 7)
        self.assertEqual(len(out_of_scope), 14)
        self.assertFalse(supported & out_of_scope)
        self.assertEqual(len(supported | out_of_scope), 21)

    def test_corpus_manifest_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-bridge-drift-") as temporary:
            root = Path(temporary)
            shutil.copytree(REPO_ROOT / "tests" / "vectors", root / "tests" / "vectors")
            corpus = root / "tests" / "vectors" / "math" / "v1" / "manifest.json"
            corpus.write_bytes(corpus.read_bytes() + b"\n")
            with self.assertRaisesRegex(DiagnosticConfigurationError, "manifest drifted"):
                load_bridge_bundle(root)

    def test_noop_adapter_cannot_produce_a_green_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-noop-adapter-") as temporary:
            root = Path(temporary)
            copy_diagnostic_repository(root)
            adapter = root / "tests" / "sdk" / "vector_adapter.py"
            adapter.write_text("def compute(request):\n    return {}\n", encoding="utf-8")
            report, exit_code = evaluate_repository(root, include_mutations=False)
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["status"], "local_sdk_conformance_failed")
        self.assertEqual(report["failure"]["stage"], "base_evaluation")

    def test_wrong_sdk_math_is_observed_through_the_subprocess(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-wrong-sdk-") as temporary:
            root = Path(temporary)
            copy_diagnostic_repository(root)
            source = root / "src" / "financial_planning_sdk_br" / "deterministic.py"
            text = source.read_text(encoding="utf-8")
            old = 'exact = _exact_multiply(cashflow.amount.value, factor, f"/cashflows/{len(exact_contributions)}")'
            self.assertEqual(text.count(old), 1)
            source.write_text(
                text.replace(
                    old,
                    'exact = _exact_multiply(cashflow.amount.value, Decimal("1"), '
                    'f"/cashflows/{len(exact_contributions)}")',
                ),
                encoding="utf-8",
            )
            report, exit_code = evaluate_repository(root, include_mutations=False)
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["failure"]["stage"], "base_evaluation")

    def test_skip_mutations_is_explicitly_partial(self) -> None:
        report, exit_code = evaluate_repository(REPO_ROOT, include_mutations=False)
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["status"], "local_sdk_conformance_partial")
        self.assertFalse(report["counts"]["mutation"]["evaluated"])

    def test_adapter_rejects_vectors_outside_the_declared_slice(self) -> None:
        request = {
            "protocol": MATH_SUT_PROTOCOL,
            "id": "portfolio-two-asset-convex",
            "topic": "two_asset_minimum_variance_closed_form",
            "input": {},
        }
        with self.assertRaisesRegex(ValueError, "outside"):
            compute_vector(request)

    def _worker_snapshot(self, path: Path) -> FileSnapshot:
        payload = path.read_bytes()
        status = path.stat()
        return FileSnapshot(
            path,
            path.name,
            payload,
            hashlib.sha256(payload).hexdigest(),
            (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns),
        )

    def test_worker_timeout_kills_descendant_before_temporary_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-sdk-timeout-test-") as directory:
            root = Path(directory)
            marker = root / "descendant-survived.txt"
            worker = root / "worker.py"
            child = (
                "import pathlib,time;"
                "time.sleep(0.8);"
                f"pathlib.Path({str(marker)!r}).write_text('bad')"
            )
            worker.write_text(
                "import subprocess,sys,time\n"
                f"subprocess.Popen([sys.executable,'-c',{child!r}])\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            with mock.patch.object(conformance, "WORKER_TIMEOUT_SECONDS", 0.2):
                with self.assertRaises(WorkerTimeout):
                    conformance._run_worker(REPO_ROOT, REPO_ROOT / "src", (), self._worker_snapshot(worker))
            time.sleep(1)
            self.assertFalse(marker.exists())

    def test_worker_output_limit_is_enforced_while_worker_is_running(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-sdk-output-test-") as directory:
            worker = Path(directory) / "worker.py"
            worker.write_text(
                "import sys,time\nsys.stdout.buffer.write(b'x'*1048576)\nsys.stdout.flush()\ntime.sleep(30)\n",
                encoding="utf-8",
            )
            started = time.monotonic()
            with mock.patch.object(conformance, "MAX_WORKER_OUTPUT_BYTES", 1024):
                with self.assertRaisesRegex(WorkerCrash, "stdout output budget"):
                    conformance._run_worker(REPO_ROOT, REPO_ROOT / "src", (), self._worker_snapshot(worker))
            self.assertLess(time.monotonic() - started, 5)

    def test_worker_limit_plus_one_is_not_misclassified_as_timeout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-sdk-output-sentinel-") as directory:
            worker = Path(directory) / "worker.py"
            worker.write_text(
                "import sys,time\nsys.stdout.buffer.write(b'x'*1025)\nsys.stdout.flush()\ntime.sleep(30)\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(conformance, "MAX_WORKER_OUTPUT_BYTES", 1024),
                mock.patch.object(conformance, "WORKER_TIMEOUT_SECONDS", 1),
            ):
                with self.assertRaisesRegex(WorkerCrash, "stdout output budget"):
                    conformance._run_worker(REPO_ROOT, REPO_ROOT / "src", (), self._worker_snapshot(worker))

    def test_invalid_worker_json_is_an_execution_crash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-sdk-json-test-") as directory:
            worker = Path(directory) / "worker.py"
            worker.write_text("print('{')\n", encoding="utf-8")
            with self.assertRaisesRegex(WorkerCrash, "not closed strict JSON"):
                conformance._run_worker(REPO_ROOT, REPO_ROOT / "src", (), self._worker_snapshot(worker))


if __name__ == "__main__":
    unittest.main()
