from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.aggregate_portability_matrix import EXPECTED_CELLS, aggregate
from scripts.portability_artifact_inventory import (
    EXPECTED_PACKAGE_INVENTORY_SHA256,
    EXPECTED_SDIST_INVENTORY_SHA256,
    EXPECTED_WHEEL_INVENTORY_SHA256,
    METADATA_POLICY,
    SDIST_ARCHIVE_POLICY,
    WHEEL_ARCHIVE_POLICY,
)
from scripts.portability_artifact_inventory import (
    FORMAT as PACKAGE_FORMAT,
)
from scripts.portability_runtime_pins import PYTHON_BASE_IMAGES

FREEZE = "a" * 64


def _write_report(path: Path, report: object) -> None:
    path.write_bytes(
        json.dumps(report, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def _cell(cell: str) -> dict[str, object]:
    system, minor = cell.split("-py")
    baseline = {
        "decimal_Emax": 999999,
        "decimal_Emin": -999999,
        "decimal_precision": 28,
        "decimal_rounding": "ROUND_HALF_EVEN",
        "hash_seed": "0",
        "locale": "C",
        "tz": "UTC0",
        "tz_epoch_local": [1970, 1, 1, 0, 0, 0],
    }
    hostile = {
        "decimal_Emax": 7,
        "decimal_Emin": -7,
        "decimal_precision": 7,
        "decimal_rounding": "ROUND_FLOOR",
        "hash_seed": "4294967295",
        "locale": "C.UTF-8" if system == "linux" else "Portuguese_Brazil.1252",
        "tz": "GMT+12",
        "tz_epoch_local": [1969, 12, 31, 12, 0, 0],
    }
    return {
        "format": "finplanbr.installed-portability-cell.v1",
        "status": "passed",
        "cell": cell,
        "platform": {"system": system, "machine": "x86_64"},
        "python": minor + ".99",
        "source_freeze": {
            "manifest_sha256": FREEZE,
            "entry_count": 200,
            "rechecked_after_execution": True,
        },
        "toolchain": {
            "build": "1.4.0",
            "pip": "99.0",
            "setuptools": "84.0.0",
            "acquisition_network": (
                "enabled_before_cell_image_build" if system == "linux" else "enabled_before_firewall_boundary"
            ),
            **({"container_image_id": "sha256:" + "e" * 64} if system == "linux" else {}),
            **({"base_image_ref": PYTHON_BASE_IMAGES[minor]} if system == "linux" else {}),
        },
        "artifacts": {
            "direct_wheel": {"name": "direct.whl", "sha256": "b" * 64},
            "sdist": {"name": "source.tar.gz", "sha256": "c" * 64},
            "sdist_wheel": {"name": "rebuilt.whl", "sha256": "b" * 64},
        },
        "packaging": {
            "format": PACKAGE_FORMAT,
            "metadata_policy": METADATA_POLICY,
            "wheel_archive_policy": WHEEL_ARCHIVE_POLICY,
            "sdist_archive_policy": SDIST_ARCHIVE_POLICY,
            "package_member_count": 18,
            "wheel_member_count": 24,
            "sdist_file_count": 29,
            "sdist_member_count": 33,
            "package_inventory_sha256": EXPECTED_PACKAGE_INVENTORY_SHA256,
            "wheel_inventory_sha256": EXPECTED_WHEEL_INVENTORY_SHA256,
            "sdist_inventory_sha256": EXPECTED_SDIST_INVENTORY_SHA256,
            "package_logical_sha256": "6" * 64,
            "wheel_logical_sha256": "7" * 64,
            "wheel_archive_sha256": "b" * 64,
            "sdist_logical_sha256": "8" * 64,
            "sdist_archive_sha256": "c" * 64,
            "source_wheel_sdist_package_identical": True,
            "direct_sdist_wheel_logical_identical": True,
            "direct_sdist_wheel_archive_identical": True,
        },
        "installation": {
            "direct_wheel_venv_outside_checkout": True,
            "sdist_wheel_venv_outside_checkout": True,
            "network_boundary_active": True,
            "runtime_dependencies": 0,
            "flags": [
                "--no-index",
                "--no-deps",
                "--no-cache-dir",
                "--no-compile",
                "--disable-pip-version-check",
            ],
        },
        "controls": {
            "network": {
                "mechanism": "docker_none" if system == "linux" else "windows_firewall_exact_program",
                "precontrol_connected": True,
                "postcontrol_blocked": True,
                **(
                    {"nonce": "f" * 32, "postcontrol_error_type": "OSError"}
                    if system == "linux"
                    else {
                        "cleanup_verified": True,
                        "preexisting_rule_count": 0,
                        "program_targets_absolute": True,
                        "program_count": 5,
                    }
                ),
            },
            "filesystem": {
                "mechanism": (
                    "docker_read_only_bind_plus_posix_modes" if system == "linux" else "ntfs_acl_readonly_tested_trees"
                ),
                "writable_precontrol_triggered": True,
                "readonly_postcontrol_triggered": True,
                "protected_tree_unchanged": True,
                **(
                    {"root_write_blocked": True, "source_write_blocked": True}
                    if system == "linux"
                    else {
                        "cleanup_verified": True,
                        "target_count": 4,
                        "targets_absolute": True,
                        "prior_sddl_snapshot_count": 4,
                    }
                ),
            },
            "audit_hook": {
                "role": "secondary_observer_not_sandbox",
                "network_negative_triggered": True,
                "write_negative_triggered": True,
            },
        },
        "observations": {
            "source_direct_sdist_bytes_identical": True,
            "sdk_cli_bytes_and_rc_identical": True,
            "console_cli_bytes_and_rc_identical": True,
            "installed_console_entrypoint_count": 4,
            "installed_console_commands_per_probe": 8,
            "isolated_import_origin_count": 3,
            "isolated_import_origins": {
                "source": "/candidate/src/package/__init__.py",
                "direct_wheel": "/venv-direct/site-packages/package/__init__.py",
                "sdist_wheel": "/venv-sdist/site-packages/package/__init__.py",
            },
            "parity_sha256": "9" * 64,
            "probe_count": 6,
            "contexts": {
                f"{variant}:{surface}": dict(context)
                for variant, context in (("baseline", baseline), ("hostile", hostile))
                for surface in ("source", "direct_wheel", "sdist_wheel")
            },
            "surface_count": 3,
            "variant_count": 2,
            "schema_count": 4,
            "reason_code_count": 36,
            "skip_count": 0,
            "xfail_count": 0,
        },
        "authority": "none",
        "release_authorized": False,
    }


class AggregatePortabilityMatrixTests(unittest.TestCase):
    def _write_matrix(self, root: Path) -> None:
        for cell in EXPECTED_CELLS:
            _write_report(root.joinpath(cell + ".json"), _cell(cell))

    def test_eight_perfect_self_issued_reports_still_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            report, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["cell_count"], 8)
        self.assertTrue(report["all_cells_consistent"])
        self.assertEqual(report["evidence_authentication"], "not_implemented")
        self.assertTrue(report["single_source_freeze"])
        self.assertTrue(report["single_packaging_binding"])
        self.assertEqual(report["packaging_binding"]["sdist_archive_sha256"], "c" * 64)
        self.assertEqual(
            {issue["code"] for issue in report["issues"]},
            {"EVIDENCE_ORIGIN_UNAUTHENTICATED"},
        )

    def test_missing_cell_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            root.joinpath(EXPECTED_CELLS[-1] + ".json").unlink()
            report, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertIn(EXPECTED_CELLS[-1], report["missing_cells"])
        self.assertIn("MISSING_CELL", {issue["code"] for issue in report["issues"]})

    def test_not_observed_cell_never_claims_single_source_freeze(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            cell = EXPECTED_CELLS[-1]
            _write_report(
                root.joinpath(cell + ".json"),
                {
                    "format": "finplanbr.installed-portability-host-launch.v1",
                    "status": "not_observed",
                    "cell": cell,
                    "reason": "windows_firewall_control_requires_elevated_runner",
                    "audit_hook_fallback": False,
                    "authority": "none",
                    "release_authorized": False,
                },
            )
            report, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertFalse(report["single_source_freeze"])
        self.assertIn("SOURCE_FREEZE_MATRIX", {issue["code"] for issue in report["issues"]})

    def test_freeze_drift_and_inactive_control_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            target = root / "linux-py3.11.json"
            report = json.loads(target.read_text(encoding="utf-8"))
            report["source_freeze"]["manifest_sha256"] = "e" * 64
            report["controls"]["network"]["postcontrol_blocked"] = False
            _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        codes = {issue["code"] for issue in aggregated["issues"]}
        self.assertIn("NETWORK_POSTCONTROL", codes)
        self.assertIn("SOURCE_FREEZE_MATRIX", codes)

    def test_mutable_linux_base_image_reference_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            target = root / "linux-py3.11.json"
            report = json.loads(target.read_bytes())
            report["toolchain"]["base_image_ref"] = "python:3.11-slim-bookworm"
            _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertIn("LINUX_IMAGE_PIN", {issue["code"] for issue in aggregated["issues"]})

    def test_skip_or_xfail_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            target = root / "windows-py3.14.json"
            report = json.loads(target.read_text(encoding="utf-8"))
            report["observations"]["skip_count"] = 1
            report["observations"]["xfail_count"] = 1
            _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        codes = {issue["code"] for issue in aggregated["issues"]}
        self.assertEqual({"SKIP_COUNT", "XFAIL_COUNT"} - codes, set())

    def test_eight_distinct_product_digests_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            for index, cell in enumerate(EXPECTED_CELLS, start=1):
                target = root / (cell + ".json")
                report = json.loads(target.read_bytes())
                report["observations"]["parity_sha256"] = f"{index:064x}"
                _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertFalse(aggregated["single_product_parity"])
        self.assertIn("PRODUCT_PARITY_MATRIX", {issue["code"] for issue in aggregated["issues"]})

    def test_missing_product_digest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            target = root / "linux-py3.11.json"
            report = json.loads(target.read_bytes())
            del report["observations"]["parity_sha256"]
            _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        codes = {issue["code"] for issue in aggregated["issues"]}
        self.assertIn("PARITY_DIGEST", codes)
        self.assertIn("PRODUCT_PARITY_MATRIX", codes)

    def test_eight_distinct_package_bindings_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            for index, cell in enumerate(EXPECTED_CELLS, start=1):
                target = root / (cell + ".json")
                report = json.loads(target.read_bytes())
                report["packaging"]["package_logical_sha256"] = f"{index:064x}"
                _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertFalse(aggregated["single_packaging_binding"])
        self.assertIn("PACKAGING_MATRIX", {issue["code"] for issue in aggregated["issues"]})

    def test_wheel_archive_digest_must_match_within_and_across_cells(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            target = root / "linux-py3.11.json"
            report = json.loads(target.read_bytes())
            report["artifacts"]["sdist_wheel"]["sha256"] = "d" * 64
            _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertIn("WHEEL_ARCHIVE_DIGEST", {issue["code"] for issue in aggregated["issues"]})

        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            target = root / "linux-py3.11.json"
            report = json.loads(target.read_bytes())
            for label in ("direct_wheel", "sdist_wheel"):
                report["artifacts"][label]["sha256"] = "d" * 64
            report["packaging"]["wheel_archive_sha256"] = "d" * 64
            _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertFalse(aggregated["single_packaging_binding"])
        self.assertIn("PACKAGING_MATRIX", {issue["code"] for issue in aggregated["issues"]})

    def test_sdist_archive_digest_must_match_artifact_within_cell(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            target = root / "linux-py3.11.json"
            report = json.loads(target.read_bytes())
            report["artifacts"]["sdist"]["sha256"] = "d" * 64
            _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertFalse(aggregated["all_cells_consistent"])
        self.assertIn("SDIST_ARCHIVE_DIGEST", {issue["code"] for issue in aggregated["issues"]})

    def test_eight_distinct_self_consistent_sdist_archive_digests_fail_cross_cell(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            for index, cell in enumerate(EXPECTED_CELLS, start=1):
                target = root / (cell + ".json")
                report = json.loads(target.read_bytes())
                digest = f"{index:064x}"
                report["artifacts"]["sdist"]["sha256"] = digest
                report["packaging"]["sdist_archive_sha256"] = digest
                _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertFalse(aggregated["all_cells_consistent"])
        self.assertFalse(aggregated["single_packaging_binding"])
        self.assertIn("PACKAGING_MATRIX", {issue["code"] for issue in aggregated["issues"]})

    def test_missing_package_binding_field_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            target = root / "linux-py3.11.json"
            report = json.loads(target.read_bytes())
            del report["packaging"]["wheel_inventory_sha256"]
            _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        codes = {issue["code"] for issue in aggregated["issues"]}
        self.assertIn("PACKAGE_BINDING", codes)
        self.assertIn("PACKAGING_MATRIX", codes)

    def test_full_cell_canary_inventory_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-matrix-") as directory:
            root = Path(directory)
            self._write_matrix(root)
            target = root / "linux-py3.11.json"
            report = json.loads(target.read_bytes())
            report["packaging"]["package_member_count"] = 19
            report["packaging"]["package_inventory_sha256"] = "5" * 64
            _write_report(target, report)
            aggregated, return_code = aggregate(root)
        self.assertEqual(return_code, 1)
        self.assertFalse(aggregated["single_packaging_binding"])
        self.assertIn("PACKAGE_BINDING", {issue["code"] for issue in aggregated["issues"]})


if __name__ == "__main__":
    unittest.main()
