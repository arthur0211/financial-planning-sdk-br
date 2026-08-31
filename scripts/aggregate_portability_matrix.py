#!/usr/bin/env python3
"""Aggregate executed portability cells; declarations never satisfy a cell."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

if __package__:
    from .portability_artifact_inventory import (
        EXPECTED_PACKAGE_INVENTORY_SHA256,
        EXPECTED_SDIST_INVENTORY_SHA256,
        EXPECTED_WHEEL_INVENTORY_SHA256,
        METADATA_POLICY,
        SDIST_ARCHIVE_POLICY,
        WHEEL_ARCHIVE_POLICY,
    )
    from .portability_artifact_inventory import (
        FORMAT as PACKAGE_FORMAT,
    )
    from .portability_runtime_pins import PYTHON_BASE_IMAGES
else:
    from portability_artifact_inventory import (  # type: ignore[no-redef]
        EXPECTED_PACKAGE_INVENTORY_SHA256,
        EXPECTED_SDIST_INVENTORY_SHA256,
        EXPECTED_WHEEL_INVENTORY_SHA256,
        METADATA_POLICY,
        SDIST_ARCHIVE_POLICY,
        WHEEL_ARCHIVE_POLICY,
    )
    from portability_artifact_inventory import (
        FORMAT as PACKAGE_FORMAT,
    )
    from portability_runtime_pins import PYTHON_BASE_IMAGES  # type: ignore[no-redef]

FORMAT = "finplanbr.installed-portability-matrix.v1"
CELL_FORMAT = "finplanbr.installed-portability-cell.v1"
EXPECTED_CELLS = tuple(
    f"{system}-py{version}" for system in ("linux", "windows") for version in ("3.11", "3.12", "3.13", "3.14")
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)+(?:[^\s]*)?$")
_INSTALL_FLAGS = ["--no-index", "--no-deps", "--no-cache-dir", "--no-compile", "--disable-pip-version-check"]
_CELL_KEYS = {
    "artifacts",
    "authority",
    "cell",
    "controls",
    "format",
    "installation",
    "observations",
    "packaging",
    "platform",
    "python",
    "release_authorized",
    "source_freeze",
    "status",
    "toolchain",
}
_PACKAGING_KEYS = {
    "direct_sdist_wheel_archive_identical",
    "direct_sdist_wheel_logical_identical",
    "format",
    "metadata_policy",
    "package_inventory_sha256",
    "package_logical_sha256",
    "package_member_count",
    "sdist_file_count",
    "sdist_inventory_sha256",
    "sdist_archive_policy",
    "sdist_archive_sha256",
    "sdist_logical_sha256",
    "sdist_member_count",
    "source_wheel_sdist_package_identical",
    "wheel_inventory_sha256",
    "wheel_archive_policy",
    "wheel_archive_sha256",
    "wheel_logical_sha256",
    "wheel_member_count",
}
_OBSERVATION_KEYS = {
    "console_cli_bytes_and_rc_identical",
    "contexts",
    "installed_console_commands_per_probe",
    "installed_console_entrypoint_count",
    "isolated_import_origin_count",
    "isolated_import_origins",
    "parity_sha256",
    "probe_count",
    "reason_code_count",
    "schema_count",
    "sdk_cli_bytes_and_rc_identical",
    "skip_count",
    "source_direct_sdist_bytes_identical",
    "surface_count",
    "variant_count",
    "xfail_count",
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _issue(issues: list[dict[str, str]], code: str, cell: str, message: str) -> None:
    issues.append({"code": code, "cell": cell, "message": message})


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _strict_json(payload: bytes) -> Any:
    text = payload.decode("utf-8", errors="strict")
    return json.loads(
        text,
        parse_constant=_reject_json_constant,
        object_pairs_hook=_unique_json_object,
    )


def _nested(report: dict[str, Any], *path: str) -> Any:
    value: Any = report
    for part in path:
        if type(value) is not dict or part not in value:
            return None
        value = value[part]
    return value


def _packaging_binding(value: object) -> tuple[str, str, str, str, str, str, str, str] | None:
    if type(value) is not dict or set(value) != _PACKAGING_KEYS:
        return None
    exact: tuple[tuple[str, object], ...] = (
        ("format", PACKAGE_FORMAT),
        ("metadata_policy", METADATA_POLICY),
        ("wheel_archive_policy", WHEEL_ARCHIVE_POLICY),
        ("sdist_archive_policy", SDIST_ARCHIVE_POLICY),
        ("package_member_count", 18),
        ("wheel_member_count", 24),
        ("sdist_file_count", 29),
        ("sdist_member_count", 33),
        ("package_inventory_sha256", EXPECTED_PACKAGE_INVENTORY_SHA256),
        ("wheel_inventory_sha256", EXPECTED_WHEEL_INVENTORY_SHA256),
        ("sdist_inventory_sha256", EXPECTED_SDIST_INVENTORY_SHA256),
        ("source_wheel_sdist_package_identical", True),
        ("direct_sdist_wheel_logical_identical", True),
        ("direct_sdist_wheel_archive_identical", True),
    )
    if any(type(value.get(key)) is not type(expected) or value.get(key) != expected for key, expected in exact):
        return None
    logical_keys = (
        "package_logical_sha256",
        "wheel_logical_sha256",
        "wheel_archive_sha256",
        "sdist_logical_sha256",
        "sdist_archive_sha256",
    )
    if any(not _is_sha256(value.get(key)) for key in logical_keys):
        return None
    return (
        value["package_inventory_sha256"],
        value["wheel_inventory_sha256"],
        value["sdist_inventory_sha256"],
        value["package_logical_sha256"],
        value["wheel_logical_sha256"],
        value["sdist_logical_sha256"],
        value["wheel_archive_sha256"],
        value["sdist_archive_sha256"],
    )


def _validate_passed_cell(report: dict[str, Any], issues: list[dict[str, str]]) -> None:
    cell = str(report.get("cell", "unknown"))
    if report.get("status") != "passed":
        _issue(issues, "CELL_STATUS", cell, "cell did not pass")
        return
    system, python_minor = cell.split("-py", 1) if "-py" in cell else ("", "")
    if set(report) != _CELL_KEYS:
        _issue(issues, "CELL_ROSTER", cell, "passed cell top-level roster is not exact")
    observations = report.get("observations")
    if type(observations) is not dict or set(observations) != _OBSERVATION_KEYS:
        _issue(issues, "OBSERVATION_ROSTER", cell, "passed cell observation roster is not exact")
    if _packaging_binding(report.get("packaging")) is None:
        _issue(issues, "PACKAGE_BINDING", cell, "closed package inventory/content binding is missing or invalid")
    checks: tuple[tuple[bool, str, str], ...] = (
        (report.get("format") == CELL_FORMAT, "CELL_FORMAT", "cell format is not the closed v1 format"),
        (report.get("authority") == "none", "CELL_AUTHORITY", "cell overstated authority"),
        (report.get("release_authorized") is False, "CELL_RELEASE", "cell authorized release"),
        (_nested(report, "platform", "system") == system, "CELL_PLATFORM", "platform differs from coordinate"),
        (
            type(report.get("python")) is str and str(report["python"]).startswith(python_minor + "."),
            "CELL_PYTHON",
            "runtime Python differs from coordinate",
        ),
        (
            _nested(report, "installation", "direct_wheel_venv_outside_checkout") is True,
            "DIRECT_VENV",
            "direct wheel venv was not outside checkout",
        ),
        (
            _nested(report, "installation", "sdist_wheel_venv_outside_checkout") is True,
            "SDIST_VENV",
            "sdist wheel venv was not outside checkout",
        ),
        (
            _nested(report, "installation", "network_boundary_active") is True,
            "INSTALL_NETWORK",
            "build/install did not run with active network boundary",
        ),
        (
            _nested(report, "installation", "runtime_dependencies") == 0,
            "RUNTIME_DEPS",
            "installed distribution has a base runtime dependency",
        ),
        (
            _nested(report, "controls", "network", "precontrol_connected") is True,
            "NETWORK_PRECONTROL",
            "network precontrol did not connect",
        ),
        (
            _nested(report, "controls", "network", "postcontrol_blocked") is True,
            "NETWORK_POSTCONTROL",
            "network postcontrol was not blocked",
        ),
        (
            _nested(report, "controls", "filesystem", "writable_precontrol_triggered") is True,
            "FILESYSTEM_PRECONTROL",
            "filesystem writable precontrol did not trigger",
        ),
        (
            _nested(report, "controls", "filesystem", "readonly_postcontrol_triggered") is True,
            "FILESYSTEM_POSTCONTROL",
            "filesystem read-only postcontrol did not trigger",
        ),
        (
            _nested(report, "controls", "filesystem", "protected_tree_unchanged") is True,
            "IMPLICIT_WRITE",
            "protected runtime tree changed during tested routes",
        ),
        (
            _nested(report, "controls", "audit_hook", "role") == "secondary_observer_not_sandbox",
            "AUDIT_ROLE",
            "audit hook was not explicitly secondary",
        ),
        (
            _nested(report, "controls", "audit_hook", "network_negative_triggered") is True,
            "AUDIT_NETWORK",
            "audit network negative did not trigger",
        ),
        (
            _nested(report, "controls", "audit_hook", "write_negative_triggered") is True,
            "AUDIT_WRITE",
            "audit write negative did not trigger",
        ),
        (
            _nested(report, "observations", "source_direct_sdist_bytes_identical") is True,
            "SURFACE_PARITY",
            "source/direct/sdist bytes diverged",
        ),
        (
            _nested(report, "observations", "sdk_cli_bytes_and_rc_identical") is True,
            "SDK_CLI_PARITY",
            "SDK/CLI bytes or return codes diverged",
        ),
        (
            _nested(report, "observations", "console_cli_bytes_and_rc_identical") is True,
            "CONSOLE_CLI_PARITY",
            "installed console script bytes or return codes diverged",
        ),
        (
            _nested(report, "observations", "installed_console_entrypoint_count") == 4,
            "CONSOLE_COUNT",
            "installed console-script observation roster is incomplete",
        ),
        (
            _nested(report, "observations", "installed_console_commands_per_probe") == 8,
            "CONSOLE_COMMAND_COUNT",
            "installed console-script command roster is incomplete",
        ),
        (
            _nested(report, "observations", "isolated_import_origin_count") == 3,
            "ISOLATED_ORIGIN_COUNT",
            "isolated import-origin roster is incomplete",
        ),
        (_nested(report, "observations", "probe_count") == 6, "PROBE_COUNT", "probe roster is not six"),
        (
            _is_sha256(_nested(report, "observations", "parity_sha256")),
            "PARITY_DIGEST",
            "product parity digest is missing or invalid",
        ),
        (_nested(report, "observations", "surface_count") == 3, "SURFACE_COUNT", "surface roster is not three"),
        (
            type(_nested(report, "observations", "variant_count")) is int
            and _nested(report, "observations", "variant_count") >= 2,
            "VARIANT_COUNT",
            "hostile context matrix is incomplete",
        ),
        (_nested(report, "observations", "schema_count") == 4, "SCHEMA_COUNT", "schema roster is not four"),
        (
            _nested(report, "observations", "reason_code_count") == 36,
            "REASON_CODES",
            "reason-code roster is not the closed public roster",
        ),
        (_nested(report, "observations", "skip_count") == 0, "SKIP_COUNT", "cell contains a skip"),
        (_nested(report, "observations", "xfail_count") == 0, "XFAIL_COUNT", "cell contains an xfail"),
        (
            _nested(report, "source_freeze", "rechecked_after_execution") is True,
            "FREEZE_RECHECK",
            "source freeze was not rechecked after execution",
        ),
        (
            _is_sha256(_nested(report, "source_freeze", "manifest_sha256")),
            "FREEZE_DIGEST",
            "source-freeze digest is invalid",
        ),
        (
            type(_nested(report, "source_freeze", "entry_count")) is int
            and _nested(report, "source_freeze", "entry_count") > 0,
            "FREEZE_COUNT",
            "source-freeze inventory is empty",
        ),
    )
    expected_network = "docker_none" if system == "linux" else "windows_firewall_exact_program"
    if _nested(report, "controls", "network", "mechanism") != expected_network:
        _issue(issues, "NETWORK_MECHANISM", cell, "network mechanism differs from the platform contract")
    expected_filesystem = (
        "docker_read_only_bind_plus_posix_modes" if system == "linux" else "ntfs_acl_readonly_tested_trees"
    )
    if _nested(report, "controls", "filesystem", "mechanism") != expected_filesystem:
        _issue(issues, "FILESYSTEM_MECHANISM", cell, "filesystem mechanism differs from platform contract")
    if system == "linux":
        linux_checks: tuple[tuple[bool, str, str], ...] = (
            (
                _nested(report, "controls", "filesystem", "root_write_blocked") is True,
                "LINUX_ROOT_READONLY",
                "Linux root write negative did not trigger",
            ),
            (
                _nested(report, "controls", "filesystem", "source_write_blocked") is True,
                "LINUX_SOURCE_READONLY",
                "Linux source write negative did not trigger",
            ),
            (
                type(_nested(report, "controls", "network", "nonce")) is str
                and _NONCE.fullmatch(_nested(report, "controls", "network", "nonce")) is not None,
                "LINUX_NONCE",
                "Linux boundary nonce is invalid",
            ),
        )
        for passed, code, message in linux_checks:
            if not passed:
                _issue(issues, code, cell, message)
    if system == "windows":
        windows_checks: tuple[tuple[bool, str, str], ...] = (
            (
                _nested(report, "controls", "network", "cleanup_verified") is True,
                "WINDOWS_FIREWALL_CLEANUP",
                "Windows firewall cleanup was not verified",
            ),
            (
                _nested(report, "controls", "filesystem", "cleanup_verified") is True,
                "WINDOWS_ACL_CLEANUP",
                "Windows ACL cleanup was not verified",
            ),
            (
                _nested(report, "controls", "network", "preexisting_rule_count") == 0,
                "WINDOWS_FIREWALL_SNAPSHOT",
                "Windows firewall pre-state was not an empty exact-name snapshot",
            ),
            (
                _nested(report, "controls", "network", "program_targets_absolute") is True,
                "WINDOWS_FIREWALL_TARGETS",
                "Windows firewall program targets were not absolute",
            ),
            (
                _nested(report, "controls", "network", "program_count") == 5,
                "WINDOWS_FIREWALL_ROSTER",
                "Windows firewall program roster is incomplete",
            ),
            (
                _nested(report, "controls", "filesystem", "target_count") == 4
                and _nested(report, "controls", "filesystem", "prior_sddl_snapshot_count") == 4
                and _nested(report, "controls", "filesystem", "targets_absolute") is True,
                "WINDOWS_ACL_SNAPSHOT",
                "Windows ACL target/snapshot roster is incomplete",
            ),
        )
        for passed, code, message in windows_checks:
            if not passed:
                _issue(issues, code, cell, message)
    contexts = _nested(report, "observations", "contexts")
    context_keys = {
        f"{variant}:{surface}"
        for variant in ("baseline", "hostile")
        for surface in ("source", "direct_wheel", "sdist_wheel")
    }
    if type(contexts) is not dict or set(contexts) != context_keys:
        _issue(issues, "CONTEXT_ROSTER", cell, "runtime-context roster is not exact")
    else:
        baseline = contexts["baseline:source"]
        hostile = contexts["hostile:source"]
        context_checks: tuple[tuple[bool, str, str], ...] = (
            (
                all(contexts[f"baseline:{surface}"] == baseline for surface in ("direct_wheel", "sdist_wheel")),
                "BASELINE_CONTEXT_PARITY",
                "baseline runtime context differs across surfaces",
            ),
            (
                all(contexts[f"hostile:{surface}"] == hostile for surface in ("direct_wheel", "sdist_wheel")),
                "HOSTILE_CONTEXT_PARITY",
                "hostile runtime context differs across surfaces",
            ),
            (
                type(baseline) is dict
                and baseline.get("hash_seed") == "0"
                and baseline.get("decimal_precision") == 28
                and baseline.get("decimal_rounding") == "ROUND_HALF_EVEN"
                and baseline.get("decimal_Emin") == -999999
                and baseline.get("decimal_Emax") == 999999
                and baseline.get("tz") == "UTC0"
                and baseline.get("tz_epoch_local") == [1970, 1, 1, 0, 0, 0],
                "BASELINE_CONTEXT",
                "baseline seed/Decimal/TZ context was not effective",
            ),
            (
                type(hostile) is dict
                and hostile.get("hash_seed") == "4294967295"
                and hostile.get("decimal_precision") == 7
                and hostile.get("decimal_rounding") == "ROUND_FLOOR"
                and hostile.get("decimal_Emin") == -7
                and hostile.get("decimal_Emax") == 7
                and hostile.get("tz") == "GMT+12"
                and hostile.get("tz_epoch_local") == [1969, 12, 31, 12, 0, 0],
                "HOSTILE_CONTEXT",
                "hostile seed/Decimal/TZ context was not effective",
            ),
            (
                type(baseline) is dict
                and type(hostile) is dict
                and type(baseline.get("locale")) is str
                and type(hostile.get("locale")) is str
                and baseline["locale"] != hostile["locale"],
                "LOCALE_VARIATION",
                "locale variation was not effective",
            ),
        )
        for passed, code, message in context_checks:
            if not passed:
                _issue(issues, code, cell, message)
    flags = _nested(report, "installation", "flags")
    if flags != _INSTALL_FLAGS:
        _issue(issues, "INSTALL_FLAGS", cell, "offline install flag roster/order is not exact")
    origins = _nested(report, "observations", "isolated_import_origins")
    if (
        type(origins) is not dict
        or set(origins) != {"source", "direct_wheel", "sdist_wheel"}
        or any(type(value) is not str or not value for value in origins.values())
    ):
        _issue(issues, "ISOLATED_ORIGINS", cell, "isolated import-origin evidence is incomplete")
    toolchain = report.get("toolchain")
    expected_acquisition = (
        "enabled_before_cell_image_build" if system == "linux" else "enabled_before_firewall_boundary"
    )
    if (
        type(toolchain) is not dict
        or set(toolchain)
        != (
            {"acquisition_network", "base_image_ref", "build", "container_image_id", "pip", "setuptools"}
            if system == "linux"
            else {"acquisition_network", "build", "pip", "setuptools"}
        )
        or toolchain.get("build") != "1.4.0"
        or toolchain.get("setuptools") != "84.0.0"
        or type(toolchain.get("pip")) is not str
        or _VERSION.fullmatch(toolchain["pip"]) is None
        or toolchain.get("acquisition_network") != expected_acquisition
    ):
        _issue(issues, "TOOLCHAIN", cell, "toolchain provenance is missing or outside the closed pins")
    elif system == "linux" and (
        type(toolchain.get("container_image_id")) is not str
        or _IMAGE_ID.fullmatch(toolchain["container_image_id"]) is None
        or toolchain.get("base_image_ref") != PYTHON_BASE_IMAGES.get(python_minor)
    ):
        _issue(issues, "LINUX_IMAGE_PIN", cell, "Linux toolchain image ID or immutable base pin is invalid")
    for passed, code, message in checks:
        if not passed:
            _issue(issues, code, cell, message)
    artifacts = report.get("artifacts")
    if type(artifacts) is not dict or set(artifacts) != {"direct_wheel", "sdist", "sdist_wheel"}:
        _issue(issues, "ARTIFACT_ROSTER", cell, "artifact roster is not exact")
    else:
        for label, artifact in artifacts.items():
            expected_suffix = ".tar.gz" if label == "sdist" else ".whl"
            if (
                type(artifact) is not dict
                or set(artifact) != {"name", "sha256"}
                or type(artifact.get("name")) is not str
                or not artifact["name"].endswith(expected_suffix)
                or not _is_sha256(artifact.get("sha256"))
            ):
                _issue(issues, "ARTIFACT_DIGEST", cell, f"{label} digest is invalid")
        direct_digest = _nested(report, "artifacts", "direct_wheel", "sha256")
        rebuilt_digest = _nested(report, "artifacts", "sdist_wheel", "sha256")
        packaging_digest = _nested(report, "packaging", "wheel_archive_sha256")
        if direct_digest != rebuilt_digest or direct_digest != packaging_digest:
            _issue(
                issues,
                "WHEEL_ARCHIVE_DIGEST",
                cell,
                "direct and sdist-built wheel bytes do not bind the canonical packaging digest",
            )
        sdist_digest = _nested(report, "artifacts", "sdist", "sha256")
        packaging_sdist_digest = _nested(report, "packaging", "sdist_archive_sha256")
        if sdist_digest != packaging_sdist_digest:
            _issue(
                issues,
                "SDIST_ARCHIVE_DIGEST",
                cell,
                "sdist artifact bytes do not bind the canonical packaging digest",
            )


def aggregate(evidence_root: Path) -> tuple[dict[str, object], int]:
    root = evidence_root.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("evidence root is not a directory")
    reports: dict[str, dict[str, Any]] = {}
    issues: list[dict[str, str]] = []
    evidence_files = sorted(root.rglob("*.json"), key=lambda path: os.fsencode(path.relative_to(root)))
    for path in evidence_files:
        status = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            _issue(issues, "EVIDENCE_FILE", "matrix", "evidence must be a regular single-link file")
            continue
        try:
            payload = path.read_bytes()
            report = _strict_json(payload)
        except (OSError, UnicodeDecodeError, ValueError):
            _issue(issues, "EVIDENCE_JSON", "matrix", "evidence is not strict readable JSON")
            continue
        if type(report) is not dict or type(report.get("cell")) is not str:
            _issue(issues, "EVIDENCE_SHAPE", "matrix", "evidence lacks a cell coordinate")
            continue
        cell = report["cell"]
        if cell not in EXPECTED_CELLS:
            _issue(issues, "EXTRA_CELL", cell, "evidence coordinate is outside the closed matrix")
            continue
        if cell in reports:
            _issue(issues, "DUPLICATE_CELL", cell, "multiple evidence files claim one coordinate")
            continue
        if report.get("status") == "passed" and payload != _canonical(report) + b"\n":
            _issue(issues, "EVIDENCE_CANONICAL", cell, "passed cell evidence is not canonical JSON")
        reports[cell] = report
    missing = [cell for cell in EXPECTED_CELLS if cell not in reports]
    for cell in missing:
        _issue(issues, "MISSING_CELL", cell, "no executed evidence was supplied")
    for report in reports.values():
        _validate_passed_cell(report, issues)
    freezes = {
        (
            _nested(report, "source_freeze", "manifest_sha256"),
            _nested(report, "source_freeze", "entry_count"),
        )
        for report in reports.values()
        if report.get("status") == "passed"
    }
    all_cells_passed = len(reports) == len(EXPECTED_CELLS) and all(
        report.get("status") == "passed" for report in reports.values()
    )
    if len(freezes) != 1 or not all_cells_passed:
        _issue(issues, "SOURCE_FREEZE_MATRIX", "matrix", "cells do not bind one complete source freeze")
    parity_values = [
        _nested(report, "observations", "parity_sha256")
        for report in reports.values()
        if report.get("status") == "passed"
    ]
    parities = {value for value in parity_values if type(value) is str}
    all_parities_present = len(parity_values) == len(EXPECTED_CELLS) and all(
        _is_sha256(value) for value in parity_values
    )
    if len(parities) != 1 or not all_cells_passed or not all_parities_present:
        _issue(issues, "PRODUCT_PARITY_MATRIX", "matrix", "cells do not bind one product parity digest")
    packaging_values = [
        _packaging_binding(report.get("packaging")) for report in reports.values() if report.get("status") == "passed"
    ]
    packaging_bindings = {value for value in packaging_values if value is not None}
    all_packaging_present = len(packaging_values) == len(EXPECTED_CELLS) and all(
        value is not None for value in packaging_values
    )
    if len(packaging_bindings) != 1 or not all_cells_passed or not all_packaging_present:
        _issue(issues, "PACKAGING_MATRIX", "matrix", "cells do not bind one closed package inventory/content tuple")
    single_packaging = len(packaging_bindings) == 1 and all_cells_passed and all_packaging_present
    packaging_binding = next(iter(packaging_bindings)) if single_packaging else None
    all_cells_consistent = not issues
    _issue(
        issues,
        "EVIDENCE_ORIGIN_UNAUTHENTICATED",
        "matrix",
        "cell JSON is self-issued; no external execution receipt authenticator is implemented",
    )
    issues.sort(key=lambda item: (item["cell"], item["code"], item["message"]))
    status = "failed"
    report: dict[str, object] = {
        "format": FORMAT,
        "status": status,
        "all_cells_consistent": all_cells_consistent,
        "evidence_authentication": "not_implemented",
        "expected_cells": list(EXPECTED_CELLS),
        "observed_cells": sorted(reports),
        "missing_cells": missing,
        "cell_count": len(reports),
        "single_source_freeze": len(freezes) == 1 and all_cells_passed,
        "single_product_parity": len(parities) == 1 and all_cells_passed and all_parities_present,
        "single_packaging_binding": single_packaging,
        "product_parity_sha256": (
            next(iter(parities)) if len(parities) == 1 and all_cells_passed and all_parities_present else None
        ),
        "source_freeze": (
            {"manifest_sha256": next(iter(freezes))[0], "entry_count": next(iter(freezes))[1]}
            if len(freezes) == 1
            else None
        ),
        "packaging_binding": (
            {
                "package_inventory_sha256": packaging_binding[0],
                "wheel_inventory_sha256": packaging_binding[1],
                "sdist_inventory_sha256": packaging_binding[2],
                "package_logical_sha256": packaging_binding[3],
                "wheel_logical_sha256": packaging_binding[4],
                "sdist_logical_sha256": packaging_binding[5],
                "wheel_archive_sha256": packaging_binding[6],
                "sdist_archive_sha256": packaging_binding[7],
            }
            if packaging_binding is not None
            else None
        ),
        "issues": issues,
        "authority": "none",
        "release_authorized": False,
    }
    report["matrix_sha256"] = hashlib.sha256(_canonical(report)).hexdigest()
    return report, 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        report, return_code = aggregate(arguments.evidence_root)
    except Exception as exc:
        report = {
            "format": FORMAT,
            "status": "failed",
            "issues": [{"code": "AGGREGATOR_ERROR", "cell": "matrix", "message": str(exc)}],
            "authority": "none",
            "release_authorized": False,
        }
        return_code = 1
    payload = _canonical(report) + b"\n"
    if arguments.output is not None:
        target = arguments.output.resolve()
        try:
            target.relative_to(REPOSITORY_ROOT.resolve(strict=True))
        except ValueError:
            pass
        else:
            raise RuntimeError("matrix evidence output must remain outside the checkout")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    os.write(1, payload)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
