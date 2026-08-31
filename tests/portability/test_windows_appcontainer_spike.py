from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import types
import unittest
from collections.abc import Callable
from itertools import product
from pathlib import Path
from unittest import mock

from scripts import run_windows_appcontainer_spike as spike
from scripts import windows_appcontainer_profile as profile
from scripts import windows_host_trust as host_trust
from tests.portability import test_windows_appcontainer_boundary_report as boundary_fixture

RUN_REAL_DIAGNOSTIC = os.name == "nt" and os.environ.get("FINPLANBR_RUN_WINDOWS_APPCONTAINER_DIAGNOSTIC") == "1"


def _token() -> dict[str, object]:
    return {
        "appcontainer_sid": "S-1-15-2-101-102-103-104-105-106-107-108-109-110-111",
        "capability_count": 1,
        "capability_entries": "S-1-15-3-101-102-103-104-105-106-107|0x00000004",
        "all_application_packages_membership_api": False,
        "all_application_packages_membership_api_call_succeeded": True,
        "all_application_packages_membership_api_win32_error": None,
        "all_application_packages_restricted_sid_match_attributes": "0x00000007",
        "all_application_packages_restricted_sid_match_count": 1,
        "all_application_packages_token_group_match_attributes": "",
        "all_application_packages_token_group_match_count": 0,
        "integrity_rid": 0x1000,
        "is_appcontainer": True,
        "is_elevated": False,
        "less_privileged_appcontainer_query_result": False,
        "less_privileged_appcontainer_query_supported": True,
        "restricted_sid_count": 4,
        "token_group_count": 9,
    }


def _helper_failure_receipt(
    status: str = "failed",
    *,
    stage: str = "entry",
    substage: str | None = None,
    failure_class: str | None = None,
) -> dict[str, object]:
    return {
        "failure_class": (
            "not_observed"
            if failure_class is None and status == "not_observed"
            else "internal_invariant_failure"
            if failure_class is None
            else failure_class
        ),
        "format": spike.HELPER_FAILURE_RECEIPT_FORMAT,
        "stage": stage,
        "status": status,
        "substage": (
            "profile_binding_entry"
            if substage is None and stage == "profile_binding"
            else "network_differential_entry"
            if substage is None and stage == "network_differential"
            else spike.HELPER_FAILURE_DEFAULT_SUBSTAGE
            if substage is None
            else substage
        ),
    }


def _helper_report(
    status: str = "observations_complete",
    *,
    raw_observations: dict[str, object] | None = None,
) -> dict[str, object]:
    complete = status == "observations_complete"
    return {
        "authority": "none",
        "evidence_authentication": "not_implemented",
        "format": spike.HELPER_FORMAT,
        "helper_failure_receipt": None if complete else _helper_failure_receipt(status),
        "raw_observations": (
            copy.deepcopy(boundary_fixture._raw())
            if complete and raw_observations is None
            else raw_observations
        ),
        "reason": (
            "raw_observations_complete"
            if complete
            else "helper_not_observed"
            if status == "not_observed"
            else "helper_failed"
        ),
        "release_authorized": False,
        "status": status,
    }


def _helper_line(
    status: str = "observations_complete",
    *,
    raw_observations: dict[str, object] | None = None,
) -> bytes:
    return spike._canonical_json(
        _helper_report(status, raw_observations=raw_observations)
    ) + b"\n"


def _expected_network_failure_substage_sequence() -> tuple[str, ...]:
    token_suffixes = (
        "token_launch_policy",
        "token_read_base",
        "token_aap_membership",
        "token_aap_rosters",
        "token_lpac",
        "token_identity",
        "token_aap_effect",
        "token_validate_lpac",
        "token_validate_roster",
        "token_bind",
    )

    def arm(prefix: str) -> tuple[str, ...]:
        return (
            prefix,
            f"{prefix}_launch",
            *(f"{prefix}_{suffix}" for suffix in token_suffixes),
            f"{prefix}_process",
            f"{prefix}_report",
            f"{prefix}_exit",
            f"{prefix}_result",
        )

    return (
        "network_differential_entry",
        "network_endpoint_bind",
        "network_preflight_prepare",
        "network_preflight_profile_before",
        "network_preflight_capability_import",
        "network_preflight_request_setup",
        *arm("network_preflight_zero"),
        "network_preflight_zero_expectation",
        "network_preflight_profile_after",
        "network_control_before",
        "network_full_snapshot",
        "network_full_firewall_snapshot",
        "network_full_listener_snapshot",
        "network_full_prepare",
        "network_full_profile_before",
        "network_full_capability_import",
        "network_full_request_setup",
        *arm("network_arm_zero_1"),
        *arm("network_arm_internet_client_1"),
        *arm("network_arm_internet_client_2"),
        *arm("network_arm_zero_2"),
        "network_full_profile_after",
        "network_control_after",
    )


def _load_spike_mutant(source: str, name: str) -> types.ModuleType:
    module_name = f"scripts._fpbr_{name}"
    module = types.ModuleType(module_name)
    module.__file__ = str(Path(spike.__file__))
    module.__package__ = "scripts"
    sys.modules[module_name] = module
    try:
        exec(compile(source, module.__file__, "exec"), module.__dict__)
    finally:
        del sys.modules[module_name]
    return module


def _current_failure_receipt_contract(candidate: types.ModuleType) -> bool:
    expected_sequence = _expected_network_failure_substage_sequence()
    if (
        candidate.HELPER_FORMAT
        != "finplanbr.windows-appcontainer-boundary-helper.v17"
        or candidate.HELPER_FAILURE_RECEIPT_FORMAT
        != "finplanbr.windows-appcontainer-helper-failure-receipt.v6"
        or candidate.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGE_SEQUENCE
        != expected_sequence
        or candidate.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES
        != expected_sequence
        or type(candidate.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES) is not tuple
        or candidate._HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGE_SET
        != frozenset(expected_sequence)
    ):
        return False
    for substage in expected_sequence:
        report = {
            "authority": "none",
            "evidence_authentication": "not_implemented",
            "format": "finplanbr.windows-appcontainer-boundary-helper.v17",
            "helper_failure_receipt": {
                "failure_class": "not_observed",
                "format": "finplanbr.windows-appcontainer-helper-failure-receipt.v6",
                "stage": "network_differential",
                "status": "not_observed",
                "substage": substage,
            },
            "raw_observations": None,
            "reason": "helper_not_observed",
            "release_authorized": False,
            "status": "not_observed",
        }
        try:
            decoded = candidate._decode_helper_report(
                candidate._canonical_json(report) + b"\n"
            )
        except Exception:
            return False
        if decoded["helper_failure_receipt"] != report["helper_failure_receipt"]:
            return False
    return True


def _observation_mode_report(status: str = "observed_pass") -> dict[str, object]:
    raw = copy.deepcopy(boundary_fixture._raw())
    if status == "not_observed":
        raw["fingerprints"]["runtime_after"][  # type: ignore[index]
            "owner_matches_controller"
        ] = False
    summary = boundary_fixture.boundary.recompute_boundary_summary(
        raw,
        boundary_fixture._expected(),
        boundary_fixture._endpoint_receipt(),
        boundary_fixture._profile_receipt(),
        boundary_fixture._path_context(),
    )
    if summary["status"] != status:
        raise AssertionError("observation-mode fixture status mismatch")
    driver_binding: dict[str, object] = {
        "compiled_assembly_sha256": "a" * 64,
        "compiler_reference_set_sha256": "b" * 64,
        "format": spike.DRIVER_OUTPUT_FORMAT,
        "in_memory_driver_sha256": "e" * 64,
        "observed_bootstrap_input_sha256": "f" * 64,
        "observed_in_memory_input_sha256": "1" * 64,
        "program_cs_sha256": "2" * 64,
        "program_entry_return_code": 0,
    }
    helper_report = _helper_report(raw_observations=raw)
    canonical_helper_line = spike._canonical_json(helper_report) + b"\n"
    driver_output = dict(driver_binding)
    driver_output["helper_stdout_base64"] = base64.b64encode(
        canonical_helper_line
    ).decode("ascii")
    canonical_driver_line = spike._canonical_json(driver_output) + b"\n"
    hashes = spike._empty_hashes()
    hashes.update(
        {
            "bootstrap_input_sha256": "f" * 64,
            "driver_stdout_sha256": hashlib.sha256(canonical_driver_line).hexdigest(),
            "helper_stdout_sha256": hashlib.sha256(canonical_helper_line).hexdigest(),
            "in_memory_assembly_sha256": "a" * 64,
            "in_memory_bootstrap_sha256": "3" * 64,
            "in_memory_compiler_reference_set_sha256": "b" * 64,
            "in_memory_driver_sha256": "e" * 64,
            "in_memory_input_sha256": "1" * 64,
            "invocation_request_sha256": "4" * 64,
            "probe_source_sha256": "5" * 64,
            "program_cs_sha256": "2" * 64,
        }
    )
    return spike._report(
        status=status,
        reason=str(summary["reason"]),
        hashes=hashes,
        boundary_expected=boundary_fixture._expected(),
        boundary_summary=summary,
        driver_binding=driver_binding,
        endpoint_receipt=boundary_fixture._endpoint_receipt(),
        helper_report=helper_report,
        profile_receipt=boundary_fixture._profile_receipt(),
        temporary_directory_cleanup="verified",
        temporary_code_artifacts="absent_at_final_inventory",
        temporary_code_artifact_observation=(
            "final_inventory_only_transient_activity_not_observed"
        ),
    )


def _observation_mode_witness_digests(report: dict[str, object]) -> dict[str, str]:
    return spike._mode_b_witness_digests(
        boundary_expected=report["boundary_expected"],  # type: ignore[arg-type]
        driver_binding=report["driver_binding"],  # type: ignore[arg-type]
        endpoint_receipt=report["endpoint_receipt"],  # type: ignore[arg-type]
        helper_report=report["helper_report"],  # type: ignore[arg-type]
        profile_receipt=report["profile_receipt"],  # type: ignore[arg-type]
    )


def _public_context_witness_digests(report: dict[str, object]) -> dict[str, str]:
    return spike._public_context_witness_digests(
        boundary_expected=report["boundary_expected"],  # type: ignore[arg-type]
        endpoint_receipt=report["endpoint_receipt"],  # type: ignore[arg-type]
        host_trust=report["host_trust"],  # type: ignore[arg-type]
        input_binding=report["input_binding"],  # type: ignore[arg-type]
        moniker=report["moniker"],  # type: ignore[arg-type]
        profile_receipt=report["profile_receipt"],  # type: ignore[arg-type]
    )


def _validate_final_report(report: object, **kwargs: object) -> None:
    if "expected_public_artifacts" not in kwargs:
        artifacts = report.get("artifacts") if type(report) is dict else None
        kwargs["expected_public_artifacts"] = (
            copy.deepcopy(artifacts) if type(artifacts) is dict else None
        )
    spike._validate_final_helper_failure_receipt_relation(  # type: ignore[arg-type]
        report,
        **kwargs,
    )


def _endpoint_frame_fields() -> dict[str, str]:
    endpoint_bytes = spike._canonical_json(boundary_fixture._raw()["network"]["endpoint"])
    return {
        "network_endpoint_base64": base64.b64encode(endpoint_bytes).decode("ascii"),
        "network_endpoint_sha256": hashlib.sha256(endpoint_bytes).hexdigest(),
    }


def _profile_prelaunch(moniker: str) -> dict[str, object]:
    return {
        "appcontainer_sid": boundary_fixture.SID,
        "created_hresult": 0,
        "folder_boundary_component_count": 1,
        "folder_boundary_components_win32_valid": True,
        "folder_boundary_exact": True,
        "folder_boundary_nonempty_descendant": True,
        "folder_boundary_packages_ancestor": True,
        "folder_boundary_reason": "observed",
        "folder_boundary_reconstruction_matches": True,
        "folder_boundary_terminal_ac": False,
        "folder_exists": True,
        "folder_file_id_128_hex": boundary_fixture.PROFILE_FILE_ID_128_HEX,
        "folder_handle_delete_share_denied": True,
        "folder_handle_held": True,
        "folder_identity_format": boundary_fixture.boundary.FILE_IDENTITY_FORMAT,
        "folder_path_utf8_sha256": boundary_fixture.PROFILE_PATH_UTF8_SHA256,
        "folder_reparse_free": True,
        "folder_volume_serial_hex": boundary_fixture.PROFILE_VOLUME_SERIAL_HEX,
        "format": "finplanbr.windows-appcontainer-profile-prelaunch.v4",
        "moniker": moniker,
        "ownership_established": True,
        "sid_reconciled": True,
    }


def _profile_binding(
    moniker: str, *, overrides: dict[str, object] | None = None
) -> profile.OwnedProfileBinding:
    values = _profile_prelaunch(moniker)
    if overrides is not None:
        values.update(overrides)
    return profile.OwnedProfileBinding._issue(
        profile._OWNED_PROFILE_BINDING_ISSUER, **values  # type: ignore[arg-type]
    )


def _profile_frame_fields(moniker: str) -> dict[str, str]:
    profile_bytes = spike._canonical_json(_profile_prelaunch(moniker))
    return {
        "profile_prelaunch_base64": base64.b64encode(profile_bytes).decode("ascii"),
        "profile_prelaunch_sha256": hashlib.sha256(profile_bytes).hexdigest(),
    }


def _raw_for_request(request: dict[str, object]) -> dict[str, object]:
    raw = copy.deepcopy(boundary_fixture._raw())
    endpoint_bytes = base64.b64decode(
        str(request["network_endpoint_base64"]), validate=True
    )
    if hashlib.sha256(endpoint_bytes).hexdigest() != request["network_endpoint_sha256"]:
        raise AssertionError("network endpoint binding mismatch")
    raw["network"]["endpoint"] = json.loads(endpoint_bytes)  # type: ignore[index]
    moniker = str(request["moniker"])
    work_root = base64.b64decode(
        str(request["work_root_utf8_base64"]), validate=True
    ).decode("utf-8", errors="strict")
    runtime_root = os.fspath(Path(work_root) / "runtime")
    source_root = os.fspath(Path(work_root) / "source")
    probe_path = os.fspath(Path(source_root) / "windows_appcontainer_child_probe.py")
    python_path = os.fspath(Path(runtime_root) / "python.exe")
    permitted_canary = hashlib.sha256(
        f"finplanbr-permitted-handle-v1\0{moniker}".encode("ascii")
    ).digest()
    permitted_sha256 = hashlib.sha256(permitted_canary).hexdigest()

    raw["profile"]["moniker"] = moniker  # type: ignore[index]
    profile_bytes = base64.b64decode(
        str(request["profile_prelaunch_base64"]), validate=True
    )
    if hashlib.sha256(profile_bytes).hexdigest() != request["profile_prelaunch_sha256"]:
        raise AssertionError("profile prelaunch binding mismatch")
    profile_prelaunch = json.loads(profile_bytes)
    raw["profile"]["appcontainer_sid_prelaunch_bound"] = profile_prelaunch["appcontainer_sid"]  # type: ignore[index]
    raw["profile"]["folder_file_id_128_hex"] = profile_prelaunch["folder_file_id_128_hex"]  # type: ignore[index]
    raw["profile"]["folder_identity_format"] = profile_prelaunch["folder_identity_format"]  # type: ignore[index]
    raw["profile"]["folder_path_utf8_sha256"] = profile_prelaunch["folder_path_utf8_sha256"]  # type: ignore[index]
    raw["profile"]["folder_volume_serial_hex"] = profile_prelaunch["folder_volume_serial_hex"]  # type: ignore[index]
    raw["profile"]["prelaunch_receipt_sha256"] = request["profile_prelaunch_sha256"]  # type: ignore[index]
    fingerprints = raw["fingerprints"]  # type: ignore[assignment]
    fingerprints["probe_source_sha256"] = request["probe_source_sha256"]  # type: ignore[index]
    raw["filesystem"]["operations"]["read"]["positive"]["observation"] = request[  # type: ignore[index]
        "probe_source_sha256"
    ]
    for key in ("runtime_before", "runtime_after"):
        fingerprints[key]["root_identity"]["path_utf8_sha256"] = (  # type: ignore[index]
            boundary_fixture._path_sha(runtime_root)
        )
    for key in ("source_before", "source_after"):
        fingerprints[key]["root_identity"]["path_utf8_sha256"] = (  # type: ignore[index]
            boundary_fixture._path_sha(source_root)
        )

    for role in ("root", "child", "grandchild"):
        raw["processes"][role]["image"]["path_utf8_sha256"] = (  # type: ignore[index]
            boundary_fixture._path_sha(python_path)
        )
        runtime = raw["runtime"][role]  # type: ignore[index]
        for key in (
            "base_exec_prefix_path_utf8_sha256",
            "base_prefix_path_utf8_sha256",
            "exec_prefix_path_utf8_sha256",
            "expected_runtime_root_path_utf8_sha256",
            "prefix_path_utf8_sha256",
        ):
            runtime[key] = boundary_fixture._path_sha(runtime_root)
        runtime["executable_path_utf8_sha256"] = boundary_fixture._path_sha(python_path)
        runtime["expected_source_root_path_utf8_sha256"] = boundary_fixture._path_sha(
            source_root
        )
        runtime["probe_source_path_utf8_sha256"] = boundary_fixture._path_sha(probe_path)
        runtime["sys_path"] = [
            {
                "path_utf8_sha256": boundary_fixture._path_sha(
                    os.fspath(Path(runtime_root) / "DLLs")
                ),
                "relative_to_runtime": "DLLs",
            },
            {
                "path_utf8_sha256": boundary_fixture._path_sha(
                    os.fspath(Path(runtime_root) / "Lib")
                ),
                "relative_to_runtime": "Lib",
            },
        ]
        runtime["module_origins"] = {
            name: {
                "blob_sha256": boundary_fixture._digest("module-" + name),
                "path_utf8_sha256": boundary_fixture._path_sha(
                    os.fspath(Path(runtime_root) / "Lib" / f"{name}.py")
                ),
                "relative_to_runtime": rf"Lib\{name}.py",
            }
            for name in boundary_fixture.boundary.RUNTIME_MODULES
        }
    network_arms = [
        raw["network"]["preflight_zero_capability"],  # type: ignore[index]
        *raw["network"]["lan_appcontainer_arms"],  # type: ignore[index]
    ]
    for arm in network_arms:
        arm["image"]["path_utf8_sha256"] = boundary_fixture._path_sha(python_path)
    raw["handles"]["permitted"]["canary_sha256"] = permitted_sha256  # type: ignore[index]
    return raw


def _driver_line(
    helper_stdout: bytes,
    stdin_bytes: bytes,
    program_sha256: str,
    *,
    bootstrap_input: bytes = b'{"outer":"closed"}\n',
    assembly_sha256: str = "c" * 64,
    reference_set_sha256: str = "d" * 64,
    driver_sha256: str = "e" * 64,
    entry_return_code: int = 0,
) -> bytes:
    return spike._canonical_json(
        {
            "compiled_assembly_sha256": assembly_sha256,
            "compiler_reference_set_sha256": reference_set_sha256,
            "format": spike.DRIVER_OUTPUT_FORMAT,
            "helper_stdout_base64": base64.b64encode(helper_stdout).decode("ascii"),
            "in_memory_driver_sha256": driver_sha256,
            "observed_bootstrap_input_sha256": hashlib.sha256(bootstrap_input).hexdigest(),
            "observed_in_memory_input_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
            "program_cs_sha256": program_sha256,
            "program_entry_return_code": entry_return_code,
        }
    ) + b"\n"


def _host_identity(role: str, path: Path, *, digest_byte: str) -> host_trust.HostIdentity:
    is_pwsh = role == host_trust.POWERSHELL_7_ROLE
    return host_trust.HostIdentity(
        role=role,
        path=os.fspath(path),
        sha256=digest_byte * 64,
        file_version="7.6.4.0" if is_pwsh else "10.0.26100.1",
        file_id=("0000000000000001:" + digest_byte * 32),
        publisher="Microsoft Corporation",
        signer_common_name="Microsoft Corporation" if is_pwsh else "Microsoft Windows",
        ancestor_count=4,
        installation_profile="powershell_7_msi" if is_pwsh else "windows_inbox",
        package_full_name=None,
        package_publisher=None,
        package_version=None,
    )


class FakeHostLease:
    def __init__(
        self,
        pwsh: Path,
        windows_powershell: Path,
        *,
        fail_revalidation_number: int | None = None,
        fail_reason: str = "host_hash_changed",
        pwsh_digest_byte: str = "a",
    ) -> None:
        self.powershell_7 = _host_identity(
            host_trust.POWERSHELL_7_ROLE,
            pwsh,
            digest_byte=pwsh_digest_byte,
        )
        self.windows_powershell_5_1 = _host_identity(
            host_trust.WINDOWS_POWERSHELL_ROLE,
            windows_powershell,
            digest_byte="b",
        )
        self.fail_revalidation_number = fail_revalidation_number
        self.fail_reason = fail_reason
        self.revalidation_count = 0
        self.active = False

    def __enter__(self) -> FakeHostLease:
        self.active = True
        return self

    def __exit__(self, *_args: object) -> None:
        self.active = False

    def revalidate(self) -> None:
        if not self.active:
            raise AssertionError("host lease must be active")
        self.revalidation_count += 1
        if self.revalidation_count == self.fail_revalidation_number:
            raise host_trust.HostTrustFailure("failed", self.fail_reason)

    def to_wire(self) -> dict[str, object]:
        return {
            "format": host_trust.HOST_TRUST_FORMAT,
            "policy": host_trust.HOST_TRUST_POLICY,
            host_trust.POWERSHELL_7_ROLE: self.powershell_7.to_wire(),
            host_trust.WINDOWS_POWERSHELL_ROLE: self.windows_powershell_5_1.to_wire(),
        }


class FakeEndpointLease:
    def __init__(self) -> None:
        self.active = False
        self.closed = False
        self.start_count = 0
        self.close_count = 0

    def start(self) -> FakeEndpointLease:
        if self.active or self.closed:
            raise AssertionError("endpoint lease state invalid")
        self.active = True
        self.start_count += 1
        return self

    @property
    def prelaunch_observation(self) -> dict[str, object]:
        if not self.active:
            raise AssertionError("endpoint lease must be active")
        return copy.deepcopy(boundary_fixture._raw()["network"]["endpoint"])

    def close(self) -> None:
        if self.closed:
            return
        self.active = False
        self.closed = True
        self.close_count += 1

    @property
    def receipt(self) -> dict[str, object]:
        if not self.closed:
            raise AssertionError("endpoint receipt requires cleanup")
        return copy.deepcopy(boundary_fixture._endpoint_receipt())


class FakeProfileLease:
    def __init__(self) -> None:
        self.active = False
        self.closed = False
        self.close_count = 0
        self.moniker: str | None = None

    def acquire(self, moniker: str) -> FakeProfileLease:
        if self.active or self.closed or self.moniker is not None:
            raise AssertionError("profile lease state invalid")
        self.moniker = moniker
        self.active = True
        return self

    def child_path_utf8_sha256(self, leaf: str) -> str:
        if not self.active or self.moniker is None or leaf != "network-arm-request.json":
            raise AssertionError("profile child-path hash requires active exact lease")
        return boundary_fixture.PROFILE_NETWORK_REQUEST_PATH_UTF8_SHA256

    @property
    def owned_profile_binding(self) -> profile.OwnedProfileBinding:
        if not self.active or self.moniker is None:
            raise AssertionError("profile lease must be active")
        return _profile_binding(self.moniker)

    def close(self) -> None:
        if self.closed:
            return
        self.active = False
        self.closed = True
        self.close_count += 1

    @property
    def receipt(self) -> dict[str, object]:
        if not self.closed or self.moniker is None:
            raise AssertionError("profile receipt requires cleanup")
        receipt = copy.deepcopy(boundary_fixture._profile_receipt())
        receipt["moniker"] = self.moniker
        return receipt


class FakeProfileCleanupFailureLease(FakeProfileLease):
    @property
    def receipt(self) -> dict[str, object]:
        receipt = super().receipt
        receipt["cleanup_complete"] = False
        receipt["final_folder_absent"] = False
        return receipt


class FakeProfilePrelaunchMutationLease(FakeProfileLease):
    def __init__(self, key: str, value: object) -> None:
        super().__init__()
        self._key = key
        self._value = value

    @property
    def owned_profile_binding(self) -> profile.OwnedProfileBinding:
        if not self.active or self.moniker is None:
            raise AssertionError("profile lease must be active")
        return _profile_binding(self.moniker, overrides={self._key: self._value})


class FakeNonExactProfileBindingLease(FakeProfileLease):
    @property
    def owned_profile_binding(self) -> profile.OwnedProfileBinding:
        if not self.active or self.moniker is None:
            raise AssertionError("profile lease must be active")
        return _profile_prelaunch(self.moniker)  # type: ignore[return-value]


class FakeProfileDiagnosticLease(FakeProfileLease):
    def __init__(self, component_count: int, terminal_ac: bool) -> None:
        super().__init__()
        self._component_count = component_count
        self._terminal_ac = terminal_ac

    @property
    def owned_profile_binding(self) -> profile.OwnedProfileBinding:
        if not self.active or self.moniker is None:
            raise AssertionError("profile lease must be active")
        return _profile_binding(
            self.moniker,
            overrides={
                "folder_boundary_component_count": self._component_count,
                "folder_boundary_terminal_ac": self._terminal_ac,
            },
        )

    @property
    def receipt(self) -> dict[str, object]:
        receipt = super().receipt
        receipt["folder_boundary_component_count"] = self._component_count
        receipt["folder_boundary_terminal_ac"] = self._terminal_ac
        receipt["recreate_folder_boundary_component_count"] = self._component_count
        receipt["recreate_folder_boundary_terminal_ac"] = self._terminal_ac
        return receipt


class FakePowerShellRunner:
    def __init__(
        self,
        *,
        helper_stdout: bytes | None = None,
        helper_stderr: bytes = b"",
        helper_returncode: int = 0,
        driver_stdout: bytes | None = None,
        driver_entry_return_code: int | None = None,
        launch_error: OSError | subprocess.TimeoutExpired | None = None,
        required_lease: FakeHostLease | None = None,
        required_endpoint_lease: FakeEndpointLease | None = None,
        required_profile_lease: FakeProfileLease | None = None,
        on_invoke: Callable[[Path], None] | None = None,
    ) -> None:
        self.helper_stdout = helper_stdout
        self.helper_stderr = helper_stderr
        self.helper_returncode = helper_returncode
        self.driver_stdout = driver_stdout
        self.driver_entry_return_code = driver_entry_return_code
        self.launch_error = launch_error
        self.required_lease = required_lease
        self.required_endpoint_lease = required_endpoint_lease
        self.required_profile_lease = required_profile_lease
        self.on_invoke = on_invoke
        self.calls: list[list[str]] = []
        self.call_kwargs: list[dict[str, object]] = []
        self.temporary_directories: list[Path] = []
        self.stdin_requests: list[dict[str, object]] = []
        self.stdin_bytes: list[bytes] = []
        self.bootstrap_inputs: list[dict[str, object]] = []
        self.observed_helper_stdout: list[bytes] = []
        self.observed_driver_stdout: list[bytes] = []

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if self.required_lease is not None and not self.required_lease.active:
            raise AssertionError("host handles were released before process invocation")
        if self.required_endpoint_lease is not None and not self.required_endpoint_lease.active:
            raise AssertionError("endpoint lease was closed before process invocation")
        if self.required_profile_lease is not None and not self.required_profile_lease.active:
            raise AssertionError("profile lease was closed before process invocation")
        self.calls.append(command)
        self.call_kwargs.append(kwargs)
        temporary = Path(str(kwargs["cwd"]))
        self.temporary_directories.append(temporary)
        if self.launch_error is not None:
            raise self.launch_error
        self.assert_in_memory_request(command, kwargs)
        if self.on_invoke is not None:
            self.on_invoke(temporary)
        request_bytes = self.stdin_bytes[-1]
        parsed = self.stdin_requests[-1]
        helper_stdout = self.helper_stdout
        if helper_stdout is None:
            helper_stdout = _helper_line(raw_observations=_raw_for_request(parsed))
        self.observed_helper_stdout.append(helper_stdout)
        stdout = self.driver_stdout
        if stdout is None:
            raw_bootstrap_input = kwargs["input"]
            if not isinstance(raw_bootstrap_input, bytes):
                raise AssertionError("bootstrap input bytes required")
            stdout = _driver_line(
                helper_stdout,
                request_bytes,
                str(parsed["program_cs_sha256"]),
                bootstrap_input=raw_bootstrap_input,
                driver_sha256=hashlib.sha256(spike.IN_MEMORY_PWSH_DRIVER.encode()).hexdigest(),
                entry_return_code=(
                    self.helper_returncode
                    if self.driver_entry_return_code is None
                    else self.driver_entry_return_code
                ),
            )
        self.observed_driver_stdout.append(stdout)
        return subprocess.CompletedProcess(
            command,
            self.helper_returncode,
            stdout=stdout,
            stderr=self.helper_stderr,
        )

    def assert_in_memory_request(self, command: list[str], kwargs: dict[str, object]) -> None:
        if "-EncodedCommand" not in command:
            raise AssertionError("in-memory bootstrap must be passed by encoded command")
        encoded_bootstrap = command[command.index("-EncodedCommand") + 1]
        consumed_bootstrap = base64.b64decode(encoded_bootstrap, validate=True)
        driver_bytes = spike.IN_MEMORY_PWSH_DRIVER.encode()
        raw_input = kwargs.get("input")
        if not isinstance(raw_input, bytes) or not raw_input.endswith(b"\n"):
            raise AssertionError("canonical bootstrap input required")
        bootstrap_input = json.loads(raw_input)
        if bootstrap_input["format"] != spike.BOOTSTRAP_INPUT_FORMAT:
            raise AssertionError("unexpected bootstrap input format")
        if base64.b64decode(bootstrap_input["driver_base64"], validate=True) != driver_bytes:
            raise AssertionError("bootstrap driver bytes mismatch")
        if hashlib.sha256(driver_bytes).hexdigest() != bootstrap_input["driver_sha256"]:
            raise AssertionError("bootstrap driver hash mismatch")
        request_bytes = base64.b64decode(bootstrap_input["request_base64"], validate=True)
        if hashlib.sha256(request_bytes).hexdigest() != bootstrap_input["request_sha256"]:
            raise AssertionError("bootstrap request hash mismatch")
        if consumed_bootstrap != spike._bootstrap_bytes(driver_bytes, request_bytes):
            raise AssertionError("unexpected in-memory bootstrap")
        if raw_input != spike._bootstrap_input(driver_bytes, request_bytes):
            raise AssertionError("bootstrap input bytes are not canonical")
        parsed = json.loads(request_bytes)
        if parsed["format"] != spike.IN_MEMORY_INPUT_FORMAT:
            raise AssertionError("unexpected stdin request format")
        if request_bytes != spike._canonical_json(parsed) + b"\n":
            raise AssertionError("stdin request bytes are not canonical")
        program_bytes = base64.b64decode(parsed["program_cs_base64"], validate=True)
        if hashlib.sha256(program_bytes).hexdigest() != parsed["program_cs_sha256"]:
            raise AssertionError("program snapshot hash mismatch")
        probe_bytes = base64.b64decode(parsed["probe_source_base64"], validate=True)
        if hashlib.sha256(probe_bytes).hexdigest() != parsed["probe_source_sha256"]:
            raise AssertionError("probe source snapshot hash mismatch")
        endpoint_bytes = base64.b64decode(parsed["network_endpoint_base64"], validate=True)
        if hashlib.sha256(endpoint_bytes).hexdigest() != parsed["network_endpoint_sha256"]:
            raise AssertionError("network endpoint snapshot hash mismatch")
        if json.loads(endpoint_bytes) != boundary_fixture._raw()["network"]["endpoint"]:
            raise AssertionError("network endpoint snapshot mismatch")
        profile_bytes = base64.b64decode(parsed["profile_prelaunch_base64"], validate=True)
        if hashlib.sha256(profile_bytes).hexdigest() != parsed["profile_prelaunch_sha256"]:
            raise AssertionError("profile prelaunch snapshot hash mismatch")
        observed_profile = json.loads(profile_bytes)
        expected_profile = _profile_prelaunch(str(parsed["moniker"]))
        for diagnostic in (
            "folder_boundary_component_count",
            "folder_boundary_terminal_ac",
        ):
            observed_value = observed_profile.pop(diagnostic)
            expected_profile.pop(diagnostic)
            if diagnostic == "folder_boundary_component_count":
                if (
                    type(observed_value) is not int
                    or not 1 <= observed_value <= 0xFFFFFFFF
                ):
                    raise AssertionError("profile component count invalid")
            elif type(observed_value) is not bool:
                raise AssertionError("profile terminal diagnostic invalid")
        if observed_profile != expected_profile:
            raise AssertionError("profile prelaunch snapshot mismatch")
        for path_key in ("python_runtime_root_utf8_base64", "work_root_utf8_base64"):
            base64.b64decode(parsed[path_key], validate=True).decode("utf-8", errors="strict")
        self.bootstrap_inputs.append(bootstrap_input)
        self.stdin_bytes.append(request_bytes)
        self.stdin_requests.append(parsed)


class WindowsAppContainerSpikeProtocolTests(unittest.TestCase):
    def test_driver_protocol_binds_input_source_assembly_return_and_helper(self) -> None:
        bootstrap_input = b'{"outer":"closed"}\n'
        stdin_bytes = b'{"request":"closed"}\n'
        program_sha256 = "a" * 64
        helper_stdout = _helper_line()
        payload = _driver_line(helper_stdout, stdin_bytes, program_sha256)

        binding, observed_helper = spike._decode_driver_output(
            payload,
            expected_bootstrap_input_sha256=hashlib.sha256(bootstrap_input).hexdigest(),
            expected_driver_sha256="e" * 64,
            expected_input_sha256=hashlib.sha256(stdin_bytes).hexdigest(),
            expected_program_sha256=program_sha256,
        )

        self.assertEqual(observed_helper, helper_stdout)
        self.assertEqual(binding["compiled_assembly_sha256"], "c" * 64)
        self.assertEqual(binding["compiler_reference_set_sha256"], "d" * 64)
        self.assertEqual(
            binding["observed_bootstrap_input_sha256"],
            hashlib.sha256(bootstrap_input).hexdigest(),
        )
        self.assertEqual(
            binding["observed_in_memory_input_sha256"],
            hashlib.sha256(stdin_bytes).hexdigest(),
        )
        self.assertEqual(binding["program_cs_sha256"], program_sha256)
        self.assertEqual(binding["program_entry_return_code"], 0)

    def test_driver_protocol_rejects_raw_forged_helper_and_binding_mutations(self) -> None:
        bootstrap_input = b'{"outer":"closed"}\n'
        stdin_bytes = b'{"request":"closed"}\n'
        program_sha256 = "a" * 64
        valid = _driver_line(_helper_line(), stdin_bytes, program_sha256)
        with self.assertRaises(spike.DriverProtocolFailure):
            spike._decode_driver_output(
                _helper_line(),
                expected_bootstrap_input_sha256=hashlib.sha256(bootstrap_input).hexdigest(),
                expected_driver_sha256="e" * 64,
                expected_input_sha256=hashlib.sha256(stdin_bytes).hexdigest(),
                expected_program_sha256=program_sha256,
            )

        parsed = json.loads(valid)
        mutations = (
            ("observed_bootstrap_input_sha256", "b" * 64),
            ("observed_in_memory_input_sha256", "b" * 64),
            ("program_cs_sha256", "b" * 64),
            ("compiled_assembly_sha256", "invalid"),
            ("compiler_reference_set_sha256", "invalid"),
            ("in_memory_driver_sha256", "b" * 64),
            ("program_entry_return_code", True),
            ("helper_stdout_base64", "***"),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                mutated = dict(parsed)
                mutated[key] = value
                with self.assertRaises(spike.DriverProtocolFailure):
                    spike._decode_driver_output(
                        spike._canonical_json(mutated) + b"\n",
                        expected_bootstrap_input_sha256=hashlib.sha256(
                            bootstrap_input
                        ).hexdigest(),
                        expected_driver_sha256="e" * 64,
                        expected_input_sha256=hashlib.sha256(stdin_bytes).hexdigest(),
                        expected_program_sha256=program_sha256,
                    )

        duplicate = valid.replace(b'"format":', b'"format":"duplicate","format":', 1)
        with self.assertRaises(spike.DriverProtocolFailure):
            spike._decode_driver_output(
                duplicate,
                expected_bootstrap_input_sha256=hashlib.sha256(bootstrap_input).hexdigest(),
                expected_driver_sha256="e" * 64,
                expected_input_sha256=hashlib.sha256(stdin_bytes).hexdigest(),
                expected_program_sha256=program_sha256,
            )

    def test_helper_protocol_accepts_one_canonical_utf8_line(self) -> None:
        report = spike._decode_helper_report(_helper_line())
        self.assertEqual(report["status"], "observations_complete")
        self.assertEqual(report["authority"], "none")
        self.assertEqual(report["evidence_authentication"], "not_implemented")
        self.assertIs(report["release_authorized"], False)
        self.assertIsNone(report["helper_failure_receipt"])
        self.assertEqual(spike._decode_helper_report(_helper_line()[:-1] + b"\r\n"), report)

    def test_helper_failure_receipt_accepts_only_closed_stage_and_class_rosters(self) -> None:
        self.assertEqual(
            spike.HELPER_FORMAT,
            "finplanbr.windows-appcontainer-boundary-helper.v17",
        )
        self.assertEqual(
            spike.HELPER_FAILURE_RECEIPT_FORMAT,
            "finplanbr.windows-appcontainer-helper-failure-receipt.v6",
        )
        expected_network_sequence = _expected_network_failure_substage_sequence()
        self.assertEqual(len(expected_network_sequence), 98)
        self.assertEqual(len(set(expected_network_sequence)), 98)
        self.assertEqual(
            spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGE_SEQUENCE,
            expected_network_sequence,
        )
        self.assertEqual(
            spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES,
            expected_network_sequence,
        )
        self.assertIs(
            spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGE_SEQUENCE,
            spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES,
        )
        self.assertIs(
            type(spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES),
            tuple,
        )
        self.assertEqual(
            spike._HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGE_SET,
            frozenset(expected_network_sequence),
        )

        for stage in sorted(spike.HELPER_FAILURE_STAGES):
            with self.subTest(stage=stage):
                report = _helper_report("failed")
                report["helper_failure_receipt"] = _helper_failure_receipt(
                    stage=stage
                )
                decoded = spike._decode_helper_report(
                    spike._canonical_json(report) + b"\n"
                )
                self.assertEqual(
                    decoded["helper_failure_receipt"],
                    report["helper_failure_receipt"],
                )

        for substage in sorted(spike.HELPER_FAILURE_PROFILE_BINDING_SUBSTAGES):
            with self.subTest(profile_binding_substage=substage):
                report = _helper_report("failed")
                report["helper_failure_receipt"] = _helper_failure_receipt(
                    stage="profile_binding",
                    substage=substage,
                )
                decoded = spike._decode_helper_report(
                    spike._canonical_json(report) + b"\n"
                )
                self.assertEqual(
                    decoded["helper_failure_receipt"],
                    report["helper_failure_receipt"],
                )

        for substage in expected_network_sequence:
            with self.subTest(network_differential_substage=substage):
                report = _helper_report("failed")
                report["helper_failure_receipt"] = _helper_failure_receipt(
                    stage="network_differential",
                    substage=substage,
                )
                decoded = spike._decode_helper_report(
                    spike._canonical_json(report) + b"\n"
                )
                self.assertEqual(
                    decoded["helper_failure_receipt"],
                    report["helper_failure_receipt"],
                )

                not_observed_report = _helper_report("not_observed")
                not_observed_report["helper_failure_receipt"] = (
                    _helper_failure_receipt(
                        "not_observed",
                        stage="network_differential",
                        substage=substage,
                    )
                )
                decoded_not_observed_report = spike._decode_helper_report(
                    spike._canonical_json(not_observed_report) + b"\n"
                )
                self.assertEqual(
                    decoded_not_observed_report["helper_failure_receipt"],
                    not_observed_report["helper_failure_receipt"],
                )

        for failure_class in sorted(
            spike.HELPER_FAILURE_CLASSES - {"not_observed"}
        ):
            with self.subTest(failure_class=failure_class):
                report = _helper_report("failed")
                report["helper_failure_receipt"] = _helper_failure_receipt(
                    failure_class=failure_class
                )
                spike._decode_helper_report(spike._canonical_json(report) + b"\n")

        not_observed = _helper_report("not_observed")
        decoded_not_observed = spike._decode_helper_report(
            spike._canonical_json(not_observed) + b"\n"
        )
        self.assertEqual(
            decoded_not_observed["helper_failure_receipt"],
            _helper_failure_receipt("not_observed"),
        )

    def test_historical_v3_v4_and_v5_network_receipts_cannot_be_retroactively_refined(
        self,
    ) -> None:
        historical_receipt: dict[str, object] = {
            "failure_class": "not_observed",
            "format": "finplanbr.windows-appcontainer-helper-failure-receipt.v3",
            "stage": "network_differential",
            "status": "not_observed",
            "substage": "stage_entry",
        }
        self.assertEqual(set(historical_receipt), spike.HELPER_FAILURE_RECEIPT_KEYS)
        self.assertEqual(len(spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES), 98)
        self.assertNotIn(
            "stage_entry",
            spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES,
        )
        current_candidates = {
            tuple(
                (
                    _helper_failure_receipt(
                        "not_observed",
                        stage="network_differential",
                        substage=substage,
                    )[key]
                    if key != "substage"
                    else historical_receipt["substage"]
                )
                for key in ("status", "stage", "substage", "failure_class")
            )
            for substage in spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES
        }
        self.assertEqual(
            current_candidates,
            {
                (
                    "not_observed",
                    "network_differential",
                    "stage_entry",
                    "not_observed",
                )
            },
        )

        historical = _helper_report("not_observed")
        historical["helper_failure_receipt"] = historical_receipt
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(spike._canonical_json(historical) + b"\n")

        seventh_live_receipt: dict[str, object] = {
            "failure_class": "not_observed",
            "format": "finplanbr.windows-appcontainer-helper-failure-receipt.v4",
            "stage": "network_differential",
            "status": "not_observed",
            "substage": "network_preflight_zero_token",
        }
        self.assertNotIn(
            seventh_live_receipt["substage"],
            spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES,
        )
        historical_v4 = _helper_report("not_observed")
        historical_v4["helper_failure_receipt"] = seventh_live_receipt
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(spike._canonical_json(historical_v4) + b"\n")

        eighth_live_receipt: dict[str, object] = {
            "failure_class": "not_observed",
            "format": "finplanbr.windows-appcontainer-helper-failure-receipt.v5",
            "stage": "network_differential",
            "status": "not_observed",
            "substage": "network_preflight_zero_token_validate_lpac",
        }
        self.assertIn(
            eighth_live_receipt["substage"],
            spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES,
        )
        historical_v5 = _helper_report("not_observed")
        historical_v5["helper_failure_receipt"] = eighth_live_receipt
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(spike._canonical_json(historical_v5) + b"\n")

    def test_failure_receipt_v6_behavioral_mutants_are_killed(self) -> None:
        source = Path(spike.__file__).read_text(encoding="utf-8")
        self.assertTrue(_current_failure_receipt_contract(spike))

        adjacent = (
            '    "network_preflight_zero_token_aap_membership",\n'
            '    "network_preflight_zero_token_aap_rosters",\n'
        )
        swapped_adjacent = (
            '    "network_preflight_zero_token_aap_rosters",\n'
            '    "network_preflight_zero_token_aap_membership",\n'
        )
        validator_signature = (
            "def _validate_helper_failure_receipt(\n"
            "    value: object,\n"
            "    *,\n"
            "    expected_status: object,\n"
            ") -> dict[str, object]:\n"
        )
        blanket_rejection = validator_signature + (
            "    if (\n"
            "        isinstance(value, dict)\n"
            '        and value.get("stage") == "network_differential"\n'
            '        and value.get("status") == "not_observed"\n'
            "    ):\n"
            '        raise HelperProtocolFailure("network_not_observed_rejected")\n'
        )
        mutants = {
            "receipt_version_downgrade": source.replace(
                "finplanbr.windows-appcontainer-helper-failure-receipt.v6",
                "finplanbr.windows-appcontainer-helper-failure-receipt.v4",
                1,
            ),
            "ordered_roster_adjacent_swap": source.replace(
                adjacent,
                swapped_adjacent,
                1,
            ),
            "ordered_roster_typo": source.replace(
                '    "network_preflight_zero_token_validate_roster",',
                '    "network_preflight_zero_token_validate_rosters",',
                1,
            ),
            "blanket_network_not_observed_rejection": source.replace(
                validator_signature,
                blanket_rejection,
                1,
            ),
        }
        for name, mutant_source in mutants.items():
            with self.subTest(failure_receipt_mutant=name):
                self.assertNotEqual(mutant_source, source)
                candidate = _load_spike_mutant(mutant_source, name)
                self.assertFalse(_current_failure_receipt_contract(candidate))

        class TupleSubclass(tuple):
            pass

        expected = _expected_network_failure_substage_sequence()
        for invalid_roster in (list(expected), TupleSubclass(expected)):
            with self.subTest(roster_type=type(invalid_roster).__name__):
                with mock.patch.object(
                    spike,
                    "HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES",
                    invalid_roster,
                ):
                    self.assertFalse(_current_failure_receipt_contract(spike))

    def test_helper_failure_receipt_rejects_shape_type_private_and_forged_values(self) -> None:
        mutations: list[tuple[str, dict[str, object]]] = []

        for missing_key in ("stage", "substage"):
            missing = _helper_report("failed")
            missing_receipt = dict(missing["helper_failure_receipt"])  # type: ignore[arg-type]
            missing_receipt.pop(missing_key)
            missing["helper_failure_receipt"] = missing_receipt
            mutations.append((f"missing_{missing_key}", missing))

        extra = _helper_report("failed")
        extra_receipt = dict(extra["helper_failure_receipt"])  # type: ignore[arg-type]
        extra_receipt["detail"] = "synthetic"
        extra["helper_failure_receipt"] = extra_receipt
        mutations.append(("extra", extra))

        for key, value in (
            ("format", "unmodeled.v1"),
            (
                "format",
                "finplanbr.windows-appcontainer-helper-failure-receipt.v2",
            ),
            ("status", "observations_complete"),
            ("status", True),
            ("status", []),
            ("status", {}),
            ("stage", "unknown_stage"),
            ("stage", True),
            ("stage", r"C:\private\stage"),
            ("substage", "unknown_substage"),
            ("substage", "Profile_Prelaunch_Parse"),
            ("substage", True),
            ("substage", []),
            ("substage", {}),
            ("substage", r"C:\private\substage"),
            ("failure_class", "unknown_class"),
            ("failure_class", False),
            ("failure_class", "s-1-5-21-111111111-222222222-333333333-1001"),
        ):
            report = _helper_report("failed")
            receipt = dict(report["helper_failure_receipt"])  # type: ignore[arg-type]
            receipt[key] = value
            report["helper_failure_receipt"] = receipt
            mutations.append((f"{key}_{value!r}", report))

        for name, stage, substage in (
            ("profile_substage_on_entry", "entry", "profile_prelaunch_parse"),
            ("default_substage_on_profile", "profile_binding", "stage_entry"),
            (
                "network_substage_on_entry",
                "entry",
                "network_preflight_zero",
            ),
            (
                "default_substage_on_network",
                "network_differential",
                "stage_entry",
            ),
            (
                "profile_substage_on_network",
                "network_differential",
                "profile_prelaunch_parse",
            ),
        ):
            report = _helper_report("failed")
            report["helper_failure_receipt"] = _helper_failure_receipt(
                stage=stage,
                substage=substage,
            )
            mutations.append((name, report))

        no_receipt = _helper_report("failed")
        no_receipt["helper_failure_receipt"] = None
        mutations.append(("missing_receipt", no_receipt))

        receipt_on_success = _helper_report()
        receipt_on_success["helper_failure_receipt"] = _helper_failure_receipt()
        mutations.append(("receipt_on_success", receipt_on_success))

        failed_as_not_observed = _helper_report("failed")
        failed_as_not_observed["helper_failure_receipt"] = _helper_failure_receipt(
            failure_class="not_observed"
        )
        mutations.append(("failed_as_not_observed", failed_as_not_observed))

        not_observed_as_internal = _helper_report("not_observed")
        not_observed_as_internal["helper_failure_receipt"] = _helper_failure_receipt(
            "not_observed",
            failure_class="internal_invariant_failure",
        )
        mutations.append(("not_observed_as_internal", not_observed_as_internal))

        for name, report in mutations:
            with self.subTest(name=name):
                with self.assertRaises(spike.HelperProtocolFailure):
                    spike._decode_helper_report(
                        spike._canonical_json(report) + b"\n"
                    )

    def test_wrapper_constructor_rejects_nontransactional_failure_receipt(self) -> None:
        receipt = _helper_failure_receipt()
        invalid_calls = (
            {"reason": "helper_failed"},
            {"reason": "candidate_failure", "primary_reason": "helper_failed"},
            {"reason": "candidate_failure", "helper_failure_receipt": receipt},
            {
                "reason": "helper_not_observed",
                "helper_failure_receipt": receipt,
            },
            {
                "reason": "helper_failed",
                "helper_failure_receipt": receipt,
                "driver_binding": {"forged": True},
            },
            {
                "reason": "helper_failed",
                "helper_failure_receipt": receipt,
                "helper_report": _helper_report("failed"),
            },
            {
                "reason": "helper_failed",
                "helper_failure_receipt": receipt,
                "hashes": {
                    **spike._empty_hashes(),
                    "helper_stdout_sha256": "a" * 64,
                },
            },
            {
                "reason": "helper_failed",
                "helper_failure_receipt": _helper_failure_receipt("not_observed"),
            },
        )
        for kwargs in invalid_calls:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    spike._report(status="failed", **kwargs)  # type: ignore[arg-type]

        original = _helper_failure_receipt()
        admitted = spike._report(
            status="failed",
            reason="helper_failed",
            helper_failure_receipt=original,
            temporary_directory_cleanup="verified",
            temporary_code_artifacts="absent_at_final_inventory",
            temporary_code_artifact_observation=(
                "final_inventory_only_transient_activity_not_observed"
            ),
        )
        original["stage"] = "unknown_stage"
        original["substage"] = "unknown_substage"
        original["extra"] = "forged"
        self.assertEqual(
            admitted["helper_failure_receipt"],
            _helper_failure_receipt(),
        )
        _validate_final_report(admitted)
        for field in ("reason", "primary_reason"):
            for helper_reason in ("helper_failed", "helper_not_observed"):
                with self.subTest(field=field, helper_reason=helper_reason):
                    missing = spike._report(
                        status="failed",
                        reason="candidate_failure",
                    )
                    missing[field] = helper_reason
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(missing)

        for primary in ("candidate_failure", "helper_not_observed"):
            with self.subTest(receipt_with_primary=primary):
                mismatched = spike._report(
                    status="failed",
                    reason="helper_failed",
                    helper_failure_receipt=_helper_failure_receipt(),
                )
                mismatched["primary_reason"] = primary
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(mismatched)

    def test_final_failure_receipt_requires_closed_rosters_and_explicit_nulls(self) -> None:
        failure = spike._report(
            status="failed",
            reason="helper_failed",
            helper_failure_receipt=_helper_failure_receipt(),
            temporary_directory_cleanup="verified",
            temporary_code_artifacts="absent_at_final_inventory",
            temporary_code_artifact_observation=(
                "final_inventory_only_transient_activity_not_observed"
            ),
        )
        _validate_final_report(failure)
        self.assertEqual(set(failure), spike._PUBLIC_REPORT_KEYS)
        self.assertEqual(set(failure["artifacts"]), spike._ARTIFACT_KEYS)  # type: ignore[arg-type]

        for key in spike._PUBLIC_REPORT_KEYS:
            with self.subTest(delete_top_level=key):
                mutated = copy.deepcopy(failure)
                del mutated[key]
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(mutated)

        for key in spike._ARTIFACT_KEYS:
            with self.subTest(delete_artifact=key):
                mutated = copy.deepcopy(failure)
                del mutated["artifacts"][key]  # type: ignore[index]
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(mutated)

        for key in spike._PUBLIC_REPORT_KEYS:
            for mutation in ("object", "nan", "cycle"):
                with self.subTest(top_level_type=key, mutation=mutation):
                    mutated = copy.deepcopy(failure)
                    if mutation == "object":
                        value: object = object()
                    elif mutation == "nan":
                        value = float("nan")
                    else:
                        cyclic: dict[str, object] = {}
                        cyclic["self"] = cyclic
                        value = cyclic
                    mutated[key] = value
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(mutated)

        roster_mutations: list[tuple[str, dict[str, object]]] = []

        renamed = copy.deepcopy(failure)
        renamed["Driver_Binding"] = renamed.pop("driver_binding")
        roster_mutations.append(("renamed_top_level", renamed))

        renamed_artifact = copy.deepcopy(failure)
        artifacts = renamed_artifact["artifacts"]
        self.assertIsInstance(artifacts, dict)
        artifacts["Driver_Stdout_SHA256"] = artifacts.pop("driver_stdout_sha256")
        roster_mutations.append(("renamed_artifact", renamed_artifact))

        extra = copy.deepcopy(failure)
        extra["extra"] = None
        roster_mutations.append(("extra_top_level", extra))

        extra_artifact = copy.deepcopy(failure)
        extra_artifact["artifacts"]["extra"] = None  # type: ignore[index]
        roster_mutations.append(("extra_artifact", extra_artifact))

        nested = copy.deepcopy(failure)
        nested["driver_binding"] = {"driver_binding": None}
        roster_mutations.append(("nested_required_null", nested))

        wrong_artifact_type = copy.deepcopy(failure)
        wrong_artifact_type["artifacts"] = []
        roster_mutations.append(("artifact_type", wrong_artifact_type))

        for name, mutated in roster_mutations:
            with self.subTest(name=name):
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(mutated)

        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report([])  # type: ignore[arg-type]

    def test_final_envelope_closes_claim_context_and_temporary_state_machine(self) -> None:
        class StringSubclass(str):
            pass

        class DictSubclass(dict[str, object]):
            pass

        immutable_mutations: tuple[tuple[str, object], ...] = (
            ("format", "evil"),
            ("authority", "external"),
            ("evidence_authentication", "implemented"),
            ("release_authorized", True),
            ("diagnostic_only", False),
            ("portability_cell", "counted"),
        )
        for key, value in immutable_mutations:
            for candidate in (
                value,
                None,
                float("nan"),
                object(),
                StringSubclass(str(spike._report(status="failed", reason="candidate_failure")[key])),
            ):
                with self.subTest(immutable=key, candidate_type=type(candidate).__name__):
                    mutated = spike._report(status="failed", reason="candidate_failure")
                    mutated[key] = candidate
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(mutated)

        cleanup_states = ("not_created", "verified", "failed")
        artifact_states = (
            "not_evaluated",
            "absent_at_final_inventory",
            "detected_and_rejected",
        )
        observation_states = (
            "not_performed",
            "final_inventory_only_transient_activity_not_observed",
        )
        cleanup_overrides = (
            None,
            "appcontainer_profile_cleanup_failed",
            "temporary_directory_cleanup_failed",
        )
        for cleanup, artifacts, observation, override in product(
            cleanup_states,
            artifact_states,
            observation_states,
            cleanup_overrides,
        ):
            primary = (
                "temporary_code_artifact_detected"
                if artifacts == "detected_and_rejected"
                else "candidate_failure"
            )
            report = spike._report(
                status="failed",
                reason=primary if override is None else override,
                primary_reason=primary,
                cleanup_override_reason=override,
            )
            report["temporary_directory_cleanup"] = cleanup
            report["temporary_code_artifacts"] = artifacts
            report["temporary_code_artifact_observation"] = observation
            pair_valid = (artifacts == "not_evaluated") == (
                observation == "not_performed"
            )
            cleanup_valid = (
                (cleanup != "failed" or override is not None)
                and (
                    override != "temporary_directory_cleanup_failed"
                    or cleanup == "failed"
                )
                and not (
                    cleanup == "not_created"
                    and (
                        override is not None
                        or artifacts != "not_evaluated"
                        or observation != "not_performed"
                    )
                )
            )
            with self.subTest(
                cleanup=cleanup,
                artifacts=artifacts,
                observation=observation,
                override=override,
            ):
                private_snapshot_kwargs: dict[str, object] = {}
                if override is not None:
                    private_snapshot_kwargs["expected_artifacts"] = copy.deepcopy(
                        report["artifacts"]
                    )
                if pair_valid and cleanup_valid:
                    _validate_final_report(report, **private_snapshot_kwargs)
                else:
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(report, **private_snapshot_kwargs)

        for key in (
            "temporary_directory_cleanup",
            "temporary_code_artifacts",
            "temporary_code_artifact_observation",
        ):
            for candidate in (None, True, [], {}, float("nan"), object(), "unknown"):
                with self.subTest(temporary_field=key, candidate=repr(candidate)):
                    mutated = spike._report(status="failed", reason="candidate_failure")
                    mutated[key] = candidate
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(mutated)

        retained_artifact_keys = spike._ARTIFACT_KEYS - spike._DRIVER_DERIVED_ARTIFACT_KEYS
        retained_hashes = spike._empty_hashes()
        for index, key in enumerate(sorted(retained_artifact_keys), start=1):
            retained_hashes[key] = f"{index:x}" * 64
        retained_report = spike._report(
            status="failed",
            reason="candidate_failure",
            hashes=retained_hashes,
            temporary_directory_cleanup="verified",
        )
        retained_snapshot = copy.deepcopy(retained_report["artifacts"])
        _validate_final_report(
            retained_report,
            expected_public_artifacts=retained_snapshot,  # type: ignore[arg-type]
        )
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._validate_final_helper_failure_receipt_relation(
                retained_report,
                expected_public_artifacts=None,
            )
        for key in sorted(retained_artifact_keys):
            for value in (None, "9" * 64):
                with self.subTest(retained_artifact=key, value=value):
                    mutated = copy.deepcopy(retained_report)
                    mutated["artifacts"][key] = value  # type: ignore[index]
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(
                            mutated,
                            expected_public_artifacts=retained_snapshot,  # type: ignore[arg-type]
                        )

        null_mode_reports = (
            retained_report,
            spike._report(
                status="not_observed",
                reason="candidate_failure",
                hashes=retained_hashes,
                temporary_directory_cleanup="verified",
            ),
            spike._report(
                status="failed",
                reason="helper_failed",
                hashes=retained_hashes,
                helper_failure_receipt=_helper_failure_receipt(),
                temporary_directory_cleanup="verified",
            ),
            spike._report(
                status="not_observed",
                reason="helper_not_observed",
                hashes=retained_hashes,
                helper_failure_receipt=_helper_failure_receipt("not_observed"),
                temporary_directory_cleanup="verified",
            ),
        )
        for report_index, null_report in enumerate(null_mode_reports):
            private_snapshot = copy.deepcopy(null_report["artifacts"])
            public_snapshot = copy.deepcopy(null_report["artifacts"])
            _validate_final_report(
                null_report,
                expected_artifacts=private_snapshot,  # type: ignore[arg-type]
                expected_public_artifacts=public_snapshot,  # type: ignore[arg-type]
            )
            for key in sorted(retained_artifact_keys):
                for value in (None, "f" * 64):
                    with self.subTest(
                        coherent_null_mode_retained_drift=(
                            report_index,
                            key,
                            value,
                        )
                    ):
                        mutated = copy.deepcopy(null_report)
                        mutated["artifacts"][key] = value  # type: ignore[index]
                        coherent_public_snapshot = copy.deepcopy(
                            mutated["artifacts"]
                        )
                        with self.assertRaises(spike.HelperProtocolFailure):
                            _validate_final_report(
                                mutated,
                                expected_artifacts=private_snapshot,  # type: ignore[arg-type]
                                expected_public_artifacts=coherent_public_snapshot,  # type: ignore[arg-type]
                            )

        malformed_public_snapshots: list[object] = [
            [],
            {**retained_snapshot, "extra": None},  # type: ignore[dict-item]
            DictSubclass(retained_snapshot),  # type: ignore[arg-type]
        ]
        missing_snapshot_key = copy.deepcopy(retained_snapshot)
        del missing_snapshot_key[next(iter(spike._ARTIFACT_KEYS))]  # type: ignore[index]
        malformed_public_snapshots.append(missing_snapshot_key)
        invalid_snapshot_value = copy.deepcopy(retained_snapshot)
        invalid_snapshot_value[next(iter(spike._ARTIFACT_KEYS))] = False  # type: ignore[index]
        malformed_public_snapshots.append(invalid_snapshot_value)
        derived_public_key = {
            (StringSubclass(key) if index == 0 else key): value
            for index, (key, value) in enumerate(retained_snapshot.items())  # type: ignore[union-attr]
        }
        malformed_public_snapshots.append(derived_public_key)
        for malformed_snapshot in malformed_public_snapshots:
            with self.subTest(public_artifact_snapshot=repr(malformed_snapshot)):
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        retained_report,
                        expected_public_artifacts=malformed_snapshot,  # type: ignore[arg-type]
                    )

        cleanup_downgrade = spike._report(
            status="failed",
            reason="appcontainer_profile_cleanup_failed",
            primary_reason="candidate_failure",
            cleanup_override_reason="appcontainer_profile_cleanup_failed",
            hashes=retained_hashes,
            temporary_directory_cleanup="verified",
        )
        cleanup_snapshot = copy.deepcopy(cleanup_downgrade["artifacts"])
        pre_cleanup_snapshot = copy.deepcopy(cleanup_snapshot)
        for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
            pre_cleanup_snapshot[key] = "7" * 64  # type: ignore[index]
        _validate_final_report(
            cleanup_downgrade,
            expected_artifacts=pre_cleanup_snapshot,  # type: ignore[arg-type]
            expected_public_artifacts=cleanup_snapshot,  # type: ignore[arg-type]
        )
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                cleanup_downgrade,
                expected_public_artifacts=cleanup_snapshot,  # type: ignore[arg-type]
            )
        for key in sorted(retained_artifact_keys):
            for value in (None, "8" * 64):
                with self.subTest(cleanup_retained_artifact=key, value=value):
                    mutated = copy.deepcopy(cleanup_downgrade)
                    mutated["artifacts"][key] = value  # type: ignore[index]
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(
                            mutated,
                            expected_artifacts=pre_cleanup_snapshot,  # type: ignore[arg-type]
                            expected_public_artifacts=cleanup_snapshot,  # type: ignore[arg-type]
                        )
                    coherent_public_snapshot = copy.deepcopy(mutated["artifacts"])
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(
                            mutated,
                            expected_artifacts=pre_cleanup_snapshot,  # type: ignore[arg-type]
                            expected_public_artifacts=coherent_public_snapshot,  # type: ignore[arg-type]
                        )

        class ArtifactSnapshotDictSubclass(dict[str, str | None]):
            pass

        class ArtifactSnapshotKeySubclass(str):
            pass

        private_snapshot_mutations: list[object] = [
            [],
            {**pre_cleanup_snapshot, "extra": None},  # type: ignore[dict-item]
            ArtifactSnapshotDictSubclass(pre_cleanup_snapshot),  # type: ignore[arg-type]
        ]
        missing_private_key = copy.deepcopy(pre_cleanup_snapshot)
        del missing_private_key[next(iter(spike._ARTIFACT_KEYS))]  # type: ignore[index]
        private_snapshot_mutations.append(missing_private_key)
        invalid_private_value = copy.deepcopy(pre_cleanup_snapshot)
        invalid_private_value[next(iter(spike._ARTIFACT_KEYS))] = False  # type: ignore[index]
        private_snapshot_mutations.append(invalid_private_value)
        derived_private_key = {
            (
                ArtifactSnapshotKeySubclass(key)
                if index == 0
                else key
            ): value
            for index, (key, value) in enumerate(pre_cleanup_snapshot.items())  # type: ignore[union-attr]
        }
        private_snapshot_mutations.append(derived_private_key)
        for malformed_private_snapshot in private_snapshot_mutations:
            with self.subTest(
                malformed_private_snapshot=type(malformed_private_snapshot).__name__
            ):
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        cleanup_downgrade,
                        expected_artifacts=malformed_private_snapshot,  # type: ignore[arg-type]
                        expected_public_artifacts=cleanup_snapshot,  # type: ignore[arg-type]
                    )

        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                cleanup_downgrade,
                expected_artifacts=cleanup_downgrade["artifacts"],  # type: ignore[arg-type]
                expected_public_artifacts=cleanup_snapshot,  # type: ignore[arg-type]
            )
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                cleanup_downgrade,
                expected_artifacts=pre_cleanup_snapshot,  # type: ignore[arg-type]
                expected_public_artifacts=cleanup_downgrade["artifacts"],  # type: ignore[arg-type]
            )
        aliased_private_snapshots = copy.deepcopy(cleanup_snapshot)
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                cleanup_downgrade,
                expected_artifacts=aliased_private_snapshots,  # type: ignore[arg-type]
                expected_public_artifacts=aliased_private_snapshots,  # type: ignore[arg-type]
            )

        context_report = spike._report(
            status="failed",
            reason="candidate_failure",
            boundary_expected={"format": "expected"},
            endpoint_receipt={"format": "endpoint"},
            host_trust={"format": "host"},
            input_binding={"format": "input"},
            moniker="finplanbrac-0123456789abcdef01234567",
            profile_receipt={"format": "profile"},
            temporary_directory_cleanup="verified",
        )
        context_snapshot = _public_context_witness_digests(context_report)
        _validate_final_report(
            context_report,
            expected_context_witness_digests=context_snapshot,
        )
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(context_report)
        for key in spike._PUBLIC_CONTEXT_WITNESS_KEYS:
            with self.subTest(context_drift=key):
                mutated = copy.deepcopy(context_report)
                mutated[key] = None if key != "moniker" else "finplanbrac-89abcdef0123456701234567"
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        mutated,
                        expected_context_witness_digests=context_snapshot,
                    )

        invalid_moniker = copy.deepcopy(context_report)
        invalid_moniker["moniker"] = "invalid"
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                invalid_moniker,
                expected_context_witness_digests=_public_context_witness_digests(
                    invalid_moniker
                ),
            )

        for key in (
            "boundary_expected",
            "endpoint_receipt",
            "host_trust",
            "input_binding",
            "profile_receipt",
        ):
            with self.subTest(context_dict_subclass=key):
                mutated = copy.deepcopy(context_report)
                mutated[key] = DictSubclass(mutated[key])  # type: ignore[arg-type]
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        mutated,
                        expected_context_witness_digests=(
                            _public_context_witness_digests(mutated)
                        ),
                    )

    def test_final_observed_pass_requires_admitted_evidence_present_and_non_null(self) -> None:
        observed = _observation_mode_report()
        expected_artifacts = copy.deepcopy(observed["artifacts"])
        expected_witness_digests = _observation_mode_witness_digests(observed)
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                observed,
                expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
            )
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                observed,
                boundary_path_context=boundary_fixture._path_context(),
                expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
            )
        _validate_final_report(
            observed,
            boundary_path_context=boundary_fixture._path_context(),
            expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
            expected_witness_digests=expected_witness_digests,
        )

        for key, value in (
            ("temporary_directory_cleanup", "not_created"),
            ("temporary_directory_cleanup", "failed"),
            ("temporary_code_artifacts", "not_evaluated"),
            ("temporary_code_artifacts", "detected_and_rejected"),
            ("temporary_code_artifact_observation", "not_performed"),
        ):
            with self.subTest(mode_b_inventory_field=key, value=value):
                mutated = copy.deepcopy(observed)
                mutated[key] = value
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        mutated,
                        boundary_path_context=boundary_fixture._path_context(),
                        expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
                        expected_witness_digests=expected_witness_digests,
                    )

    def test_final_public_tree_requires_exact_builtin_json_types(self) -> None:
        class StringSubclass(str):
            pass

        class IntSubclass(int):
            pass

        class DictSubclass(dict[object, object]):
            pass

        class ListSubclass(list[object]):
            pass

        JsonPath = tuple[str | int, ...]

        def collect_nodes(
            value: object,
            path: JsonPath,
            nodes: list[tuple[JsonPath, object]],
            keys: list[tuple[JsonPath, str]],
        ) -> None:
            nodes.append((path, value))
            if type(value) is dict:
                for key, child in value.items():
                    self.assertIs(type(key), str)
                    keys.append((path, key))
                    collect_nodes(child, (*path, key), nodes, keys)
            elif type(value) is list:
                for index, child in enumerate(value):
                    collect_nodes(child, (*path, index), nodes, keys)

        def value_at(value: object, path: JsonPath) -> object:
            current = value
            for step in path:
                current = current[step]  # type: ignore[index]
            return current

        def replace_value(
            source: dict[str, object],
            path: JsonPath,
            replacement: Callable[[object], object],
        ) -> object:
            mutated: object = copy.deepcopy(source)
            target = value_at(mutated, path)
            new_value = replacement(target)
            if not path:
                return new_value
            parent = value_at(mutated, path[:-1])
            parent[path[-1]] = new_value  # type: ignore[index]
            return mutated

        def replace_key(
            source: dict[str, object],
            parent_path: JsonPath,
            key: str,
        ) -> dict[str, object]:
            mutated = copy.deepcopy(source)
            parent = value_at(mutated, parent_path)
            self.assertIs(type(parent), dict)
            items = [
                (StringSubclass(current_key) if current_key == key else current_key, child)
                for current_key, child in parent.items()  # type: ignore[union-attr]
            ]
            parent.clear()  # type: ignore[union-attr]
            parent.update(items)  # type: ignore[union-attr]
            return mutated

        observed = _observation_mode_report()
        expected_artifacts = copy.deepcopy(observed["artifacts"])
        expected_witness_digests = _observation_mode_witness_digests(observed)
        nodes: list[tuple[JsonPath, object]] = []
        keys: list[tuple[JsonPath, str]] = []
        collect_nodes(observed, (), nodes, keys)

        string_nodes = [(path, value) for path, value in nodes if type(value) is str]
        int_nodes = [(path, value) for path, value in nodes if type(value) is int]
        bool_nodes = [(path, value) for path, value in nodes if type(value) is bool]
        dict_nodes = [(path, value) for path, value in nodes if type(value) is dict]
        list_nodes = [(path, value) for path, value in nodes if type(value) is list]
        self.assertGreaterEqual(len(string_nodes), 400)
        self.assertGreaterEqual(len(keys), 400)
        for witness in (
            "boundary_expected",
            "boundary_summary",
            "driver_binding",
            "endpoint_receipt",
            "helper_report",
            "profile_receipt",
        ):
            self.assertTrue(
                any(path and path[0] == witness for path, _value in string_nodes),
                witness,
            )

        validation_kwargs: dict[str, object] = {
            "boundary_path_context": boundary_fixture._path_context(),
            "expected_artifacts": expected_artifacts,
            "expected_public_artifacts": copy.deepcopy(expected_artifacts),
            "expected_witness_digests": expected_witness_digests,
        }
        for path, _value in string_nodes:
            with self.subTest(derived_string=path):
                mutated = replace_value(observed, path, StringSubclass)
                with self.assertRaisesRegex(
                    spike.HelperProtocolFailure,
                    r"^public_json_type_invalid$",
                ):
                    _validate_final_report(mutated, **validation_kwargs)
        for path, _value in int_nodes:
            with self.subTest(derived_integer=path):
                mutated = replace_value(observed, path, IntSubclass)
                with self.assertRaisesRegex(
                    spike.HelperProtocolFailure,
                    r"^public_json_type_invalid$",
                ):
                    _validate_final_report(mutated, **validation_kwargs)
        for path, _value in bool_nodes:
            with self.subTest(bool_equivalent_integer_subclass=path):
                mutated = replace_value(
                    observed,
                    path,
                    lambda current: IntSubclass(int(current)),
                )
                with self.assertRaisesRegex(
                    spike.HelperProtocolFailure,
                    r"^public_json_type_invalid$",
                ):
                    _validate_final_report(mutated, **validation_kwargs)
        for path, _value in dict_nodes:
            with self.subTest(derived_dict=path):
                mutated = replace_value(observed, path, DictSubclass)
                with self.assertRaisesRegex(
                    spike.HelperProtocolFailure,
                    r"^public_json_type_invalid$",
                ):
                    _validate_final_report(mutated, **validation_kwargs)
        for path, _value in list_nodes:
            with self.subTest(derived_list=path):
                mutated = replace_value(observed, path, ListSubclass)
                with self.assertRaisesRegex(
                    spike.HelperProtocolFailure,
                    r"^public_json_type_invalid$",
                ):
                    _validate_final_report(mutated, **validation_kwargs)
        for parent_path, key in keys:
            with self.subTest(derived_key=(*parent_path, key)):
                mutated = replace_key(observed, parent_path, key)
                with self.assertRaisesRegex(
                    spike.HelperProtocolFailure,
                    r"^public_json_key_type_invalid$",
                ):
                    _validate_final_report(mutated, **validation_kwargs)

        failure = spike._report(
            status="failed",
            reason="helper_failed",
            helper_failure_receipt=_helper_failure_receipt(),
            temporary_directory_cleanup="verified",
            temporary_code_artifacts="absent_at_final_inventory",
            temporary_code_artifact_observation=(
                "final_inventory_only_transient_activity_not_observed"
            ),
        )
        receipt = failure["helper_failure_receipt"]
        self.assertIs(type(receipt), dict)
        for key, value in receipt.items():  # type: ignore[union-attr]
            with self.subTest(failure_receipt_string=key):
                mutated = copy.deepcopy(failure)
                mutated["helper_failure_receipt"][key] = StringSubclass(value)  # type: ignore[index]
                with self.assertRaisesRegex(
                    spike.HelperProtocolFailure,
                    r"^public_json_type_invalid$",
                ):
                    _validate_final_report(mutated)

        for witness in (
            "boundary_expected",
            "boundary_summary",
            "driver_binding",
            "endpoint_receipt",
            "helper_report",
            "profile_receipt",
        ):
            witness_node = observed[witness]
            self.assertIs(type(witness_node), dict)
            witness_key = next(iter(witness_node))  # type: ignore[arg-type]
            for invalid in (1.25, b"private", ("tuple",), {"set"}, object()):
                with self.subTest(
                    nested_non_json=witness,
                    invalid_type=type(invalid).__name__,
                ):
                    mutated = copy.deepcopy(observed)
                    mutated[witness][witness_key] = invalid  # type: ignore[index]
                    with self.assertRaisesRegex(
                        spike.HelperProtocolFailure,
                        r"^public_json_type_invalid$",
                    ):
                        _validate_final_report(mutated, **validation_kwargs)

        cyclic: list[object] = []
        cyclic.append(cyclic)
        with self.assertRaisesRegex(
            spike.HelperProtocolFailure,
            r"^public_json_cycle_invalid$",
        ):
            spike._validate_exact_public_json_types(cyclic)
        too_deep: object = None
        for _index in range(spike._PUBLIC_JSON_MAX_DEPTH + 1):
            too_deep = [too_deep]
        with self.assertRaisesRegex(
            spike.HelperProtocolFailure,
            r"^public_json_shape_too_large$",
        ):
            spike._validate_exact_public_json_types(too_deep)
        with self.assertRaisesRegex(
            spike.HelperProtocolFailure,
            r"^public_json_shape_too_large$",
        ):
            spike._validate_exact_public_json_types(
                [None] * spike._PUBLIC_JSON_MAX_NODES
            )

        for key in ("driver_binding", "helper_report", "boundary_summary"):
            for mutation in ("delete", "null", "type"):
                with self.subTest(key=key, mutation=mutation):
                    mutated = copy.deepcopy(observed)
                    if mutation == "delete":
                        del mutated[key]
                    elif mutation == "null":
                        mutated[key] = None
                    else:
                        mutated[key] = []
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(
                            mutated,
                            boundary_path_context=boundary_fixture._path_context(),
                            expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
                            expected_witness_digests=expected_witness_digests,
                        )

    def test_failed_and_unrecomputed_not_observed_require_global_null_evidence_mode(
        self,
    ) -> None:
        for status in ("failed", "not_observed"):
            with self.subTest(status=status, mutation="baseline"):
                baseline = spike._report(status=status, reason="candidate_failure")
                _validate_final_report(baseline)

            for key in ("driver_binding", "helper_report", "boundary_summary"):
                with self.subTest(status=status, witness=key):
                    mutated = spike._report(status=status, reason="candidate_failure")
                    mutated[key] = {}
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(mutated)

            for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
                with self.subTest(status=status, artifact=key):
                    mutated = spike._report(status=status, reason="candidate_failure")
                    mutated["artifacts"][key] = "a" * 64  # type: ignore[index]
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(mutated)

        failed_with_complete_observation = _observation_mode_report("not_observed")
        failed_expected_witness_digests = _observation_mode_witness_digests(
            failed_with_complete_observation
        )
        failed_with_complete_observation.update(
            {
                "primary_reason": "candidate_failure",
                "reason": "candidate_failure",
                "status": "failed",
            }
        )
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                failed_with_complete_observation,
                boundary_path_context=boundary_fixture._path_context(),
                expected_artifacts=copy.deepcopy(
                    failed_with_complete_observation["artifacts"]
                ),  # type: ignore[arg-type]
                expected_witness_digests=failed_expected_witness_digests,
            )

        cleanup_override = spike._report(
            status="failed",
            reason="appcontainer_profile_cleanup_failed",
            primary_reason="candidate_failure",
            cleanup_override_reason="appcontainer_profile_cleanup_failed",
            temporary_directory_cleanup="verified",
        )
        cleanup_private_snapshot = copy.deepcopy(cleanup_override["artifacts"])
        _validate_final_report(
            cleanup_override,
            expected_artifacts=cleanup_private_snapshot,  # type: ignore[arg-type]
        )
        invalid_cleanup_override = copy.deepcopy(cleanup_override)
        invalid_cleanup_override["reason"] = "candidate_failure"
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                invalid_cleanup_override,
                expected_artifacts=cleanup_private_snapshot,  # type: ignore[arg-type]
            )
        erased_cleanup_primary = copy.deepcopy(cleanup_override)
        erased_cleanup_primary["primary_reason"] = erased_cleanup_primary["reason"]
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                erased_cleanup_primary,
                expected_artifacts=cleanup_private_snapshot,  # type: ignore[arg-type]
            )
        missing_cleanup_override = spike._report(
            status="failed",
            reason="temporary_directory_cleanup_failed",
        )
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                missing_cleanup_override
            )
        primary_mismatch = spike._report(
            status="failed",
            reason="candidate_failure",
        )
        primary_mismatch["primary_reason"] = "other_failure"
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(primary_mismatch)
        boundary_reason_without_recompute = spike._report(
            status="not_observed",
            reason="full_boundary_not_observed",
        )
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                boundary_reason_without_recompute
            )
        swapped_cleanup_primary = copy.deepcopy(cleanup_override)
        swapped_cleanup_primary["primary_reason"] = "temporary_directory_cleanup_failed"
        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                swapped_cleanup_primary
            )

        for reason_value, primary_value in (
            (1, 1),
            ([], []),
            ({}, {}),
            ("Candidate_Failure", "Candidate_Failure"),
        ):
            with self.subTest(
                invalid_reason=reason_value,
                invalid_primary=primary_value,
            ):
                invalid_reason_type = spike._report(
                    status="failed",
                    reason="candidate_failure",
                )
                invalid_reason_type["reason"] = reason_value
                invalid_reason_type["primary_reason"] = primary_value
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        invalid_reason_type
                    )

        for override_value in (1, [], {}):
            with self.subTest(invalid_cleanup_override=override_value):
                invalid_override_type = copy.deepcopy(cleanup_override)
                invalid_override_type["cleanup_override_reason"] = override_value
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        invalid_override_type
                    )

        for primary_value in (1, [], {}):
            with self.subTest(invalid_cleanup_primary=primary_value):
                invalid_cleanup_primary = copy.deepcopy(cleanup_override)
                invalid_cleanup_primary["primary_reason"] = primary_value
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        invalid_cleanup_primary
                    )

    def test_recomputed_not_observed_requires_complete_bound_all_or_none_evidence(
        self,
    ) -> None:
        observed = _observation_mode_report("not_observed")
        expected_artifacts = copy.deepcopy(observed["artifacts"])
        expected_witness_digests = _observation_mode_witness_digests(observed)
        _validate_final_report(
            observed,
            boundary_path_context=boundary_fixture._path_context(),
            expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
            expected_witness_digests=expected_witness_digests,
        )

        for key in ("driver_binding", "helper_report", "boundary_summary"):
            with self.subTest(mixed_witness=key):
                mutated = copy.deepcopy(observed)
                mutated[key] = None
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        mutated,
                        boundary_path_context=boundary_fixture._path_context(),
                        expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
                        expected_witness_digests=expected_witness_digests,
                    )

        for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
            with self.subTest(mixed_artifact=key):
                mutated = copy.deepcopy(observed)
                mutated["artifacts"][key] = None  # type: ignore[index]
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        mutated,
                        boundary_path_context=boundary_fixture._path_context(),
                        expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
                        expected_witness_digests=expected_witness_digests,
                    )

        mutations: list[tuple[str, dict[str, object]]] = []

        failed_status = copy.deepcopy(observed)
        failed_status["status"] = "failed"
        mutations.append(("failed_status", failed_status))

        mismatched_status = copy.deepcopy(observed)
        mismatched_status["status"] = "observed_pass"
        mutations.append(("summary_status_mismatch", mismatched_status))

        mismatched_reason = copy.deepcopy(observed)
        mismatched_reason["reason"] = "candidate_failure"
        mutations.append(("summary_reason_mismatch", mismatched_reason))

        mismatched_primary = copy.deepcopy(observed)
        mismatched_primary["primary_reason"] = "candidate_failure"
        mutations.append(("summary_primary_mismatch", mismatched_primary))

        incomplete_helper = copy.deepcopy(observed)
        incomplete_helper["helper_report"] = _helper_report("failed")
        mutations.append(("helper_not_complete", incomplete_helper))

        helper_reason = copy.deepcopy(observed)
        helper_reason["helper_report"]["reason"] = "helper_failed"  # type: ignore[index]
        mutations.append(("helper_reason", helper_reason))

        helper_raw_empty = copy.deepcopy(observed)
        helper_raw_empty["helper_report"]["raw_observations"] = {}  # type: ignore[index]
        mutations.append(("helper_raw_empty", helper_raw_empty))

        helper_raw_valid_but_summary_stale = copy.deepcopy(observed)
        helper_raw_valid_but_summary_stale["helper_report"]["raw_observations"][  # type: ignore[index]
            "fingerprints"
        ]["runtime_after"]["owner_matches_controller"] = True
        mutations.append(
            ("helper_raw_valid_but_summary_stale", helper_raw_valid_but_summary_stale)
        )

        coherent_helper_and_summary = copy.deepcopy(observed)
        coherent_raw = coherent_helper_and_summary["helper_report"][  # type: ignore[index]
            "raw_observations"
        ]
        coherent_raw["fingerprints"]["runtime_after"][  # type: ignore[index]
            "owner_matches_controller"
        ] = True
        coherent_summary = boundary_fixture.boundary.recompute_boundary_summary(
            coherent_raw,
            coherent_helper_and_summary["boundary_expected"],
            coherent_helper_and_summary["endpoint_receipt"],
            coherent_helper_and_summary["profile_receipt"],
            boundary_fixture._path_context(),
        )
        coherent_helper_and_summary["boundary_summary"] = coherent_summary
        coherent_helper_and_summary["status"] = coherent_summary["status"]
        coherent_helper_and_summary["reason"] = coherent_summary["reason"]
        coherent_helper_and_summary["primary_reason"] = coherent_summary["reason"]
        mutations.append(("coherent_helper_and_summary", coherent_helper_and_summary))

        coherent_receipt_and_summary = copy.deepcopy(observed)
        coherent_receipt_and_summary["profile_receipt"][  # type: ignore[index]
            "cleanup_complete"
        ] = False
        receipt_summary = boundary_fixture.boundary.recompute_boundary_summary(
            coherent_receipt_and_summary["helper_report"]["raw_observations"],  # type: ignore[index]
            coherent_receipt_and_summary["boundary_expected"],
            coherent_receipt_and_summary["endpoint_receipt"],
            coherent_receipt_and_summary["profile_receipt"],
            boundary_fixture._path_context(),
        )
        coherent_receipt_and_summary["boundary_summary"] = receipt_summary
        coherent_receipt_and_summary["status"] = receipt_summary["status"]
        coherent_receipt_and_summary["reason"] = receipt_summary["reason"]
        coherent_receipt_and_summary["primary_reason"] = receipt_summary["reason"]
        mutations.append(("coherent_receipt_and_summary", coherent_receipt_and_summary))

        summary_extra = copy.deepcopy(observed)
        summary_extra["boundary_summary"]["extra"] = None  # type: ignore[index]
        mutations.append(("summary_extra", summary_extra))

        summary_self_consistent_forgery = copy.deepcopy(observed)
        summary_self_consistent_forgery["boundary_summary"]["network_claims"][  # type: ignore[index]
            "lan_capability_differential_observed"
        ] = False
        mutations.append(("summary_self_consistent_forgery", summary_self_consistent_forgery))

        driver_extra = copy.deepcopy(observed)
        driver_extra["driver_binding"]["extra"] = None  # type: ignore[index]
        mutations.append(("driver_extra", driver_extra))

        driver_format = copy.deepcopy(observed)
        driver_format["driver_binding"]["format"] = "invalid"  # type: ignore[index]
        mutations.append(("driver_format", driver_format))

        artifact_binding = copy.deepcopy(observed)
        artifact_binding["artifacts"]["in_memory_assembly_sha256"] = "9" * 64  # type: ignore[index]
        mutations.append(("artifact_binding", artifact_binding))

        receipt = copy.deepcopy(observed)
        receipt["helper_failure_receipt"] = _helper_failure_receipt("not_observed")
        mutations.append(("receipt_in_observation_mode", receipt))

        cleanup_without_scrub = copy.deepcopy(observed)
        cleanup_without_scrub.update(
            {
                "cleanup_override_reason": "appcontainer_profile_cleanup_failed",
                "reason": "appcontainer_profile_cleanup_failed",
                "status": "failed",
            }
        )
        mutations.append(("cleanup_without_evidence_scrub", cleanup_without_scrub))

        non_json_helper = copy.deepcopy(observed)
        non_json_helper["helper_report"]["raw_observations"][  # type: ignore[index]
            "format"
        ] = object()
        mutations.append(("non_json_helper_witness", non_json_helper))

        non_json_profile = copy.deepcopy(observed)
        non_json_profile["profile_receipt"]["format"] = object()  # type: ignore[index]
        mutations.append(("non_json_profile_witness", non_json_profile))

        non_json_expected = copy.deepcopy(observed)
        non_json_expected["boundary_expected"]["format"] = object()  # type: ignore[index]
        mutations.append(("non_json_expected_witness", non_json_expected))

        nan_expected = copy.deepcopy(observed)
        nan_expected["boundary_expected"]["format"] = float("nan")  # type: ignore[index]
        mutations.append(("nan_expected_witness", nan_expected))

        cyclic_helper = copy.deepcopy(observed)
        cyclic_helper_report = cyclic_helper["helper_report"]
        self.assertIsInstance(cyclic_helper_report, dict)
        cyclic_helper_report["cycle"] = cyclic_helper_report
        mutations.append(("cyclic_helper_witness", cyclic_helper))

        for name, mutated in mutations:
            with self.subTest(name=name):
                with self.assertRaises(spike.HelperProtocolFailure):
                    _validate_final_report(
                        mutated,
                        boundary_path_context=boundary_fixture._path_context(),
                        expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
                        expected_witness_digests=expected_witness_digests,
                    )

        with self.assertRaises(spike.HelperProtocolFailure):
            _validate_final_report(
                coherent_helper_and_summary,
                boundary_path_context=boundary_fixture._path_context(),
                expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
                expected_witness_digests=_observation_mode_witness_digests(
                    coherent_helper_and_summary
                ),
            )

        for key in spike.DRIVER_BINDING_KEYS:
            for mutation in ("delete", "type", "drift"):
                with self.subTest(driver_key=key, mutation=mutation):
                    mutated = copy.deepcopy(observed)
                    binding = mutated["driver_binding"]
                    self.assertIsInstance(binding, dict)
                    if mutation == "delete":
                        del binding[key]
                    elif mutation == "type":
                        binding[key] = None
                    elif key == "program_entry_return_code":
                        binding[key] = 1
                    elif key == "format":
                        binding[key] = "invalid"
                    else:
                        binding[key] = "9" * 64
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(
                            mutated,
                            boundary_path_context=boundary_fixture._path_context(),
                            expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
                            expected_witness_digests=expected_witness_digests,
                        )

        for key in spike._ARTIFACT_KEYS:
            for mutation in ("delete", "null", "type", "drift"):
                with self.subTest(key=key, mutation=mutation):
                    mutated = copy.deepcopy(observed)
                    artifacts = mutated["artifacts"]
                    self.assertIsInstance(artifacts, dict)
                    if mutation == "delete":
                        del artifacts[key]
                    elif mutation == "null":
                        artifacts[key] = None
                    elif mutation == "type":
                        artifacts[key] = False
                    else:
                        artifacts[key] = "9" * 64
                    with self.assertRaises(spike.HelperProtocolFailure):
                        _validate_final_report(
                            mutated,
                            boundary_path_context=boundary_fixture._path_context(),
                            expected_artifacts=expected_artifacts,  # type: ignore[arg-type]
                            expected_witness_digests=expected_witness_digests,
                        )

    def test_helper_protocol_rejects_extra_line_and_noncanonical_json(self) -> None:
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(_helper_line() + b"{}\n")
        noncanonical = json.dumps(_helper_report(), sort_keys=False).encode("utf-8") + b"\n"
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(noncanonical)

    def test_helper_protocol_rejects_duplicate_or_extra_keys(self) -> None:
        duplicate = _helper_line().replace(b'"authority":"none",', b'"authority":"none","authority":"none",', 1)
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(duplicate)
        report = _helper_report()
        report["unexpected"] = True
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(spike._canonical_json(report) + b"\n")

    def test_helper_protocol_rejects_promoted_claims(self) -> None:
        mutations = (
            ("authority", "self_issued"),
            ("evidence_authentication", "implemented"),
            ("release_authorized", True),
            ("status", "observed_pass"),
            ("status", []),
            ("status", {}),
            ("boundary_summary", {"status": "observed_pass"}),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                report = _helper_report()
                report[key] = value
                with self.assertRaises(spike.HelperProtocolFailure):
                    spike._decode_helper_report(spike._canonical_json(report) + b"\n")

    def test_helper_and_failure_bytes_reject_account_sid_and_private_values(self) -> None:
        account_sid = "S-1-5-21-111111111-222222222-333333333-1001"
        complete = _helper_report()
        complete["raw_observations"]["fingerprints"]["runtime_after"][  # type: ignore[index]
            "owner_matches_controller"
        ] = account_sid
        with self.assertRaisesRegex(
            spike.HelperProtocolFailure,
            "helper_output_privacy_invalid",
        ):
            spike._decode_helper_report(spike._canonical_json(complete) + b"\n")

        failure = _helper_report("failed")
        failure["helper_failure_receipt"]["stage"] = account_sid  # type: ignore[index]
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(spike._canonical_json(failure) + b"\n")

        private_root = r"C:\Users\private-user\boundary"
        unsafe_final = spike._report(status="failed", reason="candidate_failure")
        unsafe_final["helper_report"] = {"detail": private_root}
        unsafe_final_bytes = spike._canonical_json(unsafe_final) + b"\n"
        with self.assertRaises(spike.PublicPrivacyFailure):
            spike._assert_public_value_privacy(
                json.loads(unsafe_final_bytes),
                known_private_values=(private_root, "private-user"),
            )

        safe_failure = spike._report(
            status="failed",
            reason="public_report_privacy_invalid",
        )
        safe_failure_bytes = spike._canonical_json(safe_failure) + b"\n"
        spike._assert_public_value_privacy(
            json.loads(safe_failure_bytes),
            known_private_values=(private_root, "private-user"),
        )
        self.assertNotIn(account_sid.encode("ascii"), safe_failure_bytes)

    def test_public_privacy_matcher_is_recursive_and_token_bounded(self) -> None:
        account_sid = "S-1-5-21-111111111-222222222-333333333-1001"
        unsafe_values = (
            {"nested": [{"value": account_sid}]},
            {"nested": [{"value": account_sid.lower()}]},
            {"value": r"D:\unrelated\sensitive"},
            {"value": r"\\server\share\file"},
            {"value": "//server/share/file"},
            {"value": r"\/server\share/file"},
            {"value": r"\??\C:\device-path"},
            {"value": "/??/C:/device-path"},
            {"value": r"\Device\HarddiskVolume3\Users\private\secret.txt"},
            {"value": "/DEVICE/HarddiskVolume3/Users/private/secret.txt"},
            {"value": r"\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\secret"},
            {"value": "/GlobalRoot/Device/HarddiskVolumeShadowCopy1/secret"},
            {"value": r"\root-relative\secret"},
            {"value": "/root-relative/secret"},
            {"value": r"C:drive-relative\secret"},
            {"value": "controller=private-user"},
            {"value": "prefix C:\\Users\\private-user\\boundary suffix"},
        )
        for value in unsafe_values:
            with self.subTest(value=value):
                with self.assertRaises(spike.PublicPrivacyFailure):
                    spike._assert_public_value_privacy(
                        value,
                        known_private_values=(
                            r"C:\Users\private-user\boundary",
                            "private-user",
                        ),
                    )

        spike._assert_public_value_privacy(
            {"digest_like": "0private-user0", "relative": r"Lib\site.py"},
            known_private_values=("private-user",),
        )

    def test_helper_protocol_rejects_bom_trailing_nan_oversize_and_bool_as_int(self) -> None:
        valid = _helper_line()
        malformed_payloads = (
            b"\xef\xbb\xbf" + valid,
            valid + b"trailing",
            valid.replace(b'"integrity_rid":4096', b'"integrity_rid":NaN'),
            b'{' + b'a' * spike.MAX_HELPER_OUTPUT_BYTES + b'}\n',
        )
        for payload in malformed_payloads:
            with self.subTest(payload_prefix=payload[:16]):
                with self.assertRaises(spike.HelperProtocolFailure):
                    spike._decode_helper_report(payload)

        report = _helper_report()
        raw = copy.deepcopy(report["raw_observations"])
        process_token = dict(raw["processes"]["root"]["token"])
        process_token["capability_count"] = True
        raw["processes"]["root"]["token"] = process_token
        report["raw_observations"] = raw
        decoded = spike._decode_helper_report(spike._canonical_json(report) + b"\n")
        with self.assertRaises(boundary_fixture.boundary.BoundaryReportError):
            boundary_fixture.boundary.recompute_boundary_summary(
                decoded["raw_observations"],
                boundary_fixture._expected(),
                boundary_fixture._endpoint_receipt(),
                boundary_fixture._profile_receipt(),
                boundary_fixture._path_context(),
            )

        report = _helper_report()
        raw = copy.deepcopy(report["raw_observations"])
        raw["request"]["requested_capability_count"] = False
        report["raw_observations"] = raw
        decoded = spike._decode_helper_report(spike._canonical_json(report) + b"\n")
        with self.assertRaises(boundary_fixture.boundary.BoundaryReportError):
            boundary_fixture.boundary.recompute_boundary_summary(
                decoded["raw_observations"],
                boundary_fixture._expected(),
                boundary_fixture._endpoint_receipt(),
                boundary_fixture._profile_receipt(),
                boundary_fixture._path_context(),
            )

    def test_observations_complete_requires_raw_and_incomplete_requires_null(self) -> None:
        report = _helper_report()
        report["raw_observations"] = None
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(spike._canonical_json(report) + b"\n")

        report = _helper_report("not_observed")
        report["raw_observations"] = copy.deepcopy(boundary_fixture._raw())
        with self.assertRaises(spike.HelperProtocolFailure):
            spike._decode_helper_report(spike._canonical_json(report) + b"\n")


class WindowsAppContainerSpikeExecutionTests(unittest.TestCase):
    def _paths(self, root: Path) -> tuple[Path, Path, Path]:
        pwsh = root / "pwsh.exe"
        windows_powershell = root / "powershell.exe"
        temporary_parent = root / "temporary"
        pwsh.write_bytes(b"MZ-pwsh")
        windows_powershell.write_bytes(b"MZ-windows-powershell")
        temporary_parent.mkdir()
        return pwsh, windows_powershell, temporary_parent

    def _run_with_lease(
        self,
        *,
        pwsh: Path,
        windows_powershell: Path,
        temporary_parent: Path,
        runner: FakePowerShellRunner,
        lease: FakeHostLease | None = None,
        endpoint_lease: FakeEndpointLease | None = None,
        profile_lease: FakeProfileLease | None = None,
        profile_acquirer: spike.ProfileAcquirer | None = None,
        nonce_factory: spike.NonceFactory = os.urandom,
    ) -> tuple[dict[str, object], int, FakeHostLease]:
        active_lease = lease or FakeHostLease(pwsh, windows_powershell)
        active_endpoint = endpoint_lease or FakeEndpointLease()
        active_profile = profile_lease or FakeProfileLease()
        runner.required_lease = active_lease
        runner.required_endpoint_lease = active_endpoint
        runner.required_profile_lease = active_profile
        runtime_root = temporary_parent.parent / "cpython-3.13-runtime"
        runtime_root.mkdir(exist_ok=True)
        (runtime_root / "python.exe").write_bytes(b"MZ-cpython-3.13")
        with mock.patch.object(
            spike,
            "_resolve_cpython_313_runtime_root",
            return_value=runtime_root,
        ):
            report, return_code = spike._run_spike(
                temp_root=temporary_parent,
                timeout_seconds=180,
                platform_name="nt",
                runner=runner,
                nonce_factory=(
                    nonce_factory
                    if nonce_factory is not os.urandom
                    else lambda byte_count: "cd" * byte_count
                ),
                host_acquirer=lambda: active_lease,
                endpoint_acquirer=lambda _timeout_seconds: active_endpoint,
                profile_acquirer=profile_acquirer or active_profile.acquire,
            )
        return report, return_code, active_lease

    def test_fake_pipeline_binds_consumed_source_driver_request_output_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-test-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner()
            endpoint_lease = FakeEndpointLease()
            report, return_code, lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
                nonce_factory=lambda byte_count: "ab" * byte_count,
                endpoint_lease=endpoint_lease,
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(report["status"], "observed_pass")
        self.assertEqual(report["moniker"], "finplanbrac-" + "ab" * 12)
        self.assertEqual(report["temporary_directory_cleanup"], "verified")
        self.assertEqual(report["temporary_code_artifacts"], "absent_at_final_inventory")
        self.assertEqual(
            report["temporary_code_artifact_observation"],
            "final_inventory_only_transient_activity_not_observed",
        )

        self.assertEqual(report["portability_cell"], "not_counted")
        self.assertIs(report["diagnostic_only"], True)
        self.assertEqual(len(runner.calls), 1)
        self.assertGreaterEqual(lease.revalidation_count, 3)
        self.assertFalse(lease.active)
        self.assertFalse(endpoint_lease.active)
        self.assertEqual(endpoint_lease.start_count, 1)
        self.assertEqual(endpoint_lease.close_count, 1)
        self.assertEqual(report["endpoint_receipt"], boundary_fixture._endpoint_receipt())
        self.assertIsNotNone(runner.required_profile_lease)
        self.assertTrue(runner.required_profile_lease.closed)
        self.assertEqual(runner.required_profile_lease.close_count, 1)
        self.assertTrue(report["profile_receipt"]["owned"])
        self.assertTrue(report["profile_receipt"]["cleanup_complete"])
        serialized_surfaces = (
            spike._canonical_json(report) + b"\n",
            runner.observed_helper_stdout[0],
        )
        known_private_values = {
            os.fspath(root),
            os.fspath(temporary_parent),
            os.fspath(temporary_parent.parent / "cpython-3.13-runtime"),
            os.environ.get("USERPROFILE", ""),
            os.environ.get("USERNAME", ""),
        } - {""}
        for payload in serialized_surfaces:
            text = payload.decode("ascii", errors="strict")
            self.assertIsNone(
                re.search(r"(?i)(?:[a-z]:[/\\]+|(?:\\\\){2,}[^\\])", text),
                text,
            )
            self.assertIsNone(
                re.search(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", text, re.ASCII),
                text,
            )
            for private_value in known_private_values:
                self.assertNotIn(private_value.casefold(), text.casefold())
                escaped = json.dumps(private_value, ensure_ascii=True)[1:-1]
                self.assertNotIn(escaped.casefold(), text.casefold())
        self.assertIn("-EncodedCommand", runner.calls[0])
        self.assertNotIn("-File", runner.calls[0])
        self.assertTrue(all(not temporary.exists() for temporary in runner.temporary_directories))
        artifacts = report["artifacts"]
        self.assertEqual(set(artifacts), set(spike._empty_hashes()))  # type: ignore[arg-type]
        self.assertEqual(  # type: ignore[index]
            artifacts["in_memory_driver_sha256"],
            hashlib.sha256(spike.IN_MEMORY_PWSH_DRIVER.encode()).hexdigest(),
        )
        encoded_driver = runner.calls[0][runner.calls[0].index("-EncodedCommand") + 1]
        consumed_bootstrap = base64.b64decode(encoded_driver, validate=True)
        expected_driver_bytes = spike.IN_MEMORY_PWSH_DRIVER.encode()
        self.assertEqual(
            consumed_bootstrap,
            spike._bootstrap_bytes(expected_driver_bytes, runner.stdin_bytes[0]),
        )
        self.assertEqual(  # type: ignore[index]
            artifacts["in_memory_bootstrap_sha256"],
            hashlib.sha256(consumed_bootstrap).hexdigest(),
        )
        self.assertEqual(
            hashlib.sha256(expected_driver_bytes).hexdigest(),
            artifacts["in_memory_driver_sha256"],  # type: ignore[index]
        )
        self.assertEqual(  # type: ignore[index]
            artifacts["helper_stdout_sha256"],
            hashlib.sha256(runner.observed_helper_stdout[0]).hexdigest(),
        )
        self.assertEqual(artifacts["in_memory_assembly_sha256"], "c" * 64)  # type: ignore[index]
        self.assertEqual(artifacts["in_memory_compiler_reference_set_sha256"], "d" * 64)  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            artifacts["driver_stdout_sha256"],
            hashlib.sha256(runner.observed_driver_stdout[0]).hexdigest(),
        )
        self.assertEqual(  # type: ignore[index]
            artifacts["program_cs_sha256"],
            hashlib.sha256(spike.PROGRAM_SOURCE.read_bytes()).hexdigest(),
        )
        self.assertTrue(all(value is not None for value in artifacts.values()))  # type: ignore[union-attr]
        self.assertEqual(runner.stdin_requests[0]["program_cs_sha256"], artifacts["program_cs_sha256"])  # type: ignore[index]
        raw_input = runner.call_kwargs[0]["input"]
        self.assertIsInstance(raw_input, bytes)
        self.assertEqual(  # type: ignore[index]
            artifacts["bootstrap_input_sha256"],
            hashlib.sha256(raw_input).hexdigest(),  # type: ignore[arg-type]
        )
        self.assertEqual(  # type: ignore[index]
            artifacts["in_memory_input_sha256"],
            hashlib.sha256(runner.stdin_bytes[0]).hexdigest(),
        )
        self.assertEqual(
            hashlib.sha256(base64.b64decode(runner.stdin_requests[0]["program_cs_base64"])).hexdigest(),
            artifacts["program_cs_sha256"],  # type: ignore[index]
        )
        self.assertTrue(all("shell" not in kwargs for kwargs in runner.call_kwargs))
        public_host_trust = spike._public_host_trust(lease.to_wire())
        self.assertEqual(report["host_trust"], public_host_trust)
        driver_binding = report["driver_binding"]
        self.assertIsInstance(driver_binding, dict)
        self.assertEqual(driver_binding["compiled_assembly_sha256"], artifacts["in_memory_assembly_sha256"])  # type: ignore[index]
        self.assertEqual(
            driver_binding["compiler_reference_set_sha256"],
            artifacts["in_memory_compiler_reference_set_sha256"],  # type: ignore[index]
        )
        self.assertEqual(driver_binding["in_memory_driver_sha256"], artifacts["in_memory_driver_sha256"])  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            driver_binding["observed_bootstrap_input_sha256"],
            artifacts["bootstrap_input_sha256"],
        )
        self.assertEqual(  # type: ignore[index]
            driver_binding["observed_in_memory_input_sha256"],
            artifacts["in_memory_input_sha256"],
        )
        self.assertEqual(driver_binding["program_cs_sha256"], artifacts["program_cs_sha256"])  # type: ignore[index]
        self.assertEqual(driver_binding["program_entry_return_code"], 0)
        input_binding = report["input_binding"]
        self.assertIsInstance(input_binding, dict)
        self.assertEqual(input_binding["in_memory_bootstrap_sha256"], artifacts["in_memory_bootstrap_sha256"])  # type: ignore[index]
        self.assertEqual(input_binding["in_memory_driver_sha256"], artifacts["in_memory_driver_sha256"])  # type: ignore[index]
        self.assertEqual(input_binding["format"], spike.INPUT_BINDING_FORMAT)  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            input_binding["controller_context_appcontainer_sid"],
            boundary_fixture.SID,
        )
        self.assertEqual(  # type: ignore[index]
            input_binding["effective_appcontainer_sid_binding"],
            "lease_issued_owned_profile_binding_create_vs_same_process_derive_equals_imported_roundtrip_and_all_observed_tokens.v4",
        )
        self.assertEqual(  # type: ignore[index]
            input_binding["profile_prelaunch_sha256"],
            runner.stdin_requests[0]["profile_prelaunch_sha256"],
        )
        self.assertEqual(  # type: ignore[index]
            report["boundary_expected"]["profile_prelaunch_sha256"],
            runner.stdin_requests[0]["profile_prelaunch_sha256"],
        )
        helper_profile = report["helper_report"]["raw_observations"]["profile"]  # type: ignore[index]
        self.assertEqual(helper_profile["appcontainer_sid_prelaunch_bound"], boundary_fixture.SID)  # type: ignore[index]
        self.assertNotIn("appcontainer_sid_derived", helper_profile)  # type: ignore[operator]
        self.assertEqual(input_binding["outer_frame_canonicalization"], spike.WIRE_CANONICALIZATION)  # type: ignore[index]
        self.assertEqual(input_binding["inner_frame_canonicalization"], spike.WIRE_CANONICALIZATION)  # type: ignore[index]
        self.assertEqual(input_binding["child_observed_digest_binding"], "outer_and_inner_raw_sha256.v1")  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            input_binding["pre_execution_request_binding"],
            "encoded_bootstrap_expected_inner_sha256_and_reconstruction.v2",
        )
        program_binding = input_binding["program_cs"]  # type: ignore[index]
        self.assertEqual(program_binding["sha256"], artifacts["program_cs_sha256"])  # type: ignore[index]
        self.assertRegex(program_binding["file_id"], r"\A[0-9a-f]{16}:[0-9a-f]{32}\Z")  # type: ignore[index]
        request_binding = {
            "entrypoint": "Program.Entry",
            "format": spike.INVOCATION_REQUEST_FORMAT,
            "host_trust": public_host_trust,
            "input_binding": input_binding,
            "moniker": report["moniker"],
            "runtime_role": "cpython_3_13_external_copy_source",
        }
        self.assertEqual(
            artifacts["invocation_request_sha256"],  # type: ignore[index]
            hashlib.sha256(spike._canonical_json(request_binding)).hexdigest(),
        )
        envelope = spike._canonical_json({"input_binding": input_binding, "request": request_binding})
        for forbidden_name in (
            b"TokenProbe",
            b"WindowsAppContainerHelper.dll",
            b"compile-helper.ps1",
            b"compile-token-probe.ps1",
            b"invoke-helper.ps1",
        ):
            self.assertNotIn(forbidden_name, envelope)
        public_report_bytes = spike._canonical_json(report)
        self.assertNotIn(boundary_fixture.PROFILE.encode("utf-8"), public_report_bytes)
        self.assertNotIn(b"C:\\Users\\owner", public_report_bytes)

    def test_profile_prelaunch_identity_mutations_fail_before_endpoint_and_runner(self) -> None:
        mutations = (
            ("folder_path_utf8_sha256", "9" * 63),
            ("folder_file_id_128_hex", "ab" * 15),
            ("folder_volume_serial_hex", "cd" * 7),
            ("folder_handle_held", False),
            ("folder_handle_delete_share_denied", False),
            ("folder_identity_format", "unmodeled.v1"),
            ("folder_boundary_component_count", 0),
            ("folder_boundary_component_count", True),
            ("folder_boundary_component_count", 0x1_0000_0000),
            ("folder_boundary_components_win32_valid", False),
            ("folder_boundary_exact", False),
            ("folder_boundary_nonempty_descendant", False),
            ("folder_boundary_packages_ancestor", False),
            ("folder_boundary_reason", "components_win32_invalid"),
            ("folder_boundary_reconstruction_matches", False),
            ("folder_boundary_terminal_ac", "false"),
            ("sid_reconciled", False),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory(
                    prefix="finplanbr-profile-prelaunch-mutation-"
                ) as directory:
                    root = Path(directory).resolve()
                    pwsh, windows_powershell, temporary_parent = self._paths(root)
                    profile_lease = FakeProfilePrelaunchMutationLease(key, value)
                    endpoint_lease = FakeEndpointLease()
                    runner = FakePowerShellRunner()
                    report, return_code, _lease = self._run_with_lease(
                        pwsh=pwsh,
                        windows_powershell=windows_powershell,
                        runner=runner,
                        temporary_parent=temporary_parent,
                        endpoint_lease=endpoint_lease,
                        profile_lease=profile_lease,
                    )
                self.assertEqual(return_code, 1)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["reason"], "appcontainer_profile_cleanup_failed")
                self.assertEqual(
                    report["primary_reason"], "profile_owned_binding_issue_invalid"
                )
                self.assertEqual(runner.calls, [])
                self.assertEqual(endpoint_lease.start_count, 0)
                self.assertTrue(profile_lease.closed)
                self.assertTrue(report["profile_receipt"]["cleanup_complete"])

    def test_mutable_or_duck_typed_profile_binding_fails_before_endpoint(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="finplanbr-profile-binding-type-"
        ) as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            profile_lease = FakeNonExactProfileBindingLease()
            endpoint_lease = FakeEndpointLease()
            runner = FakePowerShellRunner()
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
                endpoint_lease=endpoint_lease,
                profile_lease=profile_lease,
            )

        self.assertEqual(return_code, 1)
        self.assertEqual(report["reason"], "profile_owned_binding_type_invalid")
        self.assertEqual(runner.calls, [])
        self.assertEqual(endpoint_lease.start_count, 0)
        self.assertTrue(profile_lease.closed)

    def test_profile_prelaunch_depth_and_terminal_are_diagnostic(self) -> None:
        for component_count, terminal_ac in ((1, False), (2, True), (3, False)):
            with self.subTest(component_count=component_count, terminal_ac=terminal_ac):
                with tempfile.TemporaryDirectory(
                    prefix="finplanbr-profile-prelaunch-diagnostic-"
                ) as directory:
                    root = Path(directory).resolve()
                    pwsh, windows_powershell, temporary_parent = self._paths(root)
                    profile_lease = FakeProfileDiagnosticLease(
                        component_count,
                        terminal_ac,
                    )
                    report, return_code, _lease = self._run_with_lease(
                        pwsh=pwsh,
                        windows_powershell=windows_powershell,
                        runner=FakePowerShellRunner(),
                        temporary_parent=temporary_parent,
                        profile_lease=profile_lease,
                    )
                self.assertEqual(return_code, 0)
                self.assertEqual(report["status"], "observed_pass")

    def test_helper_cannot_replace_prelaunch_bound_appcontainer_sid(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-test-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner()

            def forge_sid(_temporary: Path) -> None:
                raw = _raw_for_request(runner.stdin_requests[-1])
                raw["profile"]["appcontainer_sid_prelaunch_bound"] = "S-1-15-2-1"
                runner.helper_stdout = _helper_line(raw_observations=raw)

            runner.on_invoke = forge_sid
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
            )

        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "boundary_observations_invalid")
        self.assertIsNone(report["driver_binding"])
        self.assertIsNone(report["helper_report"])
        for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
            self.assertIsNone(report["artifacts"][key])

    def test_private_helper_mutations_are_rejected_without_literal_or_digest_correlation(
        self,
    ) -> None:
        mutations = (
            "s-1-5-21-111111111-222222222-333333333-1001",
            "//server/share/private-candidate",
            r"\Device\HarddiskVolume3\Users\private\secret.txt",
            "/DEVICE/HarddiskVolume3/Users/private/secret.txt",
            r"\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\secret",
            "/GlobalRoot/Device/HarddiskVolumeShadowCopy1/secret",
            r"\root-relative\secret",
            "/root-relative/secret",
            r"C:drive-relative\secret",
        )
        for private_value in mutations:
            with self.subTest(private_value=private_value):
                with tempfile.TemporaryDirectory(
                    prefix="finplanbr-helper-privacy-regression-"
                ) as directory:
                    root = Path(directory).resolve()
                    pwsh, windows_powershell, temporary_parent = self._paths(root)
                    runner = FakePowerShellRunner()

                    def inject_private_value(
                        _temporary: Path,
                        *,
                        active_runner: FakePowerShellRunner = runner,
                        injected_value: str = private_value,
                    ) -> None:
                        raw = _raw_for_request(active_runner.stdin_requests[-1])
                        raw["fingerprints"]["runtime_after"][  # type: ignore[index]
                            "owner_matches_controller"
                        ] = injected_value
                        active_runner.helper_stdout = _helper_line(raw_observations=raw)

                    runner.on_invoke = inject_private_value
                    report, return_code, _lease = self._run_with_lease(
                        pwsh=pwsh,
                        windows_powershell=windows_powershell,
                        runner=runner,
                        temporary_parent=temporary_parent,
                    )

                self.assertEqual(return_code, 1)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["reason"], "helper_output_invalid")
                self.assertIsNone(report["driver_binding"])
                self.assertIsNone(report["helper_report"])
                for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
                    self.assertIsNone(report["artifacts"][key])
                payload = spike._canonical_json(report) + b"\n"
                self.assertNotIn(private_value.encode("ascii"), payload)
                self.assertNotIn(
                    json.dumps(private_value, ensure_ascii=True)[1:-1].encode("ascii"),
                    payload,
                )
                for rejected_bytes in (
                    runner.observed_helper_stdout[0],
                    runner.observed_driver_stdout[0],
                ):
                    rejected_digest = hashlib.sha256(rejected_bytes).hexdigest().encode("ascii")
                    self.assertNotIn(rejected_digest, payload)

    def test_rejected_helper_cannot_smuggle_its_digest_through_driver_fields(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="finplanbr-driver-digest-smuggling-regression-"
        ) as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner()

            def inject_digest_alias(_temporary: Path) -> None:
                raw = _raw_for_request(runner.stdin_requests[-1])
                raw["fingerprints"]["runtime_after"][  # type: ignore[index]
                    "owner_matches_controller"
                ] = "s-1-5-21-111111111-222222222-333333333-1001"
                rejected_helper = _helper_line(raw_observations=raw)
                rejected_digest = hashlib.sha256(rejected_helper).hexdigest()
                runner.helper_stdout = rejected_helper
                runner.driver_stdout = _driver_line(
                    rejected_helper,
                    runner.stdin_bytes[-1],
                    str(runner.stdin_requests[-1]["program_cs_sha256"]),
                    bootstrap_input=runner.call_kwargs[-1]["input"],  # type: ignore[arg-type]
                    assembly_sha256=rejected_digest,
                    reference_set_sha256=rejected_digest,
                    driver_sha256=hashlib.sha256(
                        spike.IN_MEMORY_PWSH_DRIVER.encode("utf-8")
                    ).hexdigest(),
                )

            runner.on_invoke = inject_digest_alias
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
            )

        rejected_digest = hashlib.sha256(runner.observed_helper_stdout[0]).hexdigest()
        payload = spike._canonical_json(report) + b"\n"
        self.assertEqual(return_code, 1)
        self.assertEqual(report["reason"], "helper_output_invalid")
        self.assertIsNone(report["driver_binding"])
        self.assertIsNone(report["helper_report"])
        for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
            self.assertIsNone(report["artifacts"][key])
        self.assertNotIn(rejected_digest.encode("ascii"), payload)

    def test_final_privacy_failure_scrubs_previously_admitted_output_hashes(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="finplanbr-final-privacy-regression-"
        ) as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner()
            with mock.patch.object(
                spike,
                "_assert_public_value_privacy",
                side_effect=(
                    None,
                    spike.PublicPrivacyFailure("synthetic_final_privacy_rejection"),
                ),
            ):
                report, return_code, _lease = self._run_with_lease(
                    pwsh=pwsh,
                    windows_powershell=windows_powershell,
                    runner=runner,
                    temporary_parent=temporary_parent,
                )

        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "public_report_privacy_invalid")
        self.assertIsNone(report["driver_binding"])
        self.assertIsNone(report["helper_report"])
        for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
            self.assertIsNone(report["artifacts"][key])
        payload = spike._canonical_json(report) + b"\n"
        for rejected_bytes in (
            runner.observed_helper_stdout[0],
            runner.observed_driver_stdout[0],
        ):
            self.assertNotIn(
                hashlib.sha256(rejected_bytes).hexdigest().encode("ascii"),
                payload,
            )

    def test_spaces_unicode_and_shell_metacharacters_remain_argv_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-test-") as directory:
            special_root = Path(directory).resolve() / "espaco Unicode Ω &^%"
            special_root.mkdir()
            pwsh, windows_powershell, temporary_parent = self._paths(special_root)
            runner = FakePowerShellRunner()
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
            )
        self.assertEqual(return_code, 0)
        self.assertEqual(report["status"], "observed_pass")
        self.assertTrue(any("Ω &^%" in argument for command in runner.calls for argument in command))
        self.assertTrue(all("shell" not in kwargs for kwargs in runner.call_kwargs))

    def test_relative_and_quote_bearing_security_paths_are_invalid_usage(self) -> None:
        with self.assertRaises(spike.UsageFailure):
            spike._resolve_temp_parent(Path("relative-temp"))
        with self.assertRaises(spike.UsageFailure):
            spike._resolve_temp_parent(Path('C:\\invalid"temp'))

    def test_not_observed_helper_maps_to_rc1_without_promotion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-test-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner(
                helper_stdout=_helper_line("not_observed"),
                helper_returncode=1,
            )
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
            )
        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "not_observed")
        self.assertEqual(report["reason"], "helper_not_observed")
        self.assertEqual(report["portability_cell"], "not_counted")
        self.assertIs(report["release_authorized"], False)
        self.assertEqual(
            report["helper_failure_receipt"],
            _helper_failure_receipt("not_observed"),
        )
        self.assertIsNone(report["driver_binding"])
        self.assertIsNone(report["helper_report"])
        for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
            self.assertIsNone(report["artifacts"][key])

    def test_failed_helper_admits_only_closed_failure_receipt(self) -> None:
        helper = _helper_report("failed")
        helper["helper_failure_receipt"] = _helper_failure_receipt(
            stage="root_launch",
            failure_class="internal_win32_failure",
        )
        with tempfile.TemporaryDirectory(
            prefix="finplanbr-helper-failure-receipt-"
        ) as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner(
                helper_stdout=spike._canonical_json(helper) + b"\n",
                helper_returncode=1,
            )
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
            )

        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "helper_failed")
        self.assertEqual(report["primary_reason"], "helper_failed")
        self.assertIsNone(report["cleanup_override_reason"])
        self.assertEqual(
            report["helper_failure_receipt"],
            helper["helper_failure_receipt"],
        )
        self.assertIsNone(report["driver_binding"])
        self.assertIsNone(report["helper_report"])
        for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
            self.assertIsNone(report["artifacts"][key])

    def test_helper_not_observed_receipt_survives_cleanup_override_without_reclassification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="finplanbr-helper-failure-cleanup-override-"
        ) as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner(
                helper_stdout=_helper_line("not_observed"),
                helper_returncode=1,
            )
            profile_lease = FakeProfileCleanupFailureLease()
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
                profile_lease=profile_lease,
            )

        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "appcontainer_profile_cleanup_failed")
        self.assertEqual(report["cleanup_override_reason"], report["reason"])
        self.assertEqual(report["primary_reason"], "helper_not_observed")
        self.assertEqual(
            report["helper_failure_receipt"],
            _helper_failure_receipt("not_observed"),
        )
        self.assertIsNone(report["boundary_summary"])
        self.assertIsNone(report["driver_binding"])
        self.assertIsNone(report["helper_report"])
        for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
            self.assertIsNone(report["artifacts"][key])
        _validate_final_report(
            report,
            expected_artifacts=copy.deepcopy(report["artifacts"]),  # type: ignore[arg-type]
            expected_public_artifacts=copy.deepcopy(report["artifacts"]),  # type: ignore[arg-type]
            expected_context_witness_digests=_public_context_witness_digests(report),
        )

    def test_invalid_or_rc_unmatched_failure_receipt_is_never_admitted(self) -> None:
        invalid_helpers: list[tuple[str, dict[str, object]]] = []
        for name, key, value in (
            ("unknown_stage", "stage", "unknown_stage"),
            ("private_stage", "stage", r"C:\private\stage"),
            ("unknown_class", "failure_class", "unknown_class"),
            ("wrong_type", "failure_class", True),
        ):
            helper = _helper_report("failed")
            receipt = dict(helper["helper_failure_receipt"])  # type: ignore[arg-type]
            receipt[key] = value
            helper["helper_failure_receipt"] = receipt
            invalid_helpers.append((name, helper))
        extra = _helper_report("failed")
        extra_receipt = dict(extra["helper_failure_receipt"])  # type: ignore[arg-type]
        extra_receipt["detail"] = "forged"
        extra["helper_failure_receipt"] = extra_receipt
        invalid_helpers.append(("extra", extra))

        for name, helper in invalid_helpers:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory(
                    prefix="finplanbr-helper-failure-mutation-"
                ) as directory:
                    root = Path(directory).resolve()
                    pwsh, windows_powershell, temporary_parent = self._paths(root)
                    runner = FakePowerShellRunner(
                        helper_stdout=spike._canonical_json(helper) + b"\n",
                        helper_returncode=1,
                    )
                    report, return_code, _lease = self._run_with_lease(
                        pwsh=pwsh,
                        windows_powershell=windows_powershell,
                        runner=runner,
                        temporary_parent=temporary_parent,
                    )
                self.assertEqual(return_code, 1)
                self.assertEqual(report["reason"], "helper_output_invalid")
                self.assertIsNone(report["helper_failure_receipt"])
                self.assertIsNone(report["driver_binding"])
                self.assertIsNone(report["helper_report"])
                for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
                    self.assertIsNone(report["artifacts"][key])

        rc_cases = (
            (
                "driver_rc_mismatch",
                FakePowerShellRunner(
                    helper_stdout=_helper_line("failed"),
                    helper_returncode=1,
                    driver_entry_return_code=0,
                ),
                "driver_return_code_mismatch",
            ),
            (
                "helper_rc_mismatch",
                FakePowerShellRunner(
                    helper_stdout=_helper_line("failed"),
                    helper_returncode=0,
                ),
                "helper_return_code_mismatch",
            ),
        )
        for name, runner, expected_reason in rc_cases:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory(
                    prefix="finplanbr-helper-failure-rc-mutation-"
                ) as directory:
                    root = Path(directory).resolve()
                    pwsh, windows_powershell, temporary_parent = self._paths(root)
                    report, return_code, _lease = self._run_with_lease(
                        pwsh=pwsh,
                        windows_powershell=windows_powershell,
                        runner=runner,
                        temporary_parent=temporary_parent,
                    )
                self.assertEqual(return_code, 1)
                self.assertEqual(report["reason"], expected_reason)
                self.assertIsNone(report["helper_failure_receipt"])
                self.assertIsNone(report["driver_binding"])
                self.assertIsNone(report["helper_report"])
                for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
                    self.assertIsNone(report["artifacts"][key])

    def test_legacy_and_random_temp_artifact_watchers_fail_closed_and_are_cleaned(self) -> None:
        targets = (
            Path("source/Program.cs"),
            Path("source/TokenProbe.cs"),
            Path("compile-token-probe.ps1"),
            Path("compile-helper.ps1"),
            Path("invoke-helper.ps1"),
            Path("build/WindowsAppContainerHelper.dll"),
            Path("work/TokenProbe.exe"),
            Path("unlisted-f8e71c044cf6.cs"),
        )
        for relative_target in targets:
            with self.subTest(target=relative_target):
                planted: list[Path] = []

                def watcher(
                    temporary: Path,
                    target_name: Path = relative_target,
                    observed: list[Path] = planted,
                ) -> None:
                    target = temporary / target_name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"MZ-forged-watcher-payload")
                    observed.append(target)

                with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-watcher-") as directory:
                    root = Path(directory).resolve()
                    pwsh, windows_powershell, temporary_parent = self._paths(root)
                    runner = FakePowerShellRunner(on_invoke=watcher)
                    report, return_code, _lease = self._run_with_lease(
                        pwsh=pwsh,
                        windows_powershell=windows_powershell,
                        runner=runner,
                        temporary_parent=temporary_parent,
                    )
                    self.assertEqual(len(planted), 1)
                    self.assertFalse(planted[0].exists())

                self.assertEqual(return_code, 1)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["reason"], "temporary_code_artifact_detected")
                self.assertEqual(report["temporary_code_artifacts"], "detected_and_rejected")
                self.assertEqual(report["temporary_directory_cleanup"], "verified")
                self.assertIsNone(report["helper_report"])

    def test_transient_policy_probe_is_not_misreported_as_never_created(self) -> None:
        observed: list[Path] = []

        def transient_probe(temporary: Path) -> None:
            probe = temporary / "__PSScriptPolicyTest_finplanbr.psm1"
            probe.write_text("transient", encoding="utf-8")
            observed.append(probe)
            probe.unlink()

        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-transient-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                temporary_parent=temporary_parent,
                runner=FakePowerShellRunner(on_invoke=transient_probe),
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())
        self.assertEqual(report["temporary_code_artifacts"], "absent_at_final_inventory")
        self.assertEqual(
            report["temporary_code_artifact_observation"],
            "final_inventory_only_transient_activity_not_observed",
        )
        with self.assertRaises(ValueError):
            spike._report(
                status="failed",
                reason="legacy_claim_rejected",
                temporary_code_artifacts="not_created",
            )

    @unittest.skipUnless(os.name == "nt", "Windows share-mode semantics")
    def test_checkout_program_write_and_replace_are_blocked_during_in_memory_consumer(self) -> None:
        original_program = spike.PROGRAM_SOURCE.read_bytes()
        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-source-lock-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            source = root / "checkout" / "Program.cs"
            source.parent.mkdir()
            source.write_bytes(original_program)
            replacement = root / "replacement.cs"
            replacement.write_bytes(b"public class Program { public static int Entry(string[] a) => 0; }")
            write_blocked: list[bool] = []
            replace_blocked: list[bool] = []

            def watcher(_temporary: Path) -> None:
                try:
                    source.write_bytes(b"forged-in-place-source")
                except OSError:
                    write_blocked.append(True)
                else:
                    write_blocked.append(False)
                try:
                    os.replace(replacement, source)
                except OSError:
                    replace_blocked.append(True)
                else:
                    replace_blocked.append(False)

            runner = FakePowerShellRunner(on_invoke=watcher)
            with mock.patch.object(spike, "PROGRAM_SOURCE", source):
                report, return_code, _lease = self._run_with_lease(
                    pwsh=pwsh,
                    windows_powershell=windows_powershell,
                    runner=runner,
                    temporary_parent=temporary_parent,
                )

        self.assertEqual(write_blocked, [True])
        self.assertEqual(replace_blocked, [True])
        self.assertEqual(return_code, 0)
        self.assertEqual(report["status"], "observed_pass")
        self.assertEqual(report["temporary_directory_cleanup"], "verified")

    @unittest.skipUnless(os.name == "nt", "Windows share-mode semantics")
    def test_preexisting_program_writer_prevents_snapshot_before_runner(self) -> None:
        original_program = spike.PROGRAM_SOURCE.read_bytes()
        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-source-writer-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            source = root / "Program.cs"
            source.write_bytes(original_program)
            runner = FakePowerShellRunner()
            with source.open("r+b"):
                with mock.patch.object(spike, "PROGRAM_SOURCE", source):
                    report, return_code, _lease = self._run_with_lease(
                        pwsh=pwsh,
                        windows_powershell=windows_powershell,
                        runner=runner,
                        temporary_parent=temporary_parent,
                    )

        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "artifact_read_lock_failed")
        self.assertEqual(report["temporary_directory_cleanup"], "not_created")
        self.assertEqual(report["temporary_code_artifacts"], "not_evaluated")
        self.assertEqual(report["temporary_code_artifact_observation"], "not_performed")
        self.assertEqual(runner.calls, [])

    def test_helper_extra_output_and_return_code_mismatch_fail_closed(self) -> None:
        scenarios = (
            (FakePowerShellRunner(helper_stdout=_helper_line() + b"noise\n"), "helper_output_invalid"),
            (FakePowerShellRunner(helper_returncode=1), "helper_return_code_mismatch"),
            (FakePowerShellRunner(helper_stderr=b"warning"), "powershell_stderr_present"),
        )
        for runner, expected_reason in scenarios:
            with self.subTest(reason=expected_reason):
                with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-test-") as directory:
                    root = Path(directory).resolve()
                    pwsh, windows_powershell, temporary_parent = self._paths(root)
                    report, return_code, _lease = self._run_with_lease(
                        pwsh=pwsh,
                        windows_powershell=windows_powershell,
                        runner=runner,
                        temporary_parent=temporary_parent,
                    )
                self.assertEqual(return_code, 1)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["reason"], expected_reason)
                self.assertEqual(report["temporary_directory_cleanup"], "verified")
                self.assertIsNone(report["driver_binding"])
                self.assertIsNone(report["helper_report"])
                for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
                    self.assertIsNone(report["artifacts"][key])

    def test_launch_exception_does_not_expose_sensitive_path(self) -> None:
        secret = "C:\\private\\customer-name\\probe.exe"
        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-test-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner(launch_error=OSError(secret))
            endpoint_lease = FakeEndpointLease()
            profile_lease = FakeProfileLease()
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
                endpoint_lease=endpoint_lease,
                profile_lease=profile_lease,
            )
        payload = spike._canonical_json(report)
        self.assertEqual(return_code, 1)
        self.assertEqual(report["reason"], "pwsh_launch_failed")
        self.assertEqual(endpoint_lease.start_count, 1)
        self.assertEqual(endpoint_lease.close_count, 1)
        self.assertEqual(report["endpoint_receipt"], boundary_fixture._endpoint_receipt())
        self.assertEqual(profile_lease.close_count, 1)
        self.assertTrue(report["profile_receipt"]["cleanup_complete"])
        self.assertNotIn(secret.encode("utf-8"), payload)

    def test_timeout_and_crash_after_profile_ownership_always_close_exact_lease(self) -> None:
        scenarios = (
            (
                FakePowerShellRunner(
                    launch_error=subprocess.TimeoutExpired(cmd="pwsh", timeout=180)
                ),
                "helper_execution_timeout",
            ),
            (FakePowerShellRunner(driver_stdout=b"{}\n"), "driver_output_invalid"),
        )
        for runner, expected_reason in scenarios:
            with self.subTest(reason=expected_reason):
                with tempfile.TemporaryDirectory(
                    prefix="finplanbr-profile-cleanup-regression-"
                ) as directory:
                    root = Path(directory).resolve()
                    pwsh, windows_powershell, temporary_parent = self._paths(root)
                    profile_lease = FakeProfileLease()
                    report, return_code, _lease = self._run_with_lease(
                        pwsh=pwsh,
                        windows_powershell=windows_powershell,
                        runner=runner,
                        temporary_parent=temporary_parent,
                        profile_lease=profile_lease,
                    )
                self.assertEqual(return_code, 1)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["reason"], expected_reason)
                self.assertEqual(profile_lease.close_count, 1)
                self.assertTrue(profile_lease.closed)
                self.assertTrue(report["profile_receipt"]["owned"])
                self.assertTrue(report["profile_receipt"]["cleanup_complete"])
                self.assertEqual(report["temporary_directory_cleanup"], "verified")
                self.assertIsNone(report["driver_binding"])
                self.assertIsNone(report["helper_report"])
                for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
                    self.assertIsNone(report["artifacts"][key])

    def test_profile_collision_fails_before_endpoint_or_runner_and_never_deletes(self) -> None:
        collision_receipt = boundary_fixture._profile_receipt()
        collision_receipt.update(
            {
                "cleanup_attempted": False,
                "cleanup_complete": False,
                "closed": True,
                "delete_attempt_hresults": [],
                "delete_succeeded": False,
                "final_delete_attempt_hresults": [],
                "final_delete_succeeded": False,
                "final_folder_absent": False,
                "first_folder_absent": False,
                "folder_boundary_component_count": 0,
                "folder_boundary_components_win32_valid": False,
                "folder_boundary_exact": False,
                "folder_boundary_nonempty_descendant": False,
                "folder_boundary_packages_ancestor": False,
                "folder_boundary_reason": "not_observed",
                "folder_boundary_reconstruction_matches": False,
                "folder_boundary_terminal_ac": False,
                "folder_file_id_128_hex": None,
                "folder_identity_revalidated_before_release": False,
                "folder_path_utf8_sha256": None,
                "folder_volume_serial_hex": None,
                "owned": False,
                "ownership_established": False,
                "profile_directory_handle_release_attempted": False,
                "profile_directory_handle_released": False,
                "recreate_attempted": False,
                "recreate_created_hresult": None,
                "recreate_folder_boundary_component_count": 0,
                "recreate_folder_boundary_components_win32_valid": False,
                "recreate_folder_boundary_exact": False,
                "recreate_folder_boundary_nonempty_descendant": False,
                "recreate_folder_boundary_packages_ancestor": False,
                "recreate_folder_boundary_reason": "not_observed",
                "recreate_folder_boundary_reconstruction_matches": False,
                "recreate_folder_boundary_terminal_ac": False,
                "recreate_folder_exists": False,
                "recreate_folder_reparse_free": False,
                "recreate_succeeded": False,
                "recreated_sid": None,
                "recreated_sid_matches": False,
            }
        )

        def collide(moniker: str) -> spike.ProfileLease:
            receipt = copy.deepcopy(collision_receipt)
            receipt["moniker"] = moniker
            failure = spike.ProfileLeaseFailure("profile_preexisting")
            failure.receipt = receipt
            raise failure

        with tempfile.TemporaryDirectory(prefix="finplanbr-profile-collision-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner()
            endpoint_lease = FakeEndpointLease()
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
                endpoint_lease=endpoint_lease,
                profile_acquirer=collide,
            )
        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "not_observed")
        self.assertEqual(report["reason"], "profile_preexisting")
        self.assertEqual(report["primary_reason"], "profile_preexisting")
        self.assertIsNone(report["cleanup_override_reason"])
        self.assertEqual(runner.calls, [])
        self.assertEqual(endpoint_lease.start_count, 0)
        self.assertFalse(report["profile_receipt"]["owned"])
        self.assertFalse(report["profile_receipt"]["cleanup_attempted"])
        self.assertEqual(report["profile_receipt"]["delete_attempt_hresults"], [])
        self.assertEqual(report["profile_receipt"]["final_delete_attempt_hresults"], [])

    def test_profile_cleanup_failure_overrides_otherwise_complete_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-profile-cleanup-failure-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            profile_lease = FakeProfileCleanupFailureLease()
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=FakePowerShellRunner(),
                temporary_parent=temporary_parent,
                profile_lease=profile_lease,
            )
        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "appcontainer_profile_cleanup_failed")
        self.assertEqual(report["cleanup_override_reason"], "appcontainer_profile_cleanup_failed")
        self.assertNotEqual(report["primary_reason"], report["reason"])
        self.assertFalse(report["profile_receipt"]["cleanup_complete"])
        self.assertFalse(report["profile_receipt"]["final_folder_absent"])
        self.assertIsNone(report["boundary_summary"])
        self.assertIsNone(report["driver_binding"])
        self.assertIsNone(report["helper_report"])
        for key in spike._DRIVER_DERIVED_ARTIFACT_KEYS:
            self.assertIsNone(report["artifacts"][key])
        _validate_final_report(
            report,
            expected_artifacts=copy.deepcopy(report["artifacts"]),  # type: ignore[arg-type]
            expected_public_artifacts=copy.deepcopy(report["artifacts"]),  # type: ignore[arg-type]
            expected_context_witness_digests=_public_context_witness_digests(report),
        )

    def test_profile_boundary_failure_preserves_primary_reason_under_cleanup_override(self) -> None:
        failure_receipt = boundary_fixture._profile_receipt()
        boundary_fixture._set_profile_boundary_state(
            failure_receipt, prefix="", reason="components_win32_invalid"
        )
        boundary_fixture._set_profile_boundary_state(
            failure_receipt, prefix="recreate_", reason="components_win32_invalid"
        )
        failure_receipt.update(
            {
                "cleanup_complete": False,
                "folder_file_id_128_hex": None,
                "folder_identity_revalidated_before_release": False,
                "folder_path_utf8_sha256": None,
                "folder_volume_serial_hex": None,
                "profile_directory_handle_release_attempted": False,
                "profile_directory_handle_released": False,
            }
        )

        def fail_after_owned_create(moniker: str) -> spike.ProfileLease:
            receipt = copy.deepcopy(failure_receipt)
            receipt["moniker"] = moniker
            failure = spike.ProfileLeaseFailure("profile_folder_boundary_failed")
            failure.receipt = receipt
            raise failure

        with tempfile.TemporaryDirectory(prefix="finplanbr-profile-boundary-failure-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            runner = FakePowerShellRunner()
            endpoint_lease = FakeEndpointLease()
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                runner=runner,
                temporary_parent=temporary_parent,
                endpoint_lease=endpoint_lease,
                profile_acquirer=fail_after_owned_create,
            )

        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "appcontainer_profile_cleanup_failed")
        self.assertEqual(report["primary_reason"], "profile_folder_boundary_failed")
        self.assertEqual(
            report["cleanup_override_reason"], "appcontainer_profile_cleanup_failed"
        )
        self.assertEqual(runner.calls, [])
        self.assertEqual(endpoint_lease.start_count, 0)

    def test_public_api_and_cli_reject_host_overrides_before_artifact_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-poc-") as directory:
            root = Path(directory).resolve()
            fake_host = root / "attacker-host.exe"
            fake_host.write_bytes(b"attacker-would-create-MZ-and-fake-JSON")
            temporary_parent = root / "temporary"
            temporary_parent.mkdir()
            before = tuple(temporary_parent.iterdir())
            with self.assertRaises(TypeError):
                spike.run_spike(pwsh=fake_host)  # type: ignore[call-arg]
            with mock.patch.object(spike.os, "write") as write:
                return_code = spike.main(
                    [
                        "--pwsh",
                        os.fspath(fake_host),
                        "--windows-powershell",
                        os.fspath(fake_host),
                        "--temp-root",
                        os.fspath(temporary_parent),
                    ]
                )
            after = tuple(temporary_parent.iterdir())

        self.assertEqual(return_code, 2)
        self.assertEqual(before, after)
        report = json.loads(write.call_args.args[1])
        self.assertEqual(report["reason"], "invalid_usage")
        self.assertEqual(report["temporary_directory_cleanup"], "not_created")
        self.assertTrue(all(value is None for value in report["artifacts"].values()))

    def test_host_preflight_tamper_classes_fail_before_runner_or_temp_output(self) -> None:
        reasons = (
            "host_path_unexpected",
            "host_hash_changed",
            "host_chain_mutable_by_current_token",
            "host_signature_invalid",
            "host_chain_owner_untrusted",
            "host_chain_reparse",
        )
        secret = "C:\\private\\attacker-host.exe"
        for reason in reasons:
            with self.subTest(reason=reason):
                with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-preflight-") as directory:
                    temporary_parent = Path(directory).resolve() / "temporary"
                    temporary_parent.mkdir()
                    runner = FakePowerShellRunner()

                    def reject_host(failure_reason: str = reason) -> FakeHostLease:
                        raise host_trust.HostTrustFailure("failed", failure_reason) from OSError(secret)

                    report, return_code = spike._run_spike(
                        temp_root=temporary_parent,
                        timeout_seconds=180,
                        platform_name="nt",
                        runner=runner,
                        nonce_factory=lambda byte_count: "ef" * byte_count,
                        host_acquirer=reject_host,
                    )
                    remaining = tuple(temporary_parent.iterdir())

                self.assertEqual(return_code, 1)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["reason"], reason)
                self.assertEqual(report["temporary_directory_cleanup"], "not_created")
                self.assertEqual(runner.calls, [])
                self.assertEqual(remaining, ())
                self.assertNotIn(secret.encode("utf-8"), spike._canonical_json(report))

    def test_host_hash_drift_before_first_compile_prevents_runner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-drift-") as directory:
            root = Path(directory).resolve()
            pwsh, windows_powershell, temporary_parent = self._paths(root)
            lease = FakeHostLease(
                pwsh,
                windows_powershell,
                fail_revalidation_number=2,
                fail_reason="host_hash_changed",
            )
            runner = FakePowerShellRunner()
            report, return_code, _lease = self._run_with_lease(
                pwsh=pwsh,
                windows_powershell=windows_powershell,
                temporary_parent=temporary_parent,
                runner=runner,
                lease=lease,
            )
        self.assertEqual(return_code, 1)
        self.assertEqual(report["reason"], "host_hash_changed")
        self.assertEqual(runner.calls, [])
        self.assertEqual(report["temporary_directory_cleanup"], "verified")

    def test_host_identity_hash_changes_request_and_report_binding(self) -> None:
        requests: list[str] = []
        reports: list[dict[str, object]] = []
        for digest_byte in ("a", "c"):
            with tempfile.TemporaryDirectory(prefix="finplanbr-appcontainer-binding-") as directory:
                root = Path(directory).resolve()
                pwsh, windows_powershell, temporary_parent = self._paths(root)
                lease = FakeHostLease(pwsh, windows_powershell, pwsh_digest_byte=digest_byte)
                runner = FakePowerShellRunner()
                report, return_code, _lease = self._run_with_lease(
                    pwsh=pwsh,
                    windows_powershell=windows_powershell,
                    temporary_parent=temporary_parent,
                    runner=runner,
                    lease=lease,
                    nonce_factory=lambda byte_count: "12" * byte_count,
                )
            self.assertEqual(return_code, 0)
            requests.append(report["artifacts"]["invocation_request_sha256"])  # type: ignore[index,arg-type]
            reports.append(report["host_trust"])  # type: ignore[arg-type]
        self.assertNotEqual(requests[0], requests[1])
        self.assertNotEqual(
            reports[0][host_trust.POWERSHELL_7_ROLE],
            reports[1][host_trust.POWERSHELL_7_ROLE],
        )

    def test_non_windows_is_not_observed_and_never_a_cell(self) -> None:
        report, return_code = spike._run_spike(platform_name="posix")
        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "not_observed")
        self.assertEqual(report["reason"], "windows_required")
        self.assertEqual(report["portability_cell"], "not_counted")
        self.assertEqual(report["temporary_code_artifacts"], "not_evaluated")
        self.assertEqual(report["temporary_code_artifact_observation"], "not_performed")

    def test_invalid_cli_usage_is_canonical_json_and_rc2(self) -> None:
        with mock.patch.object(spike.os, "write") as write:
            return_code = spike.main(["--unknown-option"])
        self.assertEqual(return_code, 2)
        payload = write.call_args.args[1]
        self.assertEqual(payload.count(b"\n"), 1)
        report = json.loads(payload)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "invalid_usage")
        self.assertEqual(report["portability_cell"], "not_counted")


@unittest.skipUnless(os.name == "nt", "PowerShell module-resolution regression requires Windows")
class WindowsAppContainerPowerShellResolutionTests(unittest.TestCase):
    def test_watchdog_capture_enforces_output_budgets_during_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-watchdog-output-") as directory:
            root = Path(directory).resolve()
            for stream in ("stdout", "stderr"):
                target = "sys.stdout.buffer" if stream == "stdout" else "sys.stderr.buffer"
                command = [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    (
                        f"import sys,time;{target}.write(b'x'*"
                        f"{spike.MAX_DRIVER_OUTPUT_BYTES + 1});{target}.flush();time.sleep(30)"
                    ),
                ]
                started = time.monotonic()
                with self.assertRaisesRegex(spike.SpikeFailure, "powershell_output_limit_exceeded"):
                    spike._run_command_in_watchdog_job(
                        command,
                        temporary=root,
                        timeout_seconds=2,
                        timeout_reason="timeout",
                        launch_reason="launch",
                        input_bytes=b"",
                    )
                self.assertLess(time.monotonic() - started, 5)

    def test_outer_and_inner_frames_reject_noncanonical_bytes_before_consumption(self) -> None:
        driver_bytes = spike.IN_MEMORY_PWSH_DRIVER.encode("utf-8")
        program_bytes = (
            b"using System;\n"
            b"public static class Program {\n"
            b"    public static int Entry(string[] arguments) {\n"
            b'        Console.Out.WriteLine("{}");\n'
            b"        return 0;\n"
            b"    }\n"
            b"}\n"
        )
        program_sha256 = hashlib.sha256(program_bytes).hexdigest()
        probe_bytes = b"# protocol fixture\n"
        probe_sha256 = hashlib.sha256(probe_bytes).hexdigest()

        with tempfile.TemporaryDirectory(prefix="finplanbr-frame-binding-") as directory:
            runtime_temp = Path(directory).resolve()
            work_root = runtime_temp / "work"
            work_root.mkdir()
            environment = dict(os.environ)
            environment.update({"TEMP": os.fspath(runtime_temp), "TMP": os.fspath(runtime_temp)})
            with host_trust.acquire_trusted_powershell_hosts() as hosts:
                inner_document = {
                    "format": spike.IN_MEMORY_INPUT_FORMAT,
                    "moniker": "finplanbrac-" + "ef" * 12,
                    **_endpoint_frame_fields(),
                    "probe_source_base64": base64.b64encode(probe_bytes).decode("ascii"),
                    "probe_source_sha256": probe_sha256,
                    **_profile_frame_fields("finplanbrac-" + "ef" * 12),
                    "program_cs_base64": base64.b64encode(program_bytes).decode("ascii"),
                    "program_cs_sha256": program_sha256,
                    "python_runtime_root_utf8_base64": base64.b64encode(
                        os.fspath(runtime_temp).encode("utf-8")
                    ).decode("ascii"),
                    "work_root_utf8_base64": base64.b64encode(
                        os.fspath(work_root).encode("utf-8")
                    ).decode("ascii"),
                }
                canonical_inner = spike._canonical_json(inner_document) + b"\n"
                canonical_outer = spike._bootstrap_input(driver_bytes, canonical_inner)

                def invoke(
                    payload: bytes,
                    *,
                    expected_inner: bytes = canonical_inner,
                ) -> subprocess.CompletedProcess[bytes]:
                    command = [
                        hosts.powershell_7.path,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-EncodedCommand",
                        base64.b64encode(
                            spike._bootstrap_bytes(driver_bytes, expected_inner)
                        ).decode("ascii"),
                    ]
                    self.assertLessEqual(
                        spike._windows_command_line_length(command),
                        spike.MAX_WINDOWS_COMMAND_LINE_CHARACTERS
                        - spike.MIN_WINDOWS_COMMAND_LINE_HEADROOM_CHARACTERS,
                    )
                    hosts.revalidate()
                    result = subprocess.run(
                        command,
                        input=payload,
                        capture_output=True,
                        check=False,
                        env=environment,
                        cwd=runtime_temp,
                        timeout=30,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    hosts.revalidate()
                    return result

                positive_control = invoke(canonical_outer)
                self.assertEqual(positive_control.returncode, 0, positive_control.stderr)
                self.assertEqual(positive_control.stderr, b"")
                binding, helper_stdout = spike._decode_driver_output(
                    positive_control.stdout,
                    expected_bootstrap_input_sha256=hashlib.sha256(canonical_outer).hexdigest(),
                    expected_driver_sha256=hashlib.sha256(driver_bytes).hexdigest(),
                    expected_input_sha256=hashlib.sha256(canonical_inner).hexdigest(),
                    expected_program_sha256=program_sha256,
                )
                self.assertEqual(helper_stdout, b"{}\n")
                self.assertEqual(
                    binding["observed_bootstrap_input_sha256"],
                    hashlib.sha256(canonical_outer).hexdigest(),
                )
                self.assertEqual(
                    binding["observed_in_memory_input_sha256"],
                    hashlib.sha256(canonical_inner).hexdigest(),
                )

                outer_document = json.loads(canonical_outer)
                reordered_outer = dict(reversed(tuple(outer_document.items())))
                duplicate_outer = canonical_outer.replace(
                    b'{"driver_base64":',
                    b'{"driver_base64":"duplicate","driver_base64":',
                    1,
                )
                outer_extra = dict(outer_document)
                outer_extra["unexpected"] = "rejected"
                outer_noncanonical_base64 = dict(outer_document)
                outer_noncanonical_base64["driver_base64"] += " "
                outer_driver_hash = dict(outer_document)
                outer_driver_hash["driver_sha256"] = str(
                    outer_driver_hash["driver_sha256"]
                ).upper()
                outer_request_hash = dict(outer_document)
                outer_request_hash["request_sha256"] = str(
                    outer_request_hash["request_sha256"]
                ).upper()
                rebound_inner_document = dict(inner_document)
                rebound_inner_document["moniker"] = "finplanbrac-" + "12" * 12
                rebound_inner = spike._canonical_json(rebound_inner_document) + b"\n"
                outer_mutations = {
                    "leading_space": b" " + canonical_outer,
                    "trailing_space": canonical_outer[:-1] + b" \n",
                    "key_reorder": json.dumps(
                        reordered_outer,
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ).encode("ascii")
                    + b"\n",
                    "crlf": canonical_outer[:-1] + b"\r\n",
                    "multiline": canonical_outer.replace(b',"driver_sha256"', b',\n"driver_sha256"', 1),
                    "duplicate": duplicate_outer,
                    "extra": spike._canonical_json(outer_extra) + b"\n",
                    "noncanonical_base64": spike._canonical_json(outer_noncanonical_base64) + b"\n",
                    "noncanonical_driver_hash": spike._canonical_json(outer_driver_hash) + b"\n",
                    "noncanonical_request_hash": spike._canonical_json(outer_request_hash) + b"\n",
                    "self_rebound_inner": spike._bootstrap_input(driver_bytes, rebound_inner),
                }
                for mutation_name, mutated_outer in outer_mutations.items():
                    with self.subTest(layer="outer", mutation=mutation_name):
                        completed = invoke(mutated_outer)
                        self.assertEqual(completed.returncode, 1)
                        self.assertEqual(completed.stdout, b"")
                        self.assertIn(b"in_memory_bootstrap_failed", completed.stderr)
                        self.assertNotIn(b"in_memory_driver_failed", completed.stderr)

                reordered_inner = dict(reversed(tuple(inner_document.items())))
                duplicate_inner = canonical_inner.replace(
                    b'{"format":',
                    b'{"format":"duplicate","format":',
                    1,
                )
                inner_extra = dict(inner_document)
                inner_extra["unexpected"] = "rejected"
                inner_noncanonical_base64 = dict(inner_document)
                inner_noncanonical_base64["program_cs_base64"] += " "
                inner_hash = dict(inner_document)
                inner_hash["program_cs_sha256"] = str(inner_hash["program_cs_sha256"]).upper()
                inner_mutations = {
                    "leading_space": b" " + canonical_inner,
                    "trailing_space": canonical_inner[:-1] + b" \n",
                    "key_reorder": json.dumps(
                        reordered_inner,
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ).encode("ascii")
                    + b"\n",
                    "crlf": canonical_inner[:-1] + b"\r\n",
                    "multiline": canonical_inner.replace(b',"moniker"', b',\n"moniker"', 1),
                    "duplicate": duplicate_inner,
                    "extra": spike._canonical_json(inner_extra) + b"\n",
                    "noncanonical_base64": spike._canonical_json(inner_noncanonical_base64) + b"\n",
                    "noncanonical_hash": spike._canonical_json(inner_hash) + b"\n",
                }
                for mutation_name, mutated_inner in inner_mutations.items():
                    with self.subTest(layer="inner", mutation=mutation_name):
                        completed = invoke(
                            spike._bootstrap_input(driver_bytes, mutated_inner),
                            expected_inner=mutated_inner,
                        )
                        self.assertEqual(completed.returncode, 1)
                        self.assertEqual(completed.stdout, b"")
                        self.assertIn(b"in_memory_bootstrap_failed", completed.stderr)
                        self.assertNotIn(b"in_memory_driver_failed", completed.stderr)

    def test_exact_driver_has_no_commands_and_ignores_malicious_utility_module(self) -> None:
        driver_bytes = spike.IN_MEMORY_PWSH_DRIVER.encode("utf-8")
        bootstrap_template = spike.IN_MEMORY_PWSH_BOOTSTRAP_TEMPLATE
        instantiated_bootstrap = spike._bootstrap_bytes(driver_bytes, b"{}\n").decode(
            "utf-16-le"
        )
        bootstrap_first_statement = next(
            line.strip() for line in bootstrap_template.splitlines() if line.strip()
        )
        self.assertEqual(bootstrap_first_statement, "$PSModuleAutoLoadingPreference = 'None'")
        first_statement = next(
            line.strip() for line in spike.IN_MEMORY_PWSH_DRIVER.splitlines() if line.strip()
        )
        self.assertEqual(first_statement, "$PSModuleAutoLoadingPreference = 'None'")
        for removed_command in (
            "Add-Type",
            "Compare-Object",
            "ConvertFrom-Json",
            "Join-Path",
            "Set-StrictMode",
            "Sort-Object",
        ):
            self.assertNotIn(removed_command, spike.IN_MEMORY_PWSH_DRIVER)

        parser_driver = r"""
$source = [Console]::In.ReadToEnd()
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput(
    $source,
    [ref] $tokens,
    [ref] $parseErrors
)
$commands = $ast.FindAll(
    { param($node) $node -is [Management.Automation.Language.CommandAst] },
    $true
)
[Console]::WriteLine(([string] $parseErrors.Count + '|' + [string] $commands.Count))
"""
        helper_json = _helper_line().decode("utf-8").removesuffix("\n")
        csharp_helper_literal = json.dumps(helper_json, ensure_ascii=True)
        program_bytes = (
            "using System;\n"
            "public static class Program {\n"
            "    public static int Entry(string[] arguments) {\n"
            "        if (arguments.Length != 10) return 1;\n"
            f"        Console.Out.WriteLine({csharp_helper_literal});\n"
            "        return 0;\n"
            "    }\n"
            "}\n"
        ).encode()
        program_sha256 = hashlib.sha256(program_bytes).hexdigest()
        probe_bytes = b"# module resolution fixture\n"
        probe_sha256 = hashlib.sha256(probe_bytes).hexdigest()

        with tempfile.TemporaryDirectory(prefix="finplanbr-powershell-resolution-") as directory:
            root = Path(directory).resolve()
            module_directory = root / "modules" / "Microsoft.PowerShell.Utility"
            module_directory.mkdir(parents=True)
            marker = root / "malicious-module-loaded.txt"
            forged_helper_base64 = base64.b64encode(_helper_line()).decode("ascii")
            (module_directory / "Microsoft.PowerShell.Utility.psm1").write_text(
                "[IO.File]::WriteAllText($env:FINPLANBR_MALICIOUS_MODULE_MARKER, 'loaded')\n"
                "function ConvertFrom-Json {\n"
                "    $forged = [Convert]::FromBase64String($env:FINPLANBR_FORGED_HELPER_BASE64)\n"
                "    $output = [Console]::OpenStandardOutput()\n"
                "    $output.Write($forged, 0, $forged.Length)\n"
                "    $output.Flush()\n"
                "    [Environment]::Exit(0)\n"
                "}\n"
                "Export-ModuleMember -Function ConvertFrom-Json\n",
                encoding="utf-8",
            )
            (module_directory / "Microsoft.PowerShell.Utility.psd1").write_text(
                "@{\n"
                "RootModule = 'Microsoft.PowerShell.Utility.psm1'\n"
                "ModuleVersion = '999.0.0'\n"
                "GUID = '9f27a6b9-9ee1-4ac0-8180-3ce6fde5d21d'\n"
                "FunctionsToExport = @('ConvertFrom-Json')\n"
                "CmdletsToExport = @()\n"
                "VariablesToExport = @()\n"
                "AliasesToExport = @()\n"
                "}\n",
                encoding="utf-8",
            )
            runtime_temp = root / "runtime-temp"
            work_root = runtime_temp / "work"
            work_root.mkdir(parents=True)
            inherited_module_path = os.environ.get("PSModulePath", "")
            environment = {
                key: value
                for key, value in os.environ.items()
                if key.casefold() not in {"psmoduleanalysiscachepath", "psmodulepath"}
            }
            environment.update(
                {
                    "FINPLANBR_FORGED_HELPER_BASE64": forged_helper_base64,
                    "FINPLANBR_MALICIOUS_MODULE_MARKER": os.fspath(marker),
                    "PSModuleAnalysisCachePath": os.fspath(root / "module-analysis-cache"),
                    "PSModulePath": os.fspath(root / "modules")
                    + (os.pathsep + inherited_module_path if inherited_module_path else ""),
                    "TEMP": os.fspath(runtime_temp),
                    "TMP": os.fspath(runtime_temp),
                }
            )
            with host_trust.acquire_trusted_powershell_hosts() as hosts:
                pwsh = hosts.powershell_7.path
                for script_text in (instantiated_bootstrap, spike.IN_MEMORY_PWSH_DRIVER):
                    parser = subprocess.run(
                        [
                            pwsh,
                            "-NoLogo",
                            "-NoProfile",
                            "-NonInteractive",
                            "-EncodedCommand",
                            base64.b64encode(parser_driver.encode("utf-16-le")).decode("ascii"),
                        ],
                        input=script_text.encode("utf-8"),
                        capture_output=True,
                        check=False,
                        env=environment,
                        cwd=runtime_temp,
                        timeout=30,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    self.assertEqual(parser.returncode, 0, parser.stderr)
                    self.assertEqual(parser.stderr, b"")
                    self.assertEqual(parser.stdout.strip(), b"0|0")

                positive_control = subprocess.run(
                    [
                        pwsh,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-EncodedCommand",
                        base64.b64encode(
                            "'{}' | ConvertFrom-Json -Depth 8 | Out-Null".encode("utf-16-le")
                        ).decode("ascii"),
                    ],
                    capture_output=True,
                    check=False,
                    env=environment,
                    cwd=runtime_temp,
                    timeout=30,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                self.assertEqual(positive_control.returncode, 0, positive_control.stderr)
                self.assertTrue(
                    marker.exists(),
                    "malicious module positive control did not load: "
                    f"stdout={positive_control.stdout!r}, stderr={positive_control.stderr!r}",
                )
                marker.unlink()

                stdin_request = {
                    "format": spike.IN_MEMORY_INPUT_FORMAT,
                    "moniker": "finplanbrac-" + "ab" * 12,
                    **_endpoint_frame_fields(),
                    "probe_source_base64": base64.b64encode(probe_bytes).decode("ascii"),
                    "probe_source_sha256": probe_sha256,
                    **_profile_frame_fields("finplanbrac-" + "ab" * 12),
                    "program_cs_base64": base64.b64encode(program_bytes).decode("ascii"),
                    "program_cs_sha256": program_sha256,
                    "python_runtime_root_utf8_base64": base64.b64encode(
                        os.fspath(runtime_temp).encode("utf-8")
                    ).decode("ascii"),
                    "work_root_utf8_base64": base64.b64encode(
                        os.fspath(work_root).encode("utf-8")
                    ).decode("ascii"),
                }
                stdin_bytes = spike._canonical_json(stdin_request) + b"\n"
                bootstrap_bytes = spike._bootstrap_bytes(driver_bytes, stdin_bytes)
                command = [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-EncodedCommand",
                    base64.b64encode(bootstrap_bytes).decode("ascii"),
                ]
                self.assertLessEqual(
                    spike._windows_command_line_length(command),
                    spike.MAX_WINDOWS_COMMAND_LINE_CHARACTERS
                    - spike.MIN_WINDOWS_COMMAND_LINE_HEADROOM_CHARACTERS,
                )
                hosts.revalidate()
                bootstrap_input = spike._bootstrap_input(driver_bytes, stdin_bytes)
                completed = subprocess.run(
                    command,
                    input=bootstrap_input,
                    capture_output=True,
                    check=False,
                    env=environment,
                    cwd=runtime_temp,
                    timeout=60,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                hosts.revalidate()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, b"")
            self.assertFalse(marker.exists(), "malicious CurrentUser-priority module was loaded")
            binding, helper_stdout = spike._decode_driver_output(
                completed.stdout,
                expected_bootstrap_input_sha256=hashlib.sha256(bootstrap_input).hexdigest(),
                expected_driver_sha256=hashlib.sha256(driver_bytes).hexdigest(),
                expected_input_sha256=hashlib.sha256(stdin_bytes).hexdigest(),
                expected_program_sha256=program_sha256,
            )
            self.assertEqual(binding["program_cs_sha256"], program_sha256)
            self.assertRegex(binding["compiled_assembly_sha256"], r"\A[0-9a-f]{64}\Z")
            self.assertRegex(binding["compiler_reference_set_sha256"], r"\A[0-9a-f]{64}\Z")
            self.assertEqual(binding["program_entry_return_code"], 0)
            self.assertEqual(spike._decode_helper_report(helper_stdout), _helper_report())
            self.assertEqual(tuple(work_root.iterdir()), ())

    def test_instantiated_bootstrap_ignores_preloaded_functions_and_aliases(self) -> None:
        helper_json = _helper_line().decode("utf-8").removesuffix("\n")
        program_bytes = (
            "using System;\n"
            "public static class Program {\n"
            "    public static int Entry(string[] arguments) {\n"
            "        if (arguments.Length != 10) return 1;\n"
            f"        Console.Out.WriteLine({json.dumps(helper_json, ensure_ascii=True)});\n"
            "        return 0;\n"
            "    }\n"
            "}\n"
        ).encode()
        program_sha256 = hashlib.sha256(program_bytes).hexdigest()
        probe_bytes = b"# preloaded fixture\n"
        probe_sha256 = hashlib.sha256(probe_bytes).hexdigest()
        driver_bytes = spike.IN_MEMORY_PWSH_DRIVER.encode("utf-8")
        prelude = r"""
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
public static class Program {
    public static int Entry(string[] arguments) {
        System.IO.File.WriteAllText(
            System.Environment.GetEnvironmentVariable("FINPLANBR_PRELOADED_MARKER"),
            "preloaded_type"
        );
        return 0;
    }
}
'@
function global:finplanbrEvil {
    [IO.File]::WriteAllText($env:FINPLANBR_PRELOADED_MARKER, 'called')
    throw 'preloaded_command_called'
}
function global:ConvertFrom-Json { finplanbrEvil }
function global:Add-Type { finplanbrEvil }
function global:Join-Path { finplanbrEvil }
function global:Compare-Object { finplanbrEvil }
function global:Sort-Object { finplanbrEvil }
function global:Set-StrictMode { finplanbrEvil }
function global:Microsoft.PowerShell.Utility\Add-Type { finplanbrEvil }
function global:Microsoft.PowerShell.Core\Import-Module { finplanbrEvil }
Set-Alias -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -Value finplanbrEvil -Scope Global -Force
Set-Alias -Name 'Add-Type' -Value finplanbrEvil -Scope Global -Force
"""
        with tempfile.TemporaryDirectory(prefix="finplanbr-powershell-preloaded-") as directory:
            runtime_temp = Path(directory).resolve()
            work_root = runtime_temp / "work"
            work_root.mkdir()
            marker = runtime_temp / "preloaded-command-called.txt"
            environment = dict(os.environ)
            environment.update(
                {
                    "FINPLANBR_PRELOADED_MARKER": os.fspath(marker),
                    "TEMP": os.fspath(runtime_temp),
                    "TMP": os.fspath(runtime_temp),
                }
            )
            with host_trust.acquire_trusted_powershell_hosts() as hosts:
                positive_control = subprocess.run(
                    [
                        hosts.powershell_7.path,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-EncodedCommand",
                        base64.b64encode(
                            (prelude + "\nMicrosoft.PowerShell.Utility\\Add-Type\n").encode(
                                "utf-16-le"
                            )
                        ).decode("ascii"),
                    ],
                    capture_output=True,
                    check=False,
                    env=environment,
                    cwd=runtime_temp,
                    timeout=30,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                self.assertNotEqual(positive_control.returncode, 0)
                self.assertTrue(
                    marker.exists(),
                    "preloaded function positive control was not invoked: "
                    f"stdout={positive_control.stdout!r}, stderr={positive_control.stderr!r}",
                )
                marker.unlink()
                stdin_request = {
                    "format": spike.IN_MEMORY_INPUT_FORMAT,
                    "moniker": "finplanbrac-" + "cd" * 12,
                    **_endpoint_frame_fields(),
                    "probe_source_base64": base64.b64encode(probe_bytes).decode("ascii"),
                    "probe_source_sha256": probe_sha256,
                    **_profile_frame_fields("finplanbrac-" + "cd" * 12),
                    "program_cs_base64": base64.b64encode(program_bytes).decode("ascii"),
                    "program_cs_sha256": program_sha256,
                    "python_runtime_root_utf8_base64": base64.b64encode(
                        os.fspath(runtime_temp).encode("utf-8")
                    ).decode("ascii"),
                    "work_root_utf8_base64": base64.b64encode(
                        os.fspath(work_root).encode("utf-8")
                    ).decode("ascii"),
                }
                stdin_bytes = spike._canonical_json(stdin_request) + b"\n"
                exact_bootstrap = spike._bootstrap_bytes(driver_bytes, stdin_bytes)
                environment["FINPLANBR_TEST_BOOTSTRAP_BASE64"] = base64.b64encode(
                    exact_bootstrap
                ).decode("ascii")
                wrapped_bootstrap = (
                    prelude
                    + "\n$finplanbrBootstrap = [Text.Encoding]::Unicode.GetString("
                    + "[Convert]::FromBase64String($env:FINPLANBR_TEST_BOOTSTRAP_BASE64))\n"
                    + "[Management.Automation.ScriptBlock]::Create($finplanbrBootstrap).Invoke()\n"
                )
                command = [
                    hosts.powershell_7.path,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-EncodedCommand",
                    base64.b64encode(wrapped_bootstrap.encode("utf-16-le")).decode("ascii"),
                ]
                self.assertLessEqual(
                    spike._windows_command_line_length(command),
                    spike.MAX_WINDOWS_COMMAND_LINE_CHARACTERS
                    - spike.MIN_WINDOWS_COMMAND_LINE_HEADROOM_CHARACTERS,
                )
                hosts.revalidate()
                bootstrap_input = spike._bootstrap_input(driver_bytes, stdin_bytes)
                completed = subprocess.run(
                    command,
                    input=bootstrap_input,
                    capture_output=True,
                    check=False,
                    env=environment,
                    cwd=runtime_temp,
                    timeout=60,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                hosts.revalidate()

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, b"")
            self.assertFalse(marker.exists(), "preloaded function or alias was invoked")
            binding, helper_stdout = spike._decode_driver_output(
                completed.stdout,
                expected_bootstrap_input_sha256=hashlib.sha256(bootstrap_input).hexdigest(),
                expected_driver_sha256=hashlib.sha256(driver_bytes).hexdigest(),
                expected_input_sha256=hashlib.sha256(stdin_bytes).hexdigest(),
                expected_program_sha256=program_sha256,
            )
            self.assertEqual(binding["program_entry_return_code"], 0)
            self.assertEqual(spike._decode_helper_report(helper_stdout), _helper_report())
            self.assertEqual(tuple(work_root.iterdir()), ())

    def test_bootstrap_fails_closed_before_driver_under_constrained_language(self) -> None:
        driver_bytes = spike.IN_MEMORY_PWSH_DRIVER.encode("utf-8")
        bootstrap_text = spike._bootstrap_bytes(driver_bytes, b"{}\n").decode("utf-16-le")
        constrained_bootstrap = (
            "$ExecutionContext.SessionState.LanguageMode = "
            "[Management.Automation.PSLanguageMode]::ConstrainedLanguage\n"
            + bootstrap_text
        ).encode("utf-16-le")
        command_suffix = [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            base64.b64encode(constrained_bootstrap).decode("ascii"),
        ]
        with tempfile.TemporaryDirectory(prefix="finplanbr-powershell-policy-") as directory:
            runtime_temp = Path(directory).resolve()
            environment = dict(os.environ)
            environment.update({"TEMP": os.fspath(runtime_temp), "TMP": os.fspath(runtime_temp)})
            with host_trust.acquire_trusted_powershell_hosts() as hosts:
                command = [hosts.powershell_7.path, *command_suffix]
                self.assertLessEqual(
                    spike._windows_command_line_length(command),
                    spike.MAX_WINDOWS_COMMAND_LINE_CHARACTERS
                    - spike.MIN_WINDOWS_COMMAND_LINE_HEADROOM_CHARACTERS,
                )
                hosts.revalidate()
                completed = subprocess.run(
                    command,
                    input=spike._bootstrap_input(driver_bytes, b"{}\n"),
                    capture_output=True,
                    check=False,
                    env=environment,
                    cwd=runtime_temp,
                    timeout=30,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                hosts.revalidate()

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b"")
        self.assertIn(b"in_memory_bootstrap_failed", completed.stderr)


@unittest.skipUnless(
    RUN_REAL_DIAGNOSTIC,
    "diagnostic-only Windows AppContainer test; opt in explicitly and never count it as a portability cell",
)
class WindowsAppContainerRealDiagnosticTests(unittest.TestCase):
    def test_real_private_runner_prefixes_outer_frame_and_fails_before_driver(self) -> None:
        observed: dict[str, str] = {}

        def prefixing_runner(
            command: list[str],
            **kwargs: object,
        ) -> subprocess.CompletedProcess[bytes]:
            producer_input = kwargs.get("input")
            if not isinstance(producer_input, bytes):
                raise AssertionError("producer bootstrap bytes required")
            consumed_input = b" " + producer_input
            observed["producer_sha256"] = hashlib.sha256(producer_input).hexdigest()
            observed["consumed_sha256"] = hashlib.sha256(consumed_input).hexdigest()
            mutated_kwargs = dict(kwargs)
            mutated_kwargs["input"] = consumed_input
            return subprocess.run(command, **mutated_kwargs)  # type: ignore[arg-type]

        report, return_code = spike._run_spike(
            platform_name="nt",
            timeout_seconds=300,
            runner=prefixing_runner,
        )

        self.assertEqual(return_code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "powershell_stderr_present")
        self.assertIsNone(report["driver_binding"])
        self.assertIsNone(report["helper_report"])
        self.assertEqual(report["temporary_directory_cleanup"], "verified")
        self.assertEqual(report["temporary_code_artifacts"], "absent_at_final_inventory")
        self.assertEqual(
            report["artifacts"]["bootstrap_input_sha256"],  # type: ignore[index]
            observed["producer_sha256"],
        )
        self.assertNotEqual(observed["producer_sha256"], observed["consumed_sha256"])

    def test_real_windows_diagnostic_is_explicitly_not_a_portability_cell(self) -> None:
        report, return_code = spike.run_spike(timeout_seconds=300)
        self.assertEqual(return_code, 0)
        self.assertEqual(report["status"], "observed_pass")
        self.assertIsNotNone(report["helper_report"])
        self.assertIsNotNone(report["host_trust"])
        self.assertEqual(report["temporary_directory_cleanup"], "verified")
        self.assertEqual(report["temporary_code_artifacts"], "absent_at_final_inventory")
        self.assertEqual(
            report["temporary_code_artifact_observation"],
            "final_inventory_only_transient_activity_not_observed",
        )
        self.assertEqual(report["portability_cell"], "not_counted")
        self.assertIs(report["diagnostic_only"], True)
        self.assertEqual(report["authority"], "none")
        self.assertEqual(report["evidence_authentication"], "not_implemented")
        self.assertIs(report["release_authorized"], False)
        self.assertTrue(all(value is not None for value in report["artifacts"].values()))  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
