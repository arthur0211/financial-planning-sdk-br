from __future__ import annotations

import copy
import hashlib
import ntpath
import unittest

from scripts import windows_appcontainer_boundary_report as boundary

SID = "S-1-15-2-101-102-103-104-105-106-107-108-109-110-111"
CAPABILITY = "S-1-15-3-101-102-103-104-105-106-107|0x00000004"
INTERNET_CLIENT_CAPABILITY = "S-1-15-3-1|0x00000004"
MONIKER = "finplanbrac-0123456789abcdef01234567"
RUNTIME = r"C:\Temp\fpbr\runtime"
SOURCE = r"C:\Temp\fpbr\source"
PROFILE = r"C:\Users\owner\AppData\Local\Packages\profile"
GUEST_IP = "172.29.60.71"
GUEST_PREFIX = 20
GUEST_BOOT_ID = "f596e7b8-c93b-4b3f-86b1-1faf403afc0a"
GUEST_NETNS = "net:[4026532896]"
LISTENER_PID = 321
HOST_LAUNCHER_PID = 654
LISTENER_PORT = 55_123
LISTENER_SOCKET_INODE = 987_654
LISTENER_STARTTIME_TICKS = 12_345
LISTENER_COMMAND_SHA256 = "d" * 64
STARTUP_NONCE_SHA256 = "e" * 64
STARTUP_SCRIPT_SHA256 = "f" * 64
BUSYBOX_SHA256 = "0" * 64
HOST_LAUNCHER_CREATION_TIME_100NS = 133_800_000_000_000_000
WATCHDOG_PID = 322
WATCHDOG_STARTTIME_TICKS = 12_346
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
PROFILE_PRELAUNCH_SHA256 = "1" * 64
PROFILE_FILE_ID_128_HEX = "12" * 16
PROFILE_PATH_UTF8_SHA256 = "2" * 64
PROFILE_VOLUME_SERIAL_HEX = "34" * 8
PROFILE_NETWORK_REQUEST_PATH_UTF8_SHA256 = "3" * 64
NETWORK_REQUEST_FILE_ID_128_HEX = "56" * 16
PREFLIGHT_REQUEST_FILE_ID_128_HEX = "78" * 16
RUNTIME_ROOT_FILE_ID_128_HEX = "9a" * 16
SOURCE_ROOT_FILE_ID_128_HEX = "9b" * 16
PYTHON_FILE_ID_128_HEX = "9c" * 16
BOUNDARY_VOLUME_SERIAL_HEX = "ab" * 8


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _path_sha(path: str) -> str:
    canonical = ntpath.normpath(path).replace("/", "\\").lower()
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _path_context() -> dict[str, object]:
    return {"runtime_root": RUNTIME, "source_root": SOURCE}


def _path_identity(
    path: str, *, role: str, leaf: str, file_id: str
) -> dict[str, object]:
    return {
        "file_id_128_hex": file_id,
        "identity_format": boundary.FILE_IDENTITY_FORMAT,
        "leaf": leaf,
        "path_utf8_sha256": _path_sha(path),
        "role": role,
        "volume_serial_hex": BOUNDARY_VOLUME_SERIAL_HEX,
    }


def _token(*, internet_client: bool = False) -> dict[str, object]:
    capabilities = [CAPABILITY]
    if internet_client:
        capabilities.append(INTERNET_CLIENT_CAPABILITY)
    capabilities.sort()
    return {
        "all_application_packages_membership_api": False,
        "all_application_packages_membership_api_call_succeeded": True,
        "all_application_packages_membership_api_win32_error": None,
        "all_application_packages_restricted_sid_match_attributes": "0x00000007",
        "all_application_packages_restricted_sid_match_count": 1,
        "all_application_packages_token_group_match_attributes": "",
        "all_application_packages_token_group_match_count": 0,
        "appcontainer_sid": SID,
        "capability_count": len(capabilities),
        "capability_entries": ",".join(capabilities),
        "integrity_rid": 0x1000,
        "is_appcontainer": True,
        "is_elevated": False,
        "less_privileged_appcontainer_query_result": False,
        "less_privileged_appcontainer_query_supported": True,
        "restricted_sid_count": 4,
        "token_group_count": 9,
    }


def _runtime() -> dict[str, object]:
    module_origins = {
        name: {
            "blob_sha256": _digest("module-" + name),
            "path_utf8_sha256": _path_sha(RUNTIME + rf"\Lib\{name}.py"),
            "relative_to_runtime": rf"Lib\{name}.py",
        }
        for name in boundary.RUNTIME_MODULES
    }
    return {
        "base_exec_prefix_path_utf8_sha256": _path_sha(RUNTIME),
        "base_prefix_path_utf8_sha256": _path_sha(RUNTIME),
        "dont_write_bytecode": True,
        "executable_leaf": "python.exe",
        "executable_path_utf8_sha256": _path_sha(RUNTIME + r"\python.exe"),
        "exec_prefix_path_utf8_sha256": _path_sha(RUNTIME),
        "expected_runtime_root_path_utf8_sha256": _path_sha(RUNTIME),
        "expected_source_root_path_utf8_sha256": _path_sha(SOURCE),
        "ignore_environment": True,
        "implementation": "cpython",
        "isolated": True,
        "module_origins": module_origins,
        "no_user_site": True,
        "prefix_path_utf8_sha256": _path_sha(RUNTIME),
        "probe_source_leaf": "windows_appcontainer_child_probe.py",
        "probe_source_path_utf8_sha256": _path_sha(
            SOURCE + r"\windows_appcontainer_child_probe.py"
        ),
        "runtime_root_role": "external_rx_runtime_copy",
        "safe_path": True,
        "source_root_role": "protected_probe_source_copy",
        "sys_path": [
            {
                "path_utf8_sha256": _path_sha(RUNTIME + r"\DLLs"),
                "relative_to_runtime": "DLLs",
            },
            {
                "path_utf8_sha256": _path_sha(RUNTIME + r"\Lib"),
                "relative_to_runtime": "Lib",
            },
        ],
        "version": [3, 13, 14],
        "version_text_sha256": _digest("3.13.14 (boundary fixture)"),
    }


def _fingerprint(root: str, digest: str) -> dict[str, object]:
    runtime = root == RUNTIME
    return {
        "all_entries_appcontainer_mutation_rights_absent": True,
        "declared_read_execute_entries_appcontainer_read_execute": True,
        "all_entries_controller_full_control": True,
        "all_entries_owner_matches_root": True,
        "all_files_single_link": True,
        "alternate_stream_count": 0,
        "appcontainer_mutation_rights_absent": True,
        "appcontainer_read_execute": True,
        "byte_count": 1024,
        "controller_full_control": True,
        "dacl_protected": True,
        "entry_count": 4,
        "object_identity_sha256": digest,
        "owner_matches_controller": True,
        "reparse_free": True,
        "root_identity": _path_identity(
            root,
            role=("external_rx_runtime_copy" if runtime else "protected_probe_source_copy"),
            leaf=("runtime" if runtime else "source"),
            file_id=(RUNTIME_ROOT_FILE_ID_128_HEX if runtime else SOURCE_ROOT_FILE_ID_128_HEX),
        ),
        "tree_sha256": digest,
    }


def _operation(name: str) -> dict[str, object]:
    if name == "read":
        observation: object = SHA_C
    elif name in {"ads", "create", "overwrite"}:
        observation = SHA_A
    elif name in {"write_dac", "write_owner"}:
        observation = 0
    else:
        observation = True
    return {
        "negative": {"observation": "PermissionError", "status": "error", "winerror": 5},
        "positive": {"observation": observation, "status": "success", "winerror": None},
    }


def _process(pid: int, parent_pid: int) -> dict[str, object]:
    return {
        "image": _path_identity(
            RUNTIME + r"\python.exe",
            role="cpython_313_runtime_executable",
            leaf="python.exe",
            file_id=PYTHON_FILE_ID_128_HEX,
        ),
        "parent_pid": parent_pid,
        "pid": pid,
        "reported_parent_pid": parent_pid,
        "reported_pid": pid,
        "token": _token(),
    }


def _network_control(*, host: str, port: int, order: int, label: str) -> dict[str, object]:
    nonce_sha256 = _digest(label)
    return {
        "accepted": True,
        "connected": True,
        "host": host,
        "nonce_matches": True,
        "nonce_sha256": nonce_sha256,
        "order": order,
        "port": port,
        "received_nonce_sha256": nonce_sha256,
        "winerror": None,
    }


def _network_attempt(
    *,
    connected: bool,
    label: str,
    diagnosis_type: int = 2,
    host: str = GUEST_IP,
    port: int = LISTENER_PORT,
) -> dict[str, object]:
    nonce_sha256 = _digest(label)
    return {
        "connected": connected,
        "diagnosis_result": None if connected else 0,
        "diagnosis_type": None if connected else diagnosis_type,
        "echo_matches": connected,
        "echo_nonce_sha256": nonce_sha256 if connected else None,
        "host": host,
        "nonce_sha256": nonce_sha256,
        "port": port,
        "winerror": None if connected else 10_060,
    }


def _network_arm(
    *, label: str, order: int, internet_client: bool, pid: int
) -> dict[str, object]:
    attempt = _network_attempt(connected=internet_client, label="arm-" + label)
    request_sha256 = _digest("request-" + label)
    return {
        "attempt": attempt,
        "command_line_sha256": _digest("shared-command"),
        "create_suspended": True,
        "current_directory_file_id_128_hex": PROFILE_FILE_ID_128_HEX,
        "current_directory_identity_format": boundary.FILE_IDENTITY_FORMAT,
        "current_directory_path_utf8_sha256": PROFILE_PATH_UTF8_SHA256,
        "current_directory_volume_serial_hex": PROFILE_VOLUME_SERIAL_HEX,
        "environment_sha256": _digest("shared-environment"),
        "image": _path_identity(
            RUNTIME + r"\python.exe",
            role="cpython_313_runtime_executable",
            leaf="python.exe",
            file_id=PYTHON_FILE_ID_128_HEX,
        ),
        "job_member": True,
        "label": label,
        "order": order,
        "parent_pid": 99,
        "pid": pid,
        "reported_parent_pid": 99,
        "reported_pid": pid,
        "reported_request_sha256": request_sha256,
        "regular_appcontainer": {
            "aap_negative_access_denied": True,
            "aap_positive_read_sha256_matches": True,
            "claim": (
                "regular_appcontainer_effect_observed_from_same_primary_token_source"
            ),
            "regular_launch_policy_bound": True,
            "same_primary_token_source_bound": True,
        },
        "request_file_id_128_hex": (
            PREFLIGHT_REQUEST_FILE_ID_128_HEX
            if label == "preflight_zero"
            else NETWORK_REQUEST_FILE_ID_128_HEX
        ),
        "request_identity_format": boundary.FILE_IDENTITY_FORMAT,
        "request_leaf": "network-arm-request.json",
        "request_parent_file_id_128_hex": PROFILE_FILE_ID_128_HEX,
        "request_parent_identity_format": boundary.FILE_IDENTITY_FORMAT,
        "request_parent_path_utf8_sha256": PROFILE_PATH_UTF8_SHA256,
        "request_parent_volume_serial_hex": PROFILE_VOLUME_SERIAL_HEX,
        "request_path_utf8_sha256": PROFILE_NETWORK_REQUEST_PATH_UTF8_SHA256,
        "request_sha256": request_sha256,
        "request_volume_serial_hex": PROFILE_VOLUME_SERIAL_HEX,
        "requested_capabilities_pointer_null": not internet_client,
        "requested_capability_sids": (
            [boundary.INTERNET_CLIENT_CAPABILITY_SID] if internet_client else []
        ),
        "resume_thread_count": 1,
        "startup_attribute_count": 2,
        "startup_attributes": ["job_list", "security_capabilities"],
        "timeout_milliseconds": 10_000,
        "target_host": GUEST_IP,
        "target_port": LISTENER_PORT,
        "token": _token(internet_client=internet_client),
    }


def _expected() -> dict[str, object]:
    return {
        "appcontainer_sid": SID,
        "decoy_canary_sha256": SHA_B,
        "format": boundary.EXPECTED_FORMAT,
        "internet_client_capability_sid": boundary.INTERNET_CLIENT_CAPABILITY_SID,
        "moniker": MONIKER,
        "permitted_canary_sha256": SHA_A,
        "profile_folder_boundary_component_count": 1,
        "profile_folder_boundary_terminal_ac": False,
        "profile_folder_file_id_128_hex": PROFILE_FILE_ID_128_HEX,
        "profile_folder_identity_format": boundary.FILE_IDENTITY_FORMAT,
        "profile_folder_path_utf8_sha256": PROFILE_PATH_UTF8_SHA256,
        "profile_folder_volume_serial_hex": PROFILE_VOLUME_SERIAL_HEX,
        "profile_network_request_path_utf8_sha256": (
            PROFILE_NETWORK_REQUEST_PATH_UTF8_SHA256
        ),
        "profile_prelaunch_sha256": PROFILE_PRELAUNCH_SHA256,
        "probe_source_leaf": "windows_appcontainer_child_probe.py",
        "probe_source_path_utf8_sha256": _path_sha(
            SOURCE + r"\windows_appcontainer_child_probe.py"
        ),
        "probe_source_sha256": SHA_C,
        "runtime_executable_leaf": "python.exe",
        "runtime_executable_path_utf8_sha256": _path_sha(RUNTIME + r"\python.exe"),
        "runtime_root_leaf": "runtime",
        "runtime_root_path_utf8_sha256": _path_sha(RUNTIME),
        "runtime_root_role": "external_rx_runtime_copy",
        "source_root_leaf": "source",
        "source_root_path_utf8_sha256": _path_sha(SOURCE),
        "source_root_role": "protected_probe_source_copy",
    }


def _endpoint_receipt() -> dict[str, object]:
    return {
        "cleanup_exact_listener_pid_only": True,
        "busybox_sha256": BUSYBOX_SHA256,
        "distro_name": boundary.NETWORK_DISTRO_NAME,
        "distro_running_after": True,
        "distro_running_before": True,
        "endpoint_class": boundary.NETWORK_ENDPOINT_CLASS,
        "format": boundary.ENDPOINT_RECEIPT_FORMAT,
        "guest_boot_id_after": GUEST_BOOT_ID,
        "guest_boot_id_before": GUEST_BOOT_ID,
        "guest_interface": "eth0",
        "guest_ipv4_after": GUEST_IP,
        "guest_ipv4_before": GUEST_IP,
        "guest_prefix_length_after": GUEST_PREFIX,
        "guest_prefix_length_before": GUEST_PREFIX,
        "guest_residual_absent_after": True,
        "host_launcher_process_absent_after": True,
        "host_launcher_pid": HOST_LAUNCHER_PID,
        "host_launcher_creation_time_100ns": HOST_LAUNCHER_CREATION_TIME_100NS,
        "listener_command_sha256": LISTENER_COMMAND_SHA256,
        "listener_pid": LISTENER_PID,
        "listener_port": LISTENER_PORT,
        "listener_port_absent_after": True,
        "listener_port_absent_before_start": True,
        "listener_port_observed_before": True,
        "listener_process_absent_after": True,
        "listener_process_absent_before_start": True,
        "listener_process_observed_before": True,
        "listener_socket_inode": LISTENER_SOCKET_INODE,
        "listener_starttime_ticks": LISTENER_STARTTIME_TICKS,
        "listener_watchdog_timeout_seconds": boundary.NETWORK_LISTENER_TIMEOUT_SECONDS,
        "startup_nonce_sha256": STARTUP_NONCE_SHA256,
        "startup_script_sha256": STARTUP_SCRIPT_SHA256,
        "netns_inode_after": GUEST_NETNS,
        "netns_inode_before": GUEST_NETNS,
        "windows_interface_ip_absent_after": True,
        "windows_interface_ip_absent_before": True,
        "watchdog_pid": WATCHDOG_PID,
        "watchdog_process_absent_after": True,
        "watchdog_starttime_ticks": WATCHDOG_STARTTIME_TICKS,
        "wsl_version": 2,
    }


def _profile_receipt() -> dict[str, object]:
    return {
        "cleanup_attempted": True,
        "cleanup_complete": True,
        "closed": True,
        "delete_suppressed_due_identity_uncertainty": False,
        "delete_attempt_hresults": [0],
        "delete_succeeded": True,
        "final_delete_attempt_hresults": [0],
        "final_delete_succeeded": True,
        "final_folder_absent": True,
        "first_folder_absent": True,
        "folder_boundary_component_count": 1,
        "folder_boundary_components_win32_valid": True,
        "folder_boundary_exact": True,
        "folder_boundary_nonempty_descendant": True,
        "folder_boundary_packages_ancestor": True,
        "folder_boundary_reason": "observed",
        "folder_boundary_reconstruction_matches": True,
        "folder_boundary_terminal_ac": False,
        "folder_file_id_128_hex": PROFILE_FILE_ID_128_HEX,
        "folder_identity_drift_detected": False,
        "folder_identity_format": boundary.FILE_IDENTITY_FORMAT,
        "folder_identity_revalidated_before_release": True,
        "folder_path_utf8_sha256": PROFILE_PATH_UTF8_SHA256,
        "folder_volume_serial_hex": PROFILE_VOLUME_SERIAL_HEX,
        "format": boundary.PROFILE_RECEIPT_FORMAT,
        "moniker": MONIKER,
        "owned": True,
        "ownership_established": True,
        "profile_directory_handle_release_attempted": True,
        "profile_directory_handle_released": True,
        "recreate_attempted": True,
        "recreate_created_hresult": 0,
        "recreate_folder_boundary_component_count": 1,
        "recreate_folder_boundary_components_win32_valid": True,
        "recreate_folder_boundary_exact": True,
        "recreate_folder_boundary_nonempty_descendant": True,
        "recreate_folder_boundary_packages_ancestor": True,
        "recreate_folder_boundary_reason": "observed",
        "recreate_folder_boundary_reconstruction_matches": True,
        "recreate_folder_boundary_terminal_ac": False,
        "recreate_folder_exists": True,
        "recreate_folder_reparse_free": True,
        "recreate_succeeded": True,
        "recreated_sid": SID,
        "recreated_sid_matches": True,
        "residual_race_after_handle_release": "not_prevented",
    }


def _set_profile_boundary_state(
    receipt: dict[str, object], *, prefix: str, reason: str
) -> None:
    values = {
        "components_win32_invalid": (2, False, True, True, True, True),
        "empty_descendant": (0, False, False, True, False, False),
        "packages_ancestor_mismatch": (0, False, False, False, False, False),
        "reconstruction_mismatch": (2, True, True, True, False, True),
    }
    count, components, nonempty, packages, reconstruction, terminal = values[reason]
    field_prefix = f"{prefix}folder_boundary_"
    receipt[f"{field_prefix}component_count"] = count
    receipt[f"{field_prefix}components_win32_valid"] = components
    receipt[f"{field_prefix}exact"] = False
    receipt[f"{field_prefix}nonempty_descendant"] = nonempty
    receipt[f"{field_prefix}packages_ancestor"] = packages
    receipt[f"{field_prefix}reason"] = reason
    receipt[f"{field_prefix}reconstruction_matches"] = reconstruction
    receipt[f"{field_prefix}terminal_ac"] = terminal


def _raw() -> dict[str, object]:
    return {
        "cleanup": {
            "acl_restore_not_required": True,
            "attribute_list_deleted": True,
            "firewall_objects_absent": True,
            "job_handle_closed": True,
            "listener_handles_closed": True,
            "loopback_config_restored": True,
            "no_foreign_named_objects": True,
            "pipe_handles_closed": True,
            "process_handles_closed": True,
            "processes_exited": True,
            "profile_cleanup_deferred_to_wrapper": True,
            "runtime_and_source_removed": True,
            "thread_handle_closed": True,
            "work_root_empty": True,
        },
        "filesystem": {
            "operations": {name: _operation(name) for name in boundary.FILESYSTEM_OPERATIONS},
            "protected_tree_unchanged": True,
            "scratch_positive_root_under_profile": True,
        },
        "fingerprints": {
            "probe_source_sha256": SHA_C,
            "runtime_after": _fingerprint(RUNTIME, SHA_A),
            "runtime_before": _fingerprint(RUNTIME, SHA_A),
            "source_after": _fingerprint(SOURCE, SHA_B),
            "source_before": _fingerprint(SOURCE, SHA_B),
        },
        "format": boundary.RAW_FORMAT,
        "handles": {
            "decoy": {
                "canary_sha256": None,
                "get_handle_information_error": 6,
                "read_error": None,
                "valid": False,
            },
            "decoy_parent_open_during": True,
            "handle_list_attribute_applied": True,
            "handle_list_count": 1,
            "permitted": {
                "canary_sha256": SHA_A,
                "get_handle_information_error": 0,
                "read_error": 0,
                "valid": True,
            },
            "permitted_parent_open_during": True,
        },
        "identity": {
            "aap_acl_pair_only_semantic_difference": "allow_read_s-1-15-2-1",
            "aap_acl_pair_revalidated": True,
            "aap_negative_access_denied": True,
            "aap_negative_win32_error": 5,
            "aap_object_identity_revalidated": True,
            "aap_positive_read_sha256_matches": True,
            "aap_probe_contents_revalidated": True,
            "aap_probe_storage_removed": True,
            "aap_sid": "S-1-15-2-1",
            "claim": "aap_acl_effect_observed_for_this_token_run",
            "regular_launch_policy_bound": True,
            "same_primary_token_source_bound": True,
        },
        "job": {
            "breakaway_created": False,
            "breakaway_flags_absent": True,
            "breakaway_winerror": 5,
            "child_member": True,
            "grandchild_member": True,
            "job_handle_was_last_job_handle": True,
            "job_limit_flags": 0x2000,
            "job_list_attribute_applied": True,
            "kill_on_close_child": True,
            "kill_on_close_grandchild": True,
            "kill_on_close_root": True,
            "root_member": True,
        },
        "network": {
            "endpoint": {
                "busybox_sha256": BUSYBOX_SHA256,
                "distro_name": boundary.NETWORK_DISTRO_NAME,
                "distro_running_before": True,
                "endpoint_class": boundary.NETWORK_ENDPOINT_CLASS,
                "guest_boot_id": GUEST_BOOT_ID,
                "guest_interface": "eth0",
                "guest_ipv4": GUEST_IP,
                "guest_prefix_length": GUEST_PREFIX,
                "host_launcher_pid": HOST_LAUNCHER_PID,
                "host_launcher_creation_time_100ns": HOST_LAUNCHER_CREATION_TIME_100NS,
                "listener_command_sha256": LISTENER_COMMAND_SHA256,
                "listener_pid": LISTENER_PID,
                "listener_port": LISTENER_PORT,
                "listener_port_absent_before_start": True,
                "listener_port_observed_before": True,
                "listener_process_absent_before_start": True,
                "listener_process_observed_before": True,
                "listener_socket_inode": LISTENER_SOCKET_INODE,
                "listener_starttime_ticks": LISTENER_STARTTIME_TICKS,
                "listener_watchdog_timeout_seconds": (
                    boundary.NETWORK_LISTENER_TIMEOUT_SECONDS
                ),
                "startup_nonce_sha256": STARTUP_NONCE_SHA256,
                "startup_script_sha256": STARTUP_SCRIPT_SHA256,
                "netns_inode": GUEST_NETNS,
                "windows_interface_ip_absent_before": True,
                "watchdog_pid": WATCHDOG_PID,
                "watchdog_starttime_ticks": WATCHDOG_STARTTIME_TICKS,
                "wsl_version": 2,
            },
            "execution_order": [
                "preflight_zero",
                "full_trust_before",
                "zero_1",
                "internet_client_1",
                "internet_client_2",
                "zero_2",
                "full_trust_after",
            ],
            "exemption_after": False,
            "exemption_before": False,
            "exemption_digest_after": SHA_C,
            "exemption_digest_before": SHA_C,
            "exemption_digest_during": SHA_C,
            "exemption_during": False,
            "firewall_named_objects_after": 0,
            "firewall_named_objects_before": 0,
            "firewall_named_objects_during": 0,
            "lan_appcontainer_arms": [
                _network_arm(label="zero_1", order=1, internet_client=False, pid=201),
                _network_arm(label="internet_client_1", order=2, internet_client=True, pid=202),
                _network_arm(label="internet_client_2", order=3, internet_client=True, pid=203),
                _network_arm(label="zero_2", order=4, internet_client=False, pid=204),
            ],
            "lan_full_trust_controls": [
                _network_control(
                    host=GUEST_IP, port=LISTENER_PORT, order=0, label="control-before"
                ),
                _network_control(
                    host=GUEST_IP, port=LISTENER_PORT, order=5, label="control-after"
                ),
            ],
            "lan_host": GUEST_IP,
            "lan_host_is_non_loopback": True,
            "lan_port": LISTENER_PORT,
            "listener_saw_appcontainer_loopback": False,
            "listeners_closed": True,
            "loopback_full_trust_control": _network_control(
                host="127.0.0.1", port=45_124, order=0, label="loopback-control"
            ),
            "loopback_zero_capability_attempt": _network_attempt(
                connected=False,
                label="loopback-zero",
                diagnosis_type=0,
                host="127.0.0.1",
                port=45_124,
            ),
            "preflight_selected_capability_name": "internetClient",
            "preflight_selected_capability_sid": boundary.INTERNET_CLIENT_CAPABILITY_SID,
            "preflight_zero_capability": _network_arm(
                label="preflight_zero", order=0, internet_client=False, pid=200
            ),
        },
        "processes": {
            "child": _process(101, 100),
            "grandchild": _process(102, 101),
            "root": _process(100, 99),
        },
        "profile": {
            "appcontainer_sid_prelaunch_bound": SID,
            "folder_declared_entire_scratch": True,
            "folder_file_id_128_hex": PROFILE_FILE_ID_128_HEX,
            "folder_identity_format": boundary.FILE_IDENTITY_FORMAT,
            "folder_identity_matched_prelaunch": True,
            "folder_identity_revalidated_after_boundary": True,
            "folder_outside_runtime_and_source": True,
            "folder_path_utf8_sha256": PROFILE_PATH_UTF8_SHA256,
            "folder_present_during_boundary": True,
            "folder_under_local_appdata": True,
            "folder_volume_serial_hex": PROFILE_VOLUME_SERIAL_HEX,
            "moniker": MONIKER,
            "precreated_by_wrapper": True,
            "prelaunch_created_hresult": 0,
            "prelaunch_ownership_established": True,
            "prelaunch_receipt_sha256": PROFILE_PRELAUNCH_SHA256,
            "prelaunch_sid_reconciled": True,
        },
        "request": {
            "create_suspended": True,
            "inherit_handles": True,
            "python_flags": ["-I", "-B"],
            "requested_capabilities_pointer_null": True,
            "requested_capability_count": 0,
            "resume_thread_count": 1,
            "startup_attribute_count": 3,
            "startup_attributes": boundary.STARTUP_ATTRIBUTES,
        },
        "runtime": {role: _runtime() for role in boundary.PROCESS_ROLES},
    }


class WindowsAppContainerBoundaryReportTests(unittest.TestCase):
    def test_complete_observation_recomputes_local_non_authoritative_state(self) -> None:
        summary = boundary.recompute_boundary_summary(
            _raw(), _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
        )

        self.assertEqual(summary["status"], "observed_pass")
        self.assertTrue(summary["all_required_controls_observed"])
        self.assertEqual(summary["portability_cell"], "not_counted")
        self.assertEqual(summary["evidence_authentication"], "not_implemented")
        self.assertEqual(summary["authority"], "none")
        self.assertFalse(summary["release_authorized"])
        self.assertEqual(
            summary["network_claims"],
            {
                "lan_capability_differential_observed": True,
                "loopback_non_establishment_without_exemption_observed": True,
                "wfp_filter_attribution": "not_claimed",
            },
        )

    def test_aap_membership_result_is_diagnostic_but_roster_and_acl_effect_are_gated(self) -> None:
        raw = _raw()
        tokens = [
            *(raw["processes"][role]["token"] for role in boundary.PROCESS_ROLES),
            raw["network"]["preflight_zero_capability"]["token"],
            *(arm["token"] for arm in raw["network"]["lan_appcontainer_arms"]),
        ]
        for token in tokens:
            self.assertFalse(token["all_application_packages_membership_api"])
            token.update(
                {
                    "all_application_packages_membership_api": True,
                    "all_application_packages_restricted_sid_match_attributes": "",
                    "all_application_packages_restricted_sid_match_count": 0,
                    "all_application_packages_token_group_match_attributes": "0x00000004",
                    "all_application_packages_token_group_match_count": 1,
                }
            )
        summary = boundary.recompute_boundary_summary(
            raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
        )
        self.assertEqual(summary["status"], "observed_pass")

        raw["identity"]["aap_positive_read_sha256_matches"] = False
        summary = boundary.recompute_boundary_summary(
            raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
        )
        self.assertEqual(summary["status"], "not_observed")
        self.assertFalse(summary["checks"]["identity"])

    def test_every_filesystem_control_is_independently_required(self) -> None:
        for operation in boundary.FILESYSTEM_OPERATIONS:
            with self.subTest(operation=operation, side="positive"):
                raw = _raw()
                raw["filesystem"]["operations"][operation]["positive"]["status"] = "error"
                raw["filesystem"]["operations"][operation]["positive"]["winerror"] = 5
                summary = boundary.recompute_boundary_summary(
                    raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
                )
                self.assertFalse(summary["checks"]["filesystem"])
                self.assertEqual(summary["status"], "not_observed")
            with self.subTest(operation=operation, side="negative"):
                raw = _raw()
                raw["filesystem"]["operations"][operation]["negative"]["status"] = "success"
                raw["filesystem"]["operations"][operation]["negative"]["winerror"] = None
                summary = boundary.recompute_boundary_summary(
                    raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
                )
                self.assertFalse(summary["checks"]["filesystem"])
                self.assertEqual(summary["status"], "not_observed")
            with self.subTest(operation=operation, side="positive_observation"):
                raw = _raw()
                raw["filesystem"]["operations"][operation]["positive"]["observation"] = False
                summary = boundary.recompute_boundary_summary(
                    raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
                )
                self.assertFalse(summary["checks"]["filesystem"])
                self.assertEqual(summary["status"], "not_observed")

    def test_cross_dimension_mutations_cannot_preserve_observed_state(self) -> None:
        mutations = {
            "zero_capability_request": lambda raw: raw["request"].__setitem__("requested_capability_count", 1),
            "startup_handle_list": lambda raw: raw["request"].__setitem__(
                "startup_attributes", ["job_list", "security_capabilities"]
            ),
            "root_token": lambda raw: raw["processes"]["root"]["token"].__setitem__("is_appcontainer", False),
            "root_aap_roster_absent": lambda raw: raw["processes"]["root"]["token"].update(
                {
                    "all_application_packages_restricted_sid_match_attributes": "",
                    "all_application_packages_restricted_sid_match_count": 0,
                }
            ),
            "root_aap_group_deny_only": lambda raw: raw["processes"]["root"]["token"].update(
                {
                    "all_application_packages_restricted_sid_match_attributes": "",
                    "all_application_packages_restricted_sid_match_count": 0,
                    "all_application_packages_token_group_match_attributes": "0x00000010",
                    "all_application_packages_token_group_match_count": 1,
                }
            ),
            "root_aap_query_failed": lambda raw: raw["processes"]["root"]["token"].update(
                {
                    "all_application_packages_membership_api_call_succeeded": False,
                    "all_application_packages_membership_api_win32_error": 5,
                }
            ),
            "root_lpac_true": lambda raw: raw["processes"]["root"]["token"].update(
                {
                    "less_privileged_appcontainer_query_result": True,
                    "less_privileged_appcontainer_query_supported": True,
                }
            ),
            "child_lineage": lambda raw: raw["processes"]["child"].__setitem__("parent_pid", 999),
            "python_origin": lambda raw: raw["runtime"]["root"].__setitem__(
                "executable_path_utf8_sha256", _path_sha(r"C:\Windows\python.exe")
            ),
            "runtime_fingerprint": lambda raw: raw["fingerprints"]["runtime_after"].__setitem__(
                "tree_sha256", "d" * 64
            ),
            "runtime_ads": lambda raw: raw["fingerprints"]["runtime_after"].__setitem__(
                "alternate_stream_count", 1
            ),
            "runtime_hardlink": lambda raw: raw["fingerprints"]["runtime_before"].__setitem__(
                "all_files_single_link", False
            ),
            "runtime_file_id": lambda raw: raw["fingerprints"]["runtime_after"].__setitem__(
                "object_identity_sha256", "d" * 64
            ),
            "runtime_owner_not_controller": lambda raw: raw["fingerprints"][
                "runtime_after"
            ].__setitem__("owner_matches_controller", False),
            "endpoint_boot_id": lambda raw: raw["network"]["endpoint"].__setitem__(
                "guest_boot_id", "00000000-0000-0000-0000-000000000001"
            ),
            "endpoint_listener_pid": lambda raw: raw["network"]["endpoint"].__setitem__(
                "listener_pid", LISTENER_PID + 1
            ),
            "endpoint_listener_starttime": lambda raw: raw["network"]["endpoint"].__setitem__(
                "listener_starttime_ticks", LISTENER_STARTTIME_TICKS + 1
            ),
            "endpoint_listener_socket_inode": lambda raw: raw["network"]["endpoint"].__setitem__(
                "listener_socket_inode", LISTENER_SOCKET_INODE + 1
            ),
            "endpoint_listener_watchdog": lambda raw: raw["network"]["endpoint"].__setitem__(
                "listener_watchdog_timeout_seconds", 121
            ),
            "endpoint_windows_interface_collision": lambda raw: raw["network"][
                "endpoint"
            ].__setitem__("windows_interface_ip_absent_before", False),
            "network_control": lambda raw: raw["network"]["lan_full_trust_controls"][
                0
            ].__setitem__("connected", False),
            "network_control_ack": lambda raw: raw["network"]["lan_full_trust_controls"][
                0
            ].__setitem__("received_nonce_sha256", "e" * 64),
            "preflight_diagnosis": lambda raw: raw["network"]["preflight_zero_capability"][
                "attempt"
            ].__setitem__("diagnosis_type", 0),
            "preflight_capability_selection": lambda raw: raw["network"].__setitem__(
                "preflight_selected_capability_sid", None
            ),
            "preflight_command_drift": lambda raw: raw["network"][
                "preflight_zero_capability"
            ].__setitem__("command_line_sha256", "e" * 64),
            "preflight_request_digest_drift": lambda raw: raw["network"][
                "preflight_zero_capability"
            ].__setitem__("reported_request_sha256", "e" * 64),
            "preflight_nonce_reuse": lambda raw: raw["network"][
                "preflight_zero_capability"
            ]["attempt"].__setitem__(
                "nonce_sha256",
                raw["network"]["lan_full_trust_controls"][0]["nonce_sha256"],
            ),
            "zero_arm_connected": lambda raw: raw["network"]["lan_appcontainer_arms"][
                0
            ]["attempt"].__setitem__("connected", True),
            "zero_arm_echo": lambda raw: raw["network"]["lan_appcontainer_arms"][0][
                "attempt"
            ].update({"echo_matches": True, "echo_nonce_sha256": "e" * 64}),
            "internet_arm_failed": lambda raw: raw["network"]["lan_appcontainer_arms"][
                1
            ]["attempt"].update({"connected": False, "winerror": 10_060}),
            "internet_arm_echo": lambda raw: raw["network"]["lan_appcontainer_arms"][1][
                "attempt"
            ].__setitem__("echo_matches", False),
            "arm_order": lambda raw: raw["network"]["lan_appcontainer_arms"][1].__setitem__(
                "order", 3
            ),
            "arm_target_host": lambda raw: raw["network"]["lan_appcontainer_arms"][1].__setitem__(
                "target_host", "172.29.60.72"
            ),
            "arm_attempt_port": lambda raw: raw["network"]["lan_appcontainer_arms"][1][
                "attempt"
            ].__setitem__("port", LISTENER_PORT + 1),
            "arm_command_drift": lambda raw: raw["network"]["lan_appcontainer_arms"][
                2
            ].__setitem__("command_line_sha256", "d" * 64),
            "arm_environment_drift": lambda raw: raw["network"]["lan_appcontainer_arms"][
                2
            ].__setitem__("environment_sha256", "d" * 64),
            "arm_current_directory_identity_drift": lambda raw: raw["network"][
                "lan_appcontainer_arms"
            ][2].__setitem__("current_directory_file_id_128_hex", "9a" * 16),
            "arm_request_parent_identity_drift": lambda raw: raw["network"][
                "lan_appcontainer_arms"
            ][2].__setitem__("request_parent_path_utf8_sha256", "9" * 64),
            "arm_request_path_binding_drift": lambda raw: raw["network"][
                "lan_appcontainer_arms"
            ][2].__setitem__("request_path_utf8_sha256", "8" * 64),
            "arm_request_file_identity_drift": lambda raw: raw["network"][
                "lan_appcontainer_arms"
            ][2].__setitem__("request_file_id_128_hex", "7b" * 16),
            "arm_job_drift": lambda raw: raw["network"]["lan_appcontainer_arms"][2].__setitem__(
                "job_member", False
            ),
            "arm_sid_drift": lambda raw: raw["network"]["lan_appcontainer_arms"][2][
                "token"
            ].__setitem__("appcontainer_sid", "S-1-15-2-1"),
            "arm_lpac_true": lambda raw: raw["network"]["lan_appcontainer_arms"][2][
                "token"
            ].update(
                {
                    "less_privileged_appcontainer_query_result": True,
                    "less_privileged_appcontainer_query_supported": True,
                }
            ),
            "arm_regular_launch_policy_unbound": lambda raw: raw["network"][
                "lan_appcontainer_arms"
            ][2]["regular_appcontainer"].__setitem__("regular_launch_policy_bound", False),
            "arm_regular_same_token_unbound": lambda raw: raw["network"][
                "lan_appcontainer_arms"
            ][2]["regular_appcontainer"].__setitem__(
                "same_primary_token_source_bound", False
            ),
            "arm_regular_aap_positive_failed": lambda raw: raw["network"][
                "lan_appcontainer_arms"
            ][2]["regular_appcontainer"].__setitem__(
                "aap_positive_read_sha256_matches", False
            ),
            "arm_regular_aap_negative_failed": lambda raw: raw["network"][
                "lan_appcontainer_arms"
            ][2]["regular_appcontainer"].__setitem__("aap_negative_access_denied", False),
            "arm_nonce_reuse": lambda raw: raw["network"]["lan_appcontainer_arms"][1][
                "attempt"
            ].__setitem__(
                "nonce_sha256",
                raw["network"]["lan_appcontainer_arms"][0]["attempt"]["nonce_sha256"],
            ),
            "internet_capability_missing": lambda raw: raw["network"][
                "lan_appcontainer_arms"
            ][1]["token"].update(
                {"capability_count": 1, "capability_entries": CAPABILITY}
            ),
            "zero_capability_added": lambda raw: raw["network"]["lan_appcontainer_arms"][0][
                "token"
            ].update(
                {
                    "capability_count": 2,
                    "capability_entries": ",".join(
                        sorted((CAPABILITY, INTERNET_CLIENT_CAPABILITY))
                    ),
                }
            ),
            "loopback_exemption": lambda raw: raw["network"].__setitem__("exemption_during", True),
            "loopback_control_host": lambda raw: raw["network"]["loopback_full_trust_control"].__setitem__(
                "host", "127.0.0.2"
            ),
            "loopback_control_order": lambda raw: raw["network"]["loopback_full_trust_control"].__setitem__(
                "order", 1
            ),
            "loopback_nonce_reuse": lambda raw: raw["network"][
                "loopback_zero_capability_attempt"
            ].__setitem__(
                "nonce_sha256",
                raw["network"]["loopback_full_trust_control"]["nonce_sha256"],
            ),
            "firewall_object": lambda raw: raw["network"].__setitem__("firewall_named_objects_after", 1),
            "permitted_handle": lambda raw: raw["handles"]["permitted"].__setitem__(
                "canary_sha256", "d" * 64
            ),
            "decoy_handle": lambda raw: raw["handles"]["decoy"].__setitem__("valid", True),
            "aap_acl_pair": lambda raw: raw["identity"].__setitem__("aap_acl_pair_revalidated", False),
            "aap_negative_control": lambda raw: raw["identity"].update(
                {"aap_negative_access_denied": False, "aap_negative_win32_error": 0}
            ),
            "aap_object_identity": lambda raw: raw["identity"].__setitem__(
                "aap_object_identity_revalidated", False
            ),
            "aap_probe_contents": lambda raw: raw["identity"].__setitem__(
                "aap_probe_contents_revalidated", False
            ),
            "aap_probe_cleanup": lambda raw: raw["identity"].__setitem__("aap_probe_storage_removed", False),
            "aap_token_binding": lambda raw: raw["identity"].__setitem__(
                "same_primary_token_source_bound", False
            ),
            "job_breakaway": lambda raw: raw["job"].__setitem__("breakaway_created", True),
            "job_membership": lambda raw: raw["job"].__setitem__("grandchild_member", False),
            "job_kill": lambda raw: raw["job"].__setitem__("kill_on_close_child", False),
            "cleanup": lambda raw: raw["cleanup"].__setitem__("work_root_empty", False),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                raw = _raw()
                mutate(raw)
                summary = boundary.recompute_boundary_summary(
                    raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
                )
                self.assertEqual(summary["status"], "not_observed")
                self.assertFalse(summary["all_required_controls_observed"])

    def test_optional_lpac_diagnostic_needs_regular_policy_and_same_token_behavior(self) -> None:
        raw = _raw()
        for token in (
            raw["processes"]["root"]["token"],
            raw["processes"]["child"]["token"],
            raw["processes"]["grandchild"]["token"],
            raw["network"]["preflight_zero_capability"]["token"],
            *(arm["token"] for arm in raw["network"]["lan_appcontainer_arms"]),
        ):
            token.update(
                {
                    "less_privileged_appcontainer_query_result": None,
                    "less_privileged_appcontainer_query_supported": False,
                }
            )

        summary = boundary.recompute_boundary_summary(
            raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
        )
        self.assertEqual(summary["status"], "observed_pass")

        raw["network"]["preflight_zero_capability"]["regular_appcontainer"][
            "same_primary_token_source_bound"
        ] = False
        summary = boundary.recompute_boundary_summary(
            raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
        )
        self.assertEqual(summary["status"], "not_observed")
        self.assertFalse(summary["checks"]["network"])

    def test_regular_appcontainer_proof_roster_and_claim_are_closed(self) -> None:
        raw = _raw()
        proof = raw["network"]["preflight_zero_capability"]["regular_appcontainer"]
        self.assertEqual(
            proof,
            {
                "aap_negative_access_denied": True,
                "aap_positive_read_sha256_matches": True,
                "claim": (
                    "regular_appcontainer_effect_observed_from_same_primary_token_source"
                ),
                "regular_launch_policy_bound": True,
                "same_primary_token_source_bound": True,
            },
        )
        proof["claim"] = "lpac_inferred_from_query_failure"
        with self.assertRaisesRegex(boundary.BoundaryReportError, "claim_invalid"):
            boundary.recompute_boundary_summary(
                raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
            )

        raw = _raw()
        proof = raw["network"]["preflight_zero_capability"]["regular_appcontainer"]
        proof["same_token_handle_bound"] = proof.pop(
            "same_primary_token_source_bound"
        )
        with self.assertRaisesRegex(boundary.BoundaryReportError, "shape_invalid"):
            boundary.recompute_boundary_summary(
                raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
            )

        raw = _raw()
        raw["network"]["preflight_zero_capability"]["regular_appcontainer"][
            "extra"
        ] = True
        with self.assertRaisesRegex(boundary.BoundaryReportError, "shape_invalid"):
            boundary.recompute_boundary_summary(
                raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
            )

    def test_endpoint_receipt_drift_and_cleanup_mutations_fail_closed(self) -> None:
        mutations = {
            "boot_drift": lambda receipt: receipt.__setitem__(
                "guest_boot_id_after", "00000000-0000-0000-0000-000000000001"
            ),
            "ip_drift": lambda receipt: receipt.__setitem__("guest_ipv4_after", "172.29.60.72"),
            "prefix_drift": lambda receipt: receipt.__setitem__("guest_prefix_length_after", 24),
            "netns_drift": lambda receipt: receipt.__setitem__(
                "netns_inode_after", "net:[4026532897]"
            ),
            "listener_pid_mismatch": lambda receipt: receipt.__setitem__(
                "listener_pid", LISTENER_PID + 1
            ),
            "listener_port_mismatch": lambda receipt: receipt.__setitem__(
                "listener_port", LISTENER_PORT + 1
            ),
            "listener_command_mismatch": lambda receipt: receipt.__setitem__(
                "listener_command_sha256", "e" * 64
            ),
            "listener_starttime_mismatch": lambda receipt: receipt.__setitem__(
                "listener_starttime_ticks", LISTENER_STARTTIME_TICKS + 1
            ),
            "listener_socket_inode_mismatch": lambda receipt: receipt.__setitem__(
                "listener_socket_inode", LISTENER_SOCKET_INODE + 1
            ),
            "listener_watchdog_mismatch": lambda receipt: receipt.__setitem__(
                "listener_watchdog_timeout_seconds", 121
            ),
            "host_launcher_pid_mismatch": lambda receipt: receipt.__setitem__(
                "host_launcher_pid", HOST_LAUNCHER_PID + 1
            ),
            "distro_stopped": lambda receipt: receipt.__setitem__("distro_running_after", False),
            "listener_process_residual": lambda receipt: receipt.__setitem__(
                "listener_process_absent_after", False
            ),
            "listener_port_residual": lambda receipt: receipt.__setitem__(
                "listener_port_absent_after", False
            ),
            "guest_residual": lambda receipt: receipt.__setitem__(
                "guest_residual_absent_after", False
            ),
            "host_launcher_residual": lambda receipt: receipt.__setitem__(
                "host_launcher_process_absent_after", False
            ),
            "broad_cleanup": lambda receipt: receipt.__setitem__(
                "cleanup_exact_listener_pid_only", False
            ),
            "windows_interface_collision": lambda receipt: receipt.__setitem__(
                "windows_interface_ip_absent_after", False
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                receipt = _endpoint_receipt()
                mutate(receipt)
                summary = boundary.recompute_boundary_summary(
                    _raw(), _expected(), receipt, _profile_receipt(), _path_context()
                )
                self.assertFalse(summary["checks"]["network"])
                self.assertFalse(summary["checks"]["cleanup"])
                self.assertEqual(summary["status"], "not_observed")

    def test_endpoint_receipt_shape_mutations_are_rejected(self) -> None:
        extra = _endpoint_receipt()
        extra["unexpected"] = True
        missing = _endpoint_receipt()
        del missing["listener_pid"]
        bool_as_int = _endpoint_receipt()
        bool_as_int["listener_process_absent_after"] = 1

        for name, receipt in (
            ("extra", extra),
            ("missing", missing),
            ("bool_as_int", bool_as_int),
        ):
            with self.subTest(name=name):
                with self.assertRaises(boundary.BoundaryReportError):
                    boundary.recompute_boundary_summary(
                        _raw(), _expected(), receipt, _profile_receipt(), _path_context()
                    )

    def test_profile_receipt_ownership_and_cleanup_mutations_fail_closed(self) -> None:
        mutations = {
            "not_owned": lambda receipt: receipt.__setitem__("owned", False),
            "ownership_not_established": lambda receipt: receipt.__setitem__(
                "ownership_established", False
            ),
            "cleanup_not_attempted": lambda receipt: receipt.__setitem__(
                "cleanup_attempted", False
            ),
            "cleanup_incomplete": lambda receipt: receipt.__setitem__("cleanup_complete", False),
            "not_closed": lambda receipt: receipt.__setitem__("closed", False),
            "delete_suppressed": lambda receipt: receipt.__setitem__(
                "delete_suppressed_due_identity_uncertainty", True
            ),
            "identity_drift": lambda receipt: receipt.__setitem__(
                "folder_identity_drift_detected", True
            ),
            "identity_not_revalidated": lambda receipt: receipt.__setitem__(
                "folder_identity_revalidated_before_release", False
            ),
            "directory_handle_not_released": lambda receipt: receipt.__setitem__(
                "profile_directory_handle_released", False
            ),
            "folder_path_hash_drift": lambda receipt: receipt.__setitem__(
                "folder_path_utf8_sha256", "9" * 64
            ),
            "folder_file_id_drift": lambda receipt: receipt.__setitem__(
                "folder_file_id_128_hex", "ab" * 16
            ),
            "delete_no_success": lambda receipt: receipt.__setitem__("delete_succeeded", False),
            "delete_attempt_missing": lambda receipt: receipt.__setitem__(
                "delete_attempt_hresults", []
            ),
            "delete_last_failed": lambda receipt: receipt.__setitem__(
                "delete_attempt_hresults", [0x80070005]
            ),
            "first_folder_residual": lambda receipt: receipt.__setitem__(
                "first_folder_absent", False
            ),
            "recreate_not_attempted": lambda receipt: receipt.__setitem__(
                "recreate_attempted", False
            ),
            "recreate_not_s_ok": lambda receipt: receipt.__setitem__(
                "recreate_created_hresult", 0x800700B7
            ),
            "recreate_sid_drift": lambda receipt: receipt.__setitem__(
                "recreated_sid", "S-1-15-2-999"
            ),
            "recreate_folder_drift": lambda receipt: _set_profile_boundary_state(
                receipt, prefix="recreate_", reason="components_win32_invalid"
            ),
            "final_delete_no_success": lambda receipt: receipt.__setitem__(
                "final_delete_succeeded", False
            ),
            "final_folder_residual": lambda receipt: receipt.__setitem__(
                "final_folder_absent", False
            ),
            "moniker_drift": lambda receipt: receipt.__setitem__(
                "moniker", "finplanbrac-ffffffffffffffffffffffff"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                receipt = _profile_receipt()
                mutate(receipt)
                summary = boundary.recompute_boundary_summary(
                    _raw(), _expected(), _endpoint_receipt(), receipt, _path_context()
                )
                self.assertFalse(summary["checks"]["cleanup"])
                self.assertEqual(summary["status"], "not_observed")

    def test_profile_boundary_reason_and_boolean_mutations_are_closed(self) -> None:
        for prefix in ("", "recreate_"):
            for suffix in (
                "components_win32_valid",
                "exact",
                "nonempty_descendant",
                "packages_ancestor",
                "reconstruction_matches",
            ):
                with self.subTest(prefix=prefix, suffix=suffix):
                    receipt = _profile_receipt()
                    receipt[f"{prefix}folder_boundary_{suffix}"] = False
                    with self.assertRaises(boundary.BoundaryReportError):
                        boundary.recompute_boundary_summary(
                            _raw(),
                            _expected(),
                            _endpoint_receipt(),
                            receipt,
                            _path_context(),
                        )
            for reason in ("components_win32_invalid", "invented", "not_observed"):
                with self.subTest(prefix=prefix, reason=reason):
                    receipt = _profile_receipt()
                    receipt[f"{prefix}folder_boundary_reason"] = reason
                    with self.assertRaises(boundary.BoundaryReportError):
                        boundary.recompute_boundary_summary(
                            _raw(),
                            _expected(),
                            _endpoint_receipt(),
                            receipt,
                            _path_context(),
                        )

    def test_each_coherent_profile_boundary_negative_is_not_observed(self) -> None:
        reasons = (
            "components_win32_invalid",
            "empty_descendant",
            "packages_ancestor_mismatch",
            "reconstruction_mismatch",
        )
        for prefix in ("", "recreate_"):
            for reason in reasons:
                with self.subTest(prefix=prefix, reason=reason):
                    receipt = _profile_receipt()
                    _set_profile_boundary_state(receipt, prefix=prefix, reason=reason)
                    receipt["cleanup_complete"] = False
                    summary = boundary.recompute_boundary_summary(
                        _raw(),
                        _expected(),
                        _endpoint_receipt(),
                        receipt,
                        _path_context(),
                    )
                    self.assertFalse(summary["checks"]["cleanup"])
                    self.assertEqual(summary["status"], "not_observed")

    def test_profile_boundary_depth_and_terminal_diagnostics_do_not_gate(self) -> None:
        for component_count, terminal_ac in ((1, False), (2, True), (3, False)):
            with self.subTest(component_count=component_count, terminal_ac=terminal_ac):
                receipt = _profile_receipt()
                for prefix in ("", "recreate_"):
                    receipt[f"{prefix}folder_boundary_component_count"] = component_count
                    receipt[f"{prefix}folder_boundary_terminal_ac"] = terminal_ac
                receipt["recreate_folder_boundary_component_count"] = component_count + 1
                receipt["recreate_folder_boundary_terminal_ac"] = not terminal_ac
                expected = _expected()
                expected["profile_folder_boundary_component_count"] = component_count
                expected["profile_folder_boundary_terminal_ac"] = terminal_ac
                summary = boundary.recompute_boundary_summary(
                    _raw(),
                    expected,
                    _endpoint_receipt(),
                    receipt,
                    _path_context(),
                )
                self.assertEqual(summary["status"], "observed_pass")
                self.assertTrue(summary["checks"]["cleanup"])

    def test_profile_boundary_initial_diagnostics_are_bound_to_prelaunch(self) -> None:
        for key, value in (
            ("folder_boundary_component_count", 2),
            ("folder_boundary_terminal_ac", True),
        ):
            with self.subTest(key=key):
                receipt = _profile_receipt()
                receipt[key] = value
                summary = boundary.recompute_boundary_summary(
                    _raw(),
                    _expected(),
                    _endpoint_receipt(),
                    receipt,
                    _path_context(),
                )
                self.assertEqual(summary["status"], "not_observed")
                self.assertFalse(summary["checks"]["cleanup"])

    def test_profile_boundary_component_count_shape_mutations_are_closed(self) -> None:
        for prefix in ("", "recreate_"):
            for value in (True, -1, 0, 0x1_0000_0000):
                with self.subTest(prefix=prefix, value=value):
                    receipt = _profile_receipt()
                    receipt[f"{prefix}folder_boundary_component_count"] = value
                    with self.assertRaises(boundary.BoundaryReportError):
                        boundary.recompute_boundary_summary(
                            _raw(),
                            _expected(),
                            _endpoint_receipt(),
                            receipt,
                            _path_context(),
                        )

    def test_profile_boundary_outside_cannot_smuggle_positive_component_count(self) -> None:
        receipt = _profile_receipt()
        _set_profile_boundary_state(
            receipt,
            prefix="recreate_",
            reason="packages_ancestor_mismatch",
        )
        receipt["recreate_folder_boundary_component_count"] = 1
        with self.assertRaises(boundary.BoundaryReportError):
            boundary.recompute_boundary_summary(
                _raw(),
                _expected(),
                _endpoint_receipt(),
                receipt,
                _path_context(),
            )

    def test_owner_controller_fact_false_extra_and_type_fail_closed(self) -> None:
        raw = _raw()
        raw["fingerprints"]["runtime_after"]["owner_matches_controller"] = False
        summary = boundary.recompute_boundary_summary(
            raw,
            _expected(),
            _endpoint_receipt(),
            _profile_receipt(),
            _path_context(),
        )
        self.assertFalse(summary["checks"]["filesystem"])
        self.assertEqual(summary["status"], "not_observed")

        for name, mutate in (
            (
                "legacy_owner_sid_extra",
                lambda fingerprint: fingerprint.__setitem__(
                    "owner_sid", "S-1-5-21-1-2-3-1001"
                ),
            ),
            (
                "owner_boolean_wrong_type",
                lambda fingerprint: fingerprint.__setitem__(
                    "owner_matches_controller", "true"
                ),
            ),
        ):
            with self.subTest(name=name):
                raw = _raw()
                mutate(raw["fingerprints"]["runtime_after"])
                with self.assertRaises(boundary.BoundaryReportError):
                    boundary.recompute_boundary_summary(
                        raw,
                        _expected(),
                        _endpoint_receipt(),
                        _profile_receipt(),
                        _path_context(),
                    )

    def test_profile_receipt_shape_and_prelaunch_binding_mutations_are_rejected(self) -> None:
        extra = _profile_receipt()
        extra["unexpected"] = True
        missing = _profile_receipt()
        del missing["ownership_established"]
        bool_as_int = _profile_receipt()
        bool_as_int["cleanup_complete"] = 1
        too_many_attempts = _profile_receipt()
        too_many_attempts["delete_attempt_hresults"] = [1, 2, 3, 0]

        for name, receipt in (
            ("extra", extra),
            ("missing", missing),
            ("bool_as_int", bool_as_int),
            ("too_many_attempts", too_many_attempts),
        ):
            with self.subTest(name=name):
                with self.assertRaises(boundary.BoundaryReportError):
                    boundary.recompute_boundary_summary(
                        _raw(), _expected(), _endpoint_receipt(), receipt, _path_context()
                    )

        raw = _raw()
        raw["profile"]["prelaunch_receipt_sha256"] = "2" * 64
        summary = boundary.recompute_boundary_summary(
            raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
        )
        self.assertFalse(summary["checks"]["identity"])
        self.assertEqual(summary["status"], "not_observed")

    def test_coherent_untrusted_profile_path_identity_substitution_fails_external_binding(
        self,
    ) -> None:
        raw = _raw()
        receipt = _profile_receipt()
        substituted_path_sha256 = hashlib.sha256(
            rb"d:\unrelated\sensitive"
        ).hexdigest()
        substituted_file_id = "ab" * 16
        substituted_volume = "cd" * 8
        raw["profile"].update(
            {
                "folder_file_id_128_hex": substituted_file_id,
                "folder_path_utf8_sha256": substituted_path_sha256,
                "folder_volume_serial_hex": substituted_volume,
            }
        )
        receipt.update(
            {
                "folder_file_id_128_hex": substituted_file_id,
                "folder_path_utf8_sha256": substituted_path_sha256,
                "folder_volume_serial_hex": substituted_volume,
            }
        )
        for arm in [
            raw["network"]["preflight_zero_capability"],
            *raw["network"]["lan_appcontainer_arms"],
        ]:
            arm.update(
                {
                    "current_directory_file_id_128_hex": substituted_file_id,
                    "current_directory_path_utf8_sha256": substituted_path_sha256,
                    "current_directory_volume_serial_hex": substituted_volume,
                    "request_parent_file_id_128_hex": substituted_file_id,
                    "request_parent_path_utf8_sha256": substituted_path_sha256,
                    "request_parent_volume_serial_hex": substituted_volume,
                    "request_volume_serial_hex": substituted_volume,
                }
            )

        summary = boundary.recompute_boundary_summary(
            raw, _expected(), _endpoint_receipt(), receipt, _path_context()
        )
        self.assertFalse(summary["checks"]["identity"])
        self.assertFalse(summary["checks"]["network"])
        self.assertEqual(summary["status"], "not_observed")

    def test_coherent_public_runtime_path_hash_substitution_fails_private_binding(
        self,
    ) -> None:
        raw = _raw()
        expected = _expected()
        substitute_runtime = r"D:\unrelated\sensitive\runtime"
        substitute_source = r"D:\unrelated\sensitive\source"
        substitute_python = substitute_runtime + r"\python.exe"
        substitute_probe = substitute_source + r"\windows_appcontainer_child_probe.py"
        expected.update(
            {
                "probe_source_path_utf8_sha256": _path_sha(substitute_probe),
                "runtime_executable_path_utf8_sha256": _path_sha(substitute_python),
                "runtime_root_path_utf8_sha256": _path_sha(substitute_runtime),
                "source_root_path_utf8_sha256": _path_sha(substitute_source),
            }
        )
        for role in boundary.PROCESS_ROLES:
            raw["processes"][role]["image"]["path_utf8_sha256"] = _path_sha(
                substitute_python
            )
            runtime = raw["runtime"][role]
            for key in (
                "base_exec_prefix_path_utf8_sha256",
                "base_prefix_path_utf8_sha256",
                "exec_prefix_path_utf8_sha256",
                "expected_runtime_root_path_utf8_sha256",
                "prefix_path_utf8_sha256",
            ):
                runtime[key] = _path_sha(substitute_runtime)
            runtime["expected_source_root_path_utf8_sha256"] = _path_sha(substitute_source)
            runtime["executable_path_utf8_sha256"] = _path_sha(substitute_python)
            runtime["probe_source_path_utf8_sha256"] = _path_sha(substitute_probe)
            for entry in runtime["sys_path"]:
                entry["path_utf8_sha256"] = _path_sha(
                    ntpath.join(substitute_runtime, entry["relative_to_runtime"])
                )
            for entry in runtime["module_origins"].values():
                entry["path_utf8_sha256"] = _path_sha(
                    ntpath.join(substitute_runtime, entry["relative_to_runtime"])
                )
        for fingerprint_key, substitute_root in (
            ("runtime_before", substitute_runtime),
            ("runtime_after", substitute_runtime),
            ("source_before", substitute_source),
            ("source_after", substitute_source),
        ):
            raw["fingerprints"][fingerprint_key]["root_identity"][
                "path_utf8_sha256"
            ] = _path_sha(substitute_root)
        for arm in [
            raw["network"]["preflight_zero_capability"],
            *raw["network"]["lan_appcontainer_arms"],
        ]:
            arm["image"]["path_utf8_sha256"] = _path_sha(substitute_python)

        summary = boundary.recompute_boundary_summary(
            raw,
            expected,
            _endpoint_receipt(),
            _profile_receipt(),
            _path_context(),
        )

        self.assertFalse(summary["checks"]["identity"])
        self.assertFalse(summary["checks"]["filesystem"])
        self.assertEqual(summary["status"], "not_observed")

    def test_profile_evidence_contains_no_absolute_profile_path_or_username(self) -> None:
        payload = repr((_raw(), _expected(), _profile_receipt())).encode("utf-8")
        self.assertNotIn(PROFILE.encode("utf-8"), payload)
        self.assertNotIn(b"C:\\Users\\owner", payload)

    def test_report_shape_mutations_fail_closed(self) -> None:
        extra = _raw()
        extra["unexpected"] = True
        missing = _raw()
        del missing["network"]["lan_full_trust_controls"]
        wrong_type = _raw()
        wrong_type["cleanup"]["work_root_empty"] = 1
        wrong_order = _raw()
        wrong_order["network"]["execution_order"][:2] = ["full_trust_before", "preflight_zero"]

        for name, raw in (
            ("extra", extra),
            ("missing", missing),
            ("wrong_type", wrong_type),
            ("wrong_order", wrong_order),
        ):
            with self.subTest(name=name):
                with self.assertRaises(boundary.BoundaryReportError):
                    boundary.recompute_boundary_summary(
                        raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
                    )

    def test_tampered_declared_summary_is_rejected(self) -> None:
        raw = _raw()
        raw["network"]["lan_full_trust_controls"][0]["connected"] = False
        recomputed = boundary.recompute_boundary_summary(
            raw, _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
        )
        declared = copy.deepcopy(recomputed)
        declared["checks"]["network"] = True
        declared["all_required_controls_observed"] = True
        declared["reason"] = "full_boundary_observed"
        declared["status"] = "observed_pass"
        declared["network_claims"]["lan_capability_differential_observed"] = True

        with self.assertRaisesRegex(boundary.BoundaryReportError, "declared_summary_mismatch"):
            boundary.validate_declared_summary(declared, recomputed)

    def test_exact_declared_summary_round_trips(self) -> None:
        recomputed = boundary.recompute_boundary_summary(
            _raw(), _expected(), _endpoint_receipt(), _profile_receipt(), _path_context()
        )

        self.assertEqual(boundary.validate_declared_summary(copy.deepcopy(recomputed), recomputed), recomputed)


if __name__ == "__main__":
    unittest.main()
