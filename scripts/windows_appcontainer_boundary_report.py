"""Strict recomputation for the Windows AppContainer boundary observations.

The native helper and the AppContainer child are both candidate code.  This
module therefore accepts raw values only, validates a closed shape, and
recomputes the dimension summary in the outer controller.  The result remains
self-issued and can never authorize a portability cell or release.
"""

from __future__ import annotations

import hashlib
import ipaddress
import ntpath
import re
from typing import Final

RAW_FORMAT: Final = "finplanbr.windows-appcontainer-boundary-observations.v9"
EXPECTED_FORMAT: Final = "finplanbr.windows-appcontainer-boundary-expected.v11"
SUMMARY_FORMAT: Final = "finplanbr.windows-appcontainer-boundary-summary.v11"
ENDPOINT_RECEIPT_FORMAT: Final = "finplanbr.windows-appcontainer-wsl2-endpoint-receipt.v1"
PROFILE_RECEIPT_FORMAT: Final = "finplanbr.windows-appcontainer-profile-receipt.v4"
FILE_IDENTITY_FORMAT: Final = "windows-file-id-info.v1"
NETWORK_ENDPOINT_CLASS: Final = "existing_running_wsl2_nat_guest_eth0.v1"
NETWORK_DISTRO_NAME: Final = "docker-desktop"
NETWORK_LISTENER_TIMEOUT_SECONDS: Final = 120
PORTABILITY_CELL_STATE: Final = "not_counted"
ERROR_ACCESS_DENIED: Final = 5
WSAEACCES: Final = 10_013
INTERNET_CLIENT_CAPABILITY_SID: Final = "S-1-15-3-1"
LOW_INTEGRITY_RID: Final = 0x1000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final = 0x00002000
JOB_OBJECT_LIMIT_BREAKAWAY_OK: Final = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK: Final = 0x00001000
SE_GROUP_ENABLED: Final = 0x00000004
SE_GROUP_USE_FOR_DENY_ONLY: Final = 0x00000010
SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
SID_PATTERN: Final = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\Z", re.ASCII)
CAPABILITY_ENTRY_PATTERN: Final = re.compile(
    r"S-1-(?:[0-9]+-)*[0-9]+\|0x[0-9a-f]{8}\Z", re.ASCII
)
MONIKER_PATTERN: Final = re.compile(r"finplanbrac-[0-9a-f]{24}\Z", re.ASCII)
PROFILE_FOLDER_BOUNDARY_REASONS: Final = frozenset(
    {
        "components_win32_invalid",
        "empty_descendant",
        "not_observed",
        "observed",
        "packages_ancestor_mismatch",
        "reconstruction_mismatch",
    }
)
BOOT_ID_PATTERN: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.ASCII,
)
NETNS_PATTERN: Final = re.compile(r"net:\[[0-9]+\]\Z", re.ASCII)
STARTUP_ATTRIBUTES: Final = ["handle_list", "job_list", "security_capabilities"]
FILESYSTEM_OPERATIONS: Final = [
    "ads",
    "create",
    "delete",
    "hardlink",
    "overwrite",
    "read",
    "rename",
    "reparse",
    "symlink",
    "write_dac",
    "write_owner",
]
PROCESS_ROLES: Final = ("root", "child", "grandchild")
RUNTIME_MODULES: Final = ("ctypes", "hashlib", "json", "os", "select", "socket", "subprocess")
NETWORK_ARM_SEQUENCE: Final = (
    ("zero_1", 1, ()),
    ("internet_client_1", 2, (INTERNET_CLIENT_CAPABILITY_SID,)),
    ("internet_client_2", 3, (INTERNET_CLIENT_CAPABILITY_SID,)),
    ("zero_2", 4, ()),
)
TOKEN_KEYS: Final = {
    "all_application_packages_membership_api",
    "all_application_packages_membership_api_call_succeeded",
    "all_application_packages_membership_api_win32_error",
    "all_application_packages_restricted_sid_match_attributes",
    "all_application_packages_restricted_sid_match_count",
    "all_application_packages_token_group_match_attributes",
    "all_application_packages_token_group_match_count",
    "appcontainer_sid",
    "capability_count",
    "capability_entries",
    "integrity_rid",
    "is_appcontainer",
    "is_elevated",
    "less_privileged_appcontainer_query_result",
    "less_privileged_appcontainer_query_supported",
    "restricted_sid_count",
    "token_group_count",
}
SUMMARY_KEYS: Final = {
    "all_required_controls_observed",
    "authority",
    "checks",
    "evidence_authentication",
    "format",
    "network_claims",
    "portability_cell",
    "reason",
    "release_authorized",
    "status",
}


class BoundaryReportError(ValueError):
    """The observation envelope is malformed rather than merely negative."""


def _dict(value: object, keys: set[str], name: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise BoundaryReportError(f"{name}_shape_invalid")
    return value


def _bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise BoundaryReportError(f"{name}_must_be_boolean")
    return value


def _int(value: object, name: str, *, minimum: int = 0, maximum: int = 0x7FFFFFFF) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise BoundaryReportError(f"{name}_integer_invalid")
    return value


def _text(value: object, name: str, *, maximum: int = 32_767) -> str:
    if type(value) is not str or not value or len(value) > maximum or "\x00" in value:
        raise BoundaryReportError(f"{name}_text_invalid")
    return value


def _sha(value: object, name: str) -> str:
    text = _text(value, name, maximum=64)
    if SHA256_PATTERN.fullmatch(text) is None:
        raise BoundaryReportError(f"{name}_sha256_invalid")
    return text


def _lower_hex(value: object, name: str, *, length: int) -> str:
    text = _text(value, name, maximum=length)
    if len(text) != length or any(character not in "0123456789abcdef" for character in text):
        raise BoundaryReportError(f"{name}_hex_invalid")
    return text


def _sid(value: object, name: str) -> str:
    text = _text(value, name, maximum=184)
    if SID_PATTERN.fullmatch(text) is None:
        raise BoundaryReportError(f"{name}_sid_invalid")
    return text


def _path(value: object, name: str) -> str:
    text = _text(value, name)
    drive, tail = ntpath.splitdrive(text)
    if not drive or not tail.startswith(("\\", "/")):
        raise BoundaryReportError(f"{name}_path_invalid")
    normalized = ntpath.normpath(text)
    if normalized != text.rstrip("\\/") and ntpath.normcase(normalized) != ntpath.normcase(text.rstrip("\\/")):
        raise BoundaryReportError(f"{name}_path_noncanonical")
    return normalized


def _same_path(left: str, right: str) -> bool:
    return ntpath.normcase(ntpath.normpath(left)) == ntpath.normcase(ntpath.normpath(right))


def _under(path: str, root: str) -> bool:
    try:
        return (
            ntpath.commonpath([ntpath.normpath(path), ntpath.normpath(root)]).casefold()
            == ntpath.normpath(root).casefold()
        )
    except ValueError:
        return False


def _canonical_path_utf8_sha256(path: str) -> str:
    canonical = _path(path, "private_path_context").replace("/", "\\").lower()
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_path_context(value: object) -> dict[str, str]:
    context = _dict(value, {"runtime_root", "source_root"}, "private_path_context")
    runtime_root = _path(context["runtime_root"], "private_runtime_root")
    source_root = _path(context["source_root"], "private_source_root")
    if _under(runtime_root, source_root) or _under(source_root, runtime_root):
        raise BoundaryReportError("private_roots_overlap")
    return {"runtime_root": runtime_root, "source_root": source_root}


def _relative_path(value: object, name: str) -> str:
    text = _text(value, name, maximum=1024)
    drive, _tail = ntpath.splitdrive(text)
    normalized = ntpath.normpath(text)
    if (
        drive
        or ntpath.isabs(text)
        or text != text.replace("/", "\\")
        or normalized != text
        or normalized in {"", ".", ".."}
        or any(part in {"", ".", ".."} for part in text.split("\\"))
    ):
        raise BoundaryReportError(f"{name}_relative_path_invalid")
    return text


def _path_identity(value: object, name: str) -> dict[str, object]:
    identity = _dict(
        value,
        {
            "file_id_128_hex",
            "identity_format",
            "leaf",
            "path_utf8_sha256",
            "role",
            "volume_serial_hex",
        },
        name,
    )
    _lower_hex(identity["file_id_128_hex"], f"{name}_file_id", length=32)
    _lower_hex(identity["volume_serial_hex"], f"{name}_volume_serial", length=16)
    _sha(identity["path_utf8_sha256"], f"{name}_path")
    if identity["identity_format"] != FILE_IDENTITY_FORMAT:
        raise BoundaryReportError(f"{name}_identity_format_invalid")
    _text(identity["leaf"], f"{name}_leaf", maximum=184)
    _text(identity["role"], f"{name}_role", maximum=96)
    return identity


def _validate_expected(value: object) -> dict[str, object]:
    expected = _dict(
        value,
        {
            "appcontainer_sid",
            "decoy_canary_sha256",
            "format",
            "internet_client_capability_sid",
            "moniker",
            "permitted_canary_sha256",
            "profile_folder_boundary_component_count",
            "profile_folder_boundary_terminal_ac",
            "profile_folder_file_id_128_hex",
            "profile_folder_identity_format",
            "profile_folder_path_utf8_sha256",
            "profile_folder_volume_serial_hex",
            "profile_network_request_path_utf8_sha256",
            "profile_prelaunch_sha256",
            "probe_source_leaf",
            "probe_source_path_utf8_sha256",
            "probe_source_sha256",
            "runtime_executable_leaf",
            "runtime_executable_path_utf8_sha256",
            "runtime_root_leaf",
            "runtime_root_path_utf8_sha256",
            "runtime_root_role",
            "source_root_leaf",
            "source_root_path_utf8_sha256",
            "source_root_role",
        },
        "expected",
    )
    if expected["format"] != EXPECTED_FORMAT:
        raise BoundaryReportError("expected_format_invalid")
    if expected["internet_client_capability_sid"] != INTERNET_CLIENT_CAPABILITY_SID:
        raise BoundaryReportError("expected_internet_client_capability_invalid")
    _sid(expected["appcontainer_sid"], "expected_appcontainer")
    moniker = _text(expected["moniker"], "expected_moniker", maximum=64)
    if MONIKER_PATTERN.fullmatch(moniker) is None:
        raise BoundaryReportError("expected_moniker_invalid")
    for key in (
        "decoy_canary_sha256",
        "permitted_canary_sha256",
        "probe_source_sha256",
        "profile_prelaunch_sha256",
        "profile_folder_path_utf8_sha256",
        "profile_network_request_path_utf8_sha256",
        "probe_source_path_utf8_sha256",
        "runtime_executable_path_utf8_sha256",
        "runtime_root_path_utf8_sha256",
        "source_root_path_utf8_sha256",
    ):
        _sha(expected[key], f"expected_{key}")
    _lower_hex(
        expected["profile_folder_file_id_128_hex"],
        "expected_profile_folder_file_id_128",
        length=32,
    )
    _lower_hex(
        expected["profile_folder_volume_serial_hex"],
        "expected_profile_folder_volume_serial",
        length=16,
    )
    if expected["profile_folder_identity_format"] != FILE_IDENTITY_FORMAT:
        raise BoundaryReportError("expected_profile_folder_identity_format_invalid")
    _int(
        expected["profile_folder_boundary_component_count"],
        "expected_profile_folder_boundary_component_count",
        minimum=1,
        maximum=0xFFFFFFFF,
    )
    _bool(
        expected["profile_folder_boundary_terminal_ac"],
        "expected_profile_folder_boundary_terminal_ac",
    )
    fixed_values = {
        "probe_source_leaf": "windows_appcontainer_child_probe.py",
        "runtime_executable_leaf": "python.exe",
        "runtime_root_leaf": "runtime",
        "runtime_root_role": "external_rx_runtime_copy",
        "source_root_leaf": "source",
        "source_root_role": "protected_probe_source_copy",
    }
    if any(expected[key] != fixed for key, fixed in fixed_values.items()):
        raise BoundaryReportError("expected_path_role_or_leaf_invalid")
    return expected


def _validate_token(value: object, name: str) -> dict[str, object]:
    token = _dict(value, TOKEN_KEYS, name)
    _sid(token["appcontainer_sid"], f"{name}_appcontainer")
    _int(token["capability_count"], f"{name}_capability_count", maximum=4096)
    capability_entries = token["capability_entries"]
    if type(capability_entries) is not str or len(capability_entries) > 8192:
        raise BoundaryReportError(f"{name}_capability_entries_invalid")
    roster = [] if not capability_entries else capability_entries.split(",")
    if (
        roster != sorted(set(roster))
        or len(roster) != token["capability_count"]
        or any(CAPABILITY_ENTRY_PATTERN.fullmatch(item) is None for item in roster)
    ):
        raise BoundaryReportError(f"{name}_capability_roster_invalid")
    _int(token["integrity_rid"], f"{name}_integrity_rid", maximum=0xFFFFFFFF)
    for key in (
        "all_application_packages_membership_api",
        "all_application_packages_membership_api_call_succeeded",
        "is_appcontainer",
        "is_elevated",
        "less_privileged_appcontainer_query_supported",
    ):
        _bool(token[key], f"{name}_{key}")
    less_privileged_result = token["less_privileged_appcontainer_query_result"]
    if less_privileged_result is not None and type(less_privileged_result) is not bool:
        raise BoundaryReportError(f"{name}_less_privileged_query_result_invalid")
    if token["less_privileged_appcontainer_query_supported"] is not (
        less_privileged_result is not None
    ):
        raise BoundaryReportError(f"{name}_less_privileged_query_consistency_invalid")
    membership_error = token["all_application_packages_membership_api_win32_error"]
    if membership_error is not None:
        _int(membership_error, f"{name}_aap_membership_win32_error", maximum=0xFFFFFFFF)
    if token["all_application_packages_membership_api_call_succeeded"] is not (membership_error is None):
        raise BoundaryReportError(f"{name}_aap_membership_call_consistency_invalid")
    for roster_name in ("token_group", "restricted_sid"):
        total_count = _int(token[f"{roster_name}_count"], f"{name}_{roster_name}_count", maximum=65_535)
        match_count = _int(
            token[f"all_application_packages_{roster_name}_match_count"],
            f"{name}_aap_{roster_name}_match_count",
            maximum=65_535,
        )
        attributes = token[f"all_application_packages_{roster_name}_match_attributes"]
        if type(attributes) is not str or len(attributes) > 65_535:
            raise BoundaryReportError(f"{name}_aap_{roster_name}_match_attributes_invalid")
        attribute_roster = [] if not attributes else attributes.split(",")
        if (
            len(attribute_roster) != match_count
            or match_count > total_count
            or attribute_roster != sorted(attribute_roster)
            or any(re.fullmatch(r"0x[0-9a-f]{8}", item, re.ASCII) is None for item in attribute_roster)
        ):
            raise BoundaryReportError(f"{name}_aap_{roster_name}_roster_invalid")
    return token


def _lineage_capability_entry(expected_sid: str) -> str:
    components = expected_sid.split("-")
    if len(components) == 15 and components[:4] == ["S", "1", "15", "2"]:
        return "S-1-15-3-" + "-".join(components[4:11]) + "|0x00000004"
    return ""


def _token_identity_facts(token: dict[str, object], expected_sid: str) -> bool:
    attribute_rosters = (
        str(token["all_application_packages_token_group_match_attributes"]),
        str(token["all_application_packages_restricted_sid_match_attributes"]),
    )
    effective_match = any(
        (attribute & SE_GROUP_ENABLED) != 0
        and (attribute & SE_GROUP_USE_FOR_DENY_ONLY) == 0
        for roster in attribute_rosters
        for attribute in (int(item, 16) for item in roster.split(",") if item)
    )
    return (
        token["appcontainer_sid"] == expected_sid
        and token["is_appcontainer"] is True
        and token["is_elevated"] is False
        and token["integrity_rid"] == LOW_INTEGRITY_RID
        # TokenIsLessPrivilegedAppContainer is an optional diagnostic on hosts
        # where information class 46 returns ERROR_INVALID_PARAMETER.  A true
        # result still disproves the regular-AppContainer claim; false or an
        # unsupported/null pair needs the independently bound launch policy and
        # same-token AAP behaviour for network arms.
        and token["less_privileged_appcontainer_query_result"] is not True
        and token["all_application_packages_membership_api_call_succeeded"] is True
        and token["all_application_packages_membership_api_win32_error"] is None
        and effective_match
    )


def _capability_lineage(token: dict[str, object], expected_sid: str) -> bool:
    expected_capability = _lineage_capability_entry(expected_sid)
    return (
        _token_identity_facts(token, expected_sid)
        and token["capability_count"] == 1
        and token["capability_entries"] == expected_capability
    )


def _runtime_path_entry(
    value: object,
    name: str,
    runtime_root: str,
    *,
    with_blob: bool,
) -> tuple[str, str, str | None]:
    keys = {"path_utf8_sha256", "relative_to_runtime"}
    if with_blob:
        keys.add("blob_sha256")
    entry = _dict(value, keys, name)
    path_sha256 = _sha(entry["path_utf8_sha256"], f"{name}_path")
    relative = _relative_path(entry["relative_to_runtime"], f"{name}_relative")
    joined = ntpath.join(runtime_root, relative)
    if not _under(joined, runtime_root):
        raise BoundaryReportError(f"{name}_outside_runtime")
    blob_sha256 = _sha(entry["blob_sha256"], f"{name}_blob") if with_blob else None
    return path_sha256, relative, blob_sha256


def _runtime_ok(
    value: object,
    name: str,
    runtime_root: str,
    source_root: str,
) -> bool:
    runtime = _dict(
        value,
        {
            "base_exec_prefix_path_utf8_sha256",
            "base_prefix_path_utf8_sha256",
            "dont_write_bytecode",
            "executable_leaf",
            "executable_path_utf8_sha256",
            "exec_prefix_path_utf8_sha256",
            "expected_runtime_root_path_utf8_sha256",
            "expected_source_root_path_utf8_sha256",
            "ignore_environment",
            "implementation",
            "isolated",
            "module_origins",
            "no_user_site",
            "prefix_path_utf8_sha256",
            "probe_source_leaf",
            "probe_source_path_utf8_sha256",
            "runtime_root_role",
            "safe_path",
            "source_root_role",
            "sys_path",
            "version",
            "version_text_sha256",
        },
        name,
    )
    root_sha256 = _canonical_path_utf8_sha256(runtime_root)
    source_sha256 = _canonical_path_utf8_sha256(source_root)
    executable_sha256 = _canonical_path_utf8_sha256(ntpath.join(runtime_root, "python.exe"))
    probe_sha256 = _canonical_path_utf8_sha256(
        ntpath.join(source_root, "windows_appcontainer_child_probe.py")
    )
    for key in (
        "base_exec_prefix_path_utf8_sha256",
        "base_prefix_path_utf8_sha256",
        "executable_path_utf8_sha256",
        "exec_prefix_path_utf8_sha256",
        "expected_runtime_root_path_utf8_sha256",
        "expected_source_root_path_utf8_sha256",
        "prefix_path_utf8_sha256",
        "probe_source_path_utf8_sha256",
        "version_text_sha256",
    ):
        _sha(runtime[key], f"{name}_{key}")
    for key in ("dont_write_bytecode", "ignore_environment", "isolated", "no_user_site", "safe_path"):
        _bool(runtime[key], f"{name}_{key}")
    implementation = _text(runtime["implementation"], f"{name}_implementation", maximum=32)
    version = runtime["version"]
    if type(version) is not list or len(version) != 3:
        raise BoundaryReportError(f"{name}_version_shape_invalid")
    version_values = [_int(item, f"{name}_version_item", maximum=0xFFFF) for item in version]
    sys_path = runtime["sys_path"]
    if type(sys_path) is not list or not sys_path or len(sys_path) > 32:
        raise BoundaryReportError(f"{name}_sys_path_shape_invalid")
    normalized_sys_path = [
        _runtime_path_entry(item, f"{name}_sys_path_item", runtime_root, with_blob=False)
        for item in sys_path
    ]
    if len({item[:2] for item in normalized_sys_path}) != len(normalized_sys_path):
        raise BoundaryReportError(f"{name}_sys_path_duplicate")
    module_origins = _dict(runtime["module_origins"], set(RUNTIME_MODULES), f"{name}_module_origins")
    normalized_origins = [
        _runtime_path_entry(
            module_origins[key],
            f"{name}_{key}_origin",
            runtime_root,
            with_blob=True,
        )
        for key in RUNTIME_MODULES
    ]
    return (
        implementation == "cpython"
        and version_values[:2] == [3, 13]
        and runtime["runtime_root_role"] == "external_rx_runtime_copy"
        and runtime["source_root_role"] == "protected_probe_source_copy"
        and runtime["executable_leaf"] == "python.exe"
        and runtime["probe_source_leaf"] == "windows_appcontainer_child_probe.py"
        and all(
            runtime[key] is True
            for key in ("dont_write_bytecode", "ignore_environment", "isolated", "no_user_site", "safe_path")
        )
        and all(
            runtime[key] == root_sha256
            for key in (
                "base_exec_prefix_path_utf8_sha256",
                "base_prefix_path_utf8_sha256",
                "exec_prefix_path_utf8_sha256",
                "expected_runtime_root_path_utf8_sha256",
                "prefix_path_utf8_sha256",
            )
        )
        and runtime["expected_source_root_path_utf8_sha256"] == source_sha256
        and runtime["executable_path_utf8_sha256"] == executable_sha256
        and runtime["probe_source_path_utf8_sha256"] == probe_sha256
        and all(
            path_sha256 == _canonical_path_utf8_sha256(ntpath.join(runtime_root, relative))
            for path_sha256, relative, _blob in (*normalized_sys_path, *normalized_origins)
        )
    )


def _fingerprint(value: object, name: str) -> dict[str, object]:
    fingerprint = _dict(
        value,
        {
            "all_entries_appcontainer_mutation_rights_absent",
            "declared_read_execute_entries_appcontainer_read_execute",
            "all_entries_controller_full_control",
            "all_entries_owner_matches_root",
            "all_files_single_link",
            "alternate_stream_count",
            "appcontainer_mutation_rights_absent",
            "appcontainer_read_execute",
            "byte_count",
            "controller_full_control",
            "dacl_protected",
            "entry_count",
            "object_identity_sha256",
            "owner_matches_controller",
            "reparse_free",
            "root_identity",
            "tree_sha256",
        },
        name,
    )
    _path_identity(fingerprint["root_identity"], f"{name}_root_identity")
    _sha(fingerprint["tree_sha256"], f"{name}_tree")
    _sha(fingerprint["object_identity_sha256"], f"{name}_object_identity")
    _int(fingerprint["entry_count"], f"{name}_entry_count", minimum=1)
    _int(fingerprint["byte_count"], f"{name}_byte_count", minimum=1, maximum=0x7FFFFFFFFFFFFFFF)
    _int(fingerprint["alternate_stream_count"], f"{name}_alternate_stream_count", maximum=1_000_000)
    for key in (
        "all_entries_appcontainer_mutation_rights_absent",
        "declared_read_execute_entries_appcontainer_read_execute",
        "all_entries_controller_full_control",
        "all_entries_owner_matches_root",
        "all_files_single_link",
        "owner_matches_controller",
        "appcontainer_mutation_rights_absent",
        "appcontainer_read_execute",
        "controller_full_control",
        "dacl_protected",
        "reparse_free",
    ):
        _bool(fingerprint[key], f"{name}_{key}")
    return fingerprint


def _fingerprint_pair_ok(
    before: dict[str, object],
    after: dict[str, object],
    expected_role: str,
    expected_leaf: str,
    expected_path_sha256: str,
) -> bool:
    stable_keys = (
        "alternate_stream_count",
        "byte_count",
        "entry_count",
        "object_identity_sha256",
        "owner_matches_controller",
        "root_identity",
        "tree_sha256",
    )
    return (
        all(before[key] == after[key] for key in stable_keys)
        and before["root_identity"]["role"] == expected_role
        and before["root_identity"]["leaf"] == expected_leaf
        and before["root_identity"]["path_utf8_sha256"] == expected_path_sha256
        and all(
            item[key] is True
            for item in (before, after)
            for key in (
                "all_entries_appcontainer_mutation_rights_absent",
                "declared_read_execute_entries_appcontainer_read_execute",
                "all_entries_controller_full_control",
                "all_entries_owner_matches_root",
                "all_files_single_link",
                "appcontainer_mutation_rights_absent",
                "appcontainer_read_execute",
                "controller_full_control",
                "dacl_protected",
                "owner_matches_controller",
                "reparse_free",
            )
        )
        and before["alternate_stream_count"] == 0
    )


def _operation_pair_ok(
    value: object,
    name: str,
    operation: str,
    expected_probe_sha256: str,
) -> bool:
    pair = _dict(value, {"negative", "positive"}, name)
    positive = _dict(pair["positive"], {"observation", "status", "winerror"}, f"{name}_positive")
    negative = _dict(pair["negative"], {"observation", "status", "winerror"}, f"{name}_negative")
    if type(positive["observation"]) not in {bool, int, str, type(None)}:
        raise BoundaryReportError(f"{name}_positive_observation_invalid")
    if type(negative["observation"]) not in {bool, int, str, type(None)}:
        raise BoundaryReportError(f"{name}_negative_observation_invalid")
    if positive["winerror"] is not None:
        _int(positive["winerror"], f"{name}_positive_winerror", maximum=0xFFFFFFFF)
    if negative["winerror"] is not None:
        _int(negative["winerror"], f"{name}_negative_winerror", maximum=0xFFFFFFFF)
    observation = positive["observation"]
    if operation == "read":
        positive_observation_ok = observation == expected_probe_sha256
    elif operation in {"ads", "create", "overwrite"}:
        positive_observation_ok = type(observation) is str and SHA256_PATTERN.fullmatch(observation) is not None
    elif operation in {"delete", "hardlink", "rename", "reparse", "symlink"}:
        positive_observation_ok = observation is True
    elif operation in {"write_dac", "write_owner"}:
        positive_observation_ok = type(observation) is int and observation == 0
    else:
        raise BoundaryReportError(f"{name}_operation_invalid")
    return (
        positive["status"] == "success"
        and positive["winerror"] is None
        and positive_observation_ok
        and negative["status"] == "error"
        and negative["winerror"] == ERROR_ACCESS_DENIED
    )


def _network_attempt(value: object, name: str) -> dict[str, object]:
    attempt = _dict(
        value,
        {
            "connected",
            "diagnosis_result",
            "diagnosis_type",
            "echo_matches",
            "echo_nonce_sha256",
            "host",
            "nonce_sha256",
            "port",
            "winerror",
        },
        name,
    )
    _bool(attempt["connected"], f"{name}_connected")
    _bool(attempt["echo_matches"], f"{name}_echo_matches")
    _sha(attempt["nonce_sha256"], f"{name}_nonce")
    _ipv4(attempt["host"], f"{name}_host")
    _int(attempt["port"], f"{name}_port", minimum=1, maximum=65_535)
    if attempt["echo_nonce_sha256"] is not None:
        _sha(attempt["echo_nonce_sha256"], f"{name}_echo_nonce")
    for key in ("diagnosis_result", "diagnosis_type", "winerror"):
        if attempt[key] is not None:
            _int(attempt[key], f"{name}_{key}", maximum=0xFFFFFFFF)
    return attempt


def _network_control(value: object, name: str) -> dict[str, object]:
    control = _dict(
        value,
        {
            "accepted",
            "connected",
            "host",
            "nonce_matches",
            "nonce_sha256",
            "order",
            "port",
            "received_nonce_sha256",
            "winerror",
        },
        name,
    )
    for key in ("accepted", "connected", "nonce_matches"):
        _bool(control[key], f"{name}_{key}")
    _ipv4(control["host"], f"{name}_host")
    _int(control["order"], f"{name}_order", maximum=16)
    _int(control["port"], f"{name}_port", minimum=1, maximum=65_535)
    _sha(control["nonce_sha256"], f"{name}_nonce")
    if control["received_nonce_sha256"] is not None:
        _sha(control["received_nonce_sha256"], f"{name}_received_nonce")
    if control["winerror"] is not None:
        _int(control["winerror"], f"{name}_winerror", maximum=0xFFFFFFFF)
    return control


def _regular_appcontainer_proof(value: object, name: str) -> dict[str, object]:
    proof = _dict(
        value,
        {
            "aap_negative_access_denied",
            "aap_positive_read_sha256_matches",
            "claim",
            "regular_launch_policy_bound",
            "same_primary_token_source_bound",
        },
        name,
    )
    for key in (
        "aap_negative_access_denied",
        "aap_positive_read_sha256_matches",
        "regular_launch_policy_bound",
        "same_primary_token_source_bound",
    ):
        _bool(proof[key], f"{name}_{key}")
    if (
        proof["claim"]
        != "regular_appcontainer_effect_observed_from_same_primary_token_source"
    ):
        raise BoundaryReportError(f"{name}_claim_invalid")
    return proof


def _regular_appcontainer_proof_observed(proof: dict[str, object]) -> bool:
    return all(
        proof[key] is True
        for key in (
            "aap_negative_access_denied",
            "aap_positive_read_sha256_matches",
            "regular_launch_policy_bound",
            "same_primary_token_source_bound",
        )
    )


def _network_arm(value: object, name: str) -> dict[str, object]:
    arm = _dict(
        value,
        {
            "attempt",
            "command_line_sha256",
            "create_suspended",
            "current_directory_file_id_128_hex",
            "current_directory_identity_format",
            "current_directory_path_utf8_sha256",
            "current_directory_volume_serial_hex",
            "environment_sha256",
            "image",
            "job_member",
            "label",
            "order",
            "parent_pid",
            "pid",
            "reported_parent_pid",
            "reported_pid",
            "reported_request_sha256",
            "regular_appcontainer",
            "request_file_id_128_hex",
            "request_identity_format",
            "request_leaf",
            "request_parent_file_id_128_hex",
            "request_parent_identity_format",
            "request_parent_path_utf8_sha256",
            "request_parent_volume_serial_hex",
            "request_path_utf8_sha256",
            "request_sha256",
            "request_volume_serial_hex",
            "requested_capabilities_pointer_null",
            "requested_capability_sids",
            "resume_thread_count",
            "startup_attribute_count",
            "startup_attributes",
            "timeout_milliseconds",
            "target_host",
            "target_port",
            "token",
        },
        name,
    )
    for key in (
        "create_suspended",
        "job_member",
        "requested_capabilities_pointer_null",
    ):
        _bool(arm[key], f"{name}_{key}")
    for key in (
        "order",
        "parent_pid",
        "pid",
        "reported_parent_pid",
        "reported_pid",
        "resume_thread_count",
        "startup_attribute_count",
        "timeout_milliseconds",
        "target_port",
    ):
        _int(
            arm[key],
            f"{name}_{key}",
            minimum=0 if key == "order" else 1,
            maximum=0x7FFFFFFF,
        )
    for key in (
        "command_line_sha256",
        "current_directory_path_utf8_sha256",
        "environment_sha256",
        "reported_request_sha256",
        "request_parent_path_utf8_sha256",
        "request_path_utf8_sha256",
        "request_sha256",
    ):
        _sha(arm[key], f"{name}_{key}")
    _path_identity(arm["image"], f"{name}_image")
    for key in (
        "current_directory_file_id_128_hex",
        "request_file_id_128_hex",
        "request_parent_file_id_128_hex",
    ):
        _lower_hex(arm[key], f"{name}_{key}", length=32)
    for key in (
        "current_directory_volume_serial_hex",
        "request_parent_volume_serial_hex",
        "request_volume_serial_hex",
    ):
        _lower_hex(arm[key], f"{name}_{key}", length=16)
    for key in (
        "current_directory_identity_format",
        "request_identity_format",
        "request_parent_identity_format",
    ):
        if arm[key] != FILE_IDENTITY_FORMAT:
            raise BoundaryReportError(f"{name}_{key}_invalid")
    if arm["request_leaf"] != "network-arm-request.json":
        raise BoundaryReportError(f"{name}_request_leaf_invalid")
    _text(arm["label"], f"{name}_label", maximum=64)
    _ipv4(arm["target_host"], f"{name}_target_host")
    if type(arm["requested_capability_sids"]) is not list:
        raise BoundaryReportError(f"{name}_requested_capabilities_shape_invalid")
    requested = [
        _sid(item, f"{name}_requested_capability")
        for item in arm["requested_capability_sids"]
    ]
    if requested != sorted(set(requested)):
        raise BoundaryReportError(f"{name}_requested_capabilities_roster_invalid")
    if type(arm["startup_attributes"]) is not list or not all(
        type(item) is str for item in arm["startup_attributes"]
    ):
        raise BoundaryReportError(f"{name}_startup_attributes_invalid")
    _network_attempt(arm["attempt"], f"{name}_attempt")
    _validate_token(arm["token"], f"{name}_token")
    _regular_appcontainer_proof(
        arm["regular_appcontainer"], f"{name}_regular_appcontainer"
    )
    return arm


def _ipv4(value: object, name: str) -> str:
    text = _text(value, name, maximum=15)
    try:
        parsed = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError as exc:
        raise BoundaryReportError(f"{name}_ipv4_invalid") from exc
    if str(parsed) != text:
        raise BoundaryReportError(f"{name}_ipv4_noncanonical")
    return text


def _validate_endpoint_receipt(value: object) -> dict[str, object]:
    receipt = _dict(
        value,
        {
            "cleanup_exact_listener_pid_only",
            "distro_name",
            "distro_running_after",
            "distro_running_before",
            "endpoint_class",
            "format",
            "guest_boot_id_after",
            "guest_boot_id_before",
            "busybox_sha256",
            "guest_interface",
            "guest_ipv4_after",
            "guest_ipv4_before",
            "guest_prefix_length_after",
            "guest_prefix_length_before",
            "guest_residual_absent_after",
            "host_launcher_process_absent_after",
            "host_launcher_pid",
            "host_launcher_creation_time_100ns",
            "listener_command_sha256",
            "listener_pid",
            "listener_port",
            "listener_port_absent_before_start",
            "listener_port_absent_after",
            "listener_port_observed_before",
            "listener_process_absent_before_start",
            "listener_process_absent_after",
            "listener_process_observed_before",
            "listener_socket_inode",
            "listener_starttime_ticks",
            "listener_watchdog_timeout_seconds",
            "startup_nonce_sha256",
            "startup_script_sha256",
            "netns_inode_after",
            "netns_inode_before",
            "windows_interface_ip_absent_after",
            "windows_interface_ip_absent_before",
            "watchdog_pid",
            "watchdog_process_absent_after",
            "watchdog_starttime_ticks",
            "wsl_version",
        },
        "endpoint_receipt",
    )
    if receipt["format"] != ENDPOINT_RECEIPT_FORMAT:
        raise BoundaryReportError("endpoint_receipt_format_invalid")
    if receipt["endpoint_class"] != NETWORK_ENDPOINT_CLASS:
        raise BoundaryReportError("endpoint_receipt_class_invalid")
    if receipt["distro_name"] != NETWORK_DISTRO_NAME:
        raise BoundaryReportError("endpoint_receipt_distro_invalid")
    if receipt["guest_interface"] != "eth0" or receipt["wsl_version"] != 2:
        raise BoundaryReportError("endpoint_receipt_namespace_invalid")
    for key in ("guest_boot_id_before", "guest_boot_id_after"):
        text = _text(receipt[key], f"endpoint_{key}", maximum=36)
        if BOOT_ID_PATTERN.fullmatch(text) is None:
            raise BoundaryReportError(f"endpoint_{key}_invalid")
    for key in ("netns_inode_before", "netns_inode_after"):
        text = _text(receipt[key], f"endpoint_{key}", maximum=64)
        if NETNS_PATTERN.fullmatch(text) is None:
            raise BoundaryReportError(f"endpoint_{key}_invalid")
    for key in ("guest_ipv4_before", "guest_ipv4_after"):
        _ipv4(receipt[key], f"endpoint_{key}")
    for key in ("guest_prefix_length_before", "guest_prefix_length_after"):
        _int(receipt[key], f"endpoint_{key}", minimum=1, maximum=32)
    _int(receipt["listener_pid"], "endpoint_listener_pid", minimum=2)
    _int(receipt["host_launcher_pid"], "endpoint_host_launcher_pid", minimum=2)
    _int(
        receipt["host_launcher_creation_time_100ns"],
        "endpoint_host_launcher_creation_time",
        minimum=1,
        maximum=0x7FFFFFFFFFFFFFFF,
    )
    _int(receipt["listener_port"], "endpoint_listener_port", minimum=49_152, maximum=65_535)
    _int(
        receipt["listener_socket_inode"],
        "endpoint_listener_socket_inode",
        minimum=1,
        maximum=0x7FFFFFFFFFFFFFFF,
    )
    _int(
        receipt["listener_starttime_ticks"],
        "endpoint_listener_starttime_ticks",
        minimum=1,
        maximum=0x7FFFFFFFFFFFFFFF,
    )
    _int(
        receipt["listener_watchdog_timeout_seconds"],
        "endpoint_listener_watchdog_timeout",
        minimum=30,
        maximum=600,
    )
    _sha(receipt["listener_command_sha256"], "endpoint_listener_command")
    _int(receipt["watchdog_pid"], "endpoint_watchdog_pid", minimum=2)
    _int(
        receipt["watchdog_starttime_ticks"],
        "endpoint_watchdog_starttime_ticks",
        minimum=1,
        maximum=0x7FFFFFFFFFFFFFFF,
    )
    for key in (
        "busybox_sha256",
        "listener_command_sha256",
        "startup_nonce_sha256",
        "startup_script_sha256",
    ):
        _sha(receipt[key], f"endpoint_{key}")
    for key in (
        "cleanup_exact_listener_pid_only",
        "distro_running_after",
        "distro_running_before",
        "guest_residual_absent_after",
        "host_launcher_process_absent_after",
        "listener_port_absent_after",
        "listener_port_absent_before_start",
        "listener_port_observed_before",
        "listener_process_absent_after",
        "listener_process_absent_before_start",
        "listener_process_observed_before",
        "windows_interface_ip_absent_after",
        "windows_interface_ip_absent_before",
        "watchdog_process_absent_after",
    ):
        _bool(receipt[key], f"endpoint_{key}")
    return receipt


def _validate_profile_folder_boundary(
    receipt: dict[str, object], *, prefix: str
) -> None:
    field_prefix = f"{prefix}folder_boundary_"
    component_count = _int(
        receipt[f"{field_prefix}component_count"],
        f"profile_receipt_{field_prefix}component_count",
        maximum=0xFFFFFFFF,
    )
    components = _bool(
        receipt[f"{field_prefix}components_win32_valid"],
        f"profile_receipt_{field_prefix}components_win32_valid",
    )
    exact = _bool(receipt[f"{field_prefix}exact"], f"profile_receipt_{field_prefix}exact")
    nonempty = _bool(
        receipt[f"{field_prefix}nonempty_descendant"],
        f"profile_receipt_{field_prefix}nonempty_descendant",
    )
    packages = _bool(
        receipt[f"{field_prefix}packages_ancestor"],
        f"profile_receipt_{field_prefix}packages_ancestor",
    )
    reconstruction = _bool(
        receipt[f"{field_prefix}reconstruction_matches"],
        f"profile_receipt_{field_prefix}reconstruction_matches",
    )
    terminal = _bool(
        receipt[f"{field_prefix}terminal_ac"],
        f"profile_receipt_{field_prefix}terminal_ac",
    )
    reason = _text(
        receipt[f"{field_prefix}reason"],
        f"profile_receipt_{field_prefix}reason",
        maximum=64,
    )
    if reason not in PROFILE_FOLDER_BOUNDARY_REASONS:
        raise BoundaryReportError(f"profile_receipt_{field_prefix}reason_invalid")
    if reason == "not_observed":
        if component_count != 0 or any(
            (components, exact, nonempty, packages, reconstruction, terminal)
        ):
            raise BoundaryReportError(f"profile_receipt_{field_prefix}not_observed_invalid")
        return
    if (
        (not packages and component_count != 0)
        or nonempty != (packages and component_count >= 1)
        or ((components or reconstruction or terminal) and not nonempty)
        or exact != all((packages, nonempty, components, reconstruction))
    ):
        raise BoundaryReportError(f"profile_receipt_{field_prefix}booleans_incoherent")
    if not packages:
        expected_reason = "packages_ancestor_mismatch"
    elif not nonempty:
        expected_reason = "empty_descendant"
    elif not components:
        expected_reason = "components_win32_invalid"
    elif not reconstruction:
        expected_reason = "reconstruction_mismatch"
    else:
        expected_reason = "observed"
    if reason != expected_reason:
        raise BoundaryReportError(f"profile_receipt_{field_prefix}reason_incoherent")


def _validate_profile_receipt(value: object) -> dict[str, object]:
    receipt = _dict(
        value,
        {
            "cleanup_attempted",
            "cleanup_complete",
            "closed",
            "delete_suppressed_due_identity_uncertainty",
            "delete_attempt_hresults",
            "delete_succeeded",
            "final_delete_attempt_hresults",
            "final_delete_succeeded",
            "final_folder_absent",
            "first_folder_absent",
            "folder_boundary_component_count",
            "folder_boundary_components_win32_valid",
            "folder_boundary_exact",
            "folder_boundary_nonempty_descendant",
            "folder_boundary_packages_ancestor",
            "folder_boundary_reason",
            "folder_boundary_reconstruction_matches",
            "folder_boundary_terminal_ac",
            "folder_file_id_128_hex",
            "folder_identity_drift_detected",
            "folder_identity_format",
            "folder_identity_revalidated_before_release",
            "folder_path_utf8_sha256",
            "folder_volume_serial_hex",
            "format",
            "moniker",
            "owned",
            "ownership_established",
            "profile_directory_handle_release_attempted",
            "profile_directory_handle_released",
            "recreate_attempted",
            "recreate_created_hresult",
            "recreate_folder_boundary_component_count",
            "recreate_folder_boundary_components_win32_valid",
            "recreate_folder_boundary_exact",
            "recreate_folder_boundary_nonempty_descendant",
            "recreate_folder_boundary_packages_ancestor",
            "recreate_folder_boundary_reason",
            "recreate_folder_boundary_reconstruction_matches",
            "recreate_folder_boundary_terminal_ac",
            "recreate_folder_exists",
            "recreate_folder_reparse_free",
            "recreate_succeeded",
            "recreated_sid",
            "recreated_sid_matches",
            "residual_race_after_handle_release",
        },
        "profile_receipt",
    )
    if receipt["format"] != PROFILE_RECEIPT_FORMAT:
        raise BoundaryReportError("profile_receipt_format_invalid")
    moniker = _text(receipt["moniker"], "profile_receipt_moniker", maximum=64)
    if MONIKER_PATTERN.fullmatch(moniker) is None:
        raise BoundaryReportError("profile_receipt_moniker_invalid")
    for key in (
        "cleanup_attempted",
        "cleanup_complete",
        "closed",
        "delete_suppressed_due_identity_uncertainty",
        "delete_succeeded",
        "final_delete_succeeded",
        "final_folder_absent",
        "first_folder_absent",
        "folder_identity_drift_detected",
        "folder_identity_revalidated_before_release",
        "owned",
        "ownership_established",
        "profile_directory_handle_release_attempted",
        "profile_directory_handle_released",
        "recreate_attempted",
        "recreate_folder_exists",
        "recreate_folder_reparse_free",
        "recreate_succeeded",
        "recreated_sid_matches",
    ):
        _bool(receipt[key], f"profile_receipt_{key}")
    _validate_profile_folder_boundary(receipt, prefix="")
    _validate_profile_folder_boundary(receipt, prefix="recreate_")
    _lower_hex(
        receipt["folder_file_id_128_hex"],
        "profile_receipt_folder_file_id_128",
        length=32,
    )
    _sha(receipt["folder_path_utf8_sha256"], "profile_receipt_folder_path_utf8")
    _lower_hex(
        receipt["folder_volume_serial_hex"],
        "profile_receipt_folder_volume_serial",
        length=16,
    )
    if receipt["folder_identity_format"] != FILE_IDENTITY_FORMAT:
        raise BoundaryReportError("profile_receipt_folder_identity_format_invalid")
    if receipt["residual_race_after_handle_release"] != "not_prevented":
        raise BoundaryReportError("profile_receipt_residual_race_state_invalid")
    for key in ("delete_attempt_hresults", "final_delete_attempt_hresults"):
        attempts = receipt[key]
        if type(attempts) is not list or len(attempts) > 3:
            raise BoundaryReportError(f"profile_receipt_{key}_invalid")
        for index, result in enumerate(attempts):
            _int(result, f"profile_receipt_{key}_{index}", maximum=0xFFFFFFFF)
    recreate_hresult = receipt["recreate_created_hresult"]
    if recreate_hresult is not None:
        _int(recreate_hresult, "profile_receipt_recreate_created_hresult", maximum=0xFFFFFFFF)
    recreated_sid = receipt["recreated_sid"]
    if recreated_sid is not None:
        _sid(recreated_sid, "profile_receipt_recreated_sid")
    return receipt


def recompute_boundary_summary(
    raw_value: object,
    expected_value: object,
    endpoint_receipt_value: object,
    profile_receipt_value: object,
    private_path_context_value: object,
) -> dict[str, object]:
    """Validate raw observations and recompute the fail-closed local summary."""

    expected = _validate_expected(expected_value)
    private_paths = _validate_path_context(private_path_context_value)
    runtime_root = private_paths["runtime_root"]
    source_root = private_paths["source_root"]
    expected_paths_ok = (
        expected["runtime_root_path_utf8_sha256"]
        == _canonical_path_utf8_sha256(runtime_root)
        and expected["source_root_path_utf8_sha256"]
        == _canonical_path_utf8_sha256(source_root)
        and expected["runtime_executable_path_utf8_sha256"]
        == _canonical_path_utf8_sha256(ntpath.join(runtime_root, "python.exe"))
        and expected["probe_source_path_utf8_sha256"]
        == _canonical_path_utf8_sha256(
            ntpath.join(source_root, "windows_appcontainer_child_probe.py")
        )
    )
    endpoint_receipt = _validate_endpoint_receipt(endpoint_receipt_value)
    profile_receipt = _validate_profile_receipt(profile_receipt_value)
    raw = _dict(
        raw_value,
        {
            "cleanup",
            "filesystem",
            "fingerprints",
            "format",
            "handles",
            "identity",
            "job",
            "network",
            "processes",
            "profile",
            "request",
            "runtime",
        },
        "raw",
    )
    if raw["format"] != RAW_FORMAT:
        raise BoundaryReportError("raw_format_invalid")

    request = _dict(
        raw["request"],
        {
            "create_suspended",
            "inherit_handles",
            "python_flags",
            "requested_capabilities_pointer_null",
            "requested_capability_count",
            "resume_thread_count",
            "startup_attribute_count",
            "startup_attributes",
        },
        "request",
    )
    for key in ("create_suspended", "inherit_handles", "requested_capabilities_pointer_null"):
        _bool(request[key], f"request_{key}")
    requested_count = _int(request["requested_capability_count"], "requested_capability_count", maximum=4096)
    attribute_count = _int(request["startup_attribute_count"], "startup_attribute_count", maximum=16)
    resume_count = _int(request["resume_thread_count"], "resume_thread_count", maximum=16)
    if type(request["python_flags"]) is not list or not all(type(item) is str for item in request["python_flags"]):
        raise BoundaryReportError("python_flags_invalid")
    if type(request["startup_attributes"]) is not list or not all(
        type(item) is str for item in request["startup_attributes"]
    ):
        raise BoundaryReportError("startup_attributes_invalid")
    request_ok = (
        request["create_suspended"] is True
        and request["inherit_handles"] is True
        and request["requested_capabilities_pointer_null"] is True
        and requested_count == 0
        and attribute_count == len(STARTUP_ATTRIBUTES)
        and request["startup_attributes"] == STARTUP_ATTRIBUTES
        and request["python_flags"] == ["-I", "-B"]
        and resume_count == 1
    )

    profile = _dict(
        raw["profile"],
        {
            "appcontainer_sid_prelaunch_bound",
            "folder_declared_entire_scratch",
            "folder_file_id_128_hex",
            "folder_identity_format",
            "folder_identity_matched_prelaunch",
            "folder_identity_revalidated_after_boundary",
            "folder_outside_runtime_and_source",
            "folder_path_utf8_sha256",
            "folder_present_during_boundary",
            "folder_under_local_appdata",
            "folder_volume_serial_hex",
            "moniker",
            "precreated_by_wrapper",
            "prelaunch_created_hresult",
            "prelaunch_ownership_established",
            "prelaunch_receipt_sha256",
            "prelaunch_sid_reconciled",
        },
        "profile",
    )
    profile_sid = _sid(
        profile["appcontainer_sid_prelaunch_bound"],
        "profile_appcontainer_sid_prelaunch_bound",
    )
    profile_file_id = _lower_hex(
        profile["folder_file_id_128_hex"], "profile_folder_file_id_128", length=32
    )
    profile_path_sha256 = _sha(
        profile["folder_path_utf8_sha256"], "profile_folder_path_utf8"
    )
    profile_volume_serial = _lower_hex(
        profile["folder_volume_serial_hex"], "profile_folder_volume_serial", length=16
    )
    if profile["folder_identity_format"] != FILE_IDENTITY_FORMAT:
        raise BoundaryReportError("profile_folder_identity_format_invalid")
    for key in (
        "folder_declared_entire_scratch",
        "folder_identity_matched_prelaunch",
        "folder_identity_revalidated_after_boundary",
        "folder_outside_runtime_and_source",
        "folder_present_during_boundary",
        "folder_under_local_appdata",
        "precreated_by_wrapper",
        "prelaunch_ownership_established",
        "prelaunch_sid_reconciled",
    ):
        _bool(profile[key], f"profile_{key}")
    profile_created_hresult = _int(
        profile["prelaunch_created_hresult"],
        "profile_prelaunch_created_hresult",
        maximum=0xFFFFFFFF,
    )
    profile_prelaunch_sha256 = _sha(
        profile["prelaunch_receipt_sha256"], "profile_prelaunch_receipt_sha256"
    )
    profile_ok = (
        profile["moniker"] == expected["moniker"]
        and profile_sid == expected["appcontainer_sid"]
        and profile_created_hresult == 0
        and profile_prelaunch_sha256 == expected["profile_prelaunch_sha256"]
        and profile_file_id == expected["profile_folder_file_id_128_hex"]
        and profile["folder_identity_format"] == expected["profile_folder_identity_format"]
        and profile_path_sha256 == expected["profile_folder_path_utf8_sha256"]
        and profile_volume_serial == expected["profile_folder_volume_serial_hex"]
        and profile["precreated_by_wrapper"] is True
        and profile["prelaunch_ownership_established"] is True
        and profile["prelaunch_sid_reconciled"] is True
        and profile["folder_declared_entire_scratch"] is True
        and profile["folder_identity_matched_prelaunch"] is True
        and profile["folder_identity_revalidated_after_boundary"] is True
        and profile["folder_outside_runtime_and_source"] is True
        and profile["folder_present_during_boundary"] is True
        and profile["folder_under_local_appdata"] is True
    )
    delete_attempts = profile_receipt["delete_attempt_hresults"]
    final_delete_attempts = profile_receipt["final_delete_attempt_hresults"]
    profile_lifecycle_ok = (
        profile_receipt["moniker"] == expected["moniker"]
        and profile_receipt["folder_file_id_128_hex"]
        == expected["profile_folder_file_id_128_hex"]
        and profile_receipt["folder_identity_format"]
        == expected["profile_folder_identity_format"]
        and profile_receipt["folder_path_utf8_sha256"]
        == expected["profile_folder_path_utf8_sha256"]
        and profile_receipt["folder_volume_serial_hex"]
        == expected["profile_folder_volume_serial_hex"]
        and profile_receipt["folder_boundary_component_count"]
        == expected["profile_folder_boundary_component_count"]
        and profile_receipt["folder_boundary_terminal_ac"]
        == expected["profile_folder_boundary_terminal_ac"]
        and profile_receipt["owned"] is True
        and profile_receipt["ownership_established"] is True
        and profile_receipt["cleanup_attempted"] is True
        and profile_receipt["closed"] is True
        and profile_receipt["delete_suppressed_due_identity_uncertainty"] is False
        and profile_receipt["folder_identity_drift_detected"] is False
        and profile_receipt["folder_identity_revalidated_before_release"] is True
        and profile_receipt["profile_directory_handle_release_attempted"] is True
        and profile_receipt["profile_directory_handle_released"] is True
        and profile_receipt["residual_race_after_handle_release"] == "not_prevented"
        and profile_receipt["delete_succeeded"] is True
        and bool(delete_attempts)
        and delete_attempts[-1] == 0
        and profile_receipt["first_folder_absent"] is True
        and profile_receipt["recreate_attempted"] is True
        and profile_receipt["recreate_created_hresult"] == 0
        and profile_receipt["recreate_succeeded"] is True
        and profile_receipt["recreated_sid"] == expected["appcontainer_sid"]
        and profile_receipt["recreated_sid_matches"] is True
        and profile_receipt["folder_boundary_exact"] is True
        and profile_receipt["folder_boundary_reason"] == "observed"
        and profile_receipt["recreate_folder_boundary_exact"] is True
        and profile_receipt["recreate_folder_boundary_reason"] == "observed"
        and profile_receipt["recreate_folder_exists"] is True
        and profile_receipt["recreate_folder_reparse_free"] is True
        and profile_receipt["final_delete_succeeded"] is True
        and bool(final_delete_attempts)
        and final_delete_attempts[-1] == 0
        and profile_receipt["final_folder_absent"] is True
        and profile_receipt["cleanup_complete"] is True
    )

    processes = _dict(raw["processes"], set(PROCESS_ROLES), "processes")
    runtime = _dict(raw["runtime"], set(PROCESS_ROLES), "runtime")
    process_ok = True
    process_image_identities: list[tuple[tuple[str, object], ...]] = []
    for role in PROCESS_ROLES:
        process = _dict(
            processes[role],
            {"image", "parent_pid", "pid", "reported_parent_pid", "reported_pid", "token"},
            f"process_{role}",
        )
        pid = _int(process["pid"], f"process_{role}_pid", minimum=1)
        reported_pid = _int(process["reported_pid"], f"process_{role}_reported_pid", minimum=1)
        parent_pid = _int(process["parent_pid"], f"process_{role}_parent_pid", minimum=1)
        reported_parent_pid = _int(
            process["reported_parent_pid"],
            f"process_{role}_reported_parent_pid",
            minimum=1,
        )
        image = _path_identity(process["image"], f"process_{role}_image")
        process_image_identities.append(tuple(sorted(image.items())))
        token = _validate_token(process["token"], f"process_{role}_token")
        process_ok = process_ok and (
            pid == reported_pid
            and parent_pid == reported_parent_pid
            and image["role"] == "cpython_313_runtime_executable"
            and image["leaf"] == "python.exe"
            and image["path_utf8_sha256"]
            == expected["runtime_executable_path_utf8_sha256"]
            and _capability_lineage(token, str(expected["appcontainer_sid"]))
            and _runtime_ok(
                runtime[role],
                f"runtime_{role}",
                runtime_root,
                source_root,
            )
        )
    process_ok = process_ok and len(set(process_image_identities)) == 1
    root_process = processes["root"]
    child_process = processes["child"]
    grandchild_process = processes["grandchild"]
    lineage_ok = (
        child_process["parent_pid"] == root_process["pid"] and grandchild_process["parent_pid"] == child_process["pid"]
    )

    identity_observation = _dict(
        raw["identity"],
        {
            "aap_acl_pair_only_semantic_difference",
            "aap_acl_pair_revalidated",
            "aap_negative_access_denied",
            "aap_negative_win32_error",
            "aap_object_identity_revalidated",
            "aap_positive_read_sha256_matches",
            "aap_probe_contents_revalidated",
            "aap_probe_storage_removed",
            "aap_sid",
            "claim",
            "regular_launch_policy_bound",
            "same_primary_token_source_bound",
        },
        "identity_observation",
    )
    for key in (
        "aap_acl_pair_revalidated",
        "aap_negative_access_denied",
        "aap_object_identity_revalidated",
        "aap_positive_read_sha256_matches",
        "aap_probe_contents_revalidated",
        "aap_probe_storage_removed",
        "regular_launch_policy_bound",
        "same_primary_token_source_bound",
    ):
        _bool(identity_observation[key], f"identity_{key}")
    _int(identity_observation["aap_negative_win32_error"], "identity_aap_negative_win32_error", maximum=0xFFFFFFFF)
    _sid(identity_observation["aap_sid"], "identity_aap")
    identity_behavior_ok = (
        identity_observation["aap_acl_pair_only_semantic_difference"]
        == "allow_read_s-1-15-2-1"
        and identity_observation["aap_acl_pair_revalidated"] is True
        and identity_observation["aap_negative_access_denied"] is True
        and identity_observation["aap_negative_win32_error"] == ERROR_ACCESS_DENIED
        and identity_observation["aap_object_identity_revalidated"] is True
        and identity_observation["aap_positive_read_sha256_matches"] is True
        and identity_observation["aap_probe_contents_revalidated"] is True
        and identity_observation["aap_probe_storage_removed"] is True
        and identity_observation["aap_sid"] == "S-1-15-2-1"
        and identity_observation["claim"] == "aap_acl_effect_observed_for_this_token_run"
        and identity_observation["regular_launch_policy_bound"] is True
        and identity_observation["same_primary_token_source_bound"] is True
    )

    fingerprints = _dict(
        raw["fingerprints"],
        {
            "probe_source_sha256",
            "runtime_after",
            "runtime_before",
            "source_after",
            "source_before",
        },
        "fingerprints",
    )
    probe_source_sha256 = _sha(fingerprints["probe_source_sha256"], "probe_source_sha256")
    runtime_before = _fingerprint(fingerprints["runtime_before"], "runtime_before")
    runtime_after = _fingerprint(fingerprints["runtime_after"], "runtime_after")
    source_before = _fingerprint(fingerprints["source_before"], "source_before")
    source_after = _fingerprint(fingerprints["source_after"], "source_after")
    fingerprints_ok = (
        probe_source_sha256 == expected["probe_source_sha256"]
        and _fingerprint_pair_ok(
            runtime_before,
            runtime_after,
            "external_rx_runtime_copy",
            "runtime",
            _canonical_path_utf8_sha256(runtime_root),
        )
        and _fingerprint_pair_ok(
            source_before,
            source_after,
            "protected_probe_source_copy",
            "source",
            _canonical_path_utf8_sha256(source_root),
        )
    )

    filesystem = _dict(
        raw["filesystem"],
        {"operations", "protected_tree_unchanged", "scratch_positive_root_under_profile"},
        "filesystem",
    )
    operations = _dict(filesystem["operations"], set(FILESYSTEM_OPERATIONS), "filesystem_operations")
    filesystem_ok = (
        _bool(filesystem["protected_tree_unchanged"], "protected_tree_unchanged")
        and _bool(filesystem["scratch_positive_root_under_profile"], "scratch_positive_root_under_profile")
        and all(
            _operation_pair_ok(
                operations[name],
                f"filesystem_{name}",
                name,
                probe_source_sha256,
            )
            for name in FILESYSTEM_OPERATIONS
        )
        and fingerprints_ok
    )

    network = _dict(
        raw["network"],
        {
            "endpoint",
            "execution_order",
            "exemption_after",
            "exemption_before",
            "exemption_digest_after",
            "exemption_digest_before",
            "exemption_digest_during",
            "exemption_during",
            "firewall_named_objects_after",
            "firewall_named_objects_before",
            "firewall_named_objects_during",
            "lan_appcontainer_arms",
            "lan_full_trust_controls",
            "lan_host",
            "lan_host_is_non_loopback",
            "lan_port",
            "listener_saw_appcontainer_loopback",
            "listeners_closed",
            "loopback_full_trust_control",
            "loopback_zero_capability_attempt",
            "preflight_selected_capability_name",
            "preflight_selected_capability_sid",
            "preflight_zero_capability",
        },
        "network",
    )
    endpoint = _dict(
        network["endpoint"],
        {
            "distro_name",
            "distro_running_before",
            "endpoint_class",
            "guest_boot_id",
            "busybox_sha256",
            "guest_interface",
            "guest_ipv4",
            "guest_prefix_length",
            "host_launcher_pid",
            "host_launcher_creation_time_100ns",
            "listener_command_sha256",
            "listener_pid",
            "listener_port",
            "listener_port_absent_before_start",
            "listener_port_observed_before",
            "listener_process_absent_before_start",
            "listener_process_observed_before",
            "listener_socket_inode",
            "listener_starttime_ticks",
            "listener_watchdog_timeout_seconds",
            "startup_nonce_sha256",
            "startup_script_sha256",
            "netns_inode",
            "windows_interface_ip_absent_before",
            "watchdog_pid",
            "watchdog_starttime_ticks",
            "wsl_version",
        },
        "network_endpoint",
    )
    for key in (
        "distro_running_before",
        "listener_port_absent_before_start",
        "listener_port_observed_before",
        "listener_process_absent_before_start",
        "listener_process_observed_before",
        "windows_interface_ip_absent_before",
    ):
        _bool(endpoint[key], f"network_endpoint_{key}")
    _ipv4(endpoint["guest_ipv4"], "network_endpoint_guest_ipv4")
    _int(endpoint["guest_prefix_length"], "network_endpoint_guest_prefix", minimum=1, maximum=32)
    _int(endpoint["listener_pid"], "network_endpoint_listener_pid", minimum=2)
    _int(endpoint["host_launcher_pid"], "network_endpoint_host_launcher_pid", minimum=2)
    _int(
        endpoint["host_launcher_creation_time_100ns"],
        "network_endpoint_host_launcher_creation_time",
        minimum=1,
        maximum=0x7FFFFFFFFFFFFFFF,
    )
    _int(endpoint["listener_port"], "network_endpoint_listener_port", minimum=49_152, maximum=65_535)
    _int(
        endpoint["listener_socket_inode"],
        "network_endpoint_listener_socket_inode",
        minimum=1,
        maximum=0x7FFFFFFFFFFFFFFF,
    )
    _int(
        endpoint["listener_starttime_ticks"],
        "network_endpoint_listener_starttime_ticks",
        minimum=1,
        maximum=0x7FFFFFFFFFFFFFFF,
    )
    _int(
        endpoint["listener_watchdog_timeout_seconds"],
        "network_endpoint_listener_watchdog_timeout",
        minimum=30,
        maximum=600,
    )
    _sha(endpoint["listener_command_sha256"], "network_endpoint_listener_command")
    _int(endpoint["watchdog_pid"], "network_endpoint_watchdog_pid", minimum=2)
    _int(
        endpoint["watchdog_starttime_ticks"],
        "network_endpoint_watchdog_starttime_ticks",
        minimum=1,
        maximum=0x7FFFFFFFFFFFFFFF,
    )
    for key in (
        "busybox_sha256",
        "listener_command_sha256",
        "startup_nonce_sha256",
        "startup_script_sha256",
    ):
        _sha(endpoint[key], f"network_endpoint_{key}")
    endpoint_boot_id = _text(endpoint["guest_boot_id"], "network_endpoint_boot_id", maximum=36)
    endpoint_netns = _text(endpoint["netns_inode"], "network_endpoint_netns", maximum=64)
    if BOOT_ID_PATTERN.fullmatch(endpoint_boot_id) is None or NETNS_PATTERN.fullmatch(endpoint_netns) is None:
        raise BoundaryReportError("network_endpoint_identity_invalid")
    endpoint_pre_ok = (
        endpoint["endpoint_class"] == NETWORK_ENDPOINT_CLASS
        and endpoint["distro_name"] == NETWORK_DISTRO_NAME
        and endpoint["wsl_version"] == 2
        and endpoint["guest_interface"] == "eth0"
        and endpoint["distro_running_before"] is True
        and endpoint["listener_process_absent_before_start"] is True
        and endpoint["listener_port_absent_before_start"] is True
        and endpoint["listener_process_observed_before"] is True
        and endpoint["listener_port_observed_before"] is True
        and endpoint["windows_interface_ip_absent_before"] is True
        and all(
            endpoint[left] == endpoint_receipt[right]
            for left, right in (
                ("endpoint_class", "endpoint_class"),
                ("distro_name", "distro_name"),
                ("distro_running_before", "distro_running_before"),
                ("wsl_version", "wsl_version"),
                ("guest_boot_id", "guest_boot_id_before"),
                ("guest_interface", "guest_interface"),
                ("guest_ipv4", "guest_ipv4_before"),
                ("guest_prefix_length", "guest_prefix_length_before"),
                ("netns_inode", "netns_inode_before"),
                ("listener_pid", "listener_pid"),
                ("host_launcher_pid", "host_launcher_pid"),
                (
                    "host_launcher_creation_time_100ns",
                    "host_launcher_creation_time_100ns",
                ),
                ("listener_port", "listener_port"),
                ("listener_command_sha256", "listener_command_sha256"),
                ("startup_nonce_sha256", "startup_nonce_sha256"),
                ("startup_script_sha256", "startup_script_sha256"),
                ("busybox_sha256", "busybox_sha256"),
                ("listener_process_absent_before_start", "listener_process_absent_before_start"),
                ("listener_port_absent_before_start", "listener_port_absent_before_start"),
                ("listener_process_observed_before", "listener_process_observed_before"),
                ("listener_port_observed_before", "listener_port_observed_before"),
                ("listener_socket_inode", "listener_socket_inode"),
                ("listener_starttime_ticks", "listener_starttime_ticks"),
                (
                    "listener_watchdog_timeout_seconds",
                    "listener_watchdog_timeout_seconds",
                ),
                ("watchdog_pid", "watchdog_pid"),
                ("watchdog_starttime_ticks", "watchdog_starttime_ticks"),
                ("windows_interface_ip_absent_before", "windows_interface_ip_absent_before"),
            )
        )
    )
    endpoint_cleanup_ok = (
        endpoint_receipt["distro_running_before"] is True
        and endpoint_receipt["distro_running_after"] is True
        and endpoint_receipt["listener_process_absent_before_start"] is True
        and endpoint_receipt["listener_port_absent_before_start"] is True
        and endpoint_receipt["listener_process_observed_before"] is True
        and endpoint_receipt["listener_port_observed_before"] is True
        and endpoint_receipt["windows_interface_ip_absent_before"] is True
        and endpoint_receipt["listener_process_absent_after"] is True
        and endpoint_receipt["watchdog_process_absent_after"] is True
        and endpoint_receipt["listener_port_absent_after"] is True
        and endpoint_receipt["guest_residual_absent_after"] is True
        and endpoint_receipt["host_launcher_process_absent_after"] is True
        and endpoint_receipt["cleanup_exact_listener_pid_only"] is True
        and endpoint_receipt["windows_interface_ip_absent_after"] is True
        and endpoint_receipt["guest_boot_id_before"] == endpoint_receipt["guest_boot_id_after"]
        and endpoint_receipt["guest_ipv4_before"] == endpoint_receipt["guest_ipv4_after"]
        and endpoint_receipt["guest_prefix_length_before"]
        == endpoint_receipt["guest_prefix_length_after"]
        and endpoint_receipt["netns_inode_before"] == endpoint_receipt["netns_inode_after"]
    )
    endpoint_lifecycle_ok = endpoint_pre_ok and endpoint_cleanup_ok
    execution_order = network["execution_order"]
    if execution_order != [
        "preflight_zero",
        "full_trust_before",
        "zero_1",
        "internet_client_1",
        "internet_client_2",
        "zero_2",
        "full_trust_after",
    ]:
        raise BoundaryReportError("network_execution_order_invalid")
    lan_host = _text(network["lan_host"], "network_lan_host", maximum=64)
    _ipv4(lan_host, "network_lan_host")
    lan_port = _int(network["lan_port"], "network_lan_port", minimum=1, maximum=65_535)
    loopback_control = _network_control(
        network["loopback_full_trust_control"], "loopback_full_trust_control"
    )
    loopback_appcontainer = _network_attempt(
        network["loopback_zero_capability_attempt"],
        "loopback_zero_capability_attempt",
    )
    controls_value = network["lan_full_trust_controls"]
    if type(controls_value) is not list or len(controls_value) != 2:
        raise BoundaryReportError("lan_full_trust_controls_shape_invalid")
    lan_controls = [
        _network_control(item, f"lan_full_trust_control_{index}")
        for index, item in enumerate(controls_value)
    ]
    arms_value = network["lan_appcontainer_arms"]
    if type(arms_value) is not list or len(arms_value) != len(NETWORK_ARM_SEQUENCE):
        raise BoundaryReportError("lan_appcontainer_arms_shape_invalid")
    lan_arms = [
        _network_arm(item, f"lan_appcontainer_arm_{index}")
        for index, item in enumerate(arms_value)
    ]
    preflight = _network_arm(network["preflight_zero_capability"], "network_preflight")
    selected_capability_name = network["preflight_selected_capability_name"]
    selected_capability_sid = network["preflight_selected_capability_sid"]
    if selected_capability_name is not None:
        _text(selected_capability_name, "network_selected_capability_name", maximum=64)
    if selected_capability_sid is not None:
        _sid(selected_capability_sid, "network_selected_capability_sid")
    for key in (
        "exemption_after",
        "exemption_before",
        "exemption_during",
        "lan_host_is_non_loopback",
        "listener_saw_appcontainer_loopback",
        "listeners_closed",
    ):
        _bool(network[key], f"network_{key}")
    exemption_digests = [
        _sha(network[key], f"network_{key}")
        for key in ("exemption_digest_before", "exemption_digest_during", "exemption_digest_after")
    ]
    firewall_counts = [
        _int(network[key], f"network_{key}", maximum=1_000_000)
        for key in (
            "firewall_named_objects_before",
            "firewall_named_objects_during",
            "firewall_named_objects_after",
        )
    ]
    lan_controls_ok = (
        [item["order"] for item in lan_controls] == [0, 5]
        and all(
            item["connected"] is True
            and item["accepted"] is True
            and item["nonce_matches"] is True
            and item["nonce_sha256"] == item["received_nonce_sha256"]
            and item["winerror"] is None
            and item["host"] == lan_host
            and item["port"] == lan_port
            for item in lan_controls
        )
        and lan_host == endpoint["guest_ipv4"]
        and lan_port == endpoint["listener_port"]
    )
    all_network_arms = [preflight, *lan_arms]
    common_command_digests = {arm["command_line_sha256"] for arm in all_network_arms}
    common_environment_digests = {arm["environment_sha256"] for arm in all_network_arms}
    common_parent_pids = {arm["parent_pid"] for arm in all_network_arms}
    common_current_directory_identities = {
        (
            arm["current_directory_identity_format"],
            arm["current_directory_volume_serial_hex"],
            arm["current_directory_file_id_128_hex"],
            arm["current_directory_path_utf8_sha256"],
        )
        for arm in all_network_arms
    }
    common_request_parent_identities = {
        (
            arm["request_parent_identity_format"],
            arm["request_parent_volume_serial_hex"],
            arm["request_parent_file_id_128_hex"],
            arm["request_parent_path_utf8_sha256"],
        )
        for arm in all_network_arms
    }
    common_request_path_digests = {
        arm["request_path_utf8_sha256"] for arm in all_network_arms
    }
    differential_request_file_identities = {
        (
            arm["request_identity_format"],
            arm["request_volume_serial_hex"],
            arm["request_file_id_128_hex"],
        )
        for arm in lan_arms
    }
    process_ids = [arm["pid"] for arm in all_network_arms]
    baseline_entry = _lineage_capability_entry(str(expected["appcontainer_sid"]))
    internet_entry = INTERNET_CLIENT_CAPABILITY_SID + "|0x00000004"
    expected_zero_roster = baseline_entry
    expected_internet_roster = ",".join(sorted((baseline_entry, internet_entry)))
    token_common_keys = TOKEN_KEYS - {"capability_count", "capability_entries"}
    token_common_values = {
        tuple((key, arm["token"][key]) for key in sorted(token_common_keys))
        for arm in all_network_arms
    }
    arm_protocol_ok = (
        baseline_entry != ""
        and len(common_command_digests) == 1
        and len(common_environment_digests) == 1
        and len(common_parent_pids) == 1
        and len(common_current_directory_identities) == 1
        and len(common_request_parent_identities) == 1
        and len(common_request_path_digests) == 1
        and len(differential_request_file_identities) == 1
        and len(set(process_ids)) == len(process_ids)
        and len(token_common_values) == 1
        and all(
            arm["image"]["role"] == "cpython_313_runtime_executable"
            and arm["image"]["leaf"] == "python.exe"
            and arm["image"]["path_utf8_sha256"]
            == expected["runtime_executable_path_utf8_sha256"]
            and arm["image"] == processes["root"]["image"]
            for arm in all_network_arms
        )
        and all(
            arm["current_directory_identity_format"]
            == expected["profile_folder_identity_format"]
            and arm["current_directory_volume_serial_hex"]
            == expected["profile_folder_volume_serial_hex"]
            and arm["current_directory_file_id_128_hex"]
            == expected["profile_folder_file_id_128_hex"]
            and arm["current_directory_path_utf8_sha256"]
            == expected["profile_folder_path_utf8_sha256"]
            and arm["request_parent_identity_format"]
            == expected["profile_folder_identity_format"]
            and arm["request_parent_volume_serial_hex"]
            == expected["profile_folder_volume_serial_hex"]
            and arm["request_parent_file_id_128_hex"]
            == expected["profile_folder_file_id_128_hex"]
            and arm["request_parent_path_utf8_sha256"]
            == expected["profile_folder_path_utf8_sha256"]
            and arm["request_path_utf8_sha256"]
            == expected["profile_network_request_path_utf8_sha256"]
            and arm["request_leaf"] == "network-arm-request.json"
            and arm["request_volume_serial_hex"]
            == expected["profile_folder_volume_serial_hex"]
            for arm in all_network_arms
        )
        and all(arm["pid"] == arm["reported_pid"] for arm in all_network_arms)
        and all(arm["parent_pid"] == arm["reported_parent_pid"] for arm in all_network_arms)
        and all(arm["job_member"] is True for arm in all_network_arms)
        and all(arm["create_suspended"] is True for arm in all_network_arms)
        and all(arm["resume_thread_count"] == 1 for arm in all_network_arms)
        and all(arm["startup_attribute_count"] == 2 for arm in all_network_arms)
        and all(
            arm["request_sha256"] == arm["reported_request_sha256"]
            and arm["target_host"] == lan_host
            and arm["target_port"] == lan_port
            and arm["attempt"]["host"] == arm["target_host"]
            and arm["attempt"]["port"] == arm["target_port"]
            for arm in all_network_arms
        )
        and len({arm["request_sha256"] for arm in all_network_arms})
        == len(all_network_arms)
        and all(
            arm["startup_attributes"] == ["job_list", "security_capabilities"]
            for arm in all_network_arms
        )
        and all(
            _regular_appcontainer_proof_observed(arm["regular_appcontainer"])
            for arm in all_network_arms
        )
        and len({arm["timeout_milliseconds"] for arm in all_network_arms}) == 1
    )
    preflight_attempt = preflight["attempt"]
    preflight_token = preflight["token"]
    preflight_ok = (
        preflight["label"] == "preflight_zero"
        and preflight["order"] == 0
        and preflight["requested_capability_sids"] == []
        and preflight["requested_capabilities_pointer_null"] is True
        and _token_identity_facts(preflight_token, str(expected["appcontainer_sid"]))
        and preflight_token["capability_count"] == 1
        and preflight_token["capability_entries"] == expected_zero_roster
        and preflight_attempt["connected"] is False
        and preflight_attempt["winerror"] not in {0, None}
        and preflight_attempt["diagnosis_result"] == 0
        and preflight_attempt["diagnosis_type"] == 2
        and preflight_attempt["echo_matches"] is False
        and preflight_attempt["echo_nonce_sha256"] is None
        and preflight_attempt["host"] == lan_host
        and preflight_attempt["port"] == lan_port
        and selected_capability_name == "internetClient"
        and selected_capability_sid == INTERNET_CLIENT_CAPABILITY_SID
    )
    arm_outcomes_ok = True
    for arm, (label, order, requested) in zip(lan_arms, NETWORK_ARM_SEQUENCE, strict=True):
        token = arm["token"]
        attempt = arm["attempt"]
        is_zero = not requested
        expected_roster = expected_zero_roster if is_zero else expected_internet_roster
        expected_count = 1 if is_zero else 2
        arm_outcomes_ok = arm_outcomes_ok and (
            arm["label"] == label
            and arm["order"] == order
            and arm["requested_capability_sids"] == list(requested)
            and arm["requested_capabilities_pointer_null"] is is_zero
            and _token_identity_facts(token, str(expected["appcontainer_sid"]))
            and token["capability_count"] == expected_count
            and token["capability_entries"] == expected_roster
            and (
                (
                    attempt["connected"] is False
                    and attempt["winerror"] not in {0, None}
                    and attempt["diagnosis_result"] == 0
                    and attempt["diagnosis_type"] == 2
                    and attempt["echo_matches"] is False
                    and attempt["echo_nonce_sha256"] is None
                )
                if is_zero
                else (
                    attempt["connected"] is True
                    and attempt["winerror"] is None
                    and attempt["diagnosis_result"] is None
                    and attempt["diagnosis_type"] is None
                    and attempt["echo_matches"] is True
                    and attempt["echo_nonce_sha256"] == attempt["nonce_sha256"]
                )
            )
            and attempt["host"] == lan_host
            and attempt["port"] == lan_port
        )
    lan_nonce_digests = [item["nonce_sha256"] for item in lan_controls] + [
        arm["attempt"]["nonce_sha256"] for arm in lan_arms
    ]
    lan_capability_differential_observed = (
        lan_controls_ok
        and arm_protocol_ok
        and preflight_ok
        and arm_outcomes_ok
        and len(set(lan_nonce_digests)) == len(lan_nonce_digests)
        and preflight_attempt["nonce_sha256"] not in set(lan_nonce_digests)
        and network["lan_host_is_non_loopback"] is True
        and not ipaddress.IPv4Address(lan_host).is_loopback
        and endpoint_lifecycle_ok
    )
    loopback_non_establishment_without_exemption_observed = (
        loopback_control["connected"] is True
        and loopback_control["accepted"] is True
        and loopback_control["nonce_matches"] is True
        and loopback_control["nonce_sha256"] == loopback_control["received_nonce_sha256"]
        and loopback_control["winerror"] is None
        and loopback_control["host"] == "127.0.0.1"
        and loopback_control["order"] == 0
        and loopback_appcontainer["connected"] is False
        and loopback_appcontainer["winerror"] not in {0, None}
        and loopback_appcontainer["diagnosis_result"] == 0
        and loopback_appcontainer["diagnosis_type"] == 0
        and loopback_appcontainer["echo_matches"] is False
        and loopback_appcontainer["echo_nonce_sha256"] is None
        and loopback_appcontainer["host"] == "127.0.0.1"
        and loopback_appcontainer["port"] == loopback_control["port"]
        and loopback_appcontainer["nonce_sha256"] != loopback_control["nonce_sha256"]
        and network["listener_saw_appcontainer_loopback"] is False
        and network["exemption_before"] is False
        and network["exemption_during"] is False
        and network["exemption_after"] is False
        and len(set(exemption_digests)) == 1
    )
    network_ok = (
        lan_capability_differential_observed
        and loopback_non_establishment_without_exemption_observed
        and network["listeners_closed"] is True
        and firewall_counts == [0, 0, 0]
    )

    handles = _dict(
        raw["handles"],
        {
            "decoy",
            "decoy_parent_open_during",
            "handle_list_attribute_applied",
            "handle_list_count",
            "permitted",
            "permitted_parent_open_during",
        },
        "handles",
    )
    permitted = _dict(
        handles["permitted"],
        {"canary_sha256", "get_handle_information_error", "read_error", "valid"},
        "permitted_handle",
    )
    decoy = _dict(
        handles["decoy"],
        {"canary_sha256", "get_handle_information_error", "read_error", "valid"},
        "decoy_handle",
    )
    for name, item in (("permitted", permitted), ("decoy", decoy)):
        _bool(item["valid"], f"{name}_handle_valid")
        for key in ("get_handle_information_error", "read_error"):
            if item[key] is not None:
                _int(item[key], f"{name}_{key}", maximum=0xFFFFFFFF)
        if item["canary_sha256"] is not None:
            _sha(item["canary_sha256"], f"{name}_canary")
    for key in ("decoy_parent_open_during", "handle_list_attribute_applied", "permitted_parent_open_during"):
        _bool(handles[key], f"handles_{key}")
    handle_count = _int(handles["handle_list_count"], "handle_list_count", maximum=1024)
    handles_ok = (
        handles["handle_list_attribute_applied"] is True
        and handle_count == 1
        and handles["permitted_parent_open_during"] is True
        and handles["decoy_parent_open_during"] is True
        and permitted["valid"] is True
        and permitted["read_error"] == 0
        and permitted["canary_sha256"] == expected["permitted_canary_sha256"]
        and decoy["valid"] is False
        and decoy["canary_sha256"] is None
        and decoy["get_handle_information_error"] in {ERROR_ACCESS_DENIED, 6}
        and expected["decoy_canary_sha256"] != expected["permitted_canary_sha256"]
    )

    job = _dict(
        raw["job"],
        {
            "breakaway_created",
            "breakaway_flags_absent",
            "breakaway_winerror",
            "child_member",
            "grandchild_member",
            "job_handle_was_last_job_handle",
            "job_limit_flags",
            "job_list_attribute_applied",
            "kill_on_close_child",
            "kill_on_close_grandchild",
            "kill_on_close_root",
            "root_member",
        },
        "job",
    )
    for key in (
        "breakaway_created",
        "breakaway_flags_absent",
        "child_member",
        "grandchild_member",
        "job_handle_was_last_job_handle",
        "job_list_attribute_applied",
        "kill_on_close_child",
        "kill_on_close_grandchild",
        "kill_on_close_root",
        "root_member",
    ):
        _bool(job[key], f"job_{key}")
    job_flags = _int(job["job_limit_flags"], "job_limit_flags", maximum=0xFFFFFFFF)
    breakaway_winerror = _int(job["breakaway_winerror"], "breakaway_winerror", maximum=0xFFFFFFFF)
    job_ok = (
        job["job_list_attribute_applied"] is True
        and job_flags == JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        and not job_flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
        and job["breakaway_flags_absent"] is True
        and job["root_member"] is True
        and job["child_member"] is True
        and job["grandchild_member"] is True
        and job["breakaway_created"] is False
        and breakaway_winerror == ERROR_ACCESS_DENIED
        and job["job_handle_was_last_job_handle"] is True
        and job["kill_on_close_root"] is True
        and job["kill_on_close_child"] is True
        and job["kill_on_close_grandchild"] is True
    )

    cleanup = _dict(
        raw["cleanup"],
        {
            "acl_restore_not_required",
            "attribute_list_deleted",
            "firewall_objects_absent",
            "job_handle_closed",
            "listener_handles_closed",
            "loopback_config_restored",
            "no_foreign_named_objects",
            "pipe_handles_closed",
            "process_handles_closed",
            "processes_exited",
            "profile_cleanup_deferred_to_wrapper",
            "runtime_and_source_removed",
            "thread_handle_closed",
            "work_root_empty",
        },
        "cleanup",
    )
    cleanup_ok = all(_bool(cleanup[key], f"cleanup_{key}") for key in sorted(cleanup))
    cleanup_ok = cleanup_ok and profile_lifecycle_ok and endpoint_lifecycle_ok

    checks = {
        "cleanup": cleanup_ok,
        "filesystem": filesystem_ok,
        "handles": handles_ok,
        "identity": (
            expected_paths_ok
            and request_ok
            and profile_ok
            and process_ok
            and lineage_ok
            and identity_behavior_ok
        ),
        "job": job_ok,
        "network": network_ok,
    }
    all_observed = all(checks.values())
    return {
        "all_required_controls_observed": all_observed,
        "authority": "none",
        "checks": checks,
        "evidence_authentication": "not_implemented",
        "format": SUMMARY_FORMAT,
        "network_claims": {
            "lan_capability_differential_observed": lan_capability_differential_observed,
            "loopback_non_establishment_without_exemption_observed": (
                loopback_non_establishment_without_exemption_observed
            ),
            "wfp_filter_attribution": "not_claimed",
        },
        "portability_cell": PORTABILITY_CELL_STATE,
        "reason": "full_boundary_observed" if all_observed else "full_boundary_not_observed",
        "release_authorized": False,
        "status": "observed_pass" if all_observed else "not_observed",
    }


def validate_declared_summary(declared_value: object, recomputed_value: object) -> dict[str, object]:
    """Reject a helper-declared summary unless every field matches recomputation."""

    declared = _dict(declared_value, SUMMARY_KEYS, "declared_summary")
    recomputed = _dict(recomputed_value, SUMMARY_KEYS, "recomputed_summary")
    checks = {"cleanup", "filesystem", "handles", "identity", "job", "network"}
    for name, summary in (("declared", declared), ("recomputed", recomputed)):
        summary_checks = _dict(summary["checks"], checks, f"{name}_checks")
        for key in checks:
            _bool(summary_checks[key], f"{name}_{key}")
        network_claims = _dict(
            summary["network_claims"],
            {
                "lan_capability_differential_observed",
                "loopback_non_establishment_without_exemption_observed",
                "wfp_filter_attribution",
            },
            f"{name}_network_claims",
        )
        _bool(
            network_claims["lan_capability_differential_observed"],
            f"{name}_lan_capability_differential_observed",
        )
        _bool(
            network_claims["loopback_non_establishment_without_exemption_observed"],
            f"{name}_loopback_non_establishment_without_exemption_observed",
        )
        if network_claims["wfp_filter_attribution"] != "not_claimed":
            raise BoundaryReportError(f"{name}_wfp_filter_attribution_invalid")
        _bool(summary["all_required_controls_observed"], f"{name}_all_required_controls_observed")
        _bool(summary["release_authorized"], f"{name}_release_authorized")
        for key in ("authority", "evidence_authentication", "format", "portability_cell", "reason", "status"):
            _text(summary[key], f"{name}_{key}", maximum=128)
    if declared != recomputed:
        raise BoundaryReportError("declared_summary_mismatch")
    return recomputed
