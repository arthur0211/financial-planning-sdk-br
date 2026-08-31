#!/usr/bin/env python3
"""Compile and run the diagnostic-only Windows AppContainer token spike."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import ntpath
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

try:
    from .windows_host_trust import (
        HostAcquirer,
        HostTrustFailure,
        acquire_trusted_powershell_hosts,
    )
except ImportError:
    from windows_host_trust import (  # type: ignore[no-redef]
        HostAcquirer,
        HostTrustFailure,
        acquire_trusted_powershell_hosts,
    )

try:
    from .windows_appcontainer_boundary_report import (
        EXPECTED_FORMAT as BOUNDARY_EXPECTED_FORMAT,
    )
    from .windows_appcontainer_boundary_report import (
        INTERNET_CLIENT_CAPABILITY_SID,
        BoundaryReportError,
        recompute_boundary_summary,
        validate_declared_summary,
    )
    from .windows_appcontainer_boundary_report import (
        SUMMARY_FORMAT as BOUNDARY_SUMMARY_FORMAT,
    )
except ImportError:
    from windows_appcontainer_boundary_report import (
        EXPECTED_FORMAT as BOUNDARY_EXPECTED_FORMAT,
    )
    from windows_appcontainer_boundary_report import (
        INTERNET_CLIENT_CAPABILITY_SID,
        BoundaryReportError,
        recompute_boundary_summary,
        validate_declared_summary,
    )
    from windows_appcontainer_boundary_report import (
        SUMMARY_FORMAT as BOUNDARY_SUMMARY_FORMAT,
    )

try:
    from .windows_wsl2_endpoint import (
        WslEndpointFailure,
        acquire_wsl2_endpoint,
    )
except ImportError:
    from windows_wsl2_endpoint import (  # type: ignore[no-redef]
        WslEndpointFailure,
        acquire_wsl2_endpoint,
    )

try:
    from .windows_appcontainer_profile import (
        OwnedProfileBinding,
        ProfileLeaseFailure,
        acquire_appcontainer_profile,
    )
except ImportError:
    from windows_appcontainer_profile import (  # type: ignore[no-redef]
        OwnedProfileBinding,
        ProfileLeaseFailure,
        acquire_appcontainer_profile,
    )

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HELPER_DIRECTORY = REPOSITORY_ROOT / "scripts" / "windows_appcontainer_helper"
PROGRAM_SOURCE = HELPER_DIRECTORY / "Program.cs"
PROBE_SOURCE = REPOSITORY_ROOT / "scripts" / "windows_appcontainer_child_probe.py"

WRAPPER_FORMAT = "finplanbr.windows-appcontainer-spike-wrapper.v23"
HELPER_FORMAT = "finplanbr.windows-appcontainer-boundary-helper.v17"
HELPER_FAILURE_RECEIPT_FORMAT = (
    "finplanbr.windows-appcontainer-helper-failure-receipt.v6"
)
DRIVER_OUTPUT_FORMAT = "finplanbr.windows-appcontainer-driver-output.v2"
BOOTSTRAP_INPUT_FORMAT = "finplanbr.windows-appcontainer-bootstrap-input.v2"
IN_MEMORY_INPUT_FORMAT = "finplanbr.windows-appcontainer-in-memory-input.v9"
INVOCATION_REQUEST_FORMAT = "finplanbr.windows-appcontainer-spike-request.v16"
INPUT_BINDING_FORMAT = "finplanbr.windows-appcontainer-input-binding.v15"
PUBLIC_HOST_TRUST_FORMAT = "finplanbr.windows-powershell-host-trust-public.v2"
WIRE_CANONICALIZATION = "fpbr-json-ascii-fixed-order-lf.v1"
PORTABILITY_CELL_STATE = "not_counted"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
REASON_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,127}\Z", re.ASCII)
SID_PATTERN = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\Z", re.ASCII)
CAPABILITY_ENTRY_PATTERN = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\|0x[0-9a-f]{8}\Z", re.ASCII)
MONIKER_PATTERN = re.compile(r"finplanbrac-[0-9a-f]{24}\Z", re.ASCII)
MAX_HELPER_OUTPUT_BYTES = 1_048_576
MAX_DRIVER_OUTPUT_BYTES = 131_072
MAX_POWERSHELL_STDERR_BYTES = 131_072
MAX_WINDOWS_COMMAND_LINE_CHARACTERS = 32_767
MIN_WINDOWS_COMMAND_LINE_HEADROOM_CHARACTERS = 1_024
DRIVER_OUTPUT_KEYS = frozenset(
    {
        "compiled_assembly_sha256",
        "compiler_reference_set_sha256",
        "format",
        "helper_stdout_base64",
        "in_memory_driver_sha256",
        "observed_bootstrap_input_sha256",
        "observed_in_memory_input_sha256",
        "program_cs_sha256",
        "program_entry_return_code",
    }
)
DRIVER_BINDING_KEYS = DRIVER_OUTPUT_KEYS - {"helper_stdout_base64"}

HELPER_KEYS = frozenset(
    {
        "authority",
        "evidence_authentication",
        "format",
        "helper_failure_receipt",
        "raw_observations",
        "reason",
        "release_authorized",
        "status",
    }
)
HELPER_FAILURE_RECEIPT_KEYS = frozenset(
    {"failure_class", "format", "stage", "status", "substage"}
)
HELPER_FAILURE_STAGES = frozenset(
    {
        "entry",
        "profile_binding",
        "profile_storage",
        "runtime_copy_acl",
        "fingerprint_initial",
        "listeners_controls",
        "job_attributes",
        "root_launch",
        "root_report",
        "lineage",
        "network_differential",
        "fingerprint_final_cleanup",
    }
)
HELPER_FAILURE_CLASSES = frozenset(
    {
        "not_observed",
        "internal_interop_win32_failure",
        "internal_win32_failure",
        "internal_interop_hresult_failure",
        "internal_access_failure",
        "internal_io_failure",
        "internal_json_failure",
        "internal_argument_failure",
        "internal_invariant_failure",
        "internal_unexpected_failure",
    }
)
HELPER_FAILURE_PROFILE_BINDING_SUBSTAGES = frozenset(
    {
        "profile_binding_entry",
        "profile_prelaunch_parse",
        "profile_sid_import",
        "profile_sid_validate",
        "profile_sid_roundtrip",
        "profile_folder_query",
        "profile_folder_canonical",
        "profile_localappdata_canonical",
        "profile_ancestry",
        "profile_boundary_compare",
    }
)
HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES = (
    "network_differential_entry",
    "network_endpoint_bind",
    "network_preflight_prepare",
    "network_preflight_profile_before",
    "network_preflight_capability_import",
    "network_preflight_request_setup",
    "network_preflight_zero",
    "network_preflight_zero_launch",
    "network_preflight_zero_token_launch_policy",
    "network_preflight_zero_token_read_base",
    "network_preflight_zero_token_aap_membership",
    "network_preflight_zero_token_aap_rosters",
    "network_preflight_zero_token_lpac",
    "network_preflight_zero_token_identity",
    "network_preflight_zero_token_aap_effect",
    "network_preflight_zero_token_validate_lpac",
    "network_preflight_zero_token_validate_roster",
    "network_preflight_zero_token_bind",
    "network_preflight_zero_process",
    "network_preflight_zero_report",
    "network_preflight_zero_exit",
    "network_preflight_zero_result",
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
    "network_arm_zero_1",
    "network_arm_zero_1_launch",
    "network_arm_zero_1_token_launch_policy",
    "network_arm_zero_1_token_read_base",
    "network_arm_zero_1_token_aap_membership",
    "network_arm_zero_1_token_aap_rosters",
    "network_arm_zero_1_token_lpac",
    "network_arm_zero_1_token_identity",
    "network_arm_zero_1_token_aap_effect",
    "network_arm_zero_1_token_validate_lpac",
    "network_arm_zero_1_token_validate_roster",
    "network_arm_zero_1_token_bind",
    "network_arm_zero_1_process",
    "network_arm_zero_1_report",
    "network_arm_zero_1_exit",
    "network_arm_zero_1_result",
    "network_arm_internet_client_1",
    "network_arm_internet_client_1_launch",
    "network_arm_internet_client_1_token_launch_policy",
    "network_arm_internet_client_1_token_read_base",
    "network_arm_internet_client_1_token_aap_membership",
    "network_arm_internet_client_1_token_aap_rosters",
    "network_arm_internet_client_1_token_lpac",
    "network_arm_internet_client_1_token_identity",
    "network_arm_internet_client_1_token_aap_effect",
    "network_arm_internet_client_1_token_validate_lpac",
    "network_arm_internet_client_1_token_validate_roster",
    "network_arm_internet_client_1_token_bind",
    "network_arm_internet_client_1_process",
    "network_arm_internet_client_1_report",
    "network_arm_internet_client_1_exit",
    "network_arm_internet_client_1_result",
    "network_arm_internet_client_2",
    "network_arm_internet_client_2_launch",
    "network_arm_internet_client_2_token_launch_policy",
    "network_arm_internet_client_2_token_read_base",
    "network_arm_internet_client_2_token_aap_membership",
    "network_arm_internet_client_2_token_aap_rosters",
    "network_arm_internet_client_2_token_lpac",
    "network_arm_internet_client_2_token_identity",
    "network_arm_internet_client_2_token_aap_effect",
    "network_arm_internet_client_2_token_validate_lpac",
    "network_arm_internet_client_2_token_validate_roster",
    "network_arm_internet_client_2_token_bind",
    "network_arm_internet_client_2_process",
    "network_arm_internet_client_2_report",
    "network_arm_internet_client_2_exit",
    "network_arm_internet_client_2_result",
    "network_arm_zero_2",
    "network_arm_zero_2_launch",
    "network_arm_zero_2_token_launch_policy",
    "network_arm_zero_2_token_read_base",
    "network_arm_zero_2_token_aap_membership",
    "network_arm_zero_2_token_aap_rosters",
    "network_arm_zero_2_token_lpac",
    "network_arm_zero_2_token_identity",
    "network_arm_zero_2_token_aap_effect",
    "network_arm_zero_2_token_validate_lpac",
    "network_arm_zero_2_token_validate_roster",
    "network_arm_zero_2_token_bind",
    "network_arm_zero_2_process",
    "network_arm_zero_2_report",
    "network_arm_zero_2_exit",
    "network_arm_zero_2_result",
    "network_full_profile_after",
    "network_control_after",
)
HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGE_SEQUENCE = (
    HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES
)
_HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGE_SET = frozenset(
    HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGES
)
HELPER_FAILURE_DEFAULT_SUBSTAGE = "stage_entry"
TOKEN_KEYS = frozenset(
    {
        "appcontainer_sid",
        "capability_count",
        "capability_entries",
        "all_application_packages_membership_api",
        "all_application_packages_membership_api_call_succeeded",
        "all_application_packages_membership_api_win32_error",
        "all_application_packages_restricted_sid_match_attributes",
        "all_application_packages_restricted_sid_match_count",
        "all_application_packages_token_group_match_attributes",
        "all_application_packages_token_group_match_count",
        "integrity_rid",
        "is_appcontainer",
        "is_elevated",
        "less_privileged_appcontainer_query_result",
        "less_privileged_appcontainer_query_supported",
        "restricted_sid_count",
        "token_group_count",
    }
)

IN_MEMORY_PWSH_DRIVER = r"""
$PSModuleAutoLoadingPreference = 'None'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    if ($ExecutionContext.SessionState.LanguageMode -ne [Management.Automation.PSLanguageMode]::FullLanguage -or
        [Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy() -ne
            [Management.Automation.Security.SystemEnforcementMode]::None) {
        throw 'powershell_application_control_policy_unsupported'
    }
    [Environment]::SetEnvironmentVariable(
        'PSModulePath',
        '',
        [EnvironmentVariableTarget]::Process
    )
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    [Console]::OutputEncoding = $strictUtf8

    if ($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion.Major -lt 7 -or -not $IsWindows) {
        throw 'powershell_7_windows_required'
    }
    $observedHost = [IO.Path]::GetFullPath([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
    $expectedHost = [IO.Path]::GetFullPath([IO.Path]::Combine($PSHOME, 'pwsh.exe'))
    if (-not [String]::Equals($observedHost, $expectedHost, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'powershell_7_host_mismatch'
    }

    $raw = [Console]::In.ReadToEnd()
    if ($raw.Length -lt 2 -or
        $raw.Length -gt 1048576 -or
        -not $raw.EndsWith("`n") -or
        $raw.IndexOf("`n") -ne $raw.Length - 1 -or
        $raw.Contains("`r")) {
        throw 'in_memory_request_framing_invalid'
    }
    $rawBytes = $strictUtf8.GetBytes($raw)
    $transportDriverSha256 = [string] $global:FinplanbrInMemoryDriverSha256
    $transportBootstrapInputSha256 = [string] $global:FinplanbrBootstrapInputSha256
    $transportInMemoryInputSha256 = [string] $global:FinplanbrInMemoryInputSha256
    $inputHashAlgorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $decodedInMemoryInputSha256 = [Convert]::ToHexString(
            $inputHashAlgorithm.ComputeHash($rawBytes)
        ).ToLowerInvariant()
    }
    finally {
        $inputHashAlgorithm.Dispose()
    }

    $jsonOptions = [Text.Json.JsonDocumentOptions]::new()
    $jsonOptions.AllowTrailingCommas = $false
    $jsonOptions.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
    $jsonOptions.MaxDepth = 8
    $document = [Text.Json.JsonDocument]::Parse($raw, $jsonOptions)
    try {
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            throw 'in_memory_request_shape_invalid'
        }
        $expectedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $null = $expectedNames.Add('format')
        $null = $expectedNames.Add('moniker')
        $null = $expectedNames.Add('network_endpoint_base64')
        $null = $expectedNames.Add('network_endpoint_sha256')
        $null = $expectedNames.Add('probe_source_base64')
        $null = $expectedNames.Add('probe_source_sha256')
        $null = $expectedNames.Add('profile_prelaunch_base64')
        $null = $expectedNames.Add('profile_prelaunch_sha256')
        $null = $expectedNames.Add('program_cs_base64')
        $null = $expectedNames.Add('program_cs_sha256')
        $null = $expectedNames.Add('python_runtime_root_utf8_base64')
        $null = $expectedNames.Add('work_root_utf8_base64')
        $values = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
        foreach ($property in $root.EnumerateObject()) {
            if (-not $expectedNames.Remove($property.Name) -or
                $property.Value.ValueKind -ne [Text.Json.JsonValueKind]::String) {
                throw 'in_memory_request_shape_invalid'
            }
            $propertyValue = $property.Value.GetString()
            if ($null -eq $propertyValue -or -not $values.TryAdd($property.Name, $propertyValue)) {
                throw 'in_memory_request_shape_invalid'
            }
        }
        if ($expectedNames.Count -ne 0 -or $values.Count -ne 12) {
            throw 'in_memory_request_shape_invalid'
        }
        $requestFormat = $values['format']
        $moniker = $values['moniker']
        $networkEndpointBase64 = $values['network_endpoint_base64']
        $networkEndpointSha256 = $values['network_endpoint_sha256']
        $probeBase64 = $values['probe_source_base64']
        $probeSha256 = $values['probe_source_sha256']
        $profilePrelaunchBase64 = $values['profile_prelaunch_base64']
        $profilePrelaunchSha256 = $values['profile_prelaunch_sha256']
        $programBase64 = $values['program_cs_base64']
        $programSha256 = $values['program_cs_sha256']
        $pythonRuntimeRootBase64 = $values['python_runtime_root_utf8_base64']
        $workRootBase64 = $values['work_root_utf8_base64']
    }
    finally {
        $document.Dispose()
    }

    $regexOptions = [Text.RegularExpressions.RegexOptions]::CultureInvariant
    if ($requestFormat -cne 'finplanbr.windows-appcontainer-in-memory-input.v9' -or
        -not [Text.RegularExpressions.Regex]::IsMatch(
            $transportDriverSha256,
            '\A[0-9a-f]{64}\z',
            $regexOptions
        ) -or
        -not [Text.RegularExpressions.Regex]::IsMatch(
            $transportBootstrapInputSha256,
            '\A[0-9a-f]{64}\z',
            $regexOptions
        ) -or
        -not [Text.RegularExpressions.Regex]::IsMatch(
            $transportInMemoryInputSha256,
            '\A[0-9a-f]{64}\z',
            $regexOptions
        ) -or
        -not [Text.RegularExpressions.Regex]::IsMatch($probeSha256, '\A[0-9a-f]{64}\z', $regexOptions) -or
        -not [Text.RegularExpressions.Regex]::IsMatch(
            $profilePrelaunchSha256,
            '\A[0-9a-f]{64}\z',
            $regexOptions
        ) -or
        -not [Text.RegularExpressions.Regex]::IsMatch(
            $networkEndpointSha256,
            '\A[0-9a-f]{64}\z',
            $regexOptions
        ) -or
        -not [Text.RegularExpressions.Regex]::IsMatch($programSha256, '\A[0-9a-f]{64}\z', $regexOptions) -or
        -not [Text.RegularExpressions.Regex]::IsMatch($moniker, '\Afinplanbrac-[0-9a-f]{24}\z', $regexOptions)) {
        throw 'in_memory_request_value_invalid'
    }
    try {
        [byte[]] $probeBytes = [Convert]::FromBase64String($probeBase64)
        [byte[]] $profilePrelaunchBytes = [Convert]::FromBase64String($profilePrelaunchBase64)
        [byte[]] $networkEndpointBytes = [Convert]::FromBase64String($networkEndpointBase64)
        [byte[]] $programBytes = [Convert]::FromBase64String($programBase64)
        [byte[]] $pythonRuntimeRootBytes = [Convert]::FromBase64String($pythonRuntimeRootBase64)
        [byte[]] $workRootBytes = [Convert]::FromBase64String($workRootBase64)
    }
    catch {
        throw 'in_memory_request_base64_invalid'
    }
    if ([Convert]::ToBase64String($networkEndpointBytes) -cne $networkEndpointBase64 -or
        [Convert]::ToBase64String($probeBytes) -cne $probeBase64 -or
        [Convert]::ToBase64String($profilePrelaunchBytes) -cne $profilePrelaunchBase64 -or
        [Convert]::ToBase64String($programBytes) -cne $programBase64 -or
        [Convert]::ToBase64String($pythonRuntimeRootBytes) -cne $pythonRuntimeRootBase64 -or
        [Convert]::ToBase64String($workRootBytes) -cne $workRootBase64) {
        throw 'in_memory_request_base64_noncanonical'
    }
    $canonicalRequest = [Text.StringBuilder]::new()
    $null = $canonicalRequest.Append('{"format":"')
    $null = $canonicalRequest.Append($requestFormat)
    $null = $canonicalRequest.Append('","moniker":"')
    $null = $canonicalRequest.Append($moniker)
    $null = $canonicalRequest.Append('","network_endpoint_base64":"')
    $null = $canonicalRequest.Append($networkEndpointBase64)
    $null = $canonicalRequest.Append('","network_endpoint_sha256":"')
    $null = $canonicalRequest.Append($networkEndpointSha256)
    $null = $canonicalRequest.Append('","probe_source_base64":"')
    $null = $canonicalRequest.Append($probeBase64)
    $null = $canonicalRequest.Append('","probe_source_sha256":"')
    $null = $canonicalRequest.Append($probeSha256)
    $null = $canonicalRequest.Append('","profile_prelaunch_base64":"')
    $null = $canonicalRequest.Append($profilePrelaunchBase64)
    $null = $canonicalRequest.Append('","profile_prelaunch_sha256":"')
    $null = $canonicalRequest.Append($profilePrelaunchSha256)
    $null = $canonicalRequest.Append('","program_cs_base64":"')
    $null = $canonicalRequest.Append($programBase64)
    $null = $canonicalRequest.Append('","program_cs_sha256":"')
    $null = $canonicalRequest.Append($programSha256)
    $null = $canonicalRequest.Append('","python_runtime_root_utf8_base64":"')
    $null = $canonicalRequest.Append($pythonRuntimeRootBase64)
    $null = $canonicalRequest.Append('","work_root_utf8_base64":"')
    $null = $canonicalRequest.Append($workRootBase64)
    $null = $canonicalRequest.Append('"}')
    $null = $canonicalRequest.Append("`n")
    $canonicalRequestBytes = $strictUtf8.GetBytes($canonicalRequest.ToString())
    $requestBytesMatch = $rawBytes.Length -eq $canonicalRequestBytes.Length
    if ($requestBytesMatch) {
        for ($requestByteIndex = 0; $requestByteIndex -lt $rawBytes.Length; $requestByteIndex += 1) {
            if ($rawBytes[$requestByteIndex] -ne $canonicalRequestBytes[$requestByteIndex]) {
                $requestBytesMatch = $false
                break
            }
        }
    }
    if (-not $requestBytesMatch) {
        throw 'in_memory_request_not_canonical'
    }
    if ($decodedInMemoryInputSha256 -cne $transportInMemoryInputSha256) {
        throw 'in_memory_request_transport_hash_mismatch'
    }
    $networkEndpointHashAlgorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $observedNetworkEndpointSha256 = [Convert]::ToHexString(
            $networkEndpointHashAlgorithm.ComputeHash($networkEndpointBytes)
        ).ToLowerInvariant()
    }
    finally {
        $networkEndpointHashAlgorithm.Dispose()
    }
    if ($observedNetworkEndpointSha256 -cne $networkEndpointSha256) {
        throw 'network_endpoint_hash_mismatch'
    }
    $sourceHashAlgorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $observedSha256 = [Convert]::ToHexString($sourceHashAlgorithm.ComputeHash($programBytes)).ToLowerInvariant()
    }
    finally {
        $sourceHashAlgorithm.Dispose()
    }
    if ($observedSha256 -cne $programSha256) {
        throw 'program_source_hash_mismatch'
    }
    $probeHashAlgorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $observedProbeSha256 = [Convert]::ToHexString(
            $probeHashAlgorithm.ComputeHash($probeBytes)
        ).ToLowerInvariant()
    }
    finally {
        $probeHashAlgorithm.Dispose()
    }
    if ($observedProbeSha256 -cne $probeSha256) {
        throw 'probe_source_hash_mismatch'
    }
    $profileHashAlgorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $observedProfilePrelaunchSha256 = [Convert]::ToHexString(
            $profileHashAlgorithm.ComputeHash($profilePrelaunchBytes)
        ).ToLowerInvariant()
    }
    finally {
        $profileHashAlgorithm.Dispose()
    }
    if ($observedProfilePrelaunchSha256 -cne $profilePrelaunchSha256) {
        throw 'profile_prelaunch_hash_mismatch'
    }
    $programSource = $strictUtf8.GetString($programBytes)
    $pythonRuntimeRoot = $strictUtf8.GetString($pythonRuntimeRootBytes)
    $workRoot = $strictUtf8.GetString($workRootBytes)

    $psHomeFull = [IO.Path]::GetFullPath($PSHOME)
    $compilerAssemblyPath = [IO.Path]::GetFullPath([Microsoft.CodeAnalysis.Compilation].Assembly.Location)
    $csharpAssemblyPath = [IO.Path]::GetFullPath([Microsoft.CodeAnalysis.CSharp.CSharpCompilation].Assembly.Location)
    $jsonAssemblyPath = [IO.Path]::GetFullPath([Text.Json.JsonDocument].Assembly.Location)
    $expectedCompilerAssemblyPath = [IO.Path]::Combine($psHomeFull, 'Microsoft.CodeAnalysis.dll')
    $expectedCsharpAssemblyPath = [IO.Path]::Combine($psHomeFull, 'Microsoft.CodeAnalysis.CSharp.dll')
    $expectedJsonAssemblyPath = [IO.Path]::Combine($psHomeFull, 'System.Text.Json.dll')
    if (-not [String]::Equals(
            $compilerAssemblyPath,
            $expectedCompilerAssemblyPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [String]::Equals(
            $csharpAssemblyPath,
            $expectedCsharpAssemblyPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [String]::Equals(
            $jsonAssemblyPath,
            $expectedJsonAssemblyPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'in_memory_runtime_assembly_boundary_invalid'
    }

    $trustedPlatformAssemblyText = [string] [AppContext]::GetData('TRUSTED_PLATFORM_ASSEMBLIES')
    if ([String]::IsNullOrWhiteSpace($trustedPlatformAssemblyText)) {
        throw 'in_memory_compiler_reference_boundary_invalid'
    }
    $referencePaths = $trustedPlatformAssemblyText.Split(
        [IO.Path]::PathSeparator,
        [StringSplitOptions]::RemoveEmptyEntries
    )
    $referencePathSet = [Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $metadataReferences = [Collections.Generic.List[Microsoft.CodeAnalysis.MetadataReference]]::new()
    $assemblyMetadataItems = [Collections.Generic.List[Microsoft.CodeAnalysis.AssemblyMetadata]]::new()
    $referenceStreams = [Collections.Generic.List[IO.FileStream]]::new()
    $referenceDigests = [Collections.Generic.List[string]]::new()
    $psHomePrefix = $psHomeFull.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $referenceHashAlgorithm = [Security.Cryptography.SHA256]::Create()
    try {
        foreach ($referencePath in $referencePaths) {
            $referenceFullPath = [IO.Path]::GetFullPath($referencePath)
            if (-not $referenceFullPath.StartsWith($psHomePrefix, [StringComparison]::OrdinalIgnoreCase) -or
                -not [IO.File]::Exists($referenceFullPath) -or
                ([IO.File]::GetAttributes($referenceFullPath) -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'in_memory_compiler_reference_boundary_invalid'
            }
            $null = $referencePathSet.Add($referenceFullPath)
        }
        if ($referencePathSet.Count -lt 1) {
            throw 'in_memory_compiler_reference_boundary_invalid'
        }
        $referenceRosterText = [Text.StringBuilder]::new()
        foreach ($referenceFullPath in $referencePathSet) {
            $referenceStream = [IO.FileStream]::new(
                $referenceFullPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read
            )
            $null = $referenceStreams.Add($referenceStream)
            $referenceDigest = [Convert]::ToHexString(
                $referenceHashAlgorithm.ComputeHash($referenceStream)
            ).ToLowerInvariant()
            $referenceStream.Position = 0
            $null = $referenceDigests.Add($referenceDigest)
            $relativeReferencePath = $referenceFullPath.Substring($psHomePrefix.Length).Replace('\', '/')
            if ([String]::IsNullOrWhiteSpace($relativeReferencePath) -or
                $relativeReferencePath.Contains('..')) {
                throw 'in_memory_compiler_reference_boundary_invalid'
            }
            $moduleMetadata = [Microsoft.CodeAnalysis.ModuleMetadata]::CreateFromStream(
                $referenceStream,
                $true
            )
            $assemblyMetadata = [Microsoft.CodeAnalysis.AssemblyMetadata]::Create($moduleMetadata)
            $null = $assemblyMetadataItems.Add($assemblyMetadata)
            $null = $metadataReferences.Add(
                $assemblyMetadata.GetReference()
            )
            $null = $referenceRosterText.Append($relativeReferencePath)
            $null = $referenceRosterText.Append([char] 0)
            $null = $referenceRosterText.Append($referenceDigest)
            $null = $referenceRosterText.Append("`n")
        }
        if ($metadataReferences.Count -lt 1 -or
            $metadataReferences.Count -ne $referenceStreams.Count -or
            $metadataReferences.Count -ne $assemblyMetadataItems.Count -or
            $metadataReferences.Count -ne $referencePathSet.Count) {
            throw 'in_memory_compiler_reference_boundary_invalid'
        }
        $referenceRosterBytes = $strictUtf8.GetBytes($referenceRosterText.ToString())
        $compilerReferenceSetSha256 = [Convert]::ToHexString(
            $referenceHashAlgorithm.ComputeHash($referenceRosterBytes)
        ).ToLowerInvariant()

        $parseOptions = [Microsoft.CodeAnalysis.CSharp.CSharpParseOptions]::Default.WithLanguageVersion(
            [Microsoft.CodeAnalysis.CSharp.LanguageVersion]::Latest
        )
        $syntaxTree = [Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText($programSource, $parseOptions)
        $compilationOptions = [Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions]::new(
            [Microsoft.CodeAnalysis.OutputKind]::DynamicallyLinkedLibrary
        )
        $compilationOptions = $compilationOptions.WithOptimizationLevel(
            [Microsoft.CodeAnalysis.OptimizationLevel]::Release
        )
        $compilationOptions = $compilationOptions.WithDeterministic($true)
        $compilationOptions = $compilationOptions.WithAllowUnsafe($false)
        $compilationOptions = $compilationOptions.WithGeneralDiagnosticOption(
            [Microsoft.CodeAnalysis.ReportDiagnostic]::Error
        )
        $compilation = [Microsoft.CodeAnalysis.CSharp.CSharpCompilation]::Create(
            'finplanbr_windows_appcontainer_helper',
            [Microsoft.CodeAnalysis.SyntaxTree[]]@($syntaxTree),
            $metadataReferences,
            $compilationOptions
        )
        $assemblyStream = [IO.MemoryStream]::new()
        try {
            $emitResult = $compilation.Emit($assemblyStream)
            if (-not $emitResult.Success) {
                throw 'in_memory_compilation_failed'
            }
            $assemblyBytes = $assemblyStream.ToArray()
        }
        finally {
            $assemblyStream.Dispose()
        }
        for ($referenceIndex = 0; $referenceIndex -lt $referenceStreams.Count; $referenceIndex += 1) {
            $referenceStreams[$referenceIndex].Position = 0
            $recheckedDigest = [Convert]::ToHexString(
                $referenceHashAlgorithm.ComputeHash($referenceStreams[$referenceIndex])
            ).ToLowerInvariant()
            if ($recheckedDigest -cne $referenceDigests[$referenceIndex]) {
                throw 'in_memory_compiler_reference_changed'
            }
        }
    }
    finally {
        $referenceHashAlgorithm.Dispose()
        foreach ($assemblyMetadataToClose in $assemblyMetadataItems) {
            $assemblyMetadataToClose.Dispose()
        }
        foreach ($referenceStreamToClose in $referenceStreams) {
            $referenceStreamToClose.Dispose()
        }
    }
    if ($assemblyBytes.Length -lt 1) {
        throw 'in_memory_compilation_failed'
    }
    $assemblyHashAlgorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $assemblySha256 = [Convert]::ToHexString($assemblyHashAlgorithm.ComputeHash($assemblyBytes)).ToLowerInvariant()
    }
    finally {
        $assemblyHashAlgorithm.Dispose()
    }
    $compiledAssembly = [Reflection.Assembly]::Load($assemblyBytes)
    $programType = $compiledAssembly.GetType('Program', $false, $false)
    if ($null -eq $programType) {
        throw 'in_memory_entrypoint_invalid'
    }
    $entryMethod = $null
    foreach ($candidateMethod in $programType.GetMethods([Reflection.BindingFlags]'Public,Static')) {
        $candidateParameters = $candidateMethod.GetParameters()
        if ($candidateMethod.Name -ceq 'Entry' -and
            $candidateMethod.ReturnType -eq [int] -and
            $candidateParameters.Length -eq 1 -and
            $candidateParameters[0].ParameterType -eq [string[]]) {
            if ($null -ne $entryMethod) {
                throw 'in_memory_entrypoint_invalid'
            }
            $entryMethod = $candidateMethod
        }
    }
    if ($null -eq $entryMethod) {
        throw 'in_memory_entrypoint_invalid'
    }

    $helperArguments = [string[]]::new(10)
    $helperArguments[0] = 'parent'
    $helperArguments[1] = $moniker
    $helperArguments[2] = $pythonRuntimeRoot
    $helperArguments[3] = $workRoot
    $helperArguments[4] = $probeBase64
    $helperArguments[5] = $probeSha256
    $helperArguments[6] = $networkEndpointBase64
    $helperArguments[7] = $networkEndpointSha256
    $helperArguments[8] = $profilePrelaunchBase64
    $helperArguments[9] = $profilePrelaunchSha256
    $invokeArguments = [object[]]::new(1)
    $invokeArguments[0] = $helperArguments
    $originalOutput = [Console]::Out
    $capturedOutput = [IO.StringWriter]::new([Globalization.CultureInfo]::InvariantCulture)
    $capturedOutput.NewLine = "`n"
    try {
        [Console]::SetOut($capturedOutput)
        $entryReturnValue = $entryMethod.Invoke($null, $invokeArguments)
    }
    finally {
        [Console]::SetOut($originalOutput)
    }
    if ($entryReturnValue -isnot [int]) {
        throw 'in_memory_entrypoint_return_invalid'
    }
    $entryReturnCode = [int] $entryReturnValue
    if ($entryReturnCode -ne 0 -and $entryReturnCode -ne 1) {
        throw 'in_memory_entrypoint_return_invalid'
    }
    $helperOutputBytes = $strictUtf8.GetBytes($capturedOutput.ToString())
    $capturedOutput.Dispose()

    $envelopeStream = [IO.MemoryStream]::new()
    $jsonWriter = [Text.Json.Utf8JsonWriter]::new($envelopeStream)
    try {
        $jsonWriter.WriteStartObject()
        $jsonWriter.WriteString('compiled_assembly_sha256', $assemblySha256)
        $jsonWriter.WriteString('compiler_reference_set_sha256', $compilerReferenceSetSha256)
        $jsonWriter.WriteString('format', 'finplanbr.windows-appcontainer-driver-output.v2')
        $jsonWriter.WriteString('helper_stdout_base64', [Convert]::ToBase64String($helperOutputBytes))
        $jsonWriter.WriteString('in_memory_driver_sha256', $transportDriverSha256)
        $jsonWriter.WriteString('observed_bootstrap_input_sha256', $transportBootstrapInputSha256)
        $jsonWriter.WriteString('observed_in_memory_input_sha256', $transportInMemoryInputSha256)
        $jsonWriter.WriteString('program_cs_sha256', $observedSha256)
        $jsonWriter.WriteNumber('program_entry_return_code', $entryReturnCode)
        $jsonWriter.WriteEndObject()
        $jsonWriter.Flush()
        $envelopeBytes = $envelopeStream.ToArray()
    }
    finally {
        $jsonWriter.Dispose()
        $envelopeStream.Dispose()
    }
    $standardOutput = [Console]::OpenStandardOutput()
    $standardOutput.Write($envelopeBytes, 0, $envelopeBytes.Length)
    $standardOutput.WriteByte(10)
    $standardOutput.Flush()
    [Environment]::Exit($entryReturnCode)
}
catch {
    [Console]::Error.WriteLine('in_memory_driver_failed')
    [Environment]::Exit(1)
}
"""

BOOTSTRAP_DRIVER_SHA256_PLACEHOLDER = "__FINPLANBR_IN_MEMORY_DRIVER_SHA256__"
BOOTSTRAP_REQUEST_SHA256_PLACEHOLDER = "__FINPLANBR_IN_MEMORY_INPUT_SHA256__"
BOOTSTRAP_PAYLOAD_BASE64_PLACEHOLDER = "__FINPLANBR_BOOTSTRAP_PAYLOAD_BASE64__"
BOOTSTRAP_PAYLOAD_SHA256_PLACEHOLDER = "__FINPLANBR_BOOTSTRAP_PAYLOAD_SHA256__"

IN_MEMORY_PWSH_BOOTSTRAP_LOADER_TEMPLATE = r"""
$PSModuleAutoLoadingPreference = 'None'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    if ($ExecutionContext.SessionState.LanguageMode -ne [Management.Automation.PSLanguageMode]::FullLanguage -or
        [Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy() -ne
            [Management.Automation.Security.SystemEnforcementMode]::None) {
        throw 'powershell_application_control_policy_unsupported'
    }
    [Environment]::SetEnvironmentVariable('PSModulePath', '', [EnvironmentVariableTarget]::Process)
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    [Console]::InputEncoding = $strictUtf8
    [Console]::OutputEncoding = $strictUtf8
    $standardInput = [Console]::OpenStandardInput()
    $rawInput = [IO.MemoryStream]::new()
    $buffer = [byte[]]::new(8192)
    try {
        while ($true) {
            $count = $standardInput.Read($buffer, 0, $buffer.Length)
            if ($count -eq 0) { break }
            if ($rawInput.Length + $count -gt 2097152) {
                throw 'bootstrap_loader_input_oversize'
            }
            $rawInput.Write($buffer, 0, $count)
        }
        [byte[]] $capturedInput = $rawInput.ToArray()
    }
    finally {
        $rawInput.Dispose()
    }
    $b64 = '__FINPLANBR_BOOTSTRAP_PAYLOAD_BASE64__'
    $expected = '__FINPLANBR_BOOTSTRAP_PAYLOAD_SHA256__'
    [byte[]] $compressed = [Convert]::FromBase64String($b64)
    if ([Convert]::ToBase64String($compressed) -cne $b64) {
        throw 'bootstrap_payload_base64_noncanonical'
    }
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $observed = [Convert]::ToHexString(
            $algorithm.ComputeHash($compressed)
        ).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
    if ($observed -cne $expected) {
        throw 'bootstrap_payload_hash_mismatch'
    }
    $compressedInput = [IO.MemoryStream]::new($compressed, $false)
    $output = [IO.MemoryStream]::new()
    try {
        $gzip = [IO.Compression.GZipStream]::new(
            $compressedInput,
            [IO.Compression.CompressionMode]::Decompress,
            $false
        )
        try {
            $gzip.CopyTo($output)
        }
        finally {
            $gzip.Dispose()
        }
        if ($output.Length -lt 1 -or $output.Length -gt 131072) {
            throw 'bootstrap_payload_size_invalid'
        }
    $payload = $strictUtf8.GetString($output.ToArray())
    }
    finally {
        $output.Dispose()
        $compressedInput.Dispose()
    }
    $global:FinplanbrRawBootstrapInputBytes = $capturedInput
    $script = [Management.Automation.ScriptBlock]::Create($payload)
    $null = $script.Invoke()
    throw 'bootstrap_payload_returned'
}
catch {
    [Console]::Error.WriteLine('in_memory_bootstrap_failed')
    [Environment]::Exit(1)
}
"""
IN_MEMORY_PWSH_BOOTSTRAP_TEMPLATE = r"""
$PSModuleAutoLoadingPreference = 'None'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    if ($ExecutionContext.SessionState.LanguageMode -ne [Management.Automation.PSLanguageMode]::FullLanguage -or
        [Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy() -ne
            [Management.Automation.Security.SystemEnforcementMode]::None) {
        throw 'powershell_application_control_policy_unsupported'
    }
    [Environment]::SetEnvironmentVariable(
        'PSModulePath',
        '',
        [EnvironmentVariableTarget]::Process
    )
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    [Console]::InputEncoding = $strictUtf8
    [Console]::OutputEncoding = $strictUtf8
    [byte[]] $transportRawBytes = $global:FinplanbrRawBootstrapInputBytes
    $global:FinplanbrRawBootstrapInputBytes = $null
    if ($null -eq $transportRawBytes) {
        throw 'bootstrap_input_transport_missing'
    }
    [byte[]] $rawBytes = $transportRawBytes.Clone()
    if ($rawBytes.Length -lt 2 -or
        $rawBytes.Length -gt 2097152 -or
        $rawBytes[$rawBytes.Length - 1] -ne 10) {
        throw 'bootstrap_input_framing_invalid'
    }
    for ($frameByteIndex = 0; $frameByteIndex -lt $rawBytes.Length - 1; $frameByteIndex += 1) {
        if ($rawBytes[$frameByteIndex] -eq 10 -or $rawBytes[$frameByteIndex] -eq 13) {
            throw 'bootstrap_input_framing_invalid'
        }
    }
    $raw = $strictUtf8.GetString($rawBytes)
    $jsonOptions = [Text.Json.JsonDocumentOptions]::new()
    $jsonOptions.AllowTrailingCommas = $false
    $jsonOptions.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
    $jsonOptions.MaxDepth = 4
    $document = [Text.Json.JsonDocument]::Parse($raw, $jsonOptions)
    try {
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            throw 'bootstrap_input_shape_invalid'
        }
        $expectedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $null = $expectedNames.Add('driver_base64')
        $null = $expectedNames.Add('driver_sha256')
        $null = $expectedNames.Add('format')
        $null = $expectedNames.Add('request_base64')
        $null = $expectedNames.Add('request_sha256')
        $values = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
        foreach ($property in $root.EnumerateObject()) {
            if (-not $expectedNames.Remove($property.Name) -or
                $property.Value.ValueKind -ne [Text.Json.JsonValueKind]::String) {
                throw 'bootstrap_input_shape_invalid'
            }
            $propertyValue = $property.Value.GetString()
            if ($null -eq $propertyValue -or -not $values.TryAdd($property.Name, $propertyValue)) {
                throw 'bootstrap_input_shape_invalid'
            }
        }
        if ($expectedNames.Count -ne 0 -or $values.Count -ne 5) {
            throw 'bootstrap_input_shape_invalid'
        }
        $driverBase64 = $values['driver_base64']
        $driverSha256 = $values['driver_sha256']
        $frameFormat = $values['format']
        $requestBase64 = $values['request_base64']
        $requestSha256 = $values['request_sha256']
    }
    finally {
        $document.Dispose()
    }
    $expectedDriverSha256 = '__FINPLANBR_IN_MEMORY_DRIVER_SHA256__'
    $expectedRequestSha256 = '__FINPLANBR_IN_MEMORY_INPUT_SHA256__'
    $regexOptions = [Text.RegularExpressions.RegexOptions]::CultureInvariant
    if ($frameFormat -cne 'finplanbr.windows-appcontainer-bootstrap-input.v2' -or
        $driverSha256 -cne $expectedDriverSha256 -or
        $requestSha256 -cne $expectedRequestSha256 -or
        -not [Text.RegularExpressions.Regex]::IsMatch(
            $requestSha256,
            '\A[0-9a-f]{64}\z',
            $regexOptions
        )) {
        throw 'bootstrap_input_value_invalid'
    }
    try {
        [byte[]] $driverBytes = [Convert]::FromBase64String($driverBase64)
        [byte[]] $requestBytes = [Convert]::FromBase64String($requestBase64)
    }
    catch {
        throw 'bootstrap_input_base64_invalid'
    }
    if ([Convert]::ToBase64String($driverBytes) -cne $driverBase64 -or
        [Convert]::ToBase64String($requestBytes) -cne $requestBase64) {
        throw 'bootstrap_input_base64_noncanonical'
    }
    $canonicalFrame = [Text.StringBuilder]::new()
    $null = $canonicalFrame.Append('{"driver_base64":"')
    $null = $canonicalFrame.Append($driverBase64)
    $null = $canonicalFrame.Append('","driver_sha256":"')
    $null = $canonicalFrame.Append($driverSha256)
    $null = $canonicalFrame.Append('","format":"')
    $null = $canonicalFrame.Append($frameFormat)
    $null = $canonicalFrame.Append('","request_base64":"')
    $null = $canonicalFrame.Append($requestBase64)
    $null = $canonicalFrame.Append('","request_sha256":"')
    $null = $canonicalFrame.Append($requestSha256)
    $null = $canonicalFrame.Append('"}')
    $null = $canonicalFrame.Append("`n")
    $canonicalFrameBytes = $strictUtf8.GetBytes($canonicalFrame.ToString())
    $frameBytesMatch = $rawBytes.Length -eq $canonicalFrameBytes.Length
    if ($frameBytesMatch) {
        for ($canonicalByteIndex = 0; $canonicalByteIndex -lt $rawBytes.Length; $canonicalByteIndex += 1) {
            if ($rawBytes[$canonicalByteIndex] -ne $canonicalFrameBytes[$canonicalByteIndex]) {
                $frameBytesMatch = $false
                break
            }
        }
    }
    if (-not $frameBytesMatch) {
        throw 'bootstrap_input_not_canonical'
    }
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $observedBootstrapInputSha256 = [Convert]::ToHexString(
            $algorithm.ComputeHash($rawBytes)
        ).ToLowerInvariant()
        $observedDriverSha256 = [Convert]::ToHexString(
            $algorithm.ComputeHash($driverBytes)
        ).ToLowerInvariant()
        $observedRequestSha256 = [Convert]::ToHexString(
            $algorithm.ComputeHash($requestBytes)
        ).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
    if ($observedDriverSha256 -cne $expectedDriverSha256 -or
        $observedRequestSha256 -cne $requestSha256) {
        throw 'bootstrap_input_hash_mismatch'
    }
    if ($requestBytes.Length -lt 2 -or $requestBytes[$requestBytes.Length - 1] -ne 10) {
        throw 'bootstrap_request_framing_invalid'
    }
    for ($ri = 0; $ri -lt $requestBytes.Length - 1; $ri += 1) {
        if ($requestBytes[$ri] -eq 10 -or $requestBytes[$ri] -eq 13) {
            throw 'bootstrap_request_framing_invalid'
        }
    }
    $requestText = $strictUtf8.GetString($requestBytes)
    $ro = [Text.Json.JsonDocumentOptions]::new()
    $ro.AllowTrailingCommas = $false
    $ro.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
    $ro.MaxDepth = 8
    $rd = [Text.Json.JsonDocument]::Parse($requestText, $ro)
    try {
        $rr = $rd.RootElement
        if ($rr.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            throw 'bootstrap_request_shape_invalid'
        }
        $rn=[string[]]@('format','moniker','network_endpoint_base64','network_endpoint_sha256',
            'probe_source_base64','probe_source_sha256','profile_prelaunch_base64',
            'profile_prelaunch_sha256','program_cs_base64','program_cs_sha256',
            'python_runtime_root_utf8_base64','work_root_utf8_base64')
        $rv = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
        $ri = 0
        foreach ($rp in $rr.EnumerateObject()) {
            if ($ri -ge $rn.Length -or $rp.Name -cne $rn[$ri] -or
                $rp.Value.ValueKind -ne [Text.Json.JsonValueKind]::String) {
                throw 'bootstrap_request_shape_invalid'
            }
            $v = $rp.Value.GetString()
            if ($null -eq $v -or -not $rv.TryAdd($rp.Name, $v)) {
                throw 'bootstrap_request_shape_invalid'
            }
            $ri += 1
        }
        if ($ri -ne $rn.Length -or $rv.Count -ne $rn.Length) {
            throw 'bootstrap_request_shape_invalid'
        }
        $f = $rv['format']; $m = $rv['moniker']
        $neb = $rv['network_endpoint_base64']; $neh = $rv['network_endpoint_sha256']
        $prb = $rv['probe_source_base64']
        $prh = $rv['probe_source_sha256']; $pb = $rv['program_cs_base64']
        $plb = $rv['profile_prelaunch_base64']; $plh = $rv['profile_prelaunch_sha256']
        $ph = $rv['program_cs_sha256']; $pyrb = $rv['python_runtime_root_utf8_base64']
        $wb = $rv['work_root_utf8_base64']
    }
    finally {
        $rd.Dispose()
    }
    if ($f -cne 'finplanbr.windows-appcontainer-in-memory-input.v9' -or
        -not [Text.RegularExpressions.Regex]::IsMatch($m, '\Afinplanbrac-[0-9a-f]{24}\z', $regexOptions) -or
        -not [Text.RegularExpressions.Regex]::IsMatch($neh, '\A[0-9a-f]{64}\z', $regexOptions) -or
        -not [Text.RegularExpressions.Regex]::IsMatch($prh, '\A[0-9a-f]{64}\z', $regexOptions) -or
        -not [Text.RegularExpressions.Regex]::IsMatch($plh, '\A[0-9a-f]{64}\z', $regexOptions) -or
        -not [Text.RegularExpressions.Regex]::IsMatch($ph, '\A[0-9a-f]{64}\z', $regexOptions)) {
        throw 'bootstrap_request_value_invalid'
    }
    try {
        [byte[]] $nebb = [Convert]::FromBase64String($neb)
        [byte[]] $prbb = [Convert]::FromBase64String($prb)
        [byte[]] $plbb = [Convert]::FromBase64String($plb)
        [byte[]] $pbb = [Convert]::FromBase64String($pb)
        [byte[]] $pyrbb = [Convert]::FromBase64String($pyrb)
        [byte[]] $wbb = [Convert]::FromBase64String($wb)
    }
    catch {
        throw 'bootstrap_request_base64_invalid'
    }
    if ([Convert]::ToBase64String($nebb) -cne $neb -or
        [Convert]::ToBase64String($prbb) -cne $prb -or
        [Convert]::ToBase64String($plbb) -cne $plb -or
        [Convert]::ToBase64String($pbb) -cne $pb -or
        [Convert]::ToBase64String($pyrbb) -cne $pyrb -or
        [Convert]::ToBase64String($wbb) -cne $wb) {
        throw 'bootstrap_request_base64_noncanonical'
    }
    $cb = [Text.StringBuilder]::new()
    $null = $cb.Append('{"format":"'); $null = $cb.Append($f)
    $null = $cb.Append('","moniker":"'); $null = $cb.Append($m)
    $null = $cb.Append('","network_endpoint_base64":"'); $null = $cb.Append($neb)
    $null = $cb.Append('","network_endpoint_sha256":"'); $null = $cb.Append($neh)
    $null = $cb.Append('","probe_source_base64":"'); $null = $cb.Append($prb)
    $null = $cb.Append('","probe_source_sha256":"'); $null = $cb.Append($prh)
    $null = $cb.Append('","profile_prelaunch_base64":"'); $null = $cb.Append($plb)
    $null = $cb.Append('","profile_prelaunch_sha256":"'); $null = $cb.Append($plh)
    $null = $cb.Append('","program_cs_base64":"'); $null = $cb.Append($pb)
    $null = $cb.Append('","program_cs_sha256":"'); $null = $cb.Append($ph)
    $null = $cb.Append('","python_runtime_root_utf8_base64":"'); $null = $cb.Append($pyrb)
    $null = $cb.Append('","work_root_utf8_base64":"'); $null = $cb.Append($wb)
    $null = $cb.Append('"}'); $null = $cb.Append("`n")
    $cbb = $strictUtf8.GetBytes($cb.ToString())
    $rbm = $requestBytes.Length -eq $cbb.Length
    if ($rbm) {
        for ($ri = 0; $ri -lt $requestBytes.Length; $ri += 1) {
            if ($requestBytes[$ri] -ne $cbb[$ri]) {
                $rbm = $false
                break
            }
        }
    }
    if (-not $rbm) {
        throw 'bootstrap_request_not_canonical'
    }
    $driverText = $strictUtf8.GetString($driverBytes)
    $global:FinplanbrBootstrapInputSha256 = $observedBootstrapInputSha256
    $global:FinplanbrInMemoryDriverSha256 = $observedDriverSha256
    $global:FinplanbrInMemoryInputSha256 = $observedRequestSha256
    $requestReader = [IO.StringReader]::new($requestText)
    [Console]::SetIn($requestReader)
    $driver = [Management.Automation.ScriptBlock]::Create($driverText)
    try {
        $null = $driver.Invoke()
    }
    finally {
        $requestReader.Dispose()
    }
    throw 'in_memory_driver_returned'
}
catch {
    [Console]::Error.WriteLine('in_memory_bootstrap_failed')
    [Environment]::Exit(1)
}
"""

Runner = Callable[..., subprocess.CompletedProcess[bytes]]
NonceFactory = Callable[[int], str]


class EndpointLease(Protocol):
    def start(self) -> EndpointLease: ...

    @property
    def prelaunch_observation(self) -> dict[str, object]: ...

    def close(self) -> None: ...

    @property
    def receipt(self) -> dict[str, object]: ...


EndpointAcquirer = Callable[[int], EndpointLease]


class ProfileLease(Protocol):
    def child_path_utf8_sha256(self, leaf: str) -> str: ...

    @property
    def owned_profile_binding(self) -> OwnedProfileBinding: ...

    def close(self) -> None: ...

    @property
    def receipt(self) -> dict[str, object]: ...


ProfileAcquirer = Callable[[str], ProfileLease]


class UsageFailure(Exception):
    """A caller supplied an invalid CLI or path argument."""


class SpikeFailure(Exception):
    """A sanitized operational failure suitable for a public report."""

    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


class HelperProtocolFailure(Exception):
    """The helper did not satisfy its closed stdout protocol."""


class DriverProtocolFailure(Exception):
    """The in-memory driver did not satisfy its closed stdout protocol."""


class PublicPrivacyFailure(Exception):
    """A candidate public surface contains a stable private identifier or path."""


class ClosedArgumentParser(argparse.ArgumentParser):
    """Keep invalid CLI use on the canonical JSON surface."""

    def error(self, message: str) -> None:
        del message
        raise UsageFailure("invalid_usage")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _assert_public_value_privacy(
    value: object,
    *,
    known_private_values: tuple[str, ...] = (),
) -> None:
    account_sid = re.compile(
        r"S-1-5-21-(?:[0-9]+-){3}[0-9]+",
        re.ASCII | re.IGNORECASE,
    )
    drive_path = re.compile(r"(?i)(?:^|[^A-Za-z0-9])[a-z]:[\\/]+", re.ASCII)
    drive_qualified_path = re.compile(r"\A[a-z]:", re.ASCII | re.IGNORECASE)
    rooted_path = re.compile(r"\A[\\/]", re.ASCII)
    repeated_path_separator = re.compile(r"[\\/]{2}", re.ASCII)
    normalized_device_path = re.compile(r"\A[\\/]\?\?[\\/]", re.ASCII)
    closed_private_values = tuple(
        item.casefold()
        for item in known_private_values
        if type(item) is str and item
    )

    def contains_known_private(text: str) -> bool:
        folded = text.casefold()
        for private in closed_private_values:
            if folded == private:
                return True
            if any(character in private for character in "\\/:"):
                if private in folded:
                    return True
                continue
            if len(private) >= 3 and re.search(
                rf"(?<![A-Za-z0-9]){re.escape(private)}(?![A-Za-z0-9])",
                folded,
                re.ASCII,
            ) is not None:
                return True
        return False

    pending = [value]
    observed_nodes = 0
    while pending:
        current = pending.pop()
        observed_nodes += 1
        if observed_nodes > 250_000:
            raise PublicPrivacyFailure("public_privacy_roster_unbounded")
        if type(current) is dict:
            pending.extend(current.keys())
            pending.extend(current.values())
            continue
        if type(current) is list:
            pending.extend(current)
            continue
        if type(current) is not str:
            continue
        if (
            account_sid.search(current) is not None
            or drive_path.search(current) is not None
            or drive_qualified_path.search(current) is not None
            or rooted_path.search(current) is not None
            or repeated_path_separator.search(current) is not None
            or normalized_device_path.search(current) is not None
            or contains_known_private(current)
        ):
            raise PublicPrivacyFailure("public_private_identifier_detected")


def _empty_hashes() -> dict[str, str | None]:
    return {
        "bootstrap_input_sha256": None,
        "driver_stdout_sha256": None,
        "helper_stdout_sha256": None,
        "in_memory_assembly_sha256": None,
        "in_memory_bootstrap_sha256": None,
        "in_memory_compiler_reference_set_sha256": None,
        "in_memory_driver_sha256": None,
        "in_memory_input_sha256": None,
        "invocation_request_sha256": None,
        "probe_source_sha256": None,
        "program_cs_sha256": None,
    }


_DRIVER_DERIVED_ARTIFACT_KEYS = frozenset(
    {
        "driver_stdout_sha256",
        "helper_stdout_sha256",
        "in_memory_assembly_sha256",
        "in_memory_compiler_reference_set_sha256",
    }
)

_ARTIFACT_KEYS = frozenset(_empty_hashes())
_RETAINED_ARTIFACT_KEYS = _ARTIFACT_KEYS - _DRIVER_DERIVED_ARTIFACT_KEYS
_PUBLIC_REPORT_KEYS = frozenset(
    {
        "artifacts",
        "authority",
        "boundary_expected",
        "boundary_summary",
        "cleanup_override_reason",
        "diagnostic_only",
        "driver_binding",
        "evidence_authentication",
        "endpoint_receipt",
        "format",
        "helper_failure_receipt",
        "helper_report",
        "host_trust",
        "input_binding",
        "moniker",
        "portability_cell",
        "primary_reason",
        "profile_receipt",
        "reason",
        "release_authorized",
        "status",
        "temporary_code_artifact_observation",
        "temporary_code_artifacts",
        "temporary_directory_cleanup",
    }
)


def _artifact_snapshot_is_closed(value: object) -> bool:
    return (
        type(value) is dict
        and set(value) == _ARTIFACT_KEYS
        and all(type(key) is str for key in value)
        and all(
            item is None
            or (
                type(item) is str
                and SHA256_PATTERN.fullmatch(item) is not None
            )
            for item in value.values()
        )
    )


_MODE_B_WITNESS_KEYS = frozenset(
    {
        "boundary_expected",
        "driver_binding",
        "endpoint_receipt",
        "helper_report",
        "profile_receipt",
    }
)
_PUBLIC_CONTEXT_WITNESS_KEYS = frozenset(
    {
        "boundary_expected",
        "endpoint_receipt",
        "host_trust",
        "input_binding",
        "moniker",
        "profile_receipt",
    }
)
_PUBLIC_JSON_MAX_DEPTH = 128
_PUBLIC_JSON_MAX_NODES = 100_000


def _mode_b_witness_digests(
    *,
    boundary_expected: dict[str, object],
    driver_binding: dict[str, object],
    endpoint_receipt: dict[str, object],
    helper_report: dict[str, object],
    profile_receipt: dict[str, object],
) -> dict[str, str]:
    witnesses = {
        "boundary_expected": boundary_expected,
        "driver_binding": driver_binding,
        "endpoint_receipt": endpoint_receipt,
        "helper_report": helper_report,
        "profile_receipt": profile_receipt,
    }
    return {
        key: _sha256(_canonical_json(witnesses[key]))
        for key in sorted(_MODE_B_WITNESS_KEYS)
    }


def _public_context_witness_digests(
    *,
    boundary_expected: dict[str, object] | None,
    endpoint_receipt: dict[str, object] | None,
    host_trust: dict[str, object] | None,
    input_binding: dict[str, object] | None,
    moniker: str | None,
    profile_receipt: dict[str, object] | None,
) -> dict[str, str]:
    witnesses: dict[str, object] = {
        "boundary_expected": boundary_expected,
        "endpoint_receipt": endpoint_receipt,
        "host_trust": host_trust,
        "input_binding": input_binding,
        "moniker": moniker,
        "profile_receipt": profile_receipt,
    }
    return {
        key: _sha256(_canonical_json(witnesses[key]))
        for key in sorted(_PUBLIC_CONTEXT_WITNESS_KEYS)
    }


def _validate_exact_public_json_types(value: object) -> None:
    stack: list[tuple[object, int, bool]] = [(value, 0, False)]
    active_container_ids: set[int] = set()
    node_count = 0
    while stack:
        current, depth, exiting = stack.pop()
        if exiting:
            active_container_ids.remove(id(current))
            continue
        node_count += 1
        if node_count > _PUBLIC_JSON_MAX_NODES or depth > _PUBLIC_JSON_MAX_DEPTH:
            raise HelperProtocolFailure("public_json_shape_too_large")
        current_type = type(current)
        if current is None or current_type in {str, int, bool}:
            continue
        if current_type not in {dict, list}:
            raise HelperProtocolFailure("public_json_type_invalid")
        current_id = id(current)
        if current_id in active_container_ids:
            raise HelperProtocolFailure("public_json_cycle_invalid")
        active_container_ids.add(current_id)
        stack.append((current, depth, True))
        if current_type is dict:
            for key, child in reversed(tuple(current.items())):
                if type(key) is not str:
                    raise HelperProtocolFailure("public_json_key_type_invalid")
                stack.append((child, depth + 1, False))
        else:
            for child in reversed(current):
                stack.append((child, depth + 1, False))


def _admit_driver_evidence(
    hashes: dict[str, str | None],
    *,
    driver_binding: dict[str, object],
    driver_stdout: bytes,
    helper_stdout: bytes,
) -> None:
    hashes["in_memory_assembly_sha256"] = str(
        driver_binding["compiled_assembly_sha256"]
    )
    hashes["in_memory_compiler_reference_set_sha256"] = str(
        driver_binding["compiler_reference_set_sha256"]
    )
    hashes["driver_stdout_sha256"] = _sha256(driver_stdout)
    hashes["helper_stdout_sha256"] = _sha256(helper_stdout)


def _without_driver_evidence_hashes(
    hashes: dict[str, str | None],
) -> dict[str, str | None]:
    scrubbed = dict(hashes)
    for key in _DRIVER_DERIVED_ARTIFACT_KEYS:
        scrubbed[key] = None
    return scrubbed


def _report(
    *,
    status: str,
    reason: str,
    hashes: dict[str, str | None] | None = None,
    driver_binding: dict[str, object] | None = None,
    boundary_expected: dict[str, object] | None = None,
    boundary_summary: dict[str, object] | None = None,
    endpoint_receipt: dict[str, object] | None = None,
    profile_receipt: dict[str, object] | None = None,
    helper_report: dict[str, object] | None = None,
    helper_failure_receipt: dict[str, object] | None = None,
    host_trust: dict[str, object] | None = None,
    input_binding: dict[str, object] | None = None,
    moniker: str | None = None,
    primary_reason: str | None = None,
    cleanup_override_reason: str | None = None,
    temporary_directory_cleanup: str = "not_created",
    temporary_code_artifacts: str = "not_evaluated",
    temporary_code_artifact_observation: str = "not_performed",
) -> dict[str, object]:
    artifact_hashes = _empty_hashes() if hashes is None else dict(hashes)
    if set(artifact_hashes) != set(_empty_hashes()):
        raise ValueError("closed artifact hash roster violated")
    for digest in artifact_hashes.values():
        if digest is not None and SHA256_PATTERN.fullmatch(digest) is None:
            raise ValueError("invalid artifact digest")
    if type(status) is not str or status not in {
        "observed_pass",
        "not_observed",
        "failed",
    }:
        raise ValueError("invalid wrapper status")
    primary = reason if primary_reason is None else primary_reason
    if (
        type(reason) is not str
        or REASON_PATTERN.fullmatch(reason) is None
        or type(primary) is not str
        or REASON_PATTERN.fullmatch(primary) is None
        or (
            cleanup_override_reason is not None
            and (
                type(cleanup_override_reason) is not str
                or cleanup_override_reason
                not in {
                    "appcontainer_profile_cleanup_failed",
                    "temporary_directory_cleanup_failed",
                }
            )
        )
    ):
        raise ValueError("invalid wrapper reason")
    if temporary_directory_cleanup not in {"not_created", "verified", "failed"}:
        raise ValueError("invalid temporary cleanup state")
    if temporary_code_artifacts not in {
        "not_evaluated",
        "absent_at_final_inventory",
        "detected_and_rejected",
    }:
        raise ValueError("invalid temporary code artifact state")
    if temporary_code_artifact_observation not in {
        "not_performed",
        "final_inventory_only_transient_activity_not_observed",
    }:
        raise ValueError("invalid temporary code artifact observation")
    if (temporary_code_artifacts == "not_evaluated") != (
        temporary_code_artifact_observation == "not_performed"
    ):
        raise ValueError("inconsistent temporary code artifact observation")
    if helper_failure_receipt is not None:
        try:
            admitted_failure_receipt = _validate_helper_failure_receipt(
                helper_failure_receipt,
                expected_status=status,
            )
        except HelperProtocolFailure as exc:
            raise ValueError("invalid helper failure receipt") from exc
        expected_failure_reason = (
            "helper_not_observed"
            if admitted_failure_receipt["status"] == "not_observed"
            else "helper_failed"
        )
        if (
            reason != expected_failure_reason
            or primary != expected_failure_reason
            or driver_binding is not None
            or helper_report is not None
            or boundary_summary is not None
            or any(
                artifact_hashes[key] is not None
                for key in _DRIVER_DERIVED_ARTIFACT_KEYS
            )
        ):
            raise ValueError("inconsistent helper failure receipt admission")
    else:
        admitted_failure_receipt = None
        if reason in {"helper_failed", "helper_not_observed"} or primary in {
            "helper_failed",
            "helper_not_observed",
        }:
            raise ValueError("helper failure reason requires receipt")
    return {
        "artifacts": artifact_hashes,
        "authority": "none",
        "boundary_expected": boundary_expected,
        "boundary_summary": boundary_summary,
        "cleanup_override_reason": cleanup_override_reason,
        "diagnostic_only": True,
        "driver_binding": driver_binding,
        "evidence_authentication": "not_implemented",
        "endpoint_receipt": endpoint_receipt,
        "format": WRAPPER_FORMAT,
        "helper_failure_receipt": admitted_failure_receipt,
        "helper_report": helper_report,
        "host_trust": host_trust,
        "input_binding": input_binding,
        "moniker": moniker,
        "portability_cell": PORTABILITY_CELL_STATE,
        "primary_reason": primary,
        "profile_receipt": profile_receipt,
        "reason": reason,
        "release_authorized": False,
        "status": status,
        "temporary_directory_cleanup": temporary_directory_cleanup,
        "temporary_code_artifact_observation": temporary_code_artifact_observation,
        "temporary_code_artifacts": temporary_code_artifacts,
    }


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _path_text_is_safe(path: Path) -> bool:
    text = os.fspath(path)
    return '"' not in text and "\0" not in text and all(ord(character) >= 32 for character in text)


def _reparse_free_existing_chain(path: Path) -> bool:
    pending: list[Path] = []
    current = path
    while True:
        pending.append(current)
        if current.parent == current:
            break
        current = current.parent
    return all(not item.exists() or not _is_reparse_or_symlink(item) for item in reversed(pending))


def _resolve_directory(argument: Path, *, reason: str) -> Path:
    if (
        not argument.is_absolute()
        or not _path_text_is_safe(argument)
        or not _reparse_free_existing_chain(argument)
        or _is_reparse_or_symlink(argument)
    ):
        raise UsageFailure(reason)
    try:
        resolved = argument.resolve(strict=True)
    except OSError as exc:
        raise UsageFailure(reason) from exc
    if not resolved.is_dir() or not _reparse_free_existing_chain(resolved) or _is_reparse_or_symlink(resolved):
        raise UsageFailure(reason)
    return resolved


def _resolve_file(argument: Path, *, reason: str) -> Path:
    if (
        not argument.is_absolute()
        or not _path_text_is_safe(argument)
        or not _reparse_free_existing_chain(argument)
        or _is_reparse_or_symlink(argument)
    ):
        raise UsageFailure(reason)
    try:
        resolved = argument.resolve(strict=True)
    except OSError as exc:
        raise UsageFailure(reason) from exc
    if not resolved.is_file() or not _reparse_free_existing_chain(resolved) or _is_reparse_or_symlink(resolved):
        raise UsageFailure(reason)
    return resolved


def _inside_checkout(path: Path) -> bool:
    try:
        path.relative_to(REPOSITORY_ROOT.resolve(strict=True))
    except ValueError:
        return False
    return True


def _is_closed_descendant(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return False
    return bool(relative.parts) and _reparse_free_existing_chain(resolved)


def _resolve_temp_parent(argument: Path | None) -> Path:
    candidate = Path(tempfile.gettempdir()).resolve() if argument is None else argument
    temporary_parent = _resolve_directory(candidate, reason="invalid_temp_root")
    if _inside_checkout(temporary_parent):
        raise UsageFailure("temp_root_inside_checkout")
    return temporary_parent


def _resolve_cpython_313_runtime_root() -> Path:
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 13):
        raise SpikeFailure("not_observed", "cpython_3_13_required")
    try:
        runtime_root = Path(sys.base_prefix).resolve(strict=True)
        runtime_executable = (runtime_root / "python.exe").resolve(strict=True)
    except OSError as exc:
        raise SpikeFailure("not_observed", "cpython_3_13_runtime_unavailable") from exc
    if (
        _inside_checkout(runtime_root)
        or not runtime_root.is_dir()
        or not runtime_executable.is_file()
        or _is_reparse_or_symlink(runtime_executable)
        or not _reparse_free_existing_chain(runtime_root)
        or not _reparse_free_existing_chain(runtime_executable)
    ):
        raise SpikeFailure("not_observed", "cpython_3_13_runtime_boundary_invalid")
    return runtime_root


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_windows_path_utf8_sha256(value: str | os.PathLike[str]) -> str:
    text = os.fspath(value)
    drive, tail = ntpath.splitdrive(text)
    if not drive or not tail.startswith(("\\", "/")) or "\x00" in text:
        raise SpikeFailure("failed", "private_path_context_invalid")
    canonical = ntpath.normpath(text).replace("/", "\\").lower()
    return _sha256(canonical.encode("utf-8"))


def _public_host_trust(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "format",
        "policy",
        "powershell_7",
        "windows_powershell_5_1",
    }:
        raise SpikeFailure("failed", "host_trust_wire_shape_invalid")
    result: dict[str, object] = {
        "format": PUBLIC_HOST_TRUST_FORMAT,
        "policy": value["policy"],
    }
    for role, leaf in (
        ("powershell_7", "pwsh.exe"),
        ("windows_powershell_5_1", "powershell.exe"),
    ):
        host = value[role]
        if type(host) is not dict or set(host) != {
            "ancestor_count",
            "current_token_mutation_access",
            "file_id",
            "file_version",
            "installation_profile",
            "owner_policy",
            "package_full_name",
            "package_publisher",
            "package_version",
            "path",
            "publisher",
            "role",
            "sha256",
            "signature_policy",
            "signer_common_name",
        }:
            raise SpikeFailure("failed", "host_trust_identity_shape_invalid")
        path = host["path"]
        if type(path) is not str or ntpath.basename(path).casefold() != leaf.casefold():
            raise SpikeFailure("failed", "host_trust_identity_path_invalid")
        public_host = dict(host)
        del public_host["path"]
        public_host["executable_leaf"] = leaf
        public_host["path_utf8_sha256"] = _canonical_windows_path_utf8_sha256(path)
        result[role] = public_host
    return result


class _ArtifactReadLock:
    """Read/hash one regular file through a share-read-only identity handle."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: int | None = None
        self._portable_file: object | None = None
        self._file_id: str | None = None

    @staticmethod
    def _normalized_final_path(value: str) -> str:
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return os.path.normcase(os.path.abspath(value))

    def __enter__(self) -> _ArtifactReadLock:
        if os.name != "nt":
            self._portable_file = self.path.open("rb")
            metadata = os.fstat(self._portable_file.fileno())  # type: ignore[attr-defined]
            if not stat.S_ISREG(metadata.st_mode):
                self._portable_file.close()  # type: ignore[attr-defined]
                self._portable_file = None
                raise SpikeFailure("failed", "artifact_read_lock_failed")
            self._file_id = f"{metadata.st_dev:016x}:{metadata.st_ino:032x}"
            return self

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        create_file.restype = wintypes.HANDLE
        handle = create_file(
            os.fspath(self.path),
            0x80000000,
            0x00000001,
            None,
            3,
            0x00000080 | 0x00200000,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle in {None, invalid_handle}:
            raise SpikeFailure("failed", "artifact_read_lock_failed")

        class FileAttributeTagInfo(ctypes.Structure):
            _fields_ = (("attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD))

        get_information = kernel32.GetFileInformationByHandleEx
        get_information.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
        get_information.restype = wintypes.BOOL
        attribute_info = FileAttributeTagInfo()
        if not get_information(handle, 9, ctypes.byref(attribute_info), ctypes.sizeof(attribute_info)):
            kernel32.CloseHandle(handle)
            raise SpikeFailure("failed", "artifact_identity_query_failed")
        if attribute_info.attributes & 0x00000400 or attribute_info.attributes & 0x00000010:
            kernel32.CloseHandle(handle)
            raise SpikeFailure("failed", "artifact_read_lock_failed")

        get_final_path = kernel32.GetFinalPathNameByHandleW
        get_final_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
        get_final_path.restype = wintypes.DWORD
        required = get_final_path(handle, None, 0, 0)
        if required == 0:
            kernel32.CloseHandle(handle)
            raise SpikeFailure("failed", "artifact_final_path_query_failed")
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = get_final_path(handle, buffer, len(buffer), 0)
        if written == 0 or written >= len(buffer):
            kernel32.CloseHandle(handle)
            raise SpikeFailure("failed", "artifact_final_path_query_failed")
        observed = self._normalized_final_path(buffer.value)
        expected = self._normalized_final_path(os.fspath(self.path.resolve(strict=True)))
        if observed != expected:
            kernel32.CloseHandle(handle)
            raise SpikeFailure("failed", "artifact_final_path_mismatch")
        self._handle = int(handle)
        try:
            self._file_id = self._query_windows_file_id()
        except Exception:
            kernel32.CloseHandle(handle)
            self._handle = None
            raise
        return self

    @property
    def file_id(self) -> str:
        if self._file_id is None:
            raise SpikeFailure("failed", "artifact_identity_query_failed")
        return self._file_id

    def _query_windows_file_id(self) -> str:
        if self._handle is None:
            raise SpikeFailure("failed", "artifact_identity_query_failed")
        import ctypes
        from ctypes import wintypes

        class FileId128(ctypes.Structure):
            _fields_ = (("identifier", ctypes.c_ubyte * 16),)

        class FileIdInfo(ctypes.Structure):
            _fields_ = (("volume_serial_number", ctypes.c_ulonglong), ("file_id", FileId128))

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_information = kernel32.GetFileInformationByHandleEx
        get_information.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
        get_information.restype = wintypes.BOOL
        information = FileIdInfo()
        if not get_information(
            self._handle,
            18,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise SpikeFailure("failed", "artifact_identity_query_failed")
        identifier = bytes(information.file_id.identifier)
        if not any(identifier):
            raise SpikeFailure("failed", "artifact_identity_query_failed")
        return f"{int(information.volume_serial_number):016x}:{identifier.hex()}"

    def read_bytes(self) -> bytes:
        if self._portable_file is not None:
            stream = self._portable_file
            stream.seek(0)  # type: ignore[attr-defined]
            value = stream.read()  # type: ignore[attr-defined]
            stream.seek(0)  # type: ignore[attr-defined]
            if not isinstance(value, bytes):
                raise SpikeFailure("failed", "artifact_read_failed")
            return value
        if self._handle is None:
            raise SpikeFailure("failed", "artifact_read_failed")

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_size = kernel32.GetFileSizeEx
        get_size.argtypes = (wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong))
        get_size.restype = wintypes.BOOL
        size = ctypes.c_longlong()
        if not get_size(self._handle, ctypes.byref(size)) or not 0 <= size.value <= 1_048_576:
            raise SpikeFailure("failed", "artifact_read_failed")
        set_pointer = kernel32.SetFilePointerEx
        set_pointer.argtypes = (
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        )
        set_pointer.restype = wintypes.BOOL
        if not set_pointer(self._handle, 0, None, 0):
            raise SpikeFailure("failed", "artifact_read_failed")
        read_file = kernel32.ReadFile
        read_file.argtypes = (
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        )
        read_file.restype = wintypes.BOOL
        remaining = int(size.value)
        chunks: list[bytes] = []
        while remaining:
            amount = min(remaining, 65_536)
            buffer = (ctypes.c_ubyte * amount)()
            read = wintypes.DWORD()
            if not read_file(self._handle, buffer, amount, ctypes.byref(read), None) or read.value == 0:
                raise SpikeFailure("failed", "artifact_read_failed")
            chunks.append(bytes(buffer[: read.value]))
            remaining -= int(read.value)
        if not set_pointer(self._handle, 0, None, 0):
            raise SpikeFailure("failed", "artifact_read_failed")
        value = b"".join(chunks)
        if len(value) != size.value:
            raise SpikeFailure("failed", "artifact_read_failed")
        return value

    def digest(self) -> str:
        return _sha256(self.read_bytes())

    def revalidate(self, expected_digest: str, expected_file_id: str) -> None:
        if self.file_id != expected_file_id or self.digest() != expected_digest:
            raise SpikeFailure("failed", "artifact_same_handle_changed")
        if os.name == "nt" and self._query_windows_file_id() != expected_file_id:
            raise SpikeFailure("failed", "artifact_same_handle_changed")

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        if self._portable_file is not None:
            self._portable_file.close()  # type: ignore[attr-defined]
            self._portable_file = None
        if self._handle is not None:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = (wintypes.HANDLE,)
            close_handle.restype = wintypes.BOOL
            close_handle(self._handle)
            self._handle = None
        self._file_id = None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HelperProtocolFailure("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    del value
    raise HelperProtocolFailure("non_finite_json_number")


def _require_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise HelperProtocolFailure(f"{name}_must_be_boolean")
    return value


def _validate_token(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != TOKEN_KEYS:
        raise HelperProtocolFailure(f"{name}_shape_invalid")
    sid = value["appcontainer_sid"]
    capability_count = value["capability_count"]
    capability_entries = value["capability_entries"]
    integrity_rid = value["integrity_rid"]
    if not isinstance(sid, str) or len(sid) > 184 or SID_PATTERN.fullmatch(sid) is None:
        raise HelperProtocolFailure(f"{name}_sid_invalid")
    if type(capability_count) is not int or not 0 <= capability_count <= 4096:
        raise HelperProtocolFailure(f"{name}_capability_count_invalid")
    if not isinstance(capability_entries, str) or len(capability_entries) > 8192:
        raise HelperProtocolFailure(f"{name}_capability_entries_invalid")
    roster = [] if capability_entries == "" else capability_entries.split(",")
    if (
        len(roster) != capability_count
        or roster != sorted(roster)
        or len(set(roster)) != len(roster)
        or any(CAPABILITY_ENTRY_PATTERN.fullmatch(item) is None for item in roster)
    ):
        raise HelperProtocolFailure(f"{name}_capability_roster_invalid")
    if type(integrity_rid) is not int or not 0 <= integrity_rid <= 0xFFFFFFFF:
        raise HelperProtocolFailure(f"{name}_integrity_rid_invalid")
    for key in (
        "all_application_packages_membership_api",
        "all_application_packages_membership_api_call_succeeded",
        "is_appcontainer",
        "is_elevated",
        "less_privileged_appcontainer_query_supported",
    ):
        _require_bool(value[key], f"{name}_{key}")
    less_privileged_result = value["less_privileged_appcontainer_query_result"]
    if less_privileged_result is not None and type(less_privileged_result) is not bool:
        raise HelperProtocolFailure(f"{name}_less_privileged_query_result_invalid")
    if value["less_privileged_appcontainer_query_supported"] is not (
        less_privileged_result is not None
    ):
        raise HelperProtocolFailure(f"{name}_less_privileged_query_consistency_invalid")
    membership_error = value["all_application_packages_membership_api_win32_error"]
    if membership_error is not None and (
        type(membership_error) is not int or not 0 <= membership_error <= 0xFFFFFFFF
    ):
        raise HelperProtocolFailure(f"{name}_aap_membership_error_invalid")
    if value["all_application_packages_membership_api_call_succeeded"] is not (membership_error is None):
        raise HelperProtocolFailure(f"{name}_aap_membership_consistency_invalid")
    for roster_name in ("token_group", "restricted_sid"):
        total_count = value[f"{roster_name}_count"]
        match_count = value[f"all_application_packages_{roster_name}_match_count"]
        attributes = value[f"all_application_packages_{roster_name}_match_attributes"]
        if (
            type(total_count) is not int
            or not 0 <= total_count <= 65_535
            or type(match_count) is not int
            or not 0 <= match_count <= total_count
            or not isinstance(attributes, str)
            or len(attributes) > 65_535
        ):
            raise HelperProtocolFailure(f"{name}_aap_{roster_name}_invalid")
        roster = [] if not attributes else attributes.split(",")
        if (
            len(roster) != match_count
            or roster != sorted(roster)
            or any(re.fullmatch(r"0x[0-9a-f]{8}", item, re.ASCII) is None for item in roster)
        ):
            raise HelperProtocolFailure(f"{name}_aap_{roster_name}_invalid")
    return value


def _validate_helper_failure_receipt(
    value: object,
    *,
    expected_status: object,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != HELPER_FAILURE_RECEIPT_KEYS:
        raise HelperProtocolFailure("helper_failure_receipt_shape_invalid")
    if value["format"] != HELPER_FAILURE_RECEIPT_FORMAT:
        raise HelperProtocolFailure("helper_failure_receipt_format_invalid")
    status = value["status"]
    stage = value["stage"]
    substage = value["substage"]
    failure_class = value["failure_class"]
    if (
        type(status) is not str
        or status not in {"failed", "not_observed"}
        or status != expected_status
    ):
        raise HelperProtocolFailure("helper_failure_receipt_status_invalid")
    if type(stage) is not str or stage not in HELPER_FAILURE_STAGES:
        raise HelperProtocolFailure("helper_failure_receipt_stage_invalid")
    if type(substage) is not str:
        raise HelperProtocolFailure("helper_failure_receipt_substage_invalid")
    if stage == "profile_binding":
        if substage not in HELPER_FAILURE_PROFILE_BINDING_SUBSTAGES:
            raise HelperProtocolFailure("helper_failure_receipt_substage_invalid")
    elif stage == "network_differential":
        if substage not in _HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGE_SET:
            raise HelperProtocolFailure("helper_failure_receipt_substage_invalid")
    elif substage != HELPER_FAILURE_DEFAULT_SUBSTAGE:
        raise HelperProtocolFailure("helper_failure_receipt_substage_invalid")
    if type(failure_class) is not str or failure_class not in HELPER_FAILURE_CLASSES:
        raise HelperProtocolFailure("helper_failure_receipt_class_invalid")
    if (status == "not_observed") != (failure_class == "not_observed"):
        raise HelperProtocolFailure("helper_failure_receipt_semantics_invalid")
    return {
        "failure_class": failure_class,
        "format": HELPER_FAILURE_RECEIPT_FORMAT,
        "stage": stage,
        "status": status,
        "substage": substage,
    }


def _validate_helper_report(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != HELPER_KEYS:
        raise HelperProtocolFailure("helper_report_shape_invalid")
    if value["format"] != HELPER_FORMAT:
        raise HelperProtocolFailure("helper_format_invalid")
    if value["authority"] != "none":
        raise HelperProtocolFailure("helper_authority_invalid")
    if value["evidence_authentication"] != "not_implemented":
        raise HelperProtocolFailure("helper_authentication_invalid")
    if value["release_authorized"] is not False:
        raise HelperProtocolFailure("helper_release_authority_invalid")
    status = value["status"]
    if type(status) is not str or status not in {
        "observations_complete",
        "not_observed",
        "failed",
    }:
        raise HelperProtocolFailure("helper_status_invalid")
    reason = value["reason"]
    if (
        not isinstance(reason, str)
        or not 1 <= len(reason) <= 256
        or not reason.isascii()
        or any(not (character.isalnum() or character in "_.-") for character in reason)
    ):
        raise HelperProtocolFailure("helper_reason_invalid")

    raw_observations = value["raw_observations"]
    failure_receipt = value["helper_failure_receipt"]
    if status == "observations_complete":
        if (
            reason != "raw_observations_complete"
            or type(raw_observations) is not dict
            or failure_receipt is not None
        ):
            raise HelperProtocolFailure("complete_observations_invalid")
    else:
        expected_reason = "helper_not_observed" if status == "not_observed" else "helper_failed"
        if raw_observations is not None or reason != expected_reason:
            raise HelperProtocolFailure("incomplete_observations_invalid")
        value["helper_failure_receipt"] = _validate_helper_failure_receipt(
            failure_receipt,
            expected_status=status,
        )
    return value


def _validate_observation_evidence_mode(
    report: dict[str, object],
    artifacts: dict[str, object],
    *,
    boundary_path_context: dict[str, object] | None,
    expected_artifacts: dict[str, str | None] | None,
    expected_public_artifacts: dict[str, str | None] | None,
    expected_context_witness_digests: dict[str, str] | None,
    expected_witness_digests: dict[str, str] | None,
) -> None:
    if (
        type(report["format"]) is not str
        or report["format"] != WRAPPER_FORMAT
        or type(report["authority"]) is not str
        or report["authority"] != "none"
        or type(report["evidence_authentication"]) is not str
        or report["evidence_authentication"] != "not_implemented"
        or report["release_authorized"] is not False
        or report["diagnostic_only"] is not True
        or type(report["portability_cell"]) is not str
        or report["portability_cell"] != PORTABILITY_CELL_STATE
    ):
        raise HelperProtocolFailure("public_report_claim_invalid")
    status = report["status"]
    if type(status) is not str or status not in {
        "failed",
        "not_observed",
        "observed_pass",
    }:
        raise HelperProtocolFailure("public_report_status_invalid")
    reason = report["reason"]
    primary_reason = report["primary_reason"]
    if (
        type(reason) is not str
        or REASON_PATTERN.fullmatch(reason) is None
        or type(primary_reason) is not str
        or REASON_PATTERN.fullmatch(primary_reason) is None
    ):
        raise HelperProtocolFailure("public_report_reason_invalid")
    cleanup_override = report["cleanup_override_reason"]
    if cleanup_override is not None and type(cleanup_override) is not str:
        raise HelperProtocolFailure("public_cleanup_override_invalid")
    cleanup_reasons = {
        "appcontainer_profile_cleanup_failed",
        "temporary_directory_cleanup_failed",
    }
    if (
        cleanup_override is not None
        and (
            cleanup_override not in cleanup_reasons
            or status != "failed"
            or reason != cleanup_override
            or primary_reason in cleanup_reasons
        )
    ) or (
        reason in cleanup_reasons
        and cleanup_override != reason
    ):
        raise HelperProtocolFailure("public_cleanup_override_invalid")
    if cleanup_override is None and reason != primary_reason:
        raise HelperProtocolFailure("public_primary_reason_invalid")

    temporary_cleanup = report["temporary_directory_cleanup"]
    temporary_artifacts = report["temporary_code_artifacts"]
    temporary_observation = report["temporary_code_artifact_observation"]
    if (
        type(temporary_cleanup) is not str
        or temporary_cleanup not in {"not_created", "verified", "failed"}
        or type(temporary_artifacts) is not str
        or temporary_artifacts
        not in {
            "not_evaluated",
            "absent_at_final_inventory",
            "detected_and_rejected",
        }
        or type(temporary_observation) is not str
        or temporary_observation
        not in {
            "not_performed",
            "final_inventory_only_transient_activity_not_observed",
        }
        or (temporary_artifacts == "not_evaluated")
        != (temporary_observation == "not_performed")
    ):
        raise HelperProtocolFailure("public_temporary_state_invalid")
    if (
        (temporary_cleanup == "failed" and cleanup_override is None)
        or (
            cleanup_override == "temporary_directory_cleanup_failed"
            and temporary_cleanup != "failed"
        )
        or (
            temporary_cleanup == "not_created"
            and (
                cleanup_override is not None
                or temporary_artifacts != "not_evaluated"
                or temporary_observation != "not_performed"
                or any(
                    report[key] is not None
                    for key in (
                        "boundary_expected",
                        "boundary_summary",
                        "driver_binding",
                        "endpoint_receipt",
                        "helper_failure_receipt",
                        "helper_report",
                        "profile_receipt",
                    )
                )
            )
        )
        or (temporary_artifacts == "detected_and_rejected")
        != (primary_reason == "temporary_code_artifact_detected")
    ):
        raise HelperProtocolFailure("public_temporary_state_relation_invalid")

    public_context = {
        key: report[key] for key in sorted(_PUBLIC_CONTEXT_WITNESS_KEYS)
    }
    if any(
        report[key] is not None and type(report[key]) is not dict
        for key in (
            "boundary_expected",
            "endpoint_receipt",
            "host_trust",
            "input_binding",
            "profile_receipt",
        )
    ):
        raise HelperProtocolFailure("public_context_type_invalid")
    context_is_public = any(value is not None for value in public_context.values())
    if expected_context_witness_digests is None and context_is_public:
        mode_snapshot_can_bind_context = (
            report["host_trust"] is None
            and report["input_binding"] is None
            and report["moniker"] is None
            and type(expected_witness_digests) is dict
            and set(expected_witness_digests) == _MODE_B_WITNESS_KEYS
            and all(
                type(expected_witness_digests[key]) is str
                and SHA256_PATTERN.fullmatch(expected_witness_digests[key])
                is not None
                for key in (
                    "boundary_expected",
                    "endpoint_receipt",
                    "profile_receipt",
                )
            )
        )
        if not mode_snapshot_can_bind_context:
            raise HelperProtocolFailure("public_context_snapshot_invalid")
        try:
            for key in (
                "boundary_expected",
                "endpoint_receipt",
                "profile_receipt",
            ):
                if _sha256(_canonical_json(report[key])) != expected_witness_digests[key]:
                    raise HelperProtocolFailure("public_context_snapshot_drift")
        except (TypeError, ValueError, RecursionError, OverflowError) as exc:
            raise HelperProtocolFailure("public_context_snapshot_invalid") from exc
    elif expected_context_witness_digests is not None:
        if (
            type(expected_context_witness_digests) is not dict
            or set(expected_context_witness_digests)
            != _PUBLIC_CONTEXT_WITNESS_KEYS
            or any(
                type(digest) is not str
                or SHA256_PATTERN.fullmatch(digest) is None
                for digest in expected_context_witness_digests.values()
            )
        ):
            raise HelperProtocolFailure("public_context_snapshot_invalid")
        try:
            public_context_digests = _public_context_witness_digests(
                boundary_expected=report["boundary_expected"],  # type: ignore[arg-type]
                endpoint_receipt=report["endpoint_receipt"],  # type: ignore[arg-type]
                host_trust=report["host_trust"],  # type: ignore[arg-type]
                input_binding=report["input_binding"],  # type: ignore[arg-type]
                moniker=report["moniker"],  # type: ignore[arg-type]
                profile_receipt=report["profile_receipt"],  # type: ignore[arg-type]
            )
        except (TypeError, ValueError, RecursionError, OverflowError) as exc:
            raise HelperProtocolFailure("public_context_snapshot_invalid") from exc
        if public_context_digests != expected_context_witness_digests:
            raise HelperProtocolFailure("public_context_snapshot_drift")
    moniker = report["moniker"]
    if moniker is not None and (
        type(moniker) is not str or MONIKER_PATTERN.fullmatch(moniker) is None
    ):
        raise HelperProtocolFailure("public_moniker_invalid")
    for value in artifacts.values():
        if value is not None and (
            type(value) is not str or SHA256_PATTERN.fullmatch(value) is None
        ):
            raise HelperProtocolFailure("public_artifact_digest_invalid")

    witness_keys = ("driver_binding", "helper_report", "boundary_summary")
    witnesses_null = all(report[key] is None for key in witness_keys)
    derived_null = all(
        artifacts[key] is None for key in _DRIVER_DERIVED_ARTIFACT_KEYS
    )
    null_mode = witnesses_null and derived_null
    observation_mode = all(type(report[key]) is dict for key in witness_keys) and all(
        type(value) is str and SHA256_PATTERN.fullmatch(value) is not None
        for value in artifacts.values()
    )
    if expected_public_artifacts is None:
        raise HelperProtocolFailure("public_artifact_snapshot_missing")
    if (
        not _artifact_snapshot_is_closed(expected_public_artifacts)
        or expected_public_artifacts is artifacts
        or artifacts != expected_public_artifacts
    ):
        raise HelperProtocolFailure("public_artifact_snapshot_drift")
    if expected_artifacts is not None and (
        not _artifact_snapshot_is_closed(expected_artifacts)
        or expected_artifacts is artifacts
        or expected_artifacts is expected_public_artifacts
    ):
        raise HelperProtocolFailure("public_private_artifact_snapshot_invalid")
    if cleanup_override is not None and expected_artifacts is None:
        raise HelperProtocolFailure("public_private_artifact_snapshot_missing")
    if null_mode == observation_mode:
        raise HelperProtocolFailure("public_evidence_mode_invalid")
    if expected_artifacts is not None:
        if observation_mode and artifacts != expected_artifacts:
            raise HelperProtocolFailure("public_private_artifact_snapshot_drift")
        if null_mode and any(
            artifacts[key] != expected_artifacts[key]
            for key in _RETAINED_ARTIFACT_KEYS
        ):
            raise HelperProtocolFailure("public_private_artifact_snapshot_drift")
    elif observation_mode:
        raise HelperProtocolFailure("public_observation_evidence_invalid")
    if null_mode and cleanup_override is None and (
        reason in {"full_boundary_not_observed", "full_boundary_observed"}
        or primary_reason
        in {"full_boundary_not_observed", "full_boundary_observed"}
    ):
        raise HelperProtocolFailure("public_boundary_reason_without_recompute")
    if status == "failed" and not null_mode:
        raise HelperProtocolFailure("public_failed_evidence_invalid")
    if status == "observed_pass" and not observation_mode:
        raise HelperProtocolFailure("public_observed_pass_relation_invalid")
    if observation_mode and (
        temporary_cleanup != "verified"
        or temporary_artifacts != "absent_at_final_inventory"
        or temporary_observation
        != "final_inventory_only_transient_activity_not_observed"
    ):
        raise HelperProtocolFailure("public_observation_inventory_invalid")
    if not observation_mode:
        return

    if (
        status not in {"not_observed", "observed_pass"}
        or report["helper_failure_receipt"] is not None
        or report["cleanup_override_reason"] is not None
        or type(boundary_path_context) is not dict
        or set(boundary_path_context) != {"runtime_root", "source_root"}
    ):
        raise HelperProtocolFailure("public_observation_evidence_invalid")

    driver_binding = report["driver_binding"]
    helper_report = report["helper_report"]
    boundary_summary = report["boundary_summary"]
    if (
        type(driver_binding) is not dict
        or set(driver_binding) != DRIVER_BINDING_KEYS
        or driver_binding["format"] != DRIVER_OUTPUT_FORMAT
        or type(driver_binding["program_entry_return_code"]) is not int
        or driver_binding["program_entry_return_code"] != 0
    ):
        raise HelperProtocolFailure("public_driver_binding_invalid")
    for key in (
        "compiled_assembly_sha256",
        "compiler_reference_set_sha256",
        "in_memory_driver_sha256",
        "observed_bootstrap_input_sha256",
        "observed_in_memory_input_sha256",
        "program_cs_sha256",
    ):
        digest = driver_binding[key]
        if type(digest) is not str or SHA256_PATTERN.fullmatch(digest) is None:
            raise HelperProtocolFailure("public_driver_binding_invalid")
    driver_artifact_bindings = {
        "compiled_assembly_sha256": "in_memory_assembly_sha256",
        "compiler_reference_set_sha256": (
            "in_memory_compiler_reference_set_sha256"
        ),
        "in_memory_driver_sha256": "in_memory_driver_sha256",
        "observed_bootstrap_input_sha256": "bootstrap_input_sha256",
        "observed_in_memory_input_sha256": "in_memory_input_sha256",
        "program_cs_sha256": "program_cs_sha256",
    }
    if any(
        driver_binding[driver_key] != artifacts[artifact_key]
        for driver_key, artifact_key in driver_artifact_bindings.items()
    ):
        raise HelperProtocolFailure("public_driver_binding_artifact_mismatch")

    if (
        type(report["boundary_expected"]) is not dict
        or type(report["endpoint_receipt"]) is not dict
        or type(report["profile_receipt"]) is not dict
        or type(expected_witness_digests) is not dict
        or set(expected_witness_digests) != _MODE_B_WITNESS_KEYS
        or any(
            type(digest) is not str or SHA256_PATTERN.fullmatch(digest) is None
            for digest in expected_witness_digests.values()
        )
    ):
        raise HelperProtocolFailure("public_boundary_recompute_input_invalid")
    try:
        public_witness_digests = _mode_b_witness_digests(
            boundary_expected=report["boundary_expected"],
            driver_binding=driver_binding,
            endpoint_receipt=report["endpoint_receipt"],
            helper_report=helper_report,
            profile_receipt=report["profile_receipt"],
        )
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise HelperProtocolFailure("public_observation_witness_invalid") from exc
    if public_witness_digests != expected_witness_digests:
        raise HelperProtocolFailure("public_observation_witness_drift")

    try:
        admitted_helper = _validate_helper_report(helper_report)
    except HelperProtocolFailure:
        raise
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise HelperProtocolFailure("public_helper_observation_invalid") from exc
    if (
        admitted_helper["status"] != "observations_complete"
        or admitted_helper["reason"] != "raw_observations_complete"
        or admitted_helper["helper_failure_receipt"] is not None
    ):
        raise HelperProtocolFailure("public_helper_observation_invalid")
    try:
        canonical_helper_line = _canonical_json(admitted_helper) + b"\n"
        reconstructed_driver = dict(driver_binding)
        reconstructed_driver["helper_stdout_base64"] = base64.b64encode(
            canonical_helper_line
        ).decode("ascii")
        canonical_driver_line = _canonical_json(reconstructed_driver) + b"\n"
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise HelperProtocolFailure("public_observation_transcript_invalid") from exc
    if (
        _sha256(canonical_helper_line) != artifacts["helper_stdout_sha256"]
        or _sha256(canonical_driver_line) != artifacts["driver_stdout_sha256"]
    ):
        raise HelperProtocolFailure("public_observation_transcript_mismatch")
    try:
        recomputed_summary = recompute_boundary_summary(
            admitted_helper["raw_observations"],
            report["boundary_expected"],
            report["endpoint_receipt"],
            report["profile_receipt"],
            boundary_path_context,
        )
        admitted_summary = validate_declared_summary(
            boundary_summary,
            recomputed_summary,
        )
    except BoundaryReportError as exc:
        raise HelperProtocolFailure("public_boundary_summary_invalid") from exc
    expected_reason = (
        "full_boundary_observed"
        if status == "observed_pass"
        else "full_boundary_not_observed"
    )
    summary_checks = admitted_summary["checks"]
    if type(summary_checks) is not dict:
        raise HelperProtocolFailure("public_boundary_summary_invalid")
    if (
        admitted_summary["format"] != BOUNDARY_SUMMARY_FORMAT
        or admitted_summary["status"] != status
        or admitted_summary["reason"] != expected_reason
        or report["reason"] != expected_reason
        or report["primary_reason"] != expected_reason
        or admitted_summary["authority"] != "none"
        or admitted_summary["evidence_authentication"] != "not_implemented"
        or admitted_summary["portability_cell"] != PORTABILITY_CELL_STATE
        or admitted_summary["release_authorized"] is not False
        or admitted_summary["all_required_controls_observed"]
        is not (status == "observed_pass")
        or all(summary_checks.values()) is not (status == "observed_pass")
    ):
        raise HelperProtocolFailure("public_boundary_summary_relation_invalid")


def _validate_final_helper_failure_receipt_relation(
    report: dict[str, object],
    *,
    boundary_path_context: dict[str, object] | None = None,
    expected_artifacts: dict[str, str | None] | None = None,
    expected_public_artifacts: dict[str, str | None] | None = None,
    expected_context_witness_digests: dict[str, str] | None = None,
    expected_witness_digests: dict[str, str] | None = None,
) -> None:
    _validate_exact_public_json_types(report)
    if type(report) is not dict or set(report) != _PUBLIC_REPORT_KEYS:
        raise HelperProtocolFailure("public_report_roster_invalid")
    artifacts = report["artifacts"]
    if type(artifacts) is not dict or set(artifacts) != _ARTIFACT_KEYS:
        raise HelperProtocolFailure("public_artifact_roster_invalid")

    _validate_observation_evidence_mode(
        report,
        artifacts,
        boundary_path_context=boundary_path_context,
        expected_artifacts=expected_artifacts,
        expected_public_artifacts=expected_public_artifacts,
        expected_context_witness_digests=expected_context_witness_digests,
        expected_witness_digests=expected_witness_digests,
    )

    receipt = report["helper_failure_receipt"]
    if receipt is None:
        if (
            report["reason"] in {"helper_failed", "helper_not_observed"}
            or report["primary_reason"]
            in {"helper_failed", "helper_not_observed"}
        ):
            raise HelperProtocolFailure("public_helper_failure_receipt_missing")
        return
    if type(receipt) is not dict:
        raise HelperProtocolFailure("public_helper_failure_receipt_invalid")
    receipt_status = receipt.get("status")
    admitted = _validate_helper_failure_receipt(
        receipt,
        expected_status=receipt_status,
    )
    expected_primary = (
        "helper_not_observed"
        if admitted["status"] == "not_observed"
        else "helper_failed"
    )
    cleanup_override = report["cleanup_override_reason"]
    if (
        report["primary_reason"] != expected_primary
        or report["driver_binding"] is not None
        or report["helper_report"] is not None
        or report["boundary_summary"] is not None
    ):
        raise HelperProtocolFailure("public_helper_failure_relation_invalid")
    if any(artifacts[key] is not None for key in _DRIVER_DERIVED_ARTIFACT_KEYS):
        raise HelperProtocolFailure("public_helper_failure_relation_invalid")
    if cleanup_override is None:
        if (
            report["status"] != admitted["status"]
            or report["reason"] != expected_primary
        ):
            raise HelperProtocolFailure("public_helper_failure_relation_invalid")
    elif (
        cleanup_override
        not in {
            "appcontainer_profile_cleanup_failed",
            "temporary_directory_cleanup_failed",
        }
        or report["status"] != "failed"
        or report["reason"] != cleanup_override
    ):
        raise HelperProtocolFailure("public_helper_failure_relation_invalid")


def _decode_helper_report(
    payload: bytes,
    *,
    known_private_values: tuple[str, ...] = (),
) -> dict[str, object]:
    if not payload or len(payload) > MAX_HELPER_OUTPUT_BYTES:
        raise HelperProtocolFailure("helper_output_size_invalid")
    if payload.endswith(b"\r\n"):
        body = payload[:-2]
    elif payload.endswith(b"\n"):
        body = payload[:-1]
    else:
        raise HelperProtocolFailure("helper_output_line_invalid")
    if payload.startswith(b"\xef\xbb\xbf") or b"\r" in body or b"\n" in body or not body:
        raise HelperProtocolFailure("helper_output_line_invalid")
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HelperProtocolFailure("helper_output_utf8_invalid") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except HelperProtocolFailure:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HelperProtocolFailure("helper_output_json_invalid") from exc
    report = _validate_helper_report(parsed)
    if body != _canonical_json(report):
        raise HelperProtocolFailure("helper_output_not_canonical")
    try:
        _assert_public_value_privacy(
            report,
            known_private_values=known_private_values,
        )
    except PublicPrivacyFailure as exc:
        raise HelperProtocolFailure("helper_output_privacy_invalid") from exc
    return report


def _unique_driver_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DriverProtocolFailure("duplicate_json_key")
        result[key] = value
    return result


def _reject_driver_json_constant(value: str) -> object:
    del value
    raise DriverProtocolFailure("non_finite_json_number")


def _decode_driver_output(
    payload: bytes,
    *,
    expected_bootstrap_input_sha256: str,
    expected_driver_sha256: str,
    expected_input_sha256: str,
    expected_program_sha256: str,
) -> tuple[dict[str, object], bytes]:
    if not payload or len(payload) > MAX_DRIVER_OUTPUT_BYTES:
        raise DriverProtocolFailure("driver_output_size_invalid")
    if not payload.endswith(b"\n"):
        raise DriverProtocolFailure("driver_output_line_invalid")
    body = payload[:-1]
    if payload.startswith(b"\xef\xbb\xbf") or b"\r" in body or b"\n" in body or not body:
        raise DriverProtocolFailure("driver_output_line_invalid")
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DriverProtocolFailure("driver_output_utf8_invalid") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_driver_object,
            parse_constant=_reject_driver_json_constant,
        )
    except DriverProtocolFailure:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DriverProtocolFailure("driver_output_json_invalid") from exc
    if not isinstance(parsed, dict) or set(parsed) != DRIVER_OUTPUT_KEYS:
        raise DriverProtocolFailure("driver_output_shape_invalid")
    if body != _canonical_json(parsed):
        raise DriverProtocolFailure("driver_output_not_canonical")
    if parsed["format"] != DRIVER_OUTPUT_FORMAT:
        raise DriverProtocolFailure("driver_output_format_invalid")
    for key in (
        "compiled_assembly_sha256",
        "compiler_reference_set_sha256",
        "in_memory_driver_sha256",
        "observed_bootstrap_input_sha256",
        "observed_in_memory_input_sha256",
        "program_cs_sha256",
    ):
        value = parsed[key]
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise DriverProtocolFailure(f"driver_{key}_invalid")
    if parsed["observed_bootstrap_input_sha256"] != expected_bootstrap_input_sha256:
        raise DriverProtocolFailure("driver_bootstrap_input_hash_mismatch")
    if parsed["observed_in_memory_input_sha256"] != expected_input_sha256:
        raise DriverProtocolFailure("driver_input_hash_mismatch")
    if parsed["in_memory_driver_sha256"] != expected_driver_sha256:
        raise DriverProtocolFailure("driver_source_hash_mismatch")
    if parsed["program_cs_sha256"] != expected_program_sha256:
        raise DriverProtocolFailure("driver_program_hash_mismatch")
    entry_return_code = parsed["program_entry_return_code"]
    if type(entry_return_code) is not int or entry_return_code not in {0, 1}:
        raise DriverProtocolFailure("driver_entry_return_code_invalid")
    encoded_helper = parsed["helper_stdout_base64"]
    if not isinstance(encoded_helper, str) or not encoded_helper.isascii():
        raise DriverProtocolFailure("driver_helper_output_base64_invalid")
    try:
        helper_stdout = base64.b64decode(encoded_helper, validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise DriverProtocolFailure("driver_helper_output_base64_invalid") from exc
    if base64.b64encode(helper_stdout).decode("ascii") != encoded_helper:
        raise DriverProtocolFailure("driver_helper_output_base64_noncanonical")
    if len(helper_stdout) > MAX_HELPER_OUTPUT_BYTES:
        raise DriverProtocolFailure("driver_helper_output_size_invalid")
    binding = {
        "compiled_assembly_sha256": parsed["compiled_assembly_sha256"],
        "compiler_reference_set_sha256": parsed["compiler_reference_set_sha256"],
        "format": DRIVER_OUTPUT_FORMAT,
        "in_memory_driver_sha256": parsed["in_memory_driver_sha256"],
        "observed_bootstrap_input_sha256": parsed["observed_bootstrap_input_sha256"],
        "observed_in_memory_input_sha256": parsed["observed_in_memory_input_sha256"],
        "program_cs_sha256": parsed["program_cs_sha256"],
        "program_entry_return_code": entry_return_code,
    }
    return binding, helper_stdout


def _subprocess_environment(temporary: Path) -> dict[str, str]:
    permitted = {
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in permitted}
    environment.update(
        {
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_NOLOGO": "1",
            "POWERSHELL_TELEMETRY_OPTOUT": "1",
            "TEMP": os.fspath(temporary),
            "TMP": os.fspath(temporary),
        }
    )
    return environment


def _run_command(
    command: list[str],
    *,
    temporary: Path,
    timeout_seconds: int,
    timeout_reason: str,
    launch_reason: str,
    runner: Runner,
    input_bytes: bytes = b"",
) -> subprocess.CompletedProcess[bytes]:
    if os.name == "nt" and runner is subprocess.run:
        return _run_command_in_watchdog_job(
            command,
            temporary=temporary,
            timeout_seconds=timeout_seconds,
            timeout_reason=timeout_reason,
            launch_reason=launch_reason,
            input_bytes=input_bytes,
        )
    try:
        return runner(
            command,
            cwd=temporary,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env=_subprocess_environment(temporary),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise SpikeFailure("failed", timeout_reason) from exc
    except OSError as exc:
        raise SpikeFailure("failed", launch_reason) from exc


def _run_command_in_watchdog_job(
    command: list[str],
    *,
    temporary: Path,
    timeout_seconds: int,
    timeout_reason: str,
    launch_reason: str,
    input_bytes: bytes,
) -> subprocess.CompletedProcess[bytes]:
    """Launch suspended, assign to a kill-on-close job, then resume."""

    import ctypes
    from ctypes import wintypes

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = (
            ("per_process_user_time", ctypes.c_longlong),
            ("per_job_user_time", ctypes.c_longlong),
            ("limit_flags", wintypes.DWORD),
            ("minimum_working_set", ctypes.c_size_t),
            ("maximum_working_set", ctypes.c_size_t),
            ("active_process_limit", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority_class", wintypes.DWORD),
            ("scheduling_class", wintypes.DWORD),
        )

    class IoCounters(ctypes.Structure):
        _fields_ = tuple((name, ctypes.c_ulonglong) for name in (
            "read_operations",
            "write_operations",
            "other_operations",
            "read_bytes",
            "write_bytes",
            "other_bytes",
        ))

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = (
            ("basic", BasicLimitInformation),
            ("io", IoCounters),
            ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t),
            ("peak_process_memory", ctypes.c_size_t),
            ("peak_job_memory", ctypes.c_size_t),
        )

    class ThreadEntry32(ctypes.Structure):
        _fields_ = (
            ("size", wintypes.DWORD),
            ("usage", wintypes.DWORD),
            ("thread_id", wintypes.DWORD),
            ("owner_process_id", wintypes.DWORD),
            ("base_priority", wintypes.LONG),
            ("delta_priority", wintypes.LONG),
            ("flags", wintypes.DWORD),
        )

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    create_job.restype = wintypes.HANDLE
    set_job = kernel32.SetInformationJobObject
    set_job.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    set_job.restype = wintypes.BOOL
    query_job = kernel32.QueryInformationJobObject
    query_job.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    query_job.restype = wintypes.BOOL
    assign_job = kernel32.AssignProcessToJobObject
    assign_job.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    assign_job.restype = wintypes.BOOL
    snapshot_threads = kernel32.CreateToolhelp32Snapshot
    snapshot_threads.argtypes = (wintypes.DWORD, wintypes.DWORD)
    snapshot_threads.restype = wintypes.HANDLE
    first_thread = kernel32.Thread32First
    first_thread.argtypes = (wintypes.HANDLE, ctypes.POINTER(ThreadEntry32))
    first_thread.restype = wintypes.BOOL
    next_thread = kernel32.Thread32Next
    next_thread.argtypes = (wintypes.HANDLE, ctypes.POINTER(ThreadEntry32))
    next_thread.restype = wintypes.BOOL
    open_thread = kernel32.OpenThread
    open_thread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_thread.restype = wintypes.HANDLE
    resume_thread = kernel32.ResumeThread
    resume_thread.argtypes = (wintypes.HANDLE,)
    resume_thread.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    job = create_job(None, None)
    if not job:
        raise SpikeFailure("not_observed", "watchdog_job_creation_unavailable")
    process: subprocess.Popen[bytes] | None = None
    try:
        limits = ExtendedLimitInformation()
        limits.basic.limit_flags = 0x00002000
        if not set_job(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise SpikeFailure("not_observed", "watchdog_job_policy_unavailable")
        observed_limits = ExtendedLimitInformation()
        returned = wintypes.DWORD()
        if (
            not query_job(
                job,
                9,
                ctypes.byref(observed_limits),
                ctypes.sizeof(observed_limits),
                ctypes.byref(returned),
            )
            or returned.value != ctypes.sizeof(observed_limits)
            or observed_limits.basic.limit_flags != 0x00002000
        ):
            raise SpikeFailure("not_observed", "watchdog_job_policy_unverified")
        try:
            process = subprocess.Popen(
                command,
                cwd=temporary,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_subprocess_environment(temporary),
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
                ),
            )
        except OSError as exc:
            raise SpikeFailure("failed", launch_reason) from exc
        process_handle = wintypes.HANDLE(int(process._handle))  # type: ignore[attr-defined]
        if not assign_job(job, process_handle):
            raise SpikeFailure("not_observed", "watchdog_job_assignment_unavailable")

        snapshot = snapshot_threads(0x00000004, 0)
        invalid = ctypes.c_void_p(-1).value
        if int(snapshot) == invalid:
            raise SpikeFailure("failed", "watchdog_thread_snapshot_failed")
        primary_thread = wintypes.HANDLE()
        try:
            entry = ThreadEntry32()
            entry.size = ctypes.sizeof(entry)
            if not first_thread(snapshot, ctypes.byref(entry)):
                raise SpikeFailure("failed", "watchdog_thread_snapshot_failed")
            while True:
                if entry.owner_process_id == process.pid:
                    primary_thread = open_thread(0x0002, False, entry.thread_id)
                    break
                entry.size = ctypes.sizeof(entry)
                if not next_thread(snapshot, ctypes.byref(entry)):
                    break
        finally:
            close_handle(snapshot)
        if not primary_thread:
            raise SpikeFailure("failed", "watchdog_primary_thread_missing")
        try:
            if resume_thread(primary_thread) != 1:
                raise SpikeFailure("failed", "watchdog_resume_count_invalid")
        finally:
            close_handle(primary_thread)
        try:
            assert process.stdin is not None and process.stdout is not None and process.stderr is not None
            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []
            stdout_overflow = threading.Event()
            stderr_overflow = threading.Event()
            pipe_errors: list[BaseException] = []

            def read_limited(stream: object, limit: int, target: list[bytes], overflow: threading.Event) -> None:
                total = 0
                try:
                    while True:
                        remaining = limit - total
                        read_size = min(8192, remaining + 1)
                        reader = getattr(stream, "read1", stream.read)  # type: ignore[attr-defined]
                        chunk = reader(read_size)
                        if not chunk:
                            return
                        total += len(chunk)
                        if total > limit:
                            overflow.set()
                            return
                        target.append(chunk)
                except (OSError, ValueError) as exc:
                    pipe_errors.append(exc)

            def write_input() -> None:
                try:
                    process.stdin.write(input_bytes)
                    process.stdin.close()
                except (BrokenPipeError, OSError) as exc:
                    pipe_errors.append(exc)

            readers = (
                threading.Thread(
                    target=read_limited,
                    args=(process.stdout, MAX_DRIVER_OUTPUT_BYTES, stdout_chunks, stdout_overflow),
                    daemon=True,
                ),
                threading.Thread(
                    target=read_limited,
                    args=(process.stderr, MAX_POWERSHELL_STDERR_BYTES, stderr_chunks, stderr_overflow),
                    daemon=True,
                ),
            )
            for reader in readers:
                reader.start()
            writer = threading.Thread(target=write_input, daemon=True)
            writer.start()
            try:
                deadline = time.monotonic() + timeout_seconds
                while process.poll() is None:
                    if stdout_overflow.is_set() or stderr_overflow.is_set():
                        break
                    if time.monotonic() >= deadline:
                        raise SpikeFailure("failed", timeout_reason)
                    time.sleep(0.005)
                if stdout_overflow.is_set() or stderr_overflow.is_set():
                    raise SpikeFailure("failed", "powershell_output_limit_exceeded")
            finally:
                if job:
                    if not close_handle(job):
                        raise SpikeFailure("failed", "watchdog_job_close_failed")
                    job = wintypes.HANDLE()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired as exc:
                    process.kill()
                    process.wait(timeout=5)
                    raise SpikeFailure("failed", "watchdog_process_cleanup_failed") from exc
                writer.join(timeout=5)
                for reader in readers:
                    reader.join(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass
                if writer.is_alive() or any(reader.is_alive() for reader in readers):
                    raise SpikeFailure("failed", "powershell_output_reader_cleanup_failed")
                if pipe_errors:
                    raise SpikeFailure("failed", "powershell_pipe_io_failed") from pipe_errors[0]
            stdout = b"".join(stdout_chunks)
            stderr = b"".join(stderr_chunks)
        except OSError as exc:
            raise SpikeFailure("failed", "powershell_pipe_io_failed") from exc
        return subprocess.CompletedProcess(command, process.returncode, stdout=stdout, stderr=stderr)
    finally:
        if job:
            close_handle(job)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def _encoded_powershell_command(script_bytes: bytes) -> str:
    return base64.b64encode(script_bytes).decode("ascii")


def _bootstrap_bytes(driver_bytes: bytes, request_bytes: bytes) -> bytes:
    driver_sha256 = _sha256(driver_bytes)
    request_sha256 = _sha256(request_bytes)
    if (
        IN_MEMORY_PWSH_BOOTSTRAP_TEMPLATE.count(BOOTSTRAP_DRIVER_SHA256_PLACEHOLDER) != 1
        or IN_MEMORY_PWSH_BOOTSTRAP_TEMPLATE.count(BOOTSTRAP_REQUEST_SHA256_PLACEHOLDER) != 1
    ):
        raise SpikeFailure("failed", "bootstrap_template_invalid")
    payload = IN_MEMORY_PWSH_BOOTSTRAP_TEMPLATE.replace(
        BOOTSTRAP_DRIVER_SHA256_PLACEHOLDER,
        driver_sha256,
    ).replace(
        BOOTSTRAP_REQUEST_SHA256_PLACEHOLDER,
        request_sha256,
    )
    compressed = gzip.compress(payload.encode("utf-8"), compresslevel=9, mtime=0)
    compressed_base64 = base64.b64encode(compressed).decode("ascii")
    compressed_sha256 = _sha256(compressed)
    if (
        IN_MEMORY_PWSH_BOOTSTRAP_LOADER_TEMPLATE.count(
            BOOTSTRAP_PAYLOAD_BASE64_PLACEHOLDER
        )
        != 1
        or IN_MEMORY_PWSH_BOOTSTRAP_LOADER_TEMPLATE.count(
            BOOTSTRAP_PAYLOAD_SHA256_PLACEHOLDER
        )
        != 1
    ):
        raise SpikeFailure("failed", "bootstrap_loader_template_invalid")
    loader = IN_MEMORY_PWSH_BOOTSTRAP_LOADER_TEMPLATE.replace(
        BOOTSTRAP_PAYLOAD_BASE64_PLACEHOLDER,
        compressed_base64,
    ).replace(
        BOOTSTRAP_PAYLOAD_SHA256_PLACEHOLDER,
        compressed_sha256,
    )
    return loader.encode("utf-16-le")


def _bootstrap_input(driver_bytes: bytes, request_bytes: bytes) -> bytes:
    return _canonical_json(
        {
            "driver_base64": base64.b64encode(driver_bytes).decode("ascii"),
            "driver_sha256": _sha256(driver_bytes),
            "format": BOOTSTRAP_INPUT_FORMAT,
            "request_base64": base64.b64encode(request_bytes).decode("ascii"),
            "request_sha256": _sha256(request_bytes),
        }
    ) + b"\n"


def _windows_command_line_length(command: list[str]) -> int:
    return len(subprocess.list2cmdline(command)) + 1


def _verify_temporary_inventory(temporary: Path, work_directory: Path) -> None:
    try:
        root_entries = tuple(temporary.iterdir())
        work_entries = tuple(work_directory.iterdir())
    except OSError as exc:
        raise SpikeFailure("failed", "temporary_code_artifact_detected") from exc
    if (
        root_entries != (work_directory,)
        or not work_directory.is_dir()
        or _is_reparse_or_symlink(work_directory)
        or work_entries
    ):
        raise SpikeFailure("failed", "temporary_code_artifact_detected")
    if os.name == "nt":
        for path in (temporary, work_directory):
            if _named_streams(path):
                raise SpikeFailure("failed", "temporary_code_artifact_detected")


def _named_streams(path: Path) -> tuple[str, ...]:
    """Return non-default NTFS streams for one existing file or directory."""

    if os.name != "nt":
        return ()
    import ctypes
    from ctypes import wintypes

    class Win32FindStreamData(ctypes.Structure):
        _fields_ = (
            ("stream_size", ctypes.c_longlong),
            ("stream_name", wintypes.WCHAR * 296),
        )

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    first = kernel32.FindFirstStreamW
    first.argtypes = (
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.POINTER(Win32FindStreamData),
        wintypes.DWORD,
    )
    first.restype = wintypes.HANDLE
    next_stream = kernel32.FindNextStreamW
    next_stream.argtypes = (wintypes.HANDLE, ctypes.POINTER(Win32FindStreamData))
    next_stream.restype = wintypes.BOOL
    close = kernel32.FindClose
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    data = Win32FindStreamData()
    handle = first(os.fspath(path), 0, ctypes.byref(data), 0)
    invalid = ctypes.c_void_p(-1).value
    if int(handle) == invalid:
        error = ctypes.get_last_error()
        if error in {2, 38}:
            return ()
        raise OSError(error, "FindFirstStreamW")
    names: list[str] = []
    try:
        while True:
            name = data.stream_name
            if name and name != "::$DATA":
                names.append(name)
            if not next_stream(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error == 38:
                    break
                raise OSError(error, "FindNextStreamW")
    finally:
        close(handle)
    names.sort()
    return tuple(names)


def _invoke_helper(
    *,
    pwsh: Path,
    python_runtime_root: Path,
    temporary: Path,
    driver_bytes: bytes,
    probe_bytes: bytes,
    program_bytes: bytes,
    hashes: dict[str, str | None],
    moniker: str,
    timeout_seconds: int,
    runner: Runner,
    host_revalidator: Callable[[], None],
    source_revalidator: Callable[[], None],
    host_trust: dict[str, object],
    input_binding: dict[str, object],
    network_endpoint: dict[str, object],
    profile_binding: OwnedProfileBinding,
) -> subprocess.CompletedProcess[bytes]:
    work_directory = temporary / "work"
    work_directory.mkdir()
    if not _is_closed_descendant(work_directory, temporary):
        raise SpikeFailure("failed", "temporary_input_boundary_invalid")

    endpoint_bytes = _canonical_json(network_endpoint)
    endpoint_sha256 = _sha256(endpoint_bytes)
    if input_binding.get("network_endpoint_prelaunch_sha256") != endpoint_sha256:
        raise SpikeFailure("failed", "network_endpoint_input_binding_mismatch")
    if type(profile_binding) is not OwnedProfileBinding:
        raise SpikeFailure("failed", "profile_owned_binding_type_invalid")
    profile_prelaunch_bytes, profile_prelaunch_sha256 = profile_binding.current_wire()
    if input_binding.get("profile_prelaunch_sha256") != profile_prelaunch_sha256:
        raise SpikeFailure("failed", "profile_prelaunch_input_binding_mismatch")
    stdin_request = {
        "format": IN_MEMORY_INPUT_FORMAT,
        "moniker": moniker,
        "network_endpoint_base64": base64.b64encode(endpoint_bytes).decode("ascii"),
        "network_endpoint_sha256": endpoint_sha256,
        "probe_source_base64": base64.b64encode(probe_bytes).decode("ascii"),
        "probe_source_sha256": hashes["probe_source_sha256"],
        "profile_prelaunch_base64": base64.b64encode(profile_prelaunch_bytes).decode("ascii"),
        "profile_prelaunch_sha256": profile_prelaunch_sha256,
        "program_cs_base64": base64.b64encode(program_bytes).decode("ascii"),
        "program_cs_sha256": hashes["program_cs_sha256"],
        "python_runtime_root_utf8_base64": base64.b64encode(
            os.fspath(python_runtime_root).encode("utf-8")
        ).decode("ascii"),
        "work_root_utf8_base64": base64.b64encode(
            os.fspath(work_directory).encode("utf-8")
        ).decode("ascii"),
    }
    stdin_bytes = _canonical_json(stdin_request) + b"\n"
    hashes["in_memory_input_sha256"] = _sha256(stdin_bytes)
    bootstrap_bytes = _bootstrap_bytes(driver_bytes, stdin_bytes)
    hashes["in_memory_bootstrap_sha256"] = _sha256(bootstrap_bytes)
    input_binding["in_memory_bootstrap_sha256"] = hashes["in_memory_bootstrap_sha256"]
    request_binding = {
        "entrypoint": "Program.Entry",
        "format": INVOCATION_REQUEST_FORMAT,
        "host_trust": host_trust,
        "input_binding": input_binding,
        "moniker": moniker,
        "runtime_role": "cpython_3_13_external_copy_source",
    }
    hashes["invocation_request_sha256"] = _sha256(_canonical_json(request_binding))
    bootstrap_input = _bootstrap_input(driver_bytes, stdin_bytes)
    hashes["bootstrap_input_sha256"] = _sha256(bootstrap_input)
    command = [
        os.fspath(pwsh),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        _encoded_powershell_command(bootstrap_bytes),
    ]
    if (
        _windows_command_line_length(command)
        > MAX_WINDOWS_COMMAND_LINE_CHARACTERS - MIN_WINDOWS_COMMAND_LINE_HEADROOM_CHARACTERS
    ):
        raise SpikeFailure("failed", "bootstrap_command_line_headroom_insufficient")
    host_revalidator()
    source_revalidator()
    completed = _run_command(
        command,
        temporary=temporary,
        timeout_seconds=timeout_seconds,
        timeout_reason="helper_execution_timeout",
        launch_reason="pwsh_launch_failed",
        runner=runner,
        input_bytes=bootstrap_input,
    )
    source_revalidator()
    host_revalidator()
    _verify_temporary_inventory(temporary, work_directory)
    return completed


def _new_moniker(nonce_factory: NonceFactory) -> str:
    moniker = "finplanbrac-" + nonce_factory(12)
    if MONIKER_PATTERN.fullmatch(moniker) is None or len(moniker) > 64:
        raise SpikeFailure("failed", "nonce_generation_failed")
    return moniker


def _boundary_canary(moniker: str, role: str) -> bytes:
    if role not in {"decoy", "permitted"}:
        raise ValueError("invalid canary role")
    return hashlib.sha256(f"finplanbr-{role}-handle-v1\0{moniker}".encode("ascii")).digest()


def _boundary_expected(
    *,
    moniker: str,
    work_directory: Path,
    probe_source_sha256: str,
    profile_binding: OwnedProfileBinding,
    profile_prelaunch_sha256: str,
    profile_network_request_path_utf8_sha256: str,
) -> dict[str, object]:
    if type(profile_binding) is not OwnedProfileBinding:
        raise SpikeFailure("failed", "profile_owned_binding_type_invalid")
    current_bytes, current_sha256 = profile_binding.current_wire()
    if _sha256(current_bytes) != current_sha256 or current_sha256 != profile_prelaunch_sha256:
        raise SpikeFailure("failed", "profile_owned_binding_digest_invalid")
    if (
        profile_binding.format
        != "finplanbr.windows-appcontainer-profile-prelaunch.v4"
        or profile_binding.moniker != moniker
        or type(profile_binding.appcontainer_sid) is not str
        or SID_PATTERN.fullmatch(profile_binding.appcontainer_sid) is None
        or type(profile_binding.created_hresult) is not int
        or profile_binding.created_hresult != 0
        or profile_binding.folder_identity_format != "windows-file-id-info.v1"
        or type(profile_binding.folder_boundary_component_count) is not int
        or not 1 <= profile_binding.folder_boundary_component_count <= 0xFFFFFFFF
        or type(profile_binding.folder_boundary_terminal_ac) is not bool
        or any(
            value is not True
            for value in (
                profile_binding.folder_boundary_components_win32_valid,
                profile_binding.folder_boundary_exact,
                profile_binding.folder_boundary_nonempty_descendant,
                profile_binding.folder_boundary_packages_ancestor,
                profile_binding.folder_boundary_reconstruction_matches,
                profile_binding.folder_exists,
                profile_binding.folder_handle_delete_share_denied,
                profile_binding.folder_handle_held,
                profile_binding.folder_reparse_free,
                profile_binding.ownership_established,
                profile_binding.sid_reconciled,
            )
        )
        or profile_binding.folder_boundary_reason != "observed"
        or type(profile_binding.folder_file_id_128_hex) is not str
        or re.fullmatch(r"[0-9a-f]{32}", profile_binding.folder_file_id_128_hex) is None
        or type(profile_binding.folder_path_utf8_sha256) is not str
        or SHA256_PATTERN.fullmatch(profile_binding.folder_path_utf8_sha256) is None
        or type(profile_binding.folder_volume_serial_hex) is not str
        or re.fullmatch(r"[0-9a-f]{16}", profile_binding.folder_volume_serial_hex) is None
        or SHA256_PATTERN.fullmatch(profile_network_request_path_utf8_sha256) is None
    ):
        raise SpikeFailure("failed", "profile_prelaunch_binding_invalid")
    runtime_root = os.fspath(work_directory / "runtime")
    source_root = os.fspath(work_directory / "source")
    return {
        "appcontainer_sid": profile_binding.appcontainer_sid,
        "decoy_canary_sha256": _sha256(_boundary_canary(moniker, "decoy")),
        "format": BOUNDARY_EXPECTED_FORMAT,
        "internet_client_capability_sid": INTERNET_CLIENT_CAPABILITY_SID,
        "moniker": moniker,
        "permitted_canary_sha256": _sha256(_boundary_canary(moniker, "permitted")),
        "profile_folder_boundary_component_count": (
            profile_binding.folder_boundary_component_count
        ),
        "profile_folder_boundary_terminal_ac": profile_binding.folder_boundary_terminal_ac,
        "profile_folder_file_id_128_hex": profile_binding.folder_file_id_128_hex,
        "profile_folder_identity_format": profile_binding.folder_identity_format,
        "profile_folder_path_utf8_sha256": profile_binding.folder_path_utf8_sha256,
        "profile_folder_volume_serial_hex": profile_binding.folder_volume_serial_hex,
        "profile_network_request_path_utf8_sha256": profile_network_request_path_utf8_sha256,
        "profile_prelaunch_sha256": profile_prelaunch_sha256,
        "probe_source_leaf": "windows_appcontainer_child_probe.py",
        "probe_source_path_utf8_sha256": _canonical_windows_path_utf8_sha256(
            ntpath.join(source_root, "windows_appcontainer_child_probe.py")
        ),
        "probe_source_sha256": probe_source_sha256,
        "runtime_executable_leaf": "python.exe",
        "runtime_executable_path_utf8_sha256": _canonical_windows_path_utf8_sha256(
            ntpath.join(runtime_root, "python.exe")
        ),
        "runtime_root_leaf": "runtime",
        "runtime_root_path_utf8_sha256": _canonical_windows_path_utf8_sha256(runtime_root),
        "runtime_root_role": "external_rx_runtime_copy",
        "source_root_leaf": "source",
        "source_root_path_utf8_sha256": _canonical_windows_path_utf8_sha256(source_root),
        "source_root_role": "protected_probe_source_copy",
    }


def _run_spike(
    *,
    temp_root: Path | None = None,
    timeout_seconds: int = 180,
    platform_name: str,
    runner: Runner = subprocess.run,
    nonce_factory: NonceFactory = secrets.token_hex,
    host_acquirer: HostAcquirer = acquire_trusted_powershell_hosts,
    endpoint_acquirer: EndpointAcquirer = acquire_wsl2_endpoint,
    profile_acquirer: ProfileAcquirer = acquire_appcontainer_profile,
) -> tuple[dict[str, object], int]:
    """Internal execution surface with test-only dependency injection."""

    if platform_name != "nt":
        return _report(status="not_observed", reason="windows_required"), 1
    if not 30 <= timeout_seconds <= 900:
        raise UsageFailure("invalid_timeout")

    boundary_expected: dict[str, object] | None = None
    boundary_summary: dict[str, object] | None = None
    endpoint_receipt: dict[str, object] | None = None
    endpoint_lease: EndpointLease | None = None
    profile_receipt: dict[str, object] | None = None
    profile_lease: ProfileLease | None = None
    profile_cleanup_failed = False
    try:
        temporary_parent = _resolve_temp_parent(temp_root)
    except SpikeFailure as exc:
        return _report(status=exc.status, reason=exc.reason), 1

    driver_bytes = IN_MEMORY_PWSH_DRIVER.encode("utf-8")
    artifact_hashes = _empty_hashes()
    artifact_hashes["in_memory_driver_sha256"] = _sha256(driver_bytes)
    moniker = _new_moniker(nonce_factory)
    temporary_directory: tempfile.TemporaryDirectory[str] | None = None
    temporary_path: Path | None = None
    cleanup_state = "not_created"
    temporary_code_artifact_state = "not_evaluated"
    temporary_code_artifact_observation = "not_performed"
    host_trust: dict[str, object] | None = None
    input_binding: dict[str, object] | None = None
    boundary_path_context: dict[str, object] | None = None
    expected_context_witness_digests: dict[str, str] | None = None
    expected_mode_b_witness_digests: dict[str, str] | None = None
    private_public_rejection_values = {
        os.fspath(REPOSITORY_ROOT),
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("USERPROFILE", ""),
        os.environ.get("USERNAME", ""),
    } - {""}
    report = _report(
        status="failed",
        reason="wrapper_execution_not_completed",
        hashes=artifact_hashes,
        host_trust=host_trust,
        input_binding=input_binding,
        moniker=moniker,
    )

    def closed_final_failure_report(failure_reason: str) -> dict[str, object]:
        primary = (
            "temporary_code_artifact_detected"
            if temporary_code_artifact_state == "detected_and_rejected"
            else failure_reason
        )
        cleanup_override = (
            "appcontainer_profile_cleanup_failed"
            if profile_cleanup_failed
            else "temporary_directory_cleanup_failed"
            if cleanup_state == "failed"
            else None
        )
        return _report(
            status="failed",
            reason=primary if cleanup_override is None else cleanup_override,
            primary_reason=primary,
            cleanup_override_reason=cleanup_override,
            hashes=_without_driver_evidence_hashes(artifact_hashes),
            moniker=moniker,
            temporary_directory_cleanup=cleanup_state,
            temporary_code_artifacts=temporary_code_artifact_state,
            temporary_code_artifact_observation=(
                temporary_code_artifact_observation
            ),
        )
    try:
        python_runtime_root = _resolve_cpython_313_runtime_root()
        private_public_rejection_values.add(os.fspath(python_runtime_root))
        with host_acquirer() as hosts:
            private_public_rejection_values.update(
                {
                    str(hosts.powershell_7.path),
                    str(hosts.windows_powershell_5_1.path),
                }
            )
            host_trust = _public_host_trust(hosts.to_wire())
            hosts.revalidate()
            if (
                not _reparse_free_existing_chain(PROGRAM_SOURCE)
                or _is_reparse_or_symlink(PROGRAM_SOURCE)
                or not _reparse_free_existing_chain(PROBE_SOURCE)
                or _is_reparse_or_symlink(PROBE_SOURCE)
            ):
                raise SpikeFailure("failed", "helper_source_boundary_invalid")
            with (
                _ArtifactReadLock(PROGRAM_SOURCE) as program_lock,
                _ArtifactReadLock(PROBE_SOURCE) as probe_lock,
            ):
                program_bytes = program_lock.read_bytes()
                probe_bytes = probe_lock.read_bytes()
                if not program_bytes:
                    raise SpikeFailure("failed", "helper_source_empty")
                if not probe_bytes:
                    raise SpikeFailure("failed", "probe_source_empty")
                program_sha256 = _sha256(program_bytes)
                probe_sha256 = _sha256(probe_bytes)
                if program_lock.digest() != program_sha256:
                    raise SpikeFailure("failed", "artifact_same_handle_changed")
                if probe_lock.digest() != probe_sha256:
                    raise SpikeFailure("failed", "artifact_same_handle_changed")
                program_file_id = program_lock.file_id
                probe_file_id = probe_lock.file_id
                program_lock.revalidate(program_sha256, program_file_id)
                probe_lock.revalidate(probe_sha256, probe_file_id)
                artifact_hashes["program_cs_sha256"] = program_sha256
                artifact_hashes["probe_source_sha256"] = probe_sha256
                input_binding = {
                    "child_observed_digest_binding": "outer_and_inner_raw_sha256.v1",
                    "compiler_boundary": "command_free_dotnet_roslyn_pshome_in_memory.v1",
                    "execution_model": "in_memory_program_suspended_process_external_observation.v2",
                    "format": INPUT_BINDING_FORMAT,
                    "inner_frame_canonicalization": WIRE_CANONICALIZATION,
                    "in_memory_bootstrap_sha256": artifact_hashes["in_memory_bootstrap_sha256"],
                    "in_memory_driver_sha256": artifact_hashes["in_memory_driver_sha256"],
                    "outer_frame_canonicalization": WIRE_CANONICALIZATION,
                    "pre_execution_request_binding": (
                        "encoded_bootstrap_expected_inner_sha256_and_reconstruction.v2"
                    ),
                    "program_cs": {
                        "checkout_relative_path": "scripts/windows_appcontainer_helper/Program.cs",
                        "file_id": program_file_id,
                        "sha256": program_sha256,
                    },
                    "probe_source": {
                        "checkout_relative_path": "scripts/windows_appcontainer_child_probe.py",
                        "file_id": probe_file_id,
                        "sha256": probe_sha256,
                    },
                    "python_runtime_source_leaf": "cpython-3.13-source-root",
                    "python_runtime_source_path_utf8_sha256": (
                        _canonical_windows_path_utf8_sha256(python_runtime_root)
                    ),
                    "python_runtime_source_role": "installed_cpython_313_copy_source",
                    "temporary_code_artifact_policy": (
                        "wrapper_materializes_no_runtime_code_and_checks_exact_final_inventory.v2"
                    ),
                }
                report = _report(
                    status="failed",
                    reason="wrapper_execution_not_completed",
                    hashes=artifact_hashes,
                    host_trust=host_trust,
                    input_binding=input_binding,
                    moniker=moniker,
                )
                temporary_directory = tempfile.TemporaryDirectory(
                    prefix=moniker + "-",
                    dir=temporary_parent,
                )
                temporary_path = Path(temporary_directory.name).resolve(strict=True)
                private_public_rejection_values.add(os.fspath(temporary_path))
                if (
                    temporary_path.parent != temporary_parent
                    or _inside_checkout(temporary_path)
                    or not _reparse_free_existing_chain(temporary_path)
                ):
                    raise SpikeFailure("failed", "temporary_directory_boundary_invalid")
                profile_lease = profile_acquirer(moniker)
                profile_binding = profile_lease.owned_profile_binding
                if type(profile_binding) is not OwnedProfileBinding:
                    raise SpikeFailure("failed", "profile_owned_binding_type_invalid")
                _, profile_prelaunch_sha256 = profile_binding.current_wire()
                profile_network_request_path_utf8_sha256 = (
                    profile_lease.child_path_utf8_sha256("network-arm-request.json")
                )
                boundary_expected = _boundary_expected(
                    moniker=moniker,
                    work_directory=temporary_path / "work",
                    probe_source_sha256=probe_sha256,
                    profile_binding=profile_binding,
                    profile_prelaunch_sha256=profile_prelaunch_sha256,
                    profile_network_request_path_utf8_sha256=(
                        profile_network_request_path_utf8_sha256
                    ),
                )
                boundary_path_context = {
                    "runtime_root": os.fspath(temporary_path / "work" / "runtime"),
                    "source_root": os.fspath(temporary_path / "work" / "source"),
                }
                input_binding["boundary_prelaunch_expected_sha256"] = _sha256(
                    _canonical_json(boundary_expected)
                )
                input_binding["controller_context_appcontainer_sid"] = (
                    profile_binding.appcontainer_sid
                )
                input_binding["effective_appcontainer_sid_binding"] = (
                    "lease_issued_owned_profile_binding_create_vs_same_process_derive_equals_imported_roundtrip_and_all_observed_tokens.v4"
                )
                input_binding["profile_prelaunch_sha256"] = profile_prelaunch_sha256
                endpoint_lease = endpoint_acquirer(timeout_seconds)
                endpoint_lease.start()
                endpoint_prelaunch = endpoint_lease.prelaunch_observation
                input_binding["network_endpoint_prelaunch_sha256"] = _sha256(
                    _canonical_json(endpoint_prelaunch)
                )
                try:
                    completed = _invoke_helper(
                        pwsh=Path(hosts.powershell_7.path),
                        python_runtime_root=python_runtime_root,
                        temporary=temporary_path,
                        driver_bytes=driver_bytes,
                        probe_bytes=probe_bytes,
                        program_bytes=program_bytes,
                        hashes=artifact_hashes,
                        moniker=moniker,
                        timeout_seconds=timeout_seconds,
                        runner=runner,
                        host_revalidator=hosts.revalidate,
                        source_revalidator=lambda: (
                            program_lock.revalidate(program_sha256, program_file_id),
                            probe_lock.revalidate(probe_sha256, probe_file_id),
                        ),
                        host_trust=host_trust,
                        input_binding=input_binding,
                        network_endpoint=endpoint_prelaunch,
                        profile_binding=profile_binding,
                    )
                finally:
                    try:
                        endpoint_lease.close()
                        endpoint_receipt = endpoint_lease.receipt
                    finally:
                        profile_lease.close()
                        profile_receipt = profile_lease.receipt
                temporary_code_artifact_state = "absent_at_final_inventory"
                temporary_code_artifact_observation = (
                    "final_inventory_only_transient_activity_not_observed"
                )
                program_lock.revalidate(program_sha256, program_file_id)
                probe_lock.revalidate(probe_sha256, probe_file_id)
                helper_report: dict[str, object] | None = None
                if completed.stderr:
                    report = _report(
                        status="failed",
                        reason="powershell_stderr_present",
                        hashes=artifact_hashes,
                        host_trust=host_trust,
                        input_binding=input_binding,
                        moniker=moniker,
                    )
                else:
                    try:
                        expected_bootstrap_input_sha256 = artifact_hashes[
                            "bootstrap_input_sha256"
                        ]
                        expected_input_sha256 = artifact_hashes["in_memory_input_sha256"]
                        expected_driver_sha256 = artifact_hashes["in_memory_driver_sha256"]
                        expected_program_sha256 = artifact_hashes["program_cs_sha256"]
                        if (
                            expected_bootstrap_input_sha256 is None
                            or expected_driver_sha256 is None
                            or expected_input_sha256 is None
                            or expected_program_sha256 is None
                        ):
                            raise DriverProtocolFailure("driver_expected_hash_missing")
                        candidate_driver_binding, helper_stdout = _decode_driver_output(
                            completed.stdout,
                            expected_bootstrap_input_sha256=expected_bootstrap_input_sha256,
                            expected_driver_sha256=expected_driver_sha256,
                            expected_input_sha256=expected_input_sha256,
                            expected_program_sha256=expected_program_sha256,
                        )
                    except DriverProtocolFailure:
                        report = _report(
                            status="failed",
                            reason="driver_output_invalid",
                            hashes=artifact_hashes,
                            host_trust=host_trust,
                            input_binding=input_binding,
                            moniker=moniker,
                        )
                    else:
                        driver_return_code = int(
                            candidate_driver_binding["program_entry_return_code"]
                        )
                        if completed.returncode != driver_return_code:
                            report = _report(
                                status="failed",
                                reason="driver_return_code_mismatch",
                                hashes=artifact_hashes,
                                host_trust=host_trust,
                                input_binding=input_binding,
                                moniker=moniker,
                            )
                        else:
                            try:
                                helper_report = _decode_helper_report(
                                    helper_stdout,
                                    known_private_values=tuple(
                                        sorted(private_public_rejection_values)
                                    ),
                                )
                            except HelperProtocolFailure:
                                report = _report(
                                    status="failed",
                                    reason="helper_output_invalid",
                                    hashes=artifact_hashes,
                                    host_trust=host_trust,
                                    input_binding=input_binding,
                                    moniker=moniker,
                                )
                            else:
                                helper_status = helper_report["status"]
                                expected_return_code = 0 if helper_status == "observations_complete" else 1
                                if driver_return_code != expected_return_code:
                                    report = _report(
                                        status="failed",
                                        reason="helper_return_code_mismatch",
                                        hashes=artifact_hashes,
                                        host_trust=host_trust,
                                        input_binding=input_binding,
                                        moniker=moniker,
                                    )
                                elif artifact_hashes["invocation_request_sha256"] is None:
                                    report = _report(
                                        status="failed",
                                        reason="invocation_request_missing",
                                        hashes=artifact_hashes,
                                        host_trust=host_trust,
                                        input_binding=input_binding,
                                        moniker=moniker,
                                    )
                                elif helper_status != "observations_complete":
                                    helper_failure_receipt = helper_report[
                                        "helper_failure_receipt"
                                    ]
                                    if type(helper_failure_receipt) is not dict:
                                        raise AssertionError(
                                            "validated helper failure receipt missing"
                                        )
                                    report = _report(
                                        status=str(helper_status),
                                        reason=(
                                            "helper_not_observed"
                                            if helper_status == "not_observed"
                                            else "helper_failed"
                                        ),
                                        hashes=artifact_hashes,
                                        host_trust=host_trust,
                                        input_binding=input_binding,
                                        moniker=moniker,
                                        helper_failure_receipt=helper_failure_receipt,
                                    )
                                elif boundary_expected is None or boundary_path_context is None:
                                    report = _report(
                                        status="failed",
                                        reason="boundary_expected_missing",
                                        hashes=artifact_hashes,
                                        host_trust=host_trust,
                                        input_binding=input_binding,
                                        moniker=moniker,
                                    )
                                else:
                                    try:
                                        raw_observations = helper_report["raw_observations"]
                                        if type(raw_observations) is not dict:
                                            raise BoundaryReportError("raw_observations_missing")
                                        profile_observations = raw_observations.get("profile")
                                        if type(profile_observations) is not dict:
                                            raise BoundaryReportError("profile_observations_missing")
                                        effective_sid = profile_observations.get(
                                            "appcontainer_sid_prelaunch_bound"
                                        )
                                        if (
                                            type(effective_sid) is not str
                                            or SID_PATTERN.fullmatch(effective_sid) is None
                                            or effective_sid
                                            != boundary_expected["appcontainer_sid"]
                                        ):
                                            raise BoundaryReportError("effective_sid_invalid")
                                        boundary_summary = recompute_boundary_summary(
                                            raw_observations,
                                            boundary_expected,
                                            endpoint_receipt,
                                            profile_receipt,
                                            boundary_path_context,
                                        )
                                    except BoundaryReportError:
                                        report = _report(
                                            status="failed",
                                            reason="boundary_observations_invalid",
                                            hashes=artifact_hashes,
                                            host_trust=host_trust,
                                            input_binding=input_binding,
                                            moniker=moniker,
                                        )
                                    else:
                                        _admit_driver_evidence(
                                            artifact_hashes,
                                            driver_binding=candidate_driver_binding,
                                            driver_stdout=completed.stdout,
                                            helper_stdout=helper_stdout,
                                        )
                                        expected_mode_b_witness_digests = (
                                            _mode_b_witness_digests(
                                                boundary_expected=boundary_expected,
                                                driver_binding=candidate_driver_binding,
                                                endpoint_receipt=endpoint_receipt,
                                                helper_report=helper_report,
                                                profile_receipt=profile_receipt,
                                            )
                                        )
                                        report = _report(
                                            status=str(boundary_summary["status"]),
                                            reason=str(boundary_summary["reason"]),
                                            hashes=artifact_hashes,
                                            boundary_summary=boundary_summary,
                                            driver_binding=candidate_driver_binding,
                                            helper_report=helper_report,
                                            host_trust=host_trust,
                                            input_binding=input_binding,
                                            moniker=moniker,
                                        )
    except WslEndpointFailure as exc:
        report = _report(
            status="not_observed",
            reason=str(exc),
            hashes=artifact_hashes,
            endpoint_receipt=endpoint_receipt,
            host_trust=host_trust,
            input_binding=input_binding,
            moniker=moniker,
        )
    except ProfileLeaseFailure as exc:
        if exc.receipt is not None:
            profile_receipt = exc.receipt
        else:
            profile_cleanup_failed = True
        report = _report(
            status="not_observed",
            reason=str(exc),
            hashes=artifact_hashes,
            endpoint_receipt=endpoint_receipt,
            profile_receipt=profile_receipt,
            host_trust=host_trust,
            input_binding=input_binding,
            moniker=moniker,
        )
    except OSError:
        report = _report(
            status="failed",
            reason="temporary_directory_or_io_failed",
            hashes=artifact_hashes,
            host_trust=host_trust,
            input_binding=input_binding,
            moniker=moniker,
        )
    except HostTrustFailure as exc:
        report = _report(
            status=exc.status,
            reason=exc.reason,
            hashes=artifact_hashes,
            host_trust=host_trust,
            input_binding=input_binding,
            moniker=moniker,
        )
    except SpikeFailure as exc:
        if exc.reason == "temporary_code_artifact_detected":
            temporary_code_artifact_state = "detected_and_rejected"
            temporary_code_artifact_observation = (
                "final_inventory_only_transient_activity_not_observed"
            )
        report = _report(
            status=exc.status,
            reason=exc.reason,
            hashes=artifact_hashes,
            host_trust=host_trust,
            input_binding=input_binding,
            moniker=moniker,
        )
    except Exception:
        report = _report(
            status="failed",
            reason="unexpected_wrapper_failure",
            hashes=artifact_hashes,
            host_trust=host_trust,
            input_binding=input_binding,
            moniker=moniker,
        )
    finally:
        if endpoint_lease is not None:
            try:
                endpoint_lease.close()
            except WslEndpointFailure:
                pass
            try:
                endpoint_receipt = endpoint_lease.receipt
            except WslEndpointFailure:
                endpoint_receipt = None
        if profile_lease is not None:
            try:
                profile_lease.close()
            except ProfileLeaseFailure:
                profile_cleanup_failed = True
            try:
                profile_receipt = profile_lease.receipt
            except ProfileLeaseFailure:
                profile_receipt = None
                profile_cleanup_failed = True
        if profile_receipt is not None and profile_receipt.get("owned") is True:
            profile_cleanup_failed = profile_cleanup_failed or (
                profile_receipt.get("closed") is not True
                or profile_receipt.get("cleanup_complete") is not True
            )
        if temporary_directory is not None:
            try:
                temporary_directory.cleanup()
                cleanup_state = "verified" if temporary_path is not None and not temporary_path.exists() else "failed"
            except OSError:
                cleanup_state = "failed"

    try:
        expected_context_witness_digests = _public_context_witness_digests(
            boundary_expected=boundary_expected,
            endpoint_receipt=endpoint_receipt,
            host_trust=host_trust,
            input_binding=input_binding,
            moniker=moniker,
            profile_receipt=profile_receipt,
        )
    except (TypeError, ValueError, RecursionError, OverflowError):
        expected_context_witness_digests = None
    report["boundary_expected"] = boundary_expected
    report["boundary_summary"] = boundary_summary
    report["endpoint_receipt"] = endpoint_receipt
    report["profile_receipt"] = profile_receipt
    report["temporary_directory_cleanup"] = cleanup_state
    report["temporary_code_artifact_observation"] = temporary_code_artifact_observation
    report["temporary_code_artifacts"] = temporary_code_artifact_state
    if profile_cleanup_failed:
        report["status"] = "failed"
        report["reason"] = "appcontainer_profile_cleanup_failed"
        report["cleanup_override_reason"] = "appcontainer_profile_cleanup_failed"
        report["boundary_summary"] = None
        report["driver_binding"] = None
        report["helper_report"] = None
        report["artifacts"] = _without_driver_evidence_hashes(
            report["artifacts"]  # type: ignore[arg-type]
        )
    elif cleanup_state == "failed":
        report["status"] = "failed"
        report["reason"] = "temporary_directory_cleanup_failed"
        report["cleanup_override_reason"] = "temporary_directory_cleanup_failed"
        report["boundary_summary"] = None
        report["driver_binding"] = None
        report["helper_report"] = None
        report["artifacts"] = _without_driver_evidence_hashes(
            report["artifacts"]  # type: ignore[arg-type]
        )
    public_artifacts = report["artifacts"]
    expected_public_artifacts = (
        dict(public_artifacts) if type(public_artifacts) is dict else None
    )
    try:
        _validate_final_helper_failure_receipt_relation(
            report,
            boundary_path_context=boundary_path_context,
            expected_artifacts=artifact_hashes,
            expected_public_artifacts=expected_public_artifacts,
            expected_context_witness_digests=expected_context_witness_digests,
            expected_witness_digests=expected_mode_b_witness_digests,
        )
    except HelperProtocolFailure:
        report = closed_final_failure_report("helper_failure_receipt_invalid")
    try:
        _assert_public_value_privacy(
            report,
            known_private_values=tuple(sorted(private_public_rejection_values)),
        )
    except PublicPrivacyFailure:
        report = closed_final_failure_report("public_report_privacy_invalid")
    return report, 0 if report["status"] == "observed_pass" else 1


def run_spike(
    *,
    temp_root: Path | None = None,
    timeout_seconds: int = 180,
) -> tuple[dict[str, object], int]:
    """Run the evidence-mode diagnostic without any host or runner override."""

    return _run_spike(
        temp_root=temp_root,
        timeout_seconds=timeout_seconds,
        platform_name=os.name,
    )


def _parser() -> argparse.ArgumentParser:
    parser = ClosedArgumentParser(description=__doc__)
    parser.add_argument("--temp-root", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    return parser


def _emit(report: dict[str, object]) -> None:
    os.write(1, _canonical_json(report) + b"\n")


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        report, return_code = run_spike(
            temp_root=arguments.temp_root,
            timeout_seconds=arguments.timeout_seconds,
        )
    except UsageFailure as exc:
        report = _report(status="failed", reason=str(exc))
        return_code = 2
    except Exception:
        report = _report(status="failed", reason="unexpected_wrapper_failure")
        return_code = 1
    _emit(report)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
