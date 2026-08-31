from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import run_windows_appcontainer_spike as spike

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROGRAM_SOURCE = REPOSITORY_ROOT / "scripts" / "windows_appcontainer_helper" / "Program.cs"
WRAPPER_SOURCE = REPOSITORY_ROOT / "scripts" / "run_windows_appcontainer_spike.py"
PROFILE_SOURCE = REPOSITORY_ROOT / "scripts" / "windows_appcontainer_profile.py"
LEGACY_PROFILE_AUTHORITY = (
    "CreateAppContainerProfile",
    "DeleteAppContainerProfile",
    "DeriveAppContainerSidFromAppContainerName",
    "FreeSid",
)

NETWORK_FAILURE_SUBSTAGES = tuple(
    spike.HELPER_FAILURE_NETWORK_DIFFERENTIAL_SUBSTAGE_SEQUENCE
)


def _replace_occurrence(
    value: str,
    old: str,
    new: str,
    occurrence: int,
) -> str:
    starts = [match.start() for match in re.finditer(re.escape(old), value)]
    if occurrence < 1 or occurrence > len(starts):
        raise AssertionError(f"replacement occurrence missing: {old!r} #{occurrence}")
    start = starts[occurrence - 1]
    return value[:start] + new + value[start + len(old) :]


def _typed_network_failure_substage_contract(source: str) -> bool:
    roster_match = re.search(
        r"private static readonly string\[\] NetworkFailureSubstages =\s*"
        r"\{(?P<body>.*?)^    \};",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if roster_match is None:
        return False
    producer_roster = tuple(
        re.findall(r'^\s*"([a-z0-9_]+)",\s*$', roster_match.group("body"), re.MULTILINE)
    )
    if (
        len(producer_roster) != 98
        or len(set(producer_roster)) != 98
        or producer_roster != NETWORK_FAILURE_SUBSTAGES
    ):
        return False

    if (
        'private const string HelperFormat = '
        '"finplanbr.windows-appcontainer-boundary-helper.v17";' not in source
        or '"finplanbr.windows-appcontainer-helper-failure-receipt.v6";' not in source
        or '["format"] = '
        '"finplanbr.windows-appcontainer-boundary-observations.v9",' not in source
        or source.count('["regular_launch_policy_bound"] = true,') != 1
        or source.count('["same_primary_token_source_bound"] = true,') != 1
        or '["regular_launch_policy_bound"] =\n'
        '                        rootTokenObservation.RegularLaunchPolicyBound,' not in source
        or '["same_primary_token_source_bound"] =\n'
        '                        rootTokenObservation.SamePrimaryTokenSourceBound,' not in source
        or '"regular_appcontainer_effect_observed_from_same_primary_token_source"'
        not in source
        or '["less_privileged_appcontainer_query_result"] =' not in source
        or '["less_privileged_appcontainer_query_supported"] =' not in source
        or '["is_lpac"]' in source
        or '["lpac_query_supported"]' in source
        or '["same_token_handle_bound"]' in source
        or '"regular_appcontainer_effect_observed_for_same_token"' in source
        or "bool aapPositiveReadSha256Matches = true;" in source
    ):
        return False
    upper_source = source.upper()
    if (
        "ALL_APPLICATION_PACKAGES_POLICY" in upper_source
        or "OPT_OUT" in upper_source
        or re.search(r"0x0*2000F\b", source, re.IGNORECASE) is not None
        or re.search(r"\b131087\b", source) is not None
    ):
        return False
    launch_attribute_literals = set(
        re.findall(r"0x000200[0-9A-Fa-f]{2}\b", source)
    )
    if launch_attribute_literals != {"0x00020002", "0x00020009", "0x0002000D"}:
        return False

    required_structure = (
        "private enum NetworkArmStep",
        "private enum NetworkTokenStep",
        "private sealed class NetworkArmPlan",
        "private sealed class NetworkTokenObservationContext",
        "private sealed class NetworkArmCursor",
        "private sealed class NetworkArmObservation",
        "private sealed class PreflightNetworkDifferentialResult",
        "private sealed class FullNetworkDifferentialResult",
        "internal sealed class BoundClassicTokenObservation",
        "internal sealed class ValidatedClassicTokenObservation",
        "internal void SetNetworkArmSubstage(NetworkArmPlan plan, NetworkArmStep step)",
        "SetSubstage(plan.Substage(step));",
        "internal NetworkTokenObservationContext BeginNetworkTokenObservation(",
        "SetSubstage(plan.TokenSubstage(NetworkTokenStep.LaunchPolicy));",
        "return NetworkTokenObservationContext.Issue(this, plan);",
        "internal void SetNetworkTokenSubstage(",
        "SetSubstage(plan.TokenSubstage(step));",
        "internal string Substage(NetworkArmStep step) => step switch",
        "NetworkArmStep.Prepare => SubstagePrefix,",
        'NetworkArmStep.Launch => SubstagePrefix + "_launch",',
        'NetworkArmStep.Process => SubstagePrefix + "_process",',
        'NetworkArmStep.Report => SubstagePrefix + "_report",',
        'NetworkArmStep.Exit => SubstagePrefix + "_exit",',
        'NetworkArmStep.Result => SubstagePrefix + "_result",',
        "internal string TokenSubstage(NetworkTokenStep step) => step switch",
        'NetworkTokenStep.LaunchPolicy => SubstagePrefix + "_token_launch_policy",',
        'NetworkTokenStep.ReadBase => SubstagePrefix + "_token_read_base",',
        'NetworkTokenStep.AapMembership => SubstagePrefix + "_token_aap_membership",',
        'NetworkTokenStep.AapRosters => SubstagePrefix + "_token_aap_rosters",',
        'NetworkTokenStep.Lpac => SubstagePrefix + "_token_lpac",',
        'NetworkTokenStep.Identity => SubstagePrefix + "_token_identity",',
        'NetworkTokenStep.AapEffect => SubstagePrefix + "_token_aap_effect",',
        'NetworkTokenStep.ValidateLpac => SubstagePrefix + "_token_validate_lpac",',
        'NetworkTokenStep.ValidateRoster => SubstagePrefix + "_token_validate_roster",',
        'NetworkTokenStep.Bind => SubstagePrefix + "_token_bind",',
        "private NetworkTokenObservationContext(",
        "internal static NetworkTokenObservationContext Issue(",
        "private NetworkTokenStep? _next = NetworkTokenStep.ReadBase;",
        "internal void RequirePlan(NetworkArmPlan plan)",
        "if (!ReferenceEquals(_plan, plan))",
        'throw new InvalidOperationException("network_token_plan_mismatch");',
        "internal void Enter(NetworkTokenStep step)",
        'throw new InvalidOperationException("network_token_step_order_invalid");',
        "NetworkTokenStep.ReadBase => NetworkTokenStep.AapMembership,",
        "NetworkTokenStep.AapMembership => NetworkTokenStep.AapRosters,",
        "NetworkTokenStep.AapRosters => NetworkTokenStep.Lpac,",
        "NetworkTokenStep.Lpac => NetworkTokenStep.Identity,",
        "NetworkTokenStep.Identity => NetworkTokenStep.AapEffect,",
        "NetworkTokenStep.AapEffect => NetworkTokenStep.ValidateLpac,",
        "NetworkTokenStep.ValidateLpac => NetworkTokenStep.ValidateRoster,",
        "NetworkTokenStep.ValidateRoster => NetworkTokenStep.Bind,",
        "NetworkTokenStep.Bind => null,",
        "internal void RequireComplete()",
        'throw new InvalidOperationException("network_token_observation_incomplete");',
        "internal bool Matches(",
        "List<NetworkArmObservation> observations",
        "NetworkArmObservation.Issue(plan, arm)",
        'throw new InvalidOperationException("network_arm_observation_binding_invalid");',
        "(NetworkDifferentialPhase.Preflight, 0) => NetworkArmPlan.PreflightZero(),",
        "(NetworkDifferentialPhase.Full, 0) => NetworkArmPlan.FullZeroOne(),",
        "(NetworkDifferentialPhase.Full, 1) => NetworkArmPlan.FullInternetClientOne(),",
        "(NetworkDifferentialPhase.Full, 2) => NetworkArmPlan.FullInternetClientTwo(),",
        "(NetworkDifferentialPhase.Full, 3) => NetworkArmPlan.FullZeroTwo(),",
        "PreflightNetworkDifferentialResult preflight = RunNetworkPreflight(",
        "FullNetworkDifferentialResult fullNetwork = RunFullNetworkDifferential(",
        "SortedDictionary<string, object?> preflightZeroCapability = preflight.OnlyArm;",
        "List<SortedDictionary<string, object?>> lanAppContainerArms = fullNetwork.Arms;",
        "private static PreflightNetworkDifferentialResult RunNetworkPreflight(",
        "private static FullNetworkDifferentialResult RunFullNetworkDifferential(",
        "NetworkArmCursor cursor = new(phase);",
        "while (cursor.TryTakeNext(out NetworkArmPlan? plan))",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Prepare);",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Launch);",
        "failureTracker.BeginNetworkTokenObservation(plan);",
        "boundIdentity.ObserveNetworkArmToken(",
        "            launchAuthorization.RequireRegularPolicyForProcess(process);\n"
        "            context.Enter(NetworkTokenStep.ReadBase);\n"
        "            (TokenFacts facts, string aapSha256, uint noAapError) =\n"
        "                _networkTokenReader(",
        "_networkTokenReader(",
        "                    context,\n"
        "                    aapProbePath,\n"
        "                    noAapProbePath",
        "ReadNetworkTokenFactsAndObserveClassicBehavior",
        "            context.Enter(NetworkTokenStep.AapEffect);\n"
        "            (string aapSha256, uint noAapError) = "
        "ObserveClassicBehaviorWithToken(",
        "            bool aapPositiveReadSha256Matches = string.Equals(\n"
        "                aapSha256,\n"
        "                expectedAapSha256,\n"
        "                StringComparison.Ordinal\n"
        "            );",
        "bool aapNegativeAccessDenied = noAapError == ErrorAccessDenied;",
        'Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label, context);',
        "context.Enter(NetworkTokenStep.Bind);",
        "context.RequireComplete();",
        "ReadTokenFactsFromToken(token, context);",
        "context.Enter(NetworkTokenStep.AapEffect);",
        "context?.Enter(NetworkTokenStep.AapMembership);",
        "context?.Enter(NetworkTokenStep.AapRosters);",
        "context?.Enter(NetworkTokenStep.Lpac);",
        "            catch (InteropWin32Exception error) when "
        "(error.NativeErrorCode == 87)\n"
        "            {\n"
        "                (lpac, lpacQuerySupported) = "
        "UnsupportedLpacQueryDiagnostic();\n"
        "            }",
        "private static (bool? Result, bool Supported) "
        "UnsupportedLpacQueryDiagnostic()\n"
        "        => (null, false);",
        "context?.Enter(NetworkTokenStep.Identity);",
        "context?.Enter(NetworkTokenStep.ValidateLpac);",
        "context?.Enter(NetworkTokenStep.ValidateRoster);",
        "                    lpacQuerySupported,\n"
        "                    true,\n"
        "                    null,\n"
        "                    hasAllApplicationPackages",
        'throw new InvalidOperationException(view + "_aap_membership_state_invalid");',
        "                    ReadTokenFacts,\n"
        "                    ReadNetworkTokenFactsAndObserveClassicBehavior,\n"
        "                    ReadTokenFactsAndObserveClassicBehavior",
        "                _tokenReader(process),\n"
        "                process,\n"
        '                "child",',
        "                _tokenReader(process),\n"
        "                process,\n"
        '                "grandchild",',
        "            BoundClassicTokenObservation observation = _classicTokenReader(\n"
        "                    _proofIssuer,\n"
        "                    this,\n"
        "                    process,",
        "            return observation.ValidateForRoot(\n"
        "                _proofIssuer,\n"
        "                process,\n"
        "                launchAuthorization\n"
        "            );",
        "            return new BoundAppContainerIdentity.BoundClassicTokenObservation(\n"
        "                issuer,\n"
        "                owner,\n"
        "                processHandle,\n"
        "                facts,\n"
        "                aapSha256,\n"
        "                noAapError\n"
        "            );",
        "        catch (NotObservedException)\n"
        "        {\n"
        "            return EmitBoundaryFailure(\n"
        '                "not_observed",\n'
        "                failureTracker.Stage,\n"
        "                failureTracker.Substage,\n"
        '                "not_observed"\n'
        "            );\n"
        "        }",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Process);",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Report);",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Exit);",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Result);",
    )
    if any(item not in source for item in required_structure):
        return False
    forbidden_structure = (
        "string PrepareSubstage",
        "string LaunchSubstage",
        "string ProcessSubstage",
        "string ReportSubstage",
        "string ExitSubstage",
        "string ResultSubstage",
        "for (int index = 0; index < sequence.Length; index++)",
        "_aap_membership_query_unavailable",
    )
    if any(item in source for item in forbidden_structure):
        return False

    plan_factories = (
        (
            "PreflightZero",
            "NetworkDifferentialPhase.Preflight",
            "preflight_zero",
            "false",
            "0",
            "network_preflight_zero",
        ),
        (
            "FullZeroOne",
            "NetworkDifferentialPhase.Full",
            "zero_1",
            "false",
            "1",
            "network_arm_zero_1",
        ),
        (
            "FullInternetClientOne",
            "NetworkDifferentialPhase.Full",
            "internet_client_1",
            "true",
            "2",
            "network_arm_internet_client_1",
        ),
        (
            "FullInternetClientTwo",
            "NetworkDifferentialPhase.Full",
            "internet_client_2",
            "true",
            "3",
            "network_arm_internet_client_2",
        ),
        (
            "FullZeroTwo",
            "NetworkDifferentialPhase.Full",
            "zero_2",
            "false",
            "4",
            "network_arm_zero_2",
        ),
    )
    for method, phase, label, capability, order, prefix in plan_factories:
        factory = (
            f"internal static NetworkArmPlan {method}() => new(\n"
            f"            {phase},\n"
            f'            "{label}",\n'
            f"            {capability},\n"
            f"            {order},\n"
            f'            "{prefix}"\n'
            "        );"
        )
        if factory not in source:
            return False

    result_bindings = (
        (0, "NetworkDifferentialPhase.Preflight", "preflight_zero", "false", 0,
         "network_preflight_zero"),
        (0, "NetworkDifferentialPhase.Full", "zero_1", "false", 1,
         "network_arm_zero_1"),
        (1, "NetworkDifferentialPhase.Full", "internet_client_1", "true", 2,
         "network_arm_internet_client_1"),
        (2, "NetworkDifferentialPhase.Full", "internet_client_2", "true", 3,
         "network_arm_internet_client_2"),
        (3, "NetworkDifferentialPhase.Full", "zero_2", "false", 4,
         "network_arm_zero_2"),
    )
    for index, phase, label, capability, order, prefix in result_bindings:
        binding = (
            f"observations[{index}].Plan.Matches(\n"
            f"                    {phase},\n"
            f'                    "{label}",\n'
            f"                    {capability},\n"
            f"                    {order},\n"
            f'                    "{prefix}"\n'
            "                )"
        )
        if binding not in source:
            return False

    immediate_anchors = (
        '        failureTracker.SetStage("network_differential");\n'
        '        failureTracker.SetSubstage("network_endpoint_bind");\n'
        "        NetworkEndpoint networkEndpoint = ParseNetworkEndpoint(",
        '            failureTracker.SetStage("network_differential");\n'
        '            failureTracker.SetSubstage("network_preflight_prepare");\n'
        "            PreflightNetworkDifferentialResult preflight = RunNetworkPreflight(",
        '            failureTracker.SetSubstage("network_control_before");\n'
        "            SortedDictionary<string, object?> lanControlBefore = "
        "ObserveExternalEchoControl(",
        '            failureTracker.SetSubstage("network_full_snapshot");\n'
        "            LoopbackSnapshot exemptionDuring = ReadLoopbackSnapshot(",
        '            failureTracker.SetSubstage("network_full_firewall_snapshot");\n'
        "            int firewallDuring = CountFirewallObjects(moniker);",
        '            failureTracker.SetSubstage("network_full_listener_snapshot");\n'
        "            bool sawLoopback = loopbackListener.Pending();",
        '            failureTracker.SetSubstage("network_full_prepare");\n'
        "            FullNetworkDifferentialResult fullNetwork = RunFullNetworkDifferential(",
        '            failureTracker.SetSubstage("network_control_after");\n'
        "            SortedDictionary<string, object?> lanControlAfter = "
        "ObserveExternalEchoControl(",
        "        failureTracker.SetSubstage(\n"
        "            phase == NetworkDifferentialPhase.Preflight\n"
        '                ? "network_preflight_profile_before"\n'
        '                : "network_full_profile_before"\n'
        "        );\n"
        "        BoundAppContainerIdentity.ValidatedProfileIdentity "
        "validatedProfileIdentity =\n"
        "            boundIdentity.ObserveNetworkProfileFolderBefore(profileFolder);",
        "            failureTracker.SetSubstage(\n"
        "                phase == NetworkDifferentialPhase.Preflight\n"
        '                    ? "network_preflight_capability_import"\n'
        '                    : "network_full_capability_import"\n'
        "            );\n"
        "            if (!ConvertStringSidToSidW(",
        "            failureTracker.SetSubstage(\n"
        "                phase == NetworkDifferentialPhase.Preflight\n"
        '                    ? "network_preflight_request_setup"\n'
        '                    : "network_full_request_setup"\n'
        "            );\n"
        "            using FileStream requestStream = new(",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Prepare);\n"
        "                byte[] nonce = Encoding.ASCII.GetBytes(",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Launch);\n"
        "                    if (!boundSecurityCapabilities.CreateSuspendedProcess(",
        "NetworkTokenObservationContext tokenContext =\n"
        "                        failureTracker.BeginNetworkTokenObservation(plan);\n"
        "                    BoundAppContainerIdentity.ValidatedTokenFacts token =\n"
        "                        boundIdentity.ObserveNetworkArmToken(\n"
        "                            process.Process,\n"
        "                            plan,\n"
        "                            tokenContext,\n"
        "                            boundSecurityCapabilities,\n"
        "                            aapProbePath,\n"
        "                            noAapProbePath,\n"
        "                            expectedAapSha256\n"
        "                        );",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Process);\n"
        "                    bool jobMember = IsMember(process.Process, job);",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Report);\n"
        "                    JsonElement report = WaitForChildReport(",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Exit);\n"
        "                    if (WaitForSingleObject(",
        "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Result);\n"
        '                    JsonElement attempt = RequireProperty(report, "network");',
        '                        failureTracker.SetSubstage("network_preflight_zero_expectation");\n'
        '                        bool preflightConnected = ReadReportBool(attempt, "connected");',
        "                        failureTracker.SetNetworkArmSubstage(plan, "
        "NetworkArmStep.Result);\n"
        "                    }\n"
        "                    (uint reportedPid, uint reportedParentPid) =",
        "            failureTracker.SetSubstage(\n"
        "                phase == NetworkDifferentialPhase.Preflight\n"
        '                    ? "network_preflight_profile_after"\n'
        '                    : "network_full_profile_after"\n'
        "            );\n"
        "            BoundAppContainerIdentity.ValidatedProfileIdentity "
        "finalNetworkProfileIdentity =\n"
        "                boundIdentity.ObserveNetworkProfileFolderAfter(",
    )
    if any(anchor not in source for anchor in immediate_anchors):
        return False

    wrappers = (
        "    ) => new(RunNetworkDifferential(\n"
        "        pythonImage,\n"
        "        probePath,\n"
        "        profileFolder,\n"
        "        boundIdentity,\n"
        "        job,\n"
        "        lanAddress,\n"
        "        baseRequest,\n"
        "        failureTracker,\n"
        "        NetworkDifferentialPhase.Preflight,\n"
        "        aapProbePath,\n"
        "        noAapProbePath,\n"
        "        expectedAapSha256\n"
        "    ));",
        "    ) => new(RunNetworkDifferential(\n"
        "        pythonImage,\n"
        "        probePath,\n"
        "        profileFolder,\n"
        "        boundIdentity,\n"
        "        job,\n"
        "        lanAddress,\n"
        "        baseRequest,\n"
        "        failureTracker,\n"
        "        NetworkDifferentialPhase.Full,\n"
        "        aapProbePath,\n"
        "        noAapProbePath,\n"
        "        expectedAapSha256\n"
        "    ));",
    )
    if any(wrapper not in source for wrapper in wrappers):
        return False

    enum_expectations = {
        "NetworkArmStep": (
            "Prepare",
            "Launch",
            "Process",
            "Report",
            "Exit",
            "Result",
        ),
        "NetworkTokenStep": (
            "LaunchPolicy",
            "ReadBase",
            "AapMembership",
            "AapRosters",
            "Lpac",
            "Identity",
            "AapEffect",
            "ValidateLpac",
            "ValidateRoster",
            "Bind",
        ),
    }
    for enum_name, expected_members in enum_expectations.items():
        enum_match = re.search(
            rf"private enum {enum_name}\s*\{{(?P<body>.*?)^    \}}",
            source,
            re.MULTILINE | re.DOTALL,
        )
        if enum_match is None:
            return False
        actual_members = tuple(
            re.findall(
                r"^\s*([A-Za-z][A-Za-z0-9]*),\s*$",
                enum_match.group("body"),
                re.MULTILINE,
            )
        )
        if actual_members != expected_members:
            return False

    exact_flow_counts = {
        "failureTracker.BeginNetworkTokenObservation(plan);": 1,
        "context.RequirePlan(plan);": 1,
        "launchAuthorization.RequireRegularPolicyForProcess(process);": 2,
        "context.Enter(NetworkTokenStep.ReadBase);": 1,
        "_networkTokenReader(": 1,
        'Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label, context);': 1,
        "context.Enter(NetworkTokenStep.Bind);": 1,
        "context.RequireComplete();": 1,
        "ReadTokenFactsFromToken(token, context);": 1,
        "context.Enter(NetworkTokenStep.AapEffect);": 1,
        "context?.Enter(NetworkTokenStep.AapMembership);": 1,
        "context?.Enter(NetworkTokenStep.AapRosters);": 1,
        "context?.Enter(NetworkTokenStep.Lpac);": 1,
        "context?.Enter(NetworkTokenStep.Identity);": 1,
        "context?.Enter(NetworkTokenStep.ValidateLpac);": 1,
        "context?.Enter(NetworkTokenStep.ValidateRoster);": 1,
    }
    if any(source.count(text) != count for text, count in exact_flow_counts.items()):
        return False

    reader_flow = tuple(
        source.find(f"context?.Enter(NetworkTokenStep.{step});")
        for step in ("AapMembership", "AapRosters", "Lpac", "Identity")
    )
    validator_flow = tuple(
        source.find(f"context?.Enter(NetworkTokenStep.{step});")
        for step in ("ValidateLpac", "ValidateRoster")
    )
    if any(position < 0 for position in reader_flow + validator_flow):
        return False
    if reader_flow != tuple(sorted(reader_flow)) or validator_flow != tuple(
        sorted(validator_flow)
    ):
        return False

    operation_anchors = (
        (
            "context.Enter(NetworkTokenStep.ReadBase);",
            "_networkTokenReader(",
        ),
        (
            "context?.Enter(NetworkTokenStep.AapMembership);",
            'CheckAppContainerMembership(token, "S-1-15-2-1");',
        ),
        (
            "context?.Enter(NetworkTokenStep.Identity);",
            "ReadTokenInformation(token, TokenAppContainerSid);",
        ),
        (
            "context.Enter(NetworkTokenStep.AapEffect);",
            "ObserveClassicBehaviorWithToken(",
        ),
        (
            "context?.Enter(NetworkTokenStep.ValidateLpac);",
            "if (facts.IsLessPrivilegedAppContainer is true)",
        ),
        (
            "context?.Enter(NetworkTokenStep.ValidateLpac);",
            "if (facts.LpacQuerySupported != (facts.IsLessPrivilegedAppContainer is not null))",
        ),
        (
            "context?.Enter(NetworkTokenStep.ValidateRoster);",
            "if (facts.AllApplicationPackagesTokenGroupMatchCount",
        ),
    )
    for marker, operation in operation_anchors:
        marker_position = source.find(marker)
        operation_position = source.find(operation, marker_position)
        if marker_position < 0 or operation_position <= marker_position:
            return False

    observe_match = re.search(
        r"internal ValidatedTokenFacts ObserveNetworkArmToken\(.*?^        \}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if observe_match is None:
        return False
    observe_body = observe_match.group(0)
    observe_flow = (
        "context.RequirePlan(plan);",
        "launchAuthorization.RequireRegularPolicyForProcess(process);",
        "context.Enter(NetworkTokenStep.ReadBase);",
        "_networkTokenReader(",
        'Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label, context);',
        "context.Enter(NetworkTokenStep.Bind);",
        "context.RequireComplete();",
    )
    positions = tuple(observe_body.find(item) for item in observe_flow)
    if any(position < 0 for position in positions) or positions != tuple(sorted(positions)):
        return False
    return True


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"function roster invalid: {name}")
    return matches[0]


def _method(class_node: ast.ClassDef, name: str) -> ast.FunctionDef:
    matches = [
        node
        for node in class_node.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"method roster invalid: {name}")
    return matches[0]


def _class(tree: ast.Module, name: str) -> ast.ClassDef:
    matches = [
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"class roster invalid: {name}")
    return matches[0]


def _python_owned_binding_contract(wrapper_source: str, profile_source: str) -> bool:
    try:
        wrapper = ast.parse(wrapper_source)
        profile = ast.parse(profile_source)
        boundary_expected = _function(wrapper, "_boundary_expected")
        invoke_helper = _function(wrapper, "_invoke_helper")
        run_spike = _function(wrapper, "_run_spike")
        binding_class = _class(profile, "OwnedProfileBinding")
        lease_class = _class(profile, "AppContainerProfileLease")
        issue = _method(binding_class, "_issue")
        current_wire = _method(binding_class, "current_wire")
        start = _method(lease_class, "start")
    except (AssertionError, SyntaxError):
        return False

    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "object"
        and node.func.attr == "__setattr__"
        and bool(node.args)
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "profile_binding"
        for node in ast.walk(wrapper)
    ):
        return False

    if (
        "_derive_appcontainer_sid" in wrapper_source
        or "DeriveAppContainerSidFromAppContainerName" in wrapper_source
        or "profile_lease.prelaunch_observation" in wrapper_source
        or 'profile_prelaunch["appcontainer_sid"]' in wrapper_source
        or "object.__setattr__(profile_binding" in wrapper_source
    ):
        return False
    if "@dataclass(frozen=True, slots=True, init=False)" not in profile_source:
        return False
    if "@final\n@dataclass(frozen=True, slots=True, init=False)" not in profile_source:
        return False
    if "def __init_subclass__" not in profile_source:
        return False

    expected_args = [argument.arg for argument in boundary_expected.args.args]
    invoke_args = [argument.arg for argument in invoke_helper.args.kwonlyargs]
    if "profile_binding" not in expected_args + [
        argument.arg for argument in boundary_expected.args.kwonlyargs
    ]:
        return False
    if "profile_binding" not in invoke_args:
        return False
    if any(
        isinstance(node, (ast.Subscript, ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete))
        and (
            isinstance(getattr(node, "value", None), ast.Name)
            and node.value.id == "profile_binding"
        )
        for function in (boundary_expected, invoke_helper)
        for node in ast.walk(function)
    ):
        return False

    exact_type_guards = 0
    current_wire_calls = 0
    for function in (boundary_expected, invoke_helper, run_spike):
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Compare)
                and isinstance(node.left, ast.Call)
                and isinstance(node.left.func, ast.Name)
                and node.left.func.id == "type"
                and len(node.left.args) == 1
                and isinstance(node.left.args[0], ast.Name)
                and node.left.args[0].id == "profile_binding"
                and any(
                    isinstance(comparator, ast.Name)
                    and comparator.id == "OwnedProfileBinding"
                    for comparator in node.comparators
                )
            ):
                exact_type_guards += 1
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "profile_binding"
                and node.func.attr == "current_wire"
            ):
                current_wire_calls += 1
    if exact_type_guards < 3 or current_wire_calls < 3:
        return False

    boundary_sid_values: list[ast.expr] = []
    for node in ast.walk(boundary_expected):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values, strict=True):
            if isinstance(key, ast.Constant) and key.value == "appcontainer_sid":
                boundary_sid_values.append(value)
    if len(boundary_sid_values) != 1:
        return False
    boundary_sid = boundary_sid_values[0]
    if not (
        isinstance(boundary_sid, ast.Attribute)
        and isinstance(boundary_sid.value, ast.Name)
        and boundary_sid.value.id == "profile_binding"
        and boundary_sid.attr == "appcontainer_sid"
    ):
        return False

    if not any(
        isinstance(node, ast.Compare)
        and any(isinstance(op, ast.IsNot) for op in node.ops)
        and isinstance(node.left, ast.Name)
        and node.left.id == "issuer"
        for node in ast.walk(issue)
    ):
        return False
    required_snapshot_compares = {
        ("current_bytes", "_canonical_bytes"),
        ("current_sha256", "_canonical_sha256"),
    }
    observed_snapshot_compares: set[tuple[str, str]] = set()
    for node in ast.walk(current_wire):
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.NotEq)
            and isinstance(node.left, ast.Name)
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Attribute)
            and isinstance(node.comparators[0].value, ast.Name)
            and node.comparators[0].value.id == "self"
        ):
            observed_snapshot_compares.add(
                (node.left.id, node.comparators[0].attr)
            )
    if observed_snapshot_compares != required_snapshot_compares:
        return False
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "object"
        and node.func.attr == "__setattr__"
        for node in ast.walk(current_wire)
    ):
        return False

    start_text = ast.get_source_segment(profile_source, start) or ""
    reconcile = start_text.find("if not sid_reconciled:")
    issue_position = start_text.find("OwnedProfileBinding._issue(")
    if reconcile < 0 or issue_position < 0 or reconcile >= issue_position:
        return False
    if start_text.count("OwnedProfileBinding._issue(") != 1:
        return False
    if profile_source.count("OwnedProfileBinding._issue(") != 1:
        return False
    return True


def _csharp_structural_contract(source: str) -> bool:
    if any(name in source for name in LEGACY_PROFILE_AUTHORITY):
        return False
    required = (
        "private sealed class BoundAppContainerIdentity : IDisposable",
        "internal sealed class ValidatedTokenFacts",
        "internal sealed class BoundClassicTokenObservation",
        "internal sealed class ValidatedClassicTokenObservation",
        "internal sealed class ValidatedProfileIdentity",
        "internal sealed class LaunchAuthorizationProof : IDisposable",
        "internal bool CreateSuspendedProcess(",
        "internal void RequireRegularPolicyForProcess(IntPtr process)",
        "launchAuthorization.RequireRegularPolicyForProcess(process);",
        "ReadNetworkTokenFactsAndObserveClassicBehavior",
        "boundSecurityCapabilities.CreateSuspendedProcess(",
        "rootTokenObservation.BuildRootProcessObservation(",
        "childToken.BuildProcessObservation(",
        "grandchildToken.BuildProcessObservation(",
        "token.ValidateNetworkReport(process.Process, report)",
        "token.NetworkTokenWire(process.Process)",
        '["label"] = token.ArmLabel,',
        '["pid"] = token.ProcessId,',
        "boundIdentity.ObserveNetworkProfileFolderBefore(profileFolder)",
        "boundIdentity.ObserveNetworkProfileFolderAfter(",
        "profileIdentityAfter.FinalWireBinding()",
        '["regular_launch_policy_bound"] =\n'
        "                        rootTokenObservation.RegularLaunchPolicyBound,",
        '["same_primary_token_source_bound"] =\n'
        "                        rootTokenObservation.SamePrimaryTokenSourceBound,",
    )
    if any(item not in source for item in required):
        return False
    forbidden = (
        "BoundSecurityCapabilities",
        "BuildSecurityCapabilities",
        "internal IntPtr Pointer",
        "ApplyToAttributeList",
        "private static SortedDictionary<string, object?> ProcessObservation(",
        "private static SortedDictionary<string, object?> TokenDictionary(",
        "ObserveAndValidateToken(",
        "RequireCurrentProfileFolderIdentity(",
    )
    if any(item in source for item in forbidden):
        return False
    if source.count("boundSecurityCapabilities.CreateSuspendedProcess(") != 2:
        return False
    if source.count("launchAuthorization.RequireRegularPolicyForProcess(process);") != 2:
        return False
    if source.count("new ValidatedTokenFacts(") != 1:
        return False
    if source.count("TokenDictionaryFromFacts(facts)") != 1:
        return False
    if source.count("new LaunchAuthorizationProof(") != 1:
        return False
    if source.count("new BoundAppContainerIdentity.BoundClassicTokenObservation(") != 1:
        return False
    if source.count("new ValidatedClassicTokenObservation(") != 1:
        return False
    if source.count("return observation.ValidateForRoot(") != 1:
        return False
    if source.count("rootTokenObservation.BuildRootProcessObservation(") != 1:
        return False

    root_build = source.find("boundIdentity.BuildRootLaunchAuthorization()")
    root_consume = source.find("boundSecurityCapabilities.CreateSuspendedProcess(")
    root_dispose = source.find("boundSecurityCapabilities.Dispose();", root_consume)
    if not (0 <= root_build < root_consume < root_dispose):
        return False
    if "Dispose();" in source[root_build:root_consume]:
        return False
    network_build = source.find("boundIdentity.BuildNetworkLaunchAuthorization(")
    network_consume = source.find(
        "boundSecurityCapabilities.CreateSuspendedProcess(", root_consume + 1
    )
    network_dispose = source.find("boundSecurityCapabilities?.Dispose();", network_consume)
    if not (0 <= network_build < network_consume < network_dispose):
        return False
    if "Dispose();" in source[network_build:network_consume]:
        return False
    return True


class WindowsAppContainerHelperAuthorityTests(unittest.TestCase):
    def test_source_contains_only_the_boundary_lifecycle(self) -> None:
        source = PROGRAM_SOURCE.read_text(encoding="utf-8")
        wrapper = WRAPPER_SOURCE.read_text(encoding="utf-8")
        profile = PROFILE_SOURCE.read_text(encoding="utf-8")
        self.assertTrue(_csharp_structural_contract(source))
        self.assertTrue(_typed_network_failure_substage_contract(source))
        self.assertTrue(_python_owned_binding_contract(wrapper, profile))
        self.assertNotRegex(source, r"\b(?:Create|Delete)AppContainerProfile\s*\(")
        self.assertNotIn("DeriveAppContainerSidFromAppContainerName", source)
        self.assertNotIn("FreeSid", source)
        self.assertEqual(source.count("private static int RunBoundary("), 1)
        self.assertNotRegex(source, r"private\s+static\s+int\s+Run\s*\(")

    def test_structural_dataflow_mutations_are_killed(self) -> None:
        source = PROGRAM_SOURCE.read_text(encoding="utf-8")
        wrapper = WRAPPER_SOURCE.read_text(encoding="utf-8")
        profile = PROFILE_SOURCE.read_text(encoding="utf-8")
        csharp_mutations = (
            (
                "root_atomic_consumer_bypassed",
                "boundSecurityCapabilities.CreateSuspendedProcess(",
                "CreateProcessW(",
                2,
            ),
            (
                "dispose_before_atomic_consumer",
                "            if (!boundSecurityCapabilities.CreateSuspendedProcess(\n",
                "            boundSecurityCapabilities.Dispose();\n"
                "            if (!boundSecurityCapabilities.CreateSuspendedProcess(\n",
                2,
            ),
            (
                "root_child_proof_swap",
                "rootTokenObservation.BuildRootProcessObservation(",
                "childToken.BuildProcessObservation(",
                1,
            ),
            (
                "root_regular_policy_flag_hardcoded",
                "rootTokenObservation.RegularLaunchPolicyBound,",
                "true,",
                1,
            ),
            (
                "root_primary_source_flag_hardcoded",
                "rootTokenObservation.SamePrimaryTokenSourceBound,",
                "true,",
                1,
            ),
            (
                "network_relabel",
                '["label"] = token.ArmLabel,',
                '["label"] = label,',
                1,
            ),
            (
                "network_pid_relabel",
                '["pid"] = token.ProcessId,',
                '["pid"] = process.ProcessId,',
                1,
            ),
            (
                "network_profile_after_removed",
                "boundIdentity.ObserveNetworkProfileFolderAfter(",
                "boundIdentity.ObserveNetworkProfileFolderBefore(",
                1,
            ),
        )
        for name, old, new, count in csharp_mutations:
            with self.subTest(csharp_mutant=name):
                self.assertEqual(source.count(old), count)
                mutated = source.replace(old, new, 1)
                self.assertFalse(_csharp_structural_contract(mutated))

        wrapper_mutations = (
            (
                "isinstance_binding",
                "type(profile_binding) is not OwnedProfileBinding",
                "not isinstance(profile_binding, OwnedProfileBinding)",
            ),
            (
                "mutable_wire_dict",
                "profile_binding.current_wire()",
                "profile_binding._wire_dict()",
            ),
            (
                "binding_sid_from_public_summary",
                '"appcontainer_sid": profile_binding.appcontainer_sid,',
                '"appcontainer_sid": str(current_bytes),',
            ),
        )
        for name, old, new in wrapper_mutations:
            with self.subTest(wrapper_mutant=name):
                self.assertIn(old, wrapper)
                mutated = wrapper.replace(old, new, 1)
                self.assertFalse(_python_owned_binding_contract(mutated, profile))

        overwrite_mutant = wrapper.replace(
            "                _, profile_prelaunch_sha256 = "
            "profile_binding.current_wire()\n",
            "                object.__setattr__(\n"
            "                    profile_binding,\n"
            "                    'appcontainer_sid',\n"
            "                    'S-1-15-2-201-202-203-204-205-206-207-208',\n"
            "                )\n"
            "                _, profile_prelaunch_sha256 = "
            "profile_binding.current_wire()\n",
            1,
        )
        self.assertNotEqual(overwrite_mutant, wrapper)
        self.assertFalse(_python_owned_binding_contract(overwrite_mutant, profile))

        rebaseline_mutant = profile.replace(
            "        current_sha256 = hashlib.sha256(current_bytes).hexdigest()\n",
            "        current_sha256 = hashlib.sha256(current_bytes).hexdigest()\n"
            "        object.__setattr__(self, '_canonical_bytes', current_bytes)\n"
            "        object.__setattr__(self, '_canonical_sha256', current_sha256)\n",
            1,
        )
        self.assertNotEqual(rebaseline_mutant, profile)
        self.assertFalse(_python_owned_binding_contract(wrapper, rebaseline_mutant))
        tautology_mutant = profile.replace(
            "current_bytes != self._canonical_bytes",
            "current_bytes != current_bytes",
            1,
        )
        self.assertNotEqual(tautology_mutant, profile)
        self.assertFalse(_python_owned_binding_contract(wrapper, tautology_mutant))

        self.assertNotIn('profile_prelaunch["appcontainer_sid"] = derived_sid', wrapper)
        self.assertNotIn("_derive_appcontainer_sid", wrapper)
        before = profile.find("if not sid_reconciled:")
        issue = profile.find("self._owned_binding = OwnedProfileBinding._issue(")
        self.assertGreater(issue, before)
        moved = (
            profile[:before]
            + profile[issue : profile.find("\n            self._started", issue)]
            + "\n"
            + profile[before:issue]
            + profile[profile.find("\n            self._started", issue) :]
        )
        self.assertFalse(_python_owned_binding_contract(wrapper, moved))

        operational_substages = NETWORK_FAILURE_SUBSTAGES
        for index, substage in enumerate(operational_substages):
            with self.subTest(network_roster_missing=substage):
                literal = f'"{substage}"'
                missing = _replace_occurrence(
                    source,
                    literal,
                    '"network_marker_missing"',
                    1,
                )
                self.assertFalse(_typed_network_failure_substage_contract(missing))

            with self.subTest(network_roster_swapped=substage):
                other = operational_substages[(index + 1) % len(operational_substages)]
                temporary = '"network_marker_temporary"'
                swapped = _replace_occurrence(
                    source,
                    f'"{substage}"',
                    temporary,
                    1,
                )
                swapped = _replace_occurrence(
                    swapped,
                    f'"{other}"',
                    f'"{substage}"',
                    1,
                )
                swapped = swapped.replace(temporary, f'"{other}"', 1)
                self.assertFalse(_typed_network_failure_substage_contract(swapped))

        moved_outer = source.replace(
            '            failureTracker.SetSubstage("network_control_before");\n'
            "            SortedDictionary<string, object?> lanControlBefore = "
            "ObserveExternalEchoControl(",
            "            SortedDictionary<string, object?> lanControlBefore = "
            "ObserveExternalEchoControl(\n"
            '                failureTracker.SetSubstage("network_control_before");',
            1,
        )
        self.assertNotEqual(moved_outer, source)
        self.assertFalse(_typed_network_failure_substage_contract(moved_outer))

        moved_arm = source.replace(
            "                failureTracker.SetNetworkArmSubstage(plan, "
            "NetworkArmStep.Prepare);\n"
            "                byte[] nonce = Encoding.ASCII.GetBytes(\n"
            "                    Convert.ToHexString(RandomNumberGenerator.GetBytes(32))"
            ".ToLowerInvariant()\n"
            "                );",
            "                byte[] nonce = Encoding.ASCII.GetBytes(\n"
            "                    Convert.ToHexString(RandomNumberGenerator.GetBytes(32))"
            ".ToLowerInvariant()\n"
            "                );\n"
            "                failureTracker.SetNetworkArmSubstage(plan, "
            "NetworkArmStep.Prepare);",
            1,
        )
        self.assertNotEqual(moved_arm, source)
        self.assertFalse(_typed_network_failure_substage_contract(moved_arm))

        reset_after_marker = source.replace(
            "                failureTracker.SetNetworkArmSubstage(plan, "
            "NetworkArmStep.Prepare);\n",
            "                failureTracker.SetNetworkArmSubstage(plan, "
            "NetworkArmStep.Prepare);\n"
            '                failureTracker.SetStage("network_differential");\n',
            1,
        )
        self.assertNotEqual(reset_after_marker, source)
        self.assertFalse(_typed_network_failure_substage_contract(reset_after_marker))

        phase_swap = source.replace(
            "        NetworkDifferentialPhase.Preflight,\n",
            "        NetworkDifferentialPhase.Full,\n",
            1,
        )
        reverse_cursor = source.replace(
            "                (NetworkDifferentialPhase.Full, 0) => "
            "NetworkArmPlan.FullZeroOne(),\n"
            "                (NetworkDifferentialPhase.Full, 1) => "
            "NetworkArmPlan.FullInternetClientOne(),\n"
            "                (NetworkDifferentialPhase.Full, 2) => "
            "NetworkArmPlan.FullInternetClientTwo(),\n"
            "                (NetworkDifferentialPhase.Full, 3) => "
            "NetworkArmPlan.FullZeroTwo(),",
            "                (NetworkDifferentialPhase.Full, 0) => "
            "NetworkArmPlan.FullZeroTwo(),\n"
            "                (NetworkDifferentialPhase.Full, 1) => "
            "NetworkArmPlan.FullInternetClientTwo(),\n"
            "                (NetworkDifferentialPhase.Full, 2) => "
            "NetworkArmPlan.FullInternetClientOne(),\n"
            "                (NetworkDifferentialPhase.Full, 3) => "
            "NetworkArmPlan.FullZeroOne(),",
            1,
        )

        def swap_arm_steps(first: str, second: str) -> str:
            first_line = (
                "failureTracker.SetNetworkArmSubstage(plan, "
                f"NetworkArmStep.{first});"
            )
            second_line = (
                "failureTracker.SetNetworkArmSubstage(plan, "
                f"NetworkArmStep.{second});"
            )
            temporary = "failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Temporary);"
            self.assertEqual(source.count(first_line), 1)
            self.assertGreaterEqual(source.count(second_line), 1)
            return source.replace(first_line, temporary, 1).replace(
                second_line, first_line
            ).replace(temporary, second_line, 1)

        semantic_mapping_mutations = (
            ("phase_wrapper_swap", phase_swap),
            ("reverse_arm_cursor", reverse_cursor),
            ("launch_process_step_swap", swap_arm_steps("Launch", "Process")),
            ("process_report_step_swap", swap_arm_steps("Process", "Report")),
            ("exit_result_step_swap", swap_arm_steps("Exit", "Result")),
        )
        for name, mutated in semantic_mapping_mutations:
            with self.subTest(network_semantic_mapping_mutant=name):
                self.assertNotEqual(mutated, source)
                self.assertFalse(_typed_network_failure_substage_contract(mutated))

        token_flow_mutations = {
            "begin_launch_policy_setter_removed": source.replace(
                "            SetSubstage(plan.TokenSubstage(NetworkTokenStep.LaunchPolicy));\n",
                "",
                1,
            ),
            "read_base_marker_removed": source.replace(
                "            context.Enter(NetworkTokenStep.ReadBase);\n",
                "",
                1,
            ),
            "imported_network_delegate_ignores_context": source.replace(
                "                    ReadTokenFacts,\n"
                "                    ReadNetworkTokenFactsAndObserveClassicBehavior,\n"
                "                    ReadTokenFactsAndObserveClassicBehavior",
                "                    ReadTokenFacts,\n"
                "                    static (process, _, aap, noAap) =>\n"
                "                        ReadNetworkTokenFactsAndObserveClassicBehavior(\n"
                "                            process, null!, aap, noAap),\n"
                "                    ReadTokenFactsAndObserveClassicBehavior",
                1,
            ),
            "aap_membership_marker_after_operation": source.replace(
                "            context?.Enter(NetworkTokenStep.AapMembership);\n"
                "            bool hasAllApplicationPackages = "
                'CheckAppContainerMembership(token, "S-1-15-2-1");',
                "            bool hasAllApplicationPackages = "
                'CheckAppContainerMembership(token, "S-1-15-2-1");\n'
                "            context?.Enter(NetworkTokenStep.AapMembership);",
                1,
            ),
            "identity_marker_after_first_read": source.replace(
                "            context?.Enter(NetworkTokenStep.Identity);\n"
                "            IntPtr appContainerBuffer = "
                "ReadTokenInformation(token, TokenAppContainerSid);",
                "            IntPtr appContainerBuffer = "
                "ReadTokenInformation(token, TokenAppContainerSid);\n"
                "            context?.Enter(NetworkTokenStep.Identity);",
                1,
            ),
            "aap_effect_marker_after_operation": source.replace(
                "            context.Enter(NetworkTokenStep.AapEffect);\n"
                "            (string aapSha256, uint noAapError) = "
                "ObserveClassicBehaviorWithToken(",
                "            (string aapSha256, uint noAapError) = "
                "ObserveClassicBehaviorWithToken(\n"
                "            context.Enter(NetworkTokenStep.AapEffect);",
                1,
            ),
            "validate_lpac_marker_after_faults": source.replace(
                "        context?.Enter(NetworkTokenStep.ValidateLpac);\n"
                "        if (facts.IsLessPrivilegedAppContainer is true) "
                'throw new InvalidOperationException(view + "_unexpected_lpac");\n'
                "        if (facts.LpacQuerySupported != "
                "(facts.IsLessPrivilegedAppContainer is not null))\n"
                "        {\n"
                '            throw new InvalidOperationException(view + "_lpac_query_state_invalid");\n'
                "        }",
                "        if (facts.IsLessPrivilegedAppContainer is true) "
                'throw new InvalidOperationException(view + "_unexpected_lpac");\n'
                "        if (facts.LpacQuerySupported != "
                "(facts.IsLessPrivilegedAppContainer is not null))\n"
                "        {\n"
                '            throw new InvalidOperationException(view + "_lpac_query_state_invalid");\n'
                "        }\n"
                "        context?.Enter(NetworkTokenStep.ValidateLpac);",
                1,
            ),
            "validate_roster_marker_after_fault": source.replace(
                "        context?.Enter(NetworkTokenStep.ValidateRoster);\n"
                "        if (facts.AllApplicationPackagesTokenGroupMatchCount\n"
                "                + facts.AllApplicationPackagesRestrictedSidMatchCount == 0)\n"
                "        {\n"
                "            throw new NotObservedException("
                'view + "_aap_sid_not_observed_in_token_rosters");\n'
                "        }",
                "        if (facts.AllApplicationPackagesTokenGroupMatchCount\n"
                "                + facts.AllApplicationPackagesRestrictedSidMatchCount == 0)\n"
                "        {\n"
                "            throw new NotObservedException("
                'view + "_aap_sid_not_observed_in_token_rosters");\n'
                "        }\n"
                "        context?.Enter(NetworkTokenStep.ValidateRoster);",
                1,
            ),
            "reader_nulls_context": source.replace(
                "            TokenFacts facts = ReadTokenFactsFromToken(token, context);",
                "            TokenFacts facts = ReadTokenFactsFromToken(token, null);",
                1,
            ),
            "validator_nulls_context": source.replace(
                'Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label, context);',
                'Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label, null);',
                1,
            ),
            "entry_reclassifies_not_observed": source.replace(
                "        catch (NotObservedException)\n"
                "        {\n"
                "            return EmitBoundaryFailure(\n"
                '                "not_observed",\n'
                "                failureTracker.Stage,\n"
                "                failureTracker.Substage,\n"
                '                "not_observed"\n'
                "            );\n"
                "        }",
                "        catch (NotObservedException error)\n"
                "        {\n"
                "            return EmitBoundaryFailure(\n"
                '                "failed",\n'
                "                failureTracker.Stage,\n"
                "                failureTracker.Substage,\n"
                "                Sanitize(error)\n"
                "            );\n"
                "        }",
                1,
            ),
            "child_consumes_network_reader_with_null": source.replace(
                "                _tokenReader(process),\n"
                "                process,\n"
                '                "child",',
                "                _networkTokenReader(process, null!),\n"
                "                process,\n"
                '                "child",',
                1,
            ),
            "token_step_missing": source.replace(
                "            context?.Enter(NetworkTokenStep.AapRosters);\n",
                "",
                1,
            ),
            "token_step_swap": source.replace(
                "            context?.Enter(NetworkTokenStep.AapMembership);\n"
                "            bool hasAllApplicationPackages = ",
                "            context?.Enter(NetworkTokenStep.AapRosters);\n"
                "            bool hasAllApplicationPackages = ",
                1,
            ).replace(
                "            context?.Enter(NetworkTokenStep.AapRosters);\n"
                "            (uint tokenGroupCount,",
                "            context?.Enter(NetworkTokenStep.AapMembership);\n"
                "            (uint tokenGroupCount,",
                1,
            ),
            "token_context_reset": source.replace(
                "                        failureTracker.BeginNetworkTokenObservation(plan);\n",
                "                        failureTracker.BeginNetworkTokenObservation(plan);\n"
                "                    tokenContext =\n"
                "                        failureTracker.BeginNetworkTokenObservation(plan);\n",
                1,
            ),
            "token_reader_context_bypass": source.replace(
                "                _networkTokenReader(\n"
                "                    process,\n"
                "                    context,\n"
                "                    aapProbePath,\n"
                "                    noAapProbePath\n"
                "                );",
                "                (_tokenReader(process), expectedAapSha256, ErrorAccessDenied);",
                1,
            ),
            "token_validator_context_bypass": source.replace(
                'Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label, context);',
                'Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label);',
                1,
            ),
            "token_plan_binding_bypass": source.replace(
                "            context.RequirePlan(plan);\n",
                "",
                1,
            ),
            "token_issue_bypass": source.replace(
                "            return NetworkTokenObservationContext.Issue(this, plan);",
                "            return new NetworkTokenObservationContext(this, plan);",
                1,
            ),
            "launch_policy_bypass": source.replace(
                "            launchAuthorization.RequireRegularPolicyForProcess(process);\n",
                "",
                1,
            ),
            "aap_sha_match_forged": source.replace(
                "            bool aapPositiveReadSha256Matches = string.Equals(\n"
                "                aapSha256,\n"
                "                expectedAapSha256,\n"
                "                StringComparison.Ordinal\n"
                "            );",
                "            bool aapPositiveReadSha256Matches = true;",
                1,
            ),
            "aap_access_denied_forged": source.replace(
                "            bool aapNegativeAccessDenied = "
                "noAapError == ErrorAccessDenied;",
                "            bool aapNegativeAccessDenied = true;",
                1,
            ),
            "lpac_error_class_changed": source.replace(
                "error.NativeErrorCode == 87",
                "error.NativeErrorCode == ErrorAccessDenied",
                1,
            ),
            "lpac_null_promoted_false": source.replace(
                "        => (null, false);",
                "        => (false, false);",
                1,
            ),
            "lpac_unsupported_promoted_supported": source.replace(
                "        => (null, false);",
                "        => (null, true);",
                1,
            ),
            "all_application_packages_policy_injected": source.replace(
                "0x00020009",
                "0x0002000F",
                1,
            ),
        }
        for name, mutated in token_flow_mutations.items():
            with self.subTest(network_token_flow_mutant=name):
                self.assertNotEqual(mutated, source)
                self.assertFalse(_typed_network_failure_substage_contract(mutated))

    @unittest.skipUnless(os.name == "nt", "compiled helper reflection is Windows-only")
    def test_compiled_failure_receipt_v6_tracker_and_privacy(self) -> None:
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("PowerShell 7 compiler is unavailable")
        script = r'''
$ErrorActionPreference = 'Stop'
$sourcePath = [Environment]::GetEnvironmentVariable('FPBR_SOURCE','Process')
$assemblyPath = [Environment]::GetEnvironmentVariable('FPBR_ASSEMBLY','Process')
$compiled = @(Add-Type -Path $sourcePath -OutputAssembly $assemblyPath -OutputType Library -PassThru)
$program = @($compiled | Where-Object FullName -CEQ 'Program')
if ($program.Count -ne 1) { throw 'program_type_invalid' }
$program = $program[0]
$static = [Reflection.BindingFlags] 'Public,NonPublic,Static,DeclaredOnly'
$instance = [Reflection.BindingFlags] 'Public,NonPublic,Instance'
function Get-ILRows {
    param([Reflection.MethodInfo]$Method)
    $opcodeByValue = @{}
    foreach ($field in [Reflection.Emit.OpCodes].GetFields([Reflection.BindingFlags]'Public,Static')) {
        $opcode = $field.GetValue($null)
        $value = [int]$opcode.Value
        if ($value -lt 0) { $value += 65536 }
        $opcodeByValue[$value] = $opcode
    }
    $bytes = $Method.GetMethodBody().GetILAsByteArray()
    $rows = [Collections.Generic.List[object]]::new()
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $first = [int]$bytes[$offset]; $offset += 1
        if ($first -eq 0xFE) {
            $value = 0xFE00 -bor [int]$bytes[$offset]; $offset += 1
        } else { $value = $first }
        $opcode = $opcodeByValue[$value]
        if ($null -eq $opcode) { throw 'unknown_network_il_opcode' }
        $operandOffset = $offset
        switch ([string]$opcode.OperandType) {
            'InlineNone' { $size = 0 }
            'ShortInlineBrTarget' { $size = 1 }
            'ShortInlineI' { $size = 1 }
            'ShortInlineVar' { $size = 1 }
            'InlineVar' { $size = 2 }
            'InlineI8' { $size = 8 }
            'InlineR' { $size = 8 }
            'ShortInlineR' { $size = 4 }
            'InlineSwitch' { $size = 4 + 4 * [BitConverter]::ToInt32($bytes,$offset) }
            default { $size = 4 }
        }
        $integer = $null
        $text = $null
        $text = $null
        if ($opcode.Name -ceq 'ldc.i4.m1') { $integer = -1 }
        elseif ($opcode.Name -match '^ldc\.i4\.([0-8])$') { $integer = [int]$Matches[1] }
        elseif ($opcode.Name -ceq 'ldc.i4.s') { $integer = [int][sbyte]$bytes[$operandOffset] }
        elseif ($opcode.Name -ceq 'ldc.i4') { $integer = [BitConverter]::ToInt32($bytes,$operandOffset) }
        elseif ($opcode.Name -ceq 'ldstr') {
            $token = [BitConverter]::ToInt32($bytes,$operandOffset)
            $text = $Method.Module.ResolveString($token)
        }
        $called = $null
        if ((
            $opcode.Name -ceq 'call' -or
            $opcode.Name -ceq 'callvirt' -or
            $opcode.Name -ceq 'newobj'
        ) -and $size -eq 4) {
            $token = [BitConverter]::ToInt32($bytes,$operandOffset)
            $resolved = $Method.Module.ResolveMethod($token)
            $called = $resolved.DeclaringType.FullName + '::' + $resolved.Name
        }
        $rows.Add([pscustomobject]@{
            Name=$opcode.Name; Integer=$integer; Text=$text; Called=$called
        })
        $offset += $size
    }
    return @($rows)
}
$trackerType = $program.GetNestedType('FailureTracker',[Reflection.BindingFlags]'NonPublic')
$pair = $program.GetMethod('IsFailureStageSubstagePair',$static)
$emit = $program.GetMethod('EmitBoundaryFailure',$static)
$sanitize = $program.GetMethod('Sanitize',$static)
if ($null -eq $trackerType -or $null -eq $pair -or $null -eq $emit -or $null -eq $sanitize) {
    throw 'failure_protocol_reflection_surface_missing'
}
$setStage = $trackerType.GetMethod('SetStage',$instance)
$setSubstage = $trackerType.GetMethod('SetSubstage',$instance)
$stageProperty = $trackerType.GetProperty('Stage',$instance)
$substageProperty = $trackerType.GetProperty('Substage',$instance)
if ($null -eq $setStage -or $null -eq $setSubstage -or $null -eq $stageProperty -or $null -eq $substageProperty) {
    throw 'failure_tracker_surface_missing'
}
$stages = @(
    'entry','profile_binding','profile_storage','runtime_copy_acl','fingerprint_initial',
    'listeners_controls','job_attributes','root_launch','root_report','lineage',
    'network_differential','fingerprint_final_cleanup'
)
$profileSubstages = @(
    'profile_binding_entry','profile_prelaunch_parse','profile_sid_import',
    'profile_sid_validate','profile_sid_roundtrip','profile_folder_query',
    'profile_folder_canonical','profile_localappdata_canonical','profile_ancestry',
    'profile_boundary_compare'
)
$networkRosterField = $program.GetField('NetworkFailureSubstages',$static)
if ($null -eq $networkRosterField) { throw 'network_failure_roster_missing' }
$networkSubstages = @([string[]]$networkRosterField.GetValue($null))
if (
    $networkSubstages.Count -ne 98 -or
    @($networkSubstages | Select-Object -Unique).Count -ne 98
) {
    throw 'network_failure_roster_invalid'
}
$phaseType = $program.GetNestedType('NetworkDifferentialPhase',[Reflection.BindingFlags]'NonPublic')
$stepType = $program.GetNestedType('NetworkArmStep',[Reflection.BindingFlags]'NonPublic')
$tokenStepType = $program.GetNestedType('NetworkTokenStep',[Reflection.BindingFlags]'NonPublic')
$planType = $program.GetNestedType('NetworkArmPlan',[Reflection.BindingFlags]'NonPublic')
$tokenContextType = $program.GetNestedType(
    'NetworkTokenObservationContext',[Reflection.BindingFlags]'NonPublic'
)
$cursorType = $program.GetNestedType('NetworkArmCursor',[Reflection.BindingFlags]'NonPublic')
$observationType = $program.GetNestedType('NetworkArmObservation',[Reflection.BindingFlags]'NonPublic')
$preflightResultType = $program.GetNestedType(
    'PreflightNetworkDifferentialResult',[Reflection.BindingFlags]'NonPublic'
)
$fullResultType = $program.GetNestedType(
    'FullNetworkDifferentialResult',[Reflection.BindingFlags]'NonPublic'
)
if (
    $null -eq $phaseType -or $null -eq $stepType -or $null -eq $tokenStepType -or
    $null -eq $planType -or $null -eq $tokenContextType -or
    $null -eq $cursorType -or $null -eq $observationType -or
    $null -eq $preflightResultType -or $null -eq $fullResultType
) {
    throw 'network_typed_protocol_surface_missing'
}
$expectedTokenStepNames = @(
    'LaunchPolicy','ReadBase','AapMembership','AapRosters','Lpac','Identity',
    'AapEffect','ValidateLpac','ValidateRoster','Bind'
)
if (([Enum]::GetNames($tokenStepType) -join ',') -cne
    ($expectedTokenStepNames -join ',')) {
    throw 'network_token_step_enum_roster_invalid'
}
$planConstructors = @($planType.GetConstructors($instance))
$tokenContextConstructors = @($tokenContextType.GetConstructors($instance))
$observationConstructors = @($observationType.GetConstructors($instance))
if (
    $planConstructors.Count -ne 1 -or $planConstructors[0].IsPrivate -ne $true -or
    -not $tokenContextType.IsSealed -or
    $tokenContextConstructors.Count -ne 1 -or
    $tokenContextConstructors[0].IsPrivate -ne $true -or
    $observationConstructors.Count -ne 1 -or
    $observationConstructors[0].IsPrivate -ne $true
) {
    throw 'network_typed_protocol_constructor_authority_invalid'
}
$cursorConstructor = @($cursorType.GetConstructors($instance))
$takeNext = $cursorType.GetMethod('TryTakeNext',$instance)
$substageForStep = $planType.GetMethod('Substage',$instance)
$tokenSubstageForStep = $planType.GetMethod('TokenSubstage',$instance)
$planPhase = $planType.GetProperty('Phase',$instance)
$planLabel = $planType.GetProperty('Label',$instance)
$planCapability = $planType.GetProperty('InternetClient',$instance)
$planOrder = $planType.GetProperty('Order',$instance)
$issueObservation = $observationType.GetMethod('Issue',$static)
$issueTokenContext = $tokenContextType.GetMethod('Issue',$static)
$requireTokenPlan = $tokenContextType.GetMethod('RequirePlan',$instance)
$enterTokenStep = $tokenContextType.GetMethod('Enter',$instance)
$requireTokenComplete = $tokenContextType.GetMethod('RequireComplete',$instance)
if (
    $cursorConstructor.Count -ne 1 -or $null -eq $takeNext -or
    $null -eq $substageForStep -or $null -eq $planPhase -or
    $null -eq $planLabel -or $null -eq $planCapability -or
    $null -eq $planOrder -or $null -eq $issueObservation -or
    $null -eq $tokenSubstageForStep -or $null -eq $issueTokenContext -or
    $null -eq $requireTokenPlan -or $null -eq $enterTokenStep -or
    $null -eq $requireTokenComplete -or -not $issueTokenContext.IsAssembly
) {
    throw 'network_typed_protocol_reflection_invalid'
}
$stepSuffix = [ordered]@{
    Prepare = ''
    Launch = '_launch'
    Process = '_process'
    Report = '_report'
    Exit = '_exit'
    Result = '_result'
}
$tokenStepSuffix = [ordered]@{
    LaunchPolicy = '_token_launch_policy'
    ReadBase = '_token_read_base'
    AapMembership = '_token_aap_membership'
    AapRosters = '_token_aap_rosters'
    Lpac = '_token_lpac'
    Identity = '_token_identity'
    AapEffect = '_token_aap_effect'
    ValidateLpac = '_token_validate_lpac'
    ValidateRoster = '_token_validate_roster'
    Bind = '_token_bind'
}
$expectedPlans = [ordered]@{
    Preflight = ,@('Preflight','preflight_zero',$false,0,'network_preflight_zero')
    Full = @(
        @('Full','zero_1',$false,1,'network_arm_zero_1'),
        @('Full','internet_client_1',$true,2,'network_arm_internet_client_1'),
        @('Full','internet_client_2',$true,3,'network_arm_internet_client_2'),
        @('Full','zero_2',$false,4,'network_arm_zero_2')
    )
}
$observationsByPhase = @{}
foreach ($phaseName in @('Preflight','Full')) {
    $phase = [Enum]::Parse($phaseType,$phaseName,$false)
    $cursor = $cursorConstructor[0].Invoke([object[]]@($phase))
    $plans = @()
    while ($true) {
        [object[]]$arguments = @($null)
        $taken = [bool]$takeNext.Invoke($cursor,$arguments)
        if (-not $taken) { break }
        $plans += $arguments[0]
    }
    if ($plans.Count -ne $expectedPlans[$phaseName].Count) {
        throw ('network_cursor_count_invalid:' + $phaseName)
    }
    $observations = [Activator]::CreateInstance(
        [Collections.Generic.List``1].MakeGenericType($observationType)
    )
    for ($index = 0; $index -lt $plans.Count; $index++) {
        $plan = $plans[$index]
        $expected = $expectedPlans[$phaseName][$index]
        if (
            $planPhase.GetValue($plan).ToString() -cne $expected[0] -or
            $planLabel.GetValue($plan) -cne $expected[1] -or
            [bool]$planCapability.GetValue($plan) -ne [bool]$expected[2] -or
            [int]$planOrder.GetValue($plan) -ne [int]$expected[3]
        ) {
            throw ('network_plan_binding_invalid:' + $phaseName + ':' + $index)
        }
        foreach ($stepName in $stepSuffix.Keys) {
            $step = [Enum]::Parse($stepType,$stepName,$false)
            $actualSubstage = [string]$substageForStep.Invoke($plan,[object[]]@($step))
            $expectedSubstage = [string]$expected[4] + [string]$stepSuffix[$stepName]
            if ($actualSubstage -cne $expectedSubstage) {
                throw ('network_plan_step_invalid:' + $phaseName + ':' + $index + ':' + $stepName)
            }
        }
        foreach ($stepName in $tokenStepSuffix.Keys) {
            $step = [Enum]::Parse($tokenStepType,$stepName,$false)
            $actualSubstage = [string]$tokenSubstageForStep.Invoke($plan,[object[]]@($step))
            $expectedSubstage = [string]$expected[4] + [string]$tokenStepSuffix[$stepName]
            if ($actualSubstage -cne $expectedSubstage) {
                throw ('network_plan_token_step_invalid:' + $phaseName + ':' + $index + ':' + $stepName)
            }
        }
        $wire = [Collections.Generic.SortedDictionary[string,object]]::new(
            [StringComparer]::Ordinal
        )
        $wire['label'] = [string]$expected[1]
        $wire['order'] = [int]$expected[3]
        $wire['requested_capabilities_pointer_null'] = -not [bool]$expected[2]
        $observation = $issueObservation.Invoke($null,[object[]]@($plan,$wire))
        $observations.Add($observation)
        foreach ($mutation in @(
            @('label','wrong_label'),
            @('order',999),
            @('requested_capabilities_pointer_null',[bool]$expected[2])
        )) {
            $originalValue = $wire[$mutation[0]]
            $wire[$mutation[0]] = $mutation[1]
            try {
                $null = $issueObservation.Invoke($null,[object[]]@($plan,$wire))
                throw ('network_observation_mutation_accepted:' + $mutation[0])
            } catch {
                $inner = $_.Exception
                while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
                if ($inner.Message -cne 'network_arm_observation_binding_invalid') { throw }
            } finally {
                $wire[$mutation[0]] = $originalValue
            }
        }
    }
    $observationsByPhase[$phaseName] = $observations
}
$preflightConstructor = @($preflightResultType.GetConstructors($instance))
$fullConstructor = @($fullResultType.GetConstructors($instance))
if ($preflightConstructor.Count -ne 1 -or $fullConstructor.Count -ne 1) {
    throw 'network_result_constructor_roster_invalid'
}
$preflightResult = $preflightConstructor[0].Invoke(
    [object[]](,$observationsByPhase['Preflight'])
)
$fullResult = $fullConstructor[0].Invoke([object[]](,$observationsByPhase['Full']))
if (
    $null -eq $preflightResultType.GetProperty('OnlyArm',$instance).GetValue($preflightResult) -or
    @($fullResultType.GetProperty('Arms',$instance).GetValue($fullResult)).Count -ne 4
) {
    throw 'network_result_positive_invalid'
}
$preflightExtra = [Activator]::CreateInstance(
    [Collections.Generic.List``1].MakeGenericType($observationType)
)
foreach ($observation in $observationsByPhase['Preflight']) {
    $preflightExtra.Add($observation)
}
$preflightExtra.Add($observationsByPhase['Preflight'][0])
$fullExtra = [Activator]::CreateInstance(
    [Collections.Generic.List``1].MakeGenericType($observationType)
)
foreach ($observation in $observationsByPhase['Full']) {
    $fullExtra.Add($observation)
}
    $fullExtra.Add($observationsByPhase['Full'][3])
$preflightMissing = [Activator]::CreateInstance(
    [Collections.Generic.List``1].MakeGenericType($observationType)
)
$fullMissing = [Activator]::CreateInstance(
    [Collections.Generic.List``1].MakeGenericType($observationType)
)
for ($index = 0; $index -lt 3; $index++) {
    $fullMissing.Add($observationsByPhase['Full'][$index])
}
$fullDuplicate = [Activator]::CreateInstance(
    [Collections.Generic.List``1].MakeGenericType($observationType)
)
foreach ($observation in $observationsByPhase['Full']) {
    $fullDuplicate.Add($observation)
}
$fullDuplicate[3] = $fullDuplicate[2]
$fullReordered = [Activator]::CreateInstance(
    [Collections.Generic.List``1].MakeGenericType($observationType)
)
$fullReordered.Add($observationsByPhase['Full'][0])
$fullReordered.Add($observationsByPhase['Full'][2])
$fullReordered.Add($observationsByPhase['Full'][1])
$fullReordered.Add($observationsByPhase['Full'][3])
foreach ($invalid in @(
    @($observationsByPhase['Full'],$preflightConstructor[0]),
    @($observationsByPhase['Preflight'],$fullConstructor[0]),
    @($preflightExtra,$preflightConstructor[0]),
    @($fullExtra,$fullConstructor[0]),
    @($preflightMissing,$preflightConstructor[0]),
    @($fullMissing,$fullConstructor[0]),
    @($fullDuplicate,$fullConstructor[0]),
    @($fullReordered,$fullConstructor[0])
)) {
    try {
        $null = $invalid[1].Invoke([object[]](,$invalid[0]))
        throw 'network_result_wrong_phase_accepted'
    } catch {
        $inner = $_.Exception
        while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        if ($inner.Message -notin @(
            'network_preflight_roster_invalid','network_differential_roster_invalid'
        )) { throw }
    }
}
$preflightMethod = $program.GetMethod('RunNetworkPreflight',$static)
$fullMethod = $program.GetMethod('RunFullNetworkDifferential',$static)
$runNetworkMethod = $program.GetMethod('RunNetworkDifferential',$static)
if (
    $null -eq $preflightMethod -or $null -eq $fullMethod -or $null -eq $runNetworkMethod -or
    $preflightMethod.ReturnType -ne $preflightResultType -or
    $fullMethod.ReturnType -ne $fullResultType
) {
    throw 'network_typed_wrapper_signature_invalid'
}
foreach ($wrapper in @(@($preflightMethod,0),@($fullMethod,1))) {
    $rows = @(Get-ILRows $wrapper[0])
    $callIndexes = @(
        0..($rows.Count - 1) | Where-Object {
            $rows[$_].Called -ceq 'Program::RunNetworkDifferential'
        }
    )
    $phaseValues = @(
        $rows[0..($callIndexes[0] - 1)] |
        Where-Object { $null -ne $_.Integer } |
        Select-Object -Last 1
    )
    if (
        $callIndexes.Count -ne 1 -or $callIndexes[0] -lt 1 -or
        $phaseValues.Count -ne 1 -or
        [int]$phaseValues[0].Integer -ne [int]$wrapper[1]
    ) {
        throw ('network_typed_wrapper_phase_invalid:' + $wrapper[1])
    }
}
$networkRows = @(Get-ILRows $runNetworkMethod)
$runBoundaryMethod = $program.GetMethod('RunBoundary',$static)
if ($null -eq $runBoundaryMethod) { throw 'network_outer_boundary_method_missing' }
$boundaryRows = @(Get-ILRows $runBoundaryMethod)
function Assert-ImmediateSubstageBeforeOperation {
    param(
        [object[]]$Rows,
        [string]$Substage,
        [string]$Operation,
        [int]$Occurrence = 1
    )
    $operationIndexes = @(
        0..($Rows.Count - 1) | Where-Object { $Rows[$_].Called -ceq $Operation }
    )
    if ($Occurrence -lt 1 -or $Occurrence -gt $operationIndexes.Count) {
        throw ('network_outer_operation_missing:' + $Operation + ':' + $Occurrence)
    }
    $operationIndex = $operationIndexes[$Occurrence - 1]
    $setIndex = $null
    for ($index = $operationIndex - 1; $index -ge 0; $index--) {
        if ($Rows[$index].Called -ceq 'Program+FailureTracker::SetStage') {
            throw ('network_outer_stage_reset_before_operation:' + $Substage)
        }
        if ($Rows[$index].Called -ceq 'Program+FailureTracker::SetSubstage') {
            $setIndex = $index
            break
        }
    }
    if (
        $null -eq $setIndex -or $setIndex -lt 1 -or
        $Rows[$setIndex - 1].Text -cne $Substage
    ) {
        throw ('network_outer_marker_operation_mismatch:' + $Substage)
    }
}
Assert-ImmediateSubstageBeforeOperation $boundaryRows 'network_endpoint_bind' `
    'Program::ParseNetworkEndpoint' 1
Assert-ImmediateSubstageBeforeOperation $boundaryRows 'network_control_before' `
    'Program::ObserveExternalEchoControl' 1
Assert-ImmediateSubstageBeforeOperation $boundaryRows 'network_full_snapshot' `
    'Program::ReadLoopbackSnapshot' 2
Assert-ImmediateSubstageBeforeOperation $boundaryRows 'network_full_firewall_snapshot' `
    'Program::CountFirewallObjects' 2
Assert-ImmediateSubstageBeforeOperation $boundaryRows 'network_full_listener_snapshot' `
    'System.Net.Sockets.TcpListener::Pending' 1
Assert-ImmediateSubstageBeforeOperation $boundaryRows 'network_control_after' `
    'Program::ObserveExternalEchoControl' 2
Assert-ImmediateSubstageBeforeOperation $boundaryRows 'network_preflight_prepare' `
    'Program::RunNetworkPreflight' 1
Assert-ImmediateSubstageBeforeOperation $boundaryRows 'network_full_prepare' `
    'Program::RunFullNetworkDifferential' 1
Assert-ImmediateSubstageBeforeOperation $networkRows 'network_preflight_profile_before' `
    'Program+BoundAppContainerIdentity::ObserveNetworkProfileFolderBefore' 1
Assert-ImmediateSubstageBeforeOperation $networkRows 'network_preflight_capability_import' `
    'Program::ConvertStringSidToSidW' 1
Assert-ImmediateSubstageBeforeOperation $networkRows 'network_preflight_request_setup' `
    'System.IO.FileStream::.ctor' 1
Assert-ImmediateSubstageBeforeOperation $networkRows 'network_preflight_zero_expectation' `
    'Program::ReadReportBool' 1
Assert-ImmediateSubstageBeforeOperation $networkRows 'network_preflight_profile_after' `
    'Program+BoundAppContainerIdentity::ObserveNetworkProfileFolderAfter' 1
$expectedOperationSteps = [ordered]@{
    'System.Security.Cryptography.RandomNumberGenerator::GetBytes' = 0
    'Program+BoundAppContainerIdentity+LaunchAuthorizationProof::CreateSuspendedProcess' = 1
    'Program+BoundAppContainerIdentity::ObserveNetworkArmToken' = 1
    'Program::IsMember' = 2
    'Program::WaitForChildReport' = 3
    'Program::WaitForSingleObject' = 4
    'Program::RequireProperty' = 5
}
$seenOperations = @{}
$currentStep = $null
$stepSetCounts = @(0,0,0,0,0,0)
$stepMarkerIndex = $null
for ($index = 0; $index -lt $networkRows.Count; $index++) {
    $row = $networkRows[$index]
    if ($row.Called -ceq 'Program+FailureTracker::SetNetworkArmSubstage') {
        if ($index -lt 1 -or $null -eq $networkRows[$index - 1].Integer) {
            throw 'network_step_call_argument_invalid'
        }
        $currentStep = [int]$networkRows[$index - 1].Integer
        $stepMarkerIndex = $index
        if ($currentStep -lt 0 -or $currentStep -gt 5) {
            throw 'network_step_call_enum_invalid'
        }
        $stepSetCounts[$currentStep] += 1
    }
    if (
        $null -ne $row.Called -and
        $expectedOperationSteps.Contains([string]$row.Called) -and
        -not $seenOperations.ContainsKey([string]$row.Called)
    ) {
        for ($between = $stepMarkerIndex + 1; $between -lt $index; $between++) {
            if ($networkRows[$between].Called -ceq 'Program+FailureTracker::SetStage') {
                throw ('network_arm_stage_reset_before_operation:' + $row.Called)
            }
        }
        if ($currentStep -ne [int]$expectedOperationSteps[[string]$row.Called]) {
            throw ('network_step_operation_mismatch:' + $row.Called)
        }
        $seenOperations[[string]$row.Called] = $true
    }
}
if (
    $seenOperations.Count -ne $expectedOperationSteps.Count -or
    ($stepSetCounts -join ',') -cne '1,1,1,1,1,2'
) {
    throw 'network_step_operation_roster_invalid'
}
$candidates = @('stage_entry') + $profileSubstages + $networkSubstages + @(
    'unknown_substage','Network_Preflight_Zero'
)
$validPairs = 0
foreach ($stage in $stages) {
    foreach ($substage in $candidates) {
        $expected = if ($stage -ceq 'profile_binding') {
            $profileSubstages -ccontains $substage
        } elseif ($stage -ceq 'network_differential') {
            $networkSubstages -ccontains $substage
        } else {
            $substage -ceq 'stage_entry'
        }
        $actual = [bool]$pair.Invoke($null,[object[]]@($stage,$substage))
        if ($actual -ne $expected) {
            throw ('failure_pair_matrix_mismatch:'+ $stage + ':' + $substage)
        }
        if ($actual) { $validPairs += 1 }
    }
}
if ($validPairs -ne 118) { throw 'failure_pair_valid_count_invalid' }
foreach ($unknownStage in @('unknown_stage','Network_Differential')) {
    foreach ($substage in @('stage_entry','network_differential_entry')) {
        if ([bool]$pair.Invoke($null,[object[]]@($unknownStage,$substage))) {
            throw 'unknown_failure_stage_accepted'
        }
    }
}

$tracker = [Activator]::CreateInstance($trackerType,$true)
foreach ($stage in $stages) {
    $null = $setStage.Invoke($tracker,[object[]]@($stage))
    $expectedEntry = if ($stage -ceq 'profile_binding') {
        'profile_binding_entry'
    } elseif ($stage -ceq 'network_differential') {
        'network_differential_entry'
    } else {
        'stage_entry'
    }
    if ($stageProperty.GetValue($tracker) -cne $stage -or $substageProperty.GetValue($tracker) -cne $expectedEntry) {
        throw ('failure_stage_reset_invalid:'+ $stage)
    }
}
$null = $setStage.Invoke($tracker,[object[]]@('network_differential'))
$null = $setSubstage.Invoke($tracker,[object[]]@('network_arm_internet_client_1'))
try {
    $null = $setSubstage.Invoke($tracker,[object[]]@('profile_prelaunch_parse'))
    throw 'wrong_failure_pair_accepted'
} catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    if ($inner.Message -cne 'failure_substage_invalid') { throw }
}
if (
    $stageProperty.GetValue($tracker) -cne 'network_differential' -or
    $substageProperty.GetValue($tracker) -cne 'network_arm_internet_client_1'
) {
    throw 'wrong_failure_pair_mutated_tracker'
}
$null = $setStage.Invoke($tracker,[object[]]@('profile_storage'))
if ($substageProperty.GetValue($tracker) -cne 'stage_entry') {
    throw 'stale_network_substage_survived_reset'
}

function Capture-Receipt {
    param([string]$Status,[string]$Stage,[string]$Substage,[string]$FailureClass)
    $original = [Console]::Out
    $writer = [IO.StringWriter]::new([Globalization.CultureInfo]::InvariantCulture)
    try {
        [Console]::SetOut($writer)
        $rc = [int]$emit.Invoke($null,[object[]]@($Status,$Stage,$Substage,$FailureClass))
    } finally {
        [Console]::SetOut($original)
    }
    if ($rc -ne 1) { throw 'failure_receipt_rc_invalid' }
    return $writer.ToString()
}
foreach ($substage in $networkSubstages) {
    $wire = Capture-Receipt 'not_observed' 'network_differential' $substage 'not_observed'
    $document = [Text.Json.JsonDocument]::Parse($wire)
    try {
        $root = $document.RootElement
        if ($root.GetProperty('status').GetString() -cne 'not_observed') {
            throw 'failure_receipt_status_invalid'
        }
        if ($root.GetProperty('raw_observations').ValueKind -cne [Text.Json.JsonValueKind]::Null) {
            throw 'failure_receipt_raw_promoted'
        }
        $receipt = $root.GetProperty('helper_failure_receipt')
        $names = @($receipt.EnumerateObject() | ForEach-Object Name)
        if (($names -join ',') -cne 'failure_class,format,stage,status,substage') {
            throw 'failure_receipt_roster_invalid'
        }
        if (
            $receipt.GetProperty('format').GetString() -cne
                'finplanbr.windows-appcontainer-helper-failure-receipt.v6' -or
            $receipt.GetProperty('stage').GetString() -cne 'network_differential' -or
            $receipt.GetProperty('substage').GetString() -cne $substage
        ) {
            throw 'failure_receipt_binding_invalid'
        }
    } finally {
        $document.Dispose()
    }
}

$privateMessages = @(
    'C:\Users\private\secret.txt',
    'S-1-5-21-111111111-222222222-333333333-1001',
    ('a' * 64),
    'private_length_4096'
)
$privateWires = @()
foreach ($message in $privateMessages) {
    $failureClass = [string]$sanitize.Invoke(
        $null,[object[]]@([InvalidOperationException]::new($message))
    )
    $privateWires += (Capture-Receipt 'failed' 'network_differential' 'network_preflight_zero' $failureClass)
}
if (@($privateWires | Select-Object -Unique).Count -ne 1) {
    throw 'private_failure_message_changed_wire'
}
Write-Output (
    'network_substages=' + ($networkSubstages -join ',')
)
Write-Output 'failure_receipt_v6_tracker_ok'
'''
        with tempfile.TemporaryDirectory(prefix="finplanbr-helper-failure-v6-") as directory:
            root = Path(directory)
            source_path = root / "Program.cs"
            assembly = root / "helper.dll"
            script_path = root / "inspect.ps1"
            source_path.write_text(PROGRAM_SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
            script_path.write_text(script, encoding="utf-8")
            environment = os.environ.copy()
            environment["FPBR_SOURCE"] = os.fspath(source_path)
            environment["FPBR_ASSEMBLY"] = os.fspath(assembly)
            completed = subprocess.run(
                [pwsh, "-NoProfile", "-File", os.fspath(script_path)],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("failure_receipt_v6_tracker_ok", completed.stdout)
        roster_lines = [
            line.removeprefix("network_substages=")
            for line in completed.stdout.splitlines()
            if line.startswith("network_substages=")
        ]
        self.assertEqual(len(roster_lines), 1)
        self.assertEqual(tuple(roster_lines[0].split(",")), NETWORK_FAILURE_SUBSTAGES)

    @unittest.skipUnless(os.name == "nt", "compiled helper reflection is Windows-only")
    def test_compiled_network_token_context_and_fault_receipts(self) -> None:
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("PowerShell 7 compiler is unavailable")
        script = r'''
$ErrorActionPreference = 'Stop'
$sourcePath = [Environment]::GetEnvironmentVariable('FPBR_SOURCE','Process')
$assemblyPath = [Environment]::GetEnvironmentVariable('FPBR_ASSEMBLY','Process')
$compiled = @(Add-Type -Path $sourcePath -OutputAssembly $assemblyPath -OutputType Library -PassThru)
$program = @($compiled | Where-Object FullName -CEQ 'Program')
if ($program.Count -ne 1) { throw 'program_type_invalid' }
$program = $program[0]
$static = [Reflection.BindingFlags]'Public,NonPublic,Static,DeclaredOnly'
$instance = [Reflection.BindingFlags]'Public,NonPublic,Instance'
$trackerType = $program.GetNestedType('FailureTracker',[Reflection.BindingFlags]'NonPublic')
$planType = $program.GetNestedType('NetworkArmPlan',[Reflection.BindingFlags]'NonPublic')
$contextType = $program.GetNestedType('NetworkTokenObservationContext',[Reflection.BindingFlags]'NonPublic')
$stepType = $program.GetNestedType('NetworkTokenStep',[Reflection.BindingFlags]'NonPublic')
$factsType = $program.GetNestedType('TokenFacts',[Reflection.BindingFlags]'NonPublic')
$notObservedType = $program.GetNestedType('NotObservedException',[Reflection.BindingFlags]'NonPublic')
$interopType = $program.GetNestedType('InteropWin32Exception',[Reflection.BindingFlags]'NonPublic')
if (@($trackerType,$planType,$contextType,$stepType,$factsType,$notObservedType,$interopType) -contains $null) {
    throw 'network_token_reflection_surface_missing'
}
$setStage = $trackerType.GetMethod('SetStage',$instance)
$begin = $trackerType.GetMethod('BeginNetworkTokenObservation',$instance)
$stageProperty = $trackerType.GetProperty('Stage',$instance)
$substageProperty = $trackerType.GetProperty('Substage',$instance)
$enter = $contextType.GetMethod('Enter',$instance)
$requirePlan = $contextType.GetMethod('RequirePlan',$instance)
$requireComplete = $contextType.GetMethod('RequireComplete',$instance)
$preflightPlan = $planType.GetMethod('PreflightZero',$static).Invoke($null,@())
$otherPlan = $planType.GetMethod('FullZeroOne',$static).Invoke($null,@())
$emit = $program.GetMethod('EmitBoundaryFailure',$static)
$sanitize = $program.GetMethod('Sanitize',$static)
$validateFacts = $program.GetMethod('ValidateFacts',$static)
$membershipResult = $program.GetMethod('RequireObservedAppContainerMembership',$static)
if (@($setStage,$begin,$stageProperty,$substageProperty,$enter,$requirePlan,
      $requireComplete,$emit,$sanitize,$validateFacts,$membershipResult) -contains $null) {
    throw 'network_token_method_surface_missing'
}
function Unwrap([object]$ErrorRecord) {
    $inner = $ErrorRecord.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    return $inner
}
function New-TokenContext([object]$Plan) {
    $tracker = [Activator]::CreateInstance($trackerType,$true)
    $null = $setStage.Invoke($tracker,[object[]]@('network_differential'))
    $context = $begin.Invoke($tracker,[object[]]@($Plan))
    return [pscustomobject]@{ Tracker=$tracker; Context=$context }
}
function Token-Step([string]$Name) {
    return [Enum]::Parse($stepType,$Name,$false)
}
function Assert-ContextFailure([scriptblock]$Action,[string]$Message) {
    try { & $Action; throw ('expected_context_failure_missing:' + $Message) }
    catch {
        $inner = Unwrap $_
        if ($inner.Message -cne $Message) { throw }
    }
}
function Advance-To([object]$Pair,[string[]]$Steps) {
    foreach ($name in $Steps) {
        $null = $enter.Invoke($Pair.Context,[object[]]@((Token-Step $name)))
    }
}
function Capture-Receipt([object]$Tracker,[string]$Status,[string]$FailureClass) {
    $original = [Console]::Out
    $writer = [IO.StringWriter]::new([Globalization.CultureInfo]::InvariantCulture)
    try {
        [Console]::SetOut($writer)
        $rc = [int]$emit.Invoke(
            $null,
            [object[]]@(
                $Status,
                [string]$stageProperty.GetValue($Tracker),
                [string]$substageProperty.GetValue($Tracker),
                $FailureClass
            )
        )
    } finally { [Console]::SetOut($original) }
    if ($rc -ne 1) { throw 'fault_receipt_rc_invalid' }
    return [Text.Json.JsonDocument]::Parse($writer.ToString())
}
function Assert-Receipt(
    [object]$Tracker,[object]$Error,[string]$ExpectedSubstage,
    [string]$ExpectedStatus,[string]$ExpectedClass
) {
    $actualClass = if ($Error.GetType() -eq $notObservedType) {
        'not_observed'
    } else {
        [string]$sanitize.Invoke($null,[object[]]@($Error))
    }
    if ($actualClass -cne $ExpectedClass) { throw 'fault_class_invalid' }
    if ([string]$substageProperty.GetValue($Tracker) -cne $ExpectedSubstage) {
        throw 'fault_substage_invalid'
    }
    $document = Capture-Receipt $Tracker $ExpectedStatus $actualClass
    try {
        $receipt = $document.RootElement.GetProperty('helper_failure_receipt')
        if (
            $receipt.GetProperty('format').GetString() -cne
                'finplanbr.windows-appcontainer-helper-failure-receipt.v6' -or
            $receipt.GetProperty('status').GetString() -cne $ExpectedStatus -or
            $receipt.GetProperty('stage').GetString() -cne 'network_differential' -or
            $receipt.GetProperty('substage').GetString() -cne $ExpectedSubstage -or
            $receipt.GetProperty('failure_class').GetString() -cne $ExpectedClass
        ) { throw 'fault_receipt_binding_invalid' }
    } finally { $document.Dispose() }
}

if (-not $contextType.IsSealed -or @($contextType.GetConstructors($instance)).Count -ne 1 -or
    -not @($contextType.GetConstructors($instance))[0].IsPrivate) {
    throw 'network_token_context_authority_invalid'
}
$duplicate = New-TokenContext $preflightPlan
$null = $enter.Invoke($duplicate.Context,[object[]]@((Token-Step 'ReadBase')))
Assert-ContextFailure {
    $null = $enter.Invoke($duplicate.Context,[object[]]@((Token-Step 'ReadBase')))
} 'network_token_step_order_invalid'
$skip = New-TokenContext $preflightPlan
Assert-ContextFailure {
    $null = $enter.Invoke($skip.Context,[object[]]@((Token-Step 'AapMembership')))
} 'network_token_step_order_invalid'
$reverse = New-TokenContext $preflightPlan
Assert-ContextFailure {
    $null = $enter.Invoke($reverse.Context,[object[]]@((Token-Step 'Bind')))
} 'network_token_step_order_invalid'
$crossPlan = New-TokenContext $preflightPlan
Assert-ContextFailure {
    $null = $requirePlan.Invoke($crossPlan.Context,[object[]]@($otherPlan))
} 'network_token_plan_mismatch'
$incomplete = New-TokenContext $preflightPlan
Assert-ContextFailure {
    $null = $requireComplete.Invoke($incomplete.Context,@())
} 'network_token_observation_incomplete'
$complete = New-TokenContext $preflightPlan
Advance-To $complete @(
    'ReadBase','AapMembership','AapRosters','Lpac','Identity','AapEffect',
    'ValidateLpac','ValidateRoster','Bind'
)
$null = $requireComplete.Invoke($complete.Context,@())
Assert-ContextFailure {
    $null = $enter.Invoke($complete.Context,[object[]]@((Token-Step 'Bind')))
} 'network_token_step_order_invalid'

$networkObserver = $program.GetNestedType('BoundAppContainerIdentity',[Reflection.BindingFlags]'NonPublic').GetMethod(
    'ObserveNetworkArmToken',$instance
)
if ($null -eq $networkObserver) { throw 'network_token_observer_missing' }
$networkParameters = @($networkObserver.GetParameters())
if ($networkParameters.Count -ne 7 -or $networkParameters[1].ParameterType -ne $planType -or
    $networkParameters[2].ParameterType -ne $contextType -or
    $networkParameters[3].ParameterType.Name -cne 'LaunchAuthorizationProof') {
    throw 'network_token_observer_context_signature_invalid'
}
foreach ($name in @('ObserveChildToken','ObserveGrandchildToken','ObserveRootTokenWithClassicBehavior')) {
    $method = $networkObserver.DeclaringType.GetMethod($name,$instance)
    if ($null -eq $method -or @($method.GetParameters() | Where-Object ParameterType -eq $contextType).Count -ne 0) {
        throw ('nonnetwork_observer_accepts_context:' + $name)
    }
}
$networkReader = $program.GetMethod('ReadNetworkTokenFactsAndObserveClassicBehavior',$static)
if ($null -eq $networkReader -or @($networkReader.GetParameters()).Count -ne 4 -or
    $networkReader.GetParameters()[1].ParameterType -ne $contextType -or
    @($validateFacts.GetParameters()).Count -ne 4 -or
    $validateFacts.GetParameters()[3].ParameterType -ne $contextType) {
    throw 'network_token_same_context_signature_invalid'
}

$factsCtor = @($factsType.GetConstructors($instance) | Where-Object { $_.GetParameters().Count -eq 17 })
if ($factsCtor.Count -ne 1) { throw 'token_facts_ctor_invalid' }
$sid = 'S-1-15-2-101-102-103-104-105-106-107-108'
function New-Facts(
    [object]$Lpac,[bool]$LpacSupported,[uint32]$GroupMatches,
    [uint32]$RestrictedMatches,[bool]$MembershipSucceeded,[object]$MembershipError,
    [string]$ObservedSid = $sid
) {
    return $factsCtor[0].Invoke([object[]]@(
        $true,$ObservedSid,[uint32]1,'S-1-15-3-1|0x00000004',[uint32]9,
        $GroupMatches,'0x00000007',[uint32]4,$RestrictedMatches,'',[uint32]0x1000,
        $false,$Lpac,$LpacSupported,$MembershipSucceeded,$MembershipError,$true
    ))
}
$membership = New-TokenContext $preflightPlan
$null = $enter.Invoke($membership.Context,[object[]]@((Token-Step 'ReadBase')))
$null = $enter.Invoke($membership.Context,[object[]]@((Token-Step 'AapMembership')))
try {
    $null = $membershipResult.Invoke($null,[object[]]@($false,$false))
    throw 'membership_not_observed_missing'
} catch {
    $inner = Unwrap $_
    Assert-Receipt `
        $membership.Tracker $inner 'network_preflight_zero_token_aap_membership' `
        'not_observed' 'not_observed'
}
$lpac = New-TokenContext $preflightPlan
Advance-To $lpac @('ReadBase','AapMembership','AapRosters','Lpac','Identity','AapEffect')
$facts = New-Facts $null $false 1 0 $true $null
$null = $validateFacts.Invoke($null,[object[]]@($facts,$sid,'network_preflight_zero',$lpac.Context))
if ($substageProperty.GetValue($lpac.Tracker) -cne 'network_preflight_zero_token_validate_roster') {
    throw 'optional_lpac_diagnostic_blocked_or_mislabeled'
}
$lpacTrue = New-TokenContext $preflightPlan
Advance-To $lpacTrue @(
    'ReadBase','AapMembership','AapRosters','Lpac','Identity','AapEffect'
)
try {
    $facts = New-Facts $true $true 1 0 $true $null
    $null = $validateFacts.Invoke($null,[object[]]@($facts,$sid,'network_preflight_zero',$lpacTrue.Context))
    throw 'lpac_true_accepted'
} catch {
    $inner = Unwrap $_
    if ($inner.GetType() -eq $notObservedType -or
        $inner.Message -cne 'network_preflight_zero_unexpected_lpac') { throw }
    Assert-Receipt `
        $lpacTrue.Tracker $inner 'network_preflight_zero_token_validate_lpac' `
        'failed' 'internal_invariant_failure'
}
$roster = New-TokenContext $preflightPlan
Advance-To $roster @(
    'ReadBase','AapMembership','AapRosters','Lpac','Identity','AapEffect'
)
try {
    $facts = New-Facts $false $true 0 0 $true $null
    $null = $validateFacts.Invoke($null,[object[]]@($facts,$sid,'network_preflight_zero',$roster.Context))
    throw 'roster_not_observed_missing'
} catch {
    $inner = Unwrap $_
    Assert-Receipt $roster.Tracker $inner 'network_preflight_zero_token_validate_roster' 'not_observed' 'not_observed'
}
$membershipState = New-TokenContext $preflightPlan
Advance-To $membershipState @(
    'ReadBase','AapMembership','AapRosters','Lpac','Identity','AapEffect'
)
try {
    $facts = New-Facts $false $true 1 0 $false $null
    $null = $validateFacts.Invoke(
        $null,[object[]]@($facts,$sid,'network_preflight_zero',$membershipState.Context)
    )
    throw 'membership_state_invariant_missing'
} catch {
    $inner = Unwrap $_
    if ($inner.GetType() -eq $notObservedType -or
        $inner.Message -cne 'network_preflight_zero_aap_membership_state_invalid') { throw }
    Assert-Receipt `
        $membershipState.Tracker $inner 'network_preflight_zero_token_validate_lpac' `
        'failed' 'internal_invariant_failure'
}
$identity = New-TokenContext $preflightPlan
Advance-To $identity @(
    'ReadBase','AapMembership','AapRosters','Lpac','Identity','AapEffect'
)
try {
    $facts = New-Facts $false $true 1 0 $true $null 'S-1-15-2-201-202-203-204-205-206-207-208'
    $null = $validateFacts.Invoke($null,[object[]]@($facts,$sid,'network_preflight_zero',$identity.Context))
    throw 'identity_invariant_missing'
} catch {
    $inner = Unwrap $_
    Assert-Receipt `
        $identity.Tracker $inner 'network_preflight_zero_token_aap_effect' `
        'failed' 'internal_invariant_failure'
}
Write-Output 'network_token_context_and_faults_ok'
'''
        with tempfile.TemporaryDirectory(prefix="finplanbr-token-v6-") as directory:
            root = Path(directory)
            source_path = root / "Program.cs"
            assembly = root / "helper.dll"
            script_path = root / "inspect.ps1"
            source_path.write_bytes(PROGRAM_SOURCE.read_bytes())
            script_path.write_text(script, encoding="utf-8")
            environment = os.environ.copy()
            environment["FPBR_SOURCE"] = os.fspath(source_path)
            environment["FPBR_ASSEMBLY"] = os.fspath(assembly)
            completed = subprocess.run(
                [pwsh, "-NoProfile", "-File", os.fspath(script_path)],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("network_token_context_and_faults_ok", completed.stdout)

        mutation_gate_script = r'''
$ErrorActionPreference = 'Stop'
$sourcePath = [Environment]::GetEnvironmentVariable('FPBR_SOURCE','Process')
$assemblyPath = [Environment]::GetEnvironmentVariable('FPBR_ASSEMBLY','Process')
$compiled = @(Add-Type -Path $sourcePath -OutputAssembly $assemblyPath -OutputType Library -PassThru)
$program = @($compiled | Where-Object FullName -CEQ 'Program')
if ($program.Count -ne 1) { throw 'program_type_invalid' }
$program = $program[0]
$static = [Reflection.BindingFlags]'Public,NonPublic,Static,DeclaredOnly'
$instance = [Reflection.BindingFlags]'Public,NonPublic,Instance'
$bound = $program.GetNestedType('BoundAppContainerIdentity',[Reflection.BindingFlags]'NonPublic')
$contextType = $program.GetNestedType(
    'NetworkTokenObservationContext',[Reflection.BindingFlags]'NonPublic'
)
if ($null -eq $bound -or $null -eq $contextType) {
    throw 'compiled_context_flow_surface_missing'
}
$optionalLpac = $program.GetMethod('UnsupportedLpacQueryDiagnostic',$static)
if ($null -eq $optionalLpac -or -not $optionalLpac.IsPrivate) {
    throw 'compiled_optional_lpac_diagnostic_invalid'
}
$optionalLpacTuple = $optionalLpac.Invoke($null,[object[]]@())
$optionalLpacResult = $optionalLpacTuple.GetType().GetField('Item1')
$optionalLpacSupported = $optionalLpacTuple.GetType().GetField('Item2')
if ($null -eq $optionalLpacResult -or $null -eq $optionalLpacSupported -or
    $null -ne $optionalLpacResult.GetValue($optionalLpacTuple) -or
    [bool]$optionalLpacSupported.GetValue($optionalLpacTuple)) {
    throw 'compiled_optional_lpac_diagnostic_invalid'
}
function Get-ILRows {
    param([Reflection.MethodInfo]$Method)
    $opcodeByValue = @{}
    foreach ($field in [Reflection.Emit.OpCodes].GetFields([Reflection.BindingFlags]'Public,Static')) {
        $opcode = $field.GetValue($null)
        $value = [int]$opcode.Value
        if ($value -lt 0) { $value += 65536 }
        $opcodeByValue[$value] = $opcode
    }
    $bytes = $Method.GetMethodBody().GetILAsByteArray()
    $rows = [Collections.Generic.List[object]]::new()
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $first = [int]$bytes[$offset]; $offset += 1
        if ($first -eq 0xFE) {
            $value = 0xFE00 -bor [int]$bytes[$offset]; $offset += 1
        } else { $value = $first }
        $opcode = $opcodeByValue[$value]
        if ($null -eq $opcode) { throw 'unknown_context_flow_il_opcode' }
        $operandOffset = $offset
        switch ([string]$opcode.OperandType) {
            'InlineNone' { $size = 0 }
            'ShortInlineBrTarget' { $size = 1 }
            'ShortInlineI' { $size = 1 }
            'ShortInlineVar' { $size = 1 }
            'InlineVar' { $size = 2 }
            'InlineI8' { $size = 8 }
            'InlineR' { $size = 8 }
            'ShortInlineR' { $size = 4 }
            'InlineSwitch' { $size = 4 + 4 * [BitConverter]::ToInt32($bytes,$offset) }
            default { $size = 4 }
        }
        $integer = $null
        if ($opcode.Name -ceq 'ldc.i4.m1') { $integer = -1 }
        elseif ($opcode.Name -match '^ldc\.i4\.([0-8])$') { $integer = [int]$Matches[1] }
        elseif ($opcode.Name -ceq 'ldc.i4.s') { $integer = [int][sbyte]$bytes[$operandOffset] }
        elseif ($opcode.Name -ceq 'ldc.i4') {
            $integer = [BitConverter]::ToInt32($bytes,$operandOffset)
        }
        elseif ($opcode.Name -ceq 'ldstr') {
            $token = [BitConverter]::ToInt32($bytes,$operandOffset)
            $text = $Method.Module.ResolveString($token)
        }
        $variable = $null
        if ($opcode.Name -match '^(?:ld|st)loc\.([0-3])$') {
            $variable = [int]$Matches[1]
        } elseif ($opcode.OperandType -ceq [Reflection.Emit.OperandType]::ShortInlineVar) {
            $variable = [int]$bytes[$operandOffset]
        } elseif ($opcode.OperandType -ceq [Reflection.Emit.OperandType]::InlineVar) {
            $variable = [int][BitConverter]::ToUInt16($bytes,$operandOffset)
        }
        $called = $null
        if ($opcode.Name -in @('call','callvirt','newobj','ldftn','ldvirtftn')) {
            $token = [BitConverter]::ToInt32($bytes,$operandOffset)
            $resolved = $Method.Module.ResolveMethod($token)
            $called = $resolved.DeclaringType.FullName + '::' + $resolved.Name
        }
        $fieldName = $null
        if ($opcode.Name -in @('ldfld','ldsfld','stfld','stsfld')) {
            $token = [BitConverter]::ToInt32($bytes,$operandOffset)
            $resolvedField = $Method.Module.ResolveField($token)
            $fieldName = $resolvedField.DeclaringType.FullName + '::' + $resolvedField.Name
        }
        $rows.Add([pscustomobject]@{
            Name=$opcode.Name; Integer=$integer; Text=$text; Variable=$variable
            Called=$called; Field=$fieldName
        })
        $offset += $size
    }
    return @($rows)
}
function Get-TypeTree([Type]$Type) {
    $result = [Collections.Generic.List[Type]]::new()
    $result.Add($Type)
    foreach ($nested in $Type.GetNestedTypes(
        [Reflection.BindingFlags]'Public,NonPublic'
    )) {
        foreach ($item in @(Get-TypeTree $nested)) { $result.Add($item) }
    }
    return @($result)
}
$allFlags = [Reflection.BindingFlags]'Public,NonPublic,Static,Instance,DeclaredOnly'
foreach ($type in @(Get-TypeTree $program)) {
    if ($type.Name -match '(?i)ALL_APPLICATION_PACKAGES_POLICY|OPT_OUT') {
        throw 'compiled_forbidden_aap_policy_symbol'
    }
    foreach ($field in $type.GetFields($allFlags)) {
        if ($field.Name -match '(?i)ALL_APPLICATION_PACKAGES_POLICY|OPT_OUT') {
            throw 'compiled_forbidden_aap_policy_symbol'
        }
        if ($field.IsLiteral) {
            $constant = $field.GetRawConstantValue()
            if (($constant -is [int] -or $constant -is [uint32]) -and
                [uint64]$constant -eq [uint64]131087) {
                throw 'compiled_forbidden_aap_policy_attribute'
            }
            if ($constant -is [string] -and
                $constant -match '(?i)ALL_APPLICATION_PACKAGES_POLICY|OPT_OUT') {
                throw 'compiled_forbidden_aap_policy_symbol'
            }
        }
    }
    foreach ($method in $type.GetMethods($allFlags)) {
        if ($method.Name -match '(?i)ALL_APPLICATION_PACKAGES_POLICY|OPT_OUT') {
            throw 'compiled_forbidden_aap_policy_symbol'
        }
        if ($null -eq $method.GetMethodBody()) { continue }
        foreach ($row in @(Get-ILRows $method)) {
            if ($row.Integer -eq 131087) {
                throw 'compiled_forbidden_aap_policy_attribute'
            }
            if ($null -ne $row.Text -and
                $row.Text -match '(?i)ALL_APPLICATION_PACKAGES_POLICY|OPT_OUT') {
                throw 'compiled_forbidden_aap_policy_symbol'
            }
        }
    }
}
function Call-Indexes([object[]]$Rows,[string]$Called) {
    return @(0..($Rows.Count - 1) | Where-Object { $Rows[$_].Called -ceq $Called })
}
function Field-Indexes([object[]]$Rows,[string]$Field) {
    return @(0..($Rows.Count - 1) | Where-Object { $Rows[$_].Field -ceq $Field })
}
function Nearest-Integer([object[]]$Rows,[int]$Index) {
    for ($cursor = $Index - 1; $cursor -ge [Math]::Max(0,$Index - 8); $cursor--) {
        if ($null -ne $Rows[$cursor].Integer) { return [int]$Rows[$cursor].Integer }
    }
    return $null
}
function Require-ArgumentBeforeCall(
    [object[]]$Rows,[int]$CallIndex,[string]$ArgumentOpcode,[string]$Failure
) {
    if ($CallIndex -lt 1 -or $Rows[$CallIndex - 1].Name -cne $ArgumentOpcode) {
        throw $Failure
    }
    $start = [Math]::Max(0,$CallIndex - 5)
    if (@($start..($CallIndex - 1) | Where-Object { $Rows[$_].Name -ceq 'ldnull' }).Count) {
        throw $Failure
    }
}
function Require-ArgumentInWindow(
    [object[]]$Rows,[int]$CallIndex,[string]$ArgumentOpcode,[string]$Failure
) {
    $start = [Math]::Max(0,$CallIndex - 12)
    if (@($start..($CallIndex - 1) | Where-Object {
        $Rows[$_].Name -ceq $ArgumentOpcode
    }).Count -ne 1 -or @($start..($CallIndex - 1) | Where-Object {
        $Rows[$_].Name -ceq 'ldnull'
    }).Count) {
        throw $Failure
    }
}

$begin = $program.GetNestedType('FailureTracker',[Reflection.BindingFlags]'NonPublic').GetMethod(
    'BeginNetworkTokenObservation',$instance
)
$beginRows = @(Get-ILRows $begin)
$tokenSubstage = @(Call-Indexes $beginRows 'Program+NetworkArmPlan::TokenSubstage')
$setSubstage = @(Call-Indexes $beginRows 'Program+FailureTracker::SetSubstage')
$issue = @(Call-Indexes $beginRows 'Program+NetworkTokenObservationContext::Issue')
if ($tokenSubstage.Count -ne 1 -or $setSubstage.Count -ne 1 -or $issue.Count -ne 1 -or
    $tokenSubstage[0] -ge $setSubstage[0] -or $setSubstage[0] -ge $issue[0] -or
    (Nearest-Integer $beginRows $tokenSubstage[0]) -ne 0) {
    throw 'compiled_begin_launch_policy_flow_invalid'
}

$importRows = @(Get-ILRows $bound.GetMethod('Import',$static))
$directNetworkReaders = @(0..($importRows.Count - 1) | Where-Object {
    $importRows[$_].Name -ceq 'ldftn' -and
    $importRows[$_].Called -ceq 'Program::ReadNetworkTokenFactsAndObserveClassicBehavior'
})
if ($directNetworkReaders.Count -ne 1) {
    throw 'compiled_imported_network_delegate_invalid'
}

$readNetwork = $program.GetMethod('ReadNetworkTokenFactsAndObserveClassicBehavior',$static)
$readNetworkRows = @(Get-ILRows $readNetwork)
$readFromToken = @(Call-Indexes $readNetworkRows 'Program::ReadTokenFactsFromToken')
$classicBehavior = @(Call-Indexes $readNetworkRows 'Program::ObserveClassicBehaviorWithToken')
$effectEnter = @(Call-Indexes $readNetworkRows 'Program+NetworkTokenObservationContext::Enter')
if ($readFromToken.Count -ne 1 -or $classicBehavior.Count -ne 1 -or
    $effectEnter.Count -ne 1 -or (Nearest-Integer $readNetworkRows $effectEnter[0]) -ne 6 -or
    $readFromToken[0] -ge $effectEnter[0] -or $effectEnter[0] -ge $classicBehavior[0]) {
    throw 'compiled_network_reader_effect_flow_invalid'
}
Require-ArgumentBeforeCall `
    $readNetworkRows $readFromToken[0] 'ldarg.1' 'compiled_network_reader_context_invalid'
$factsTokenLoad = $readNetworkRows[$readFromToken[0] - 2]
$effectTokenLoad = $readNetworkRows[$classicBehavior[0] - 3]
if ($factsTokenLoad.Name -notlike 'ldloc*' -or $effectTokenLoad.Name -notlike 'ldloc*' -or
    $null -eq $factsTokenLoad.Variable -or
    $factsTokenLoad.Variable -ne $effectTokenLoad.Variable) {
    throw 'compiled_same_token_effect_binding_invalid'
}

$readFromTokenMethod = $program.GetMethod('ReadTokenFactsFromToken',$static)
$readerRows = @(Get-ILRows $readFromTokenMethod)
$readerEnter = @(Call-Indexes $readerRows 'Program+NetworkTokenObservationContext::Enter')
$readerSteps = @($readerEnter | ForEach-Object { Nearest-Integer $readerRows $_ })
if (($readerSteps -join ',') -cne '2,3,4,5') {
    throw 'compiled_reader_monotonic_steps_invalid'
}
$membershipOperation = @(Call-Indexes $readerRows 'Program::CheckAppContainerMembership')
$identityReads = @(Call-Indexes $readerRows 'Program::ReadTokenInformation')
if ($membershipOperation.Count -ne 1 -or $identityReads.Count -lt 1 -or
    $readerEnter[0] -ge $membershipOperation[0]) {
    throw 'compiled_membership_marker_order_invalid'
}
if ($readerEnter[3] -ge $identityReads[0]) {
    throw 'compiled_identity_marker_order_invalid'
}
$lpacErrorCalls = @(0..($readerRows.Count - 1) | Where-Object {
    $null -ne $readerRows[$_].Called -and
    $readerRows[$_].Called.EndsWith('::get_NativeErrorCode',[StringComparison]::Ordinal)
})
if ($lpacErrorCalls.Count -ne 1) {
    throw 'compiled_lpac_unsupported_error_binding_invalid'
}
$lpacErrorStart = [Math]::Max(0,$lpacErrorCalls[0] - 12)
$lpacErrorEnd = [Math]::Min($readerRows.Count - 1,$lpacErrorCalls[0] + 12)
if (@($lpacErrorStart..$lpacErrorEnd | Where-Object {
        $readerRows[$_].Integer -eq 87
    }).Count -ne 1) {
    throw 'compiled_lpac_unsupported_error_binding_invalid'
}

$validate = $program.GetMethod('ValidateFacts',$static)
$validateRows = @(Get-ILRows $validate)
$validateEnter = @(Call-Indexes $validateRows 'Program+NetworkTokenObservationContext::Enter')
$validateSteps = @($validateEnter | ForEach-Object { Nearest-Integer $validateRows $_ })
if (($validateSteps -join ',') -cne '7,8') {
    throw 'compiled_validator_monotonic_steps_invalid'
}
$lpacPredicates = @(
    (Call-Indexes $validateRows 'Program+TokenFacts::get_IsLessPrivilegedAppContainer') +
    (Call-Indexes $validateRows 'Program+TokenFacts::get_LpacQuerySupported')
) | Sort-Object
$rosterPredicates = @(
    (Call-Indexes $validateRows 'Program+TokenFacts::get_AllApplicationPackagesTokenGroupMatchCount') +
    (Call-Indexes $validateRows 'Program+TokenFacts::get_AllApplicationPackagesRestrictedSidMatchCount')
) | Sort-Object
if ($lpacPredicates.Count -lt 1 -or $validateEnter[0] -ge $lpacPredicates[0]) {
    throw 'compiled_validate_lpac_marker_order_invalid'
}
if ($rosterPredicates.Count -lt 1 -or $validateEnter[1] -ge $rosterPredicates[0]) {
    throw 'compiled_validate_roster_marker_order_invalid'
}

$observe = $bound.GetMethod('ObserveNetworkArmToken',$instance)
$observeRows = @(Get-ILRows $observe)
$regularPolicyCalls = @(
    Call-Indexes $observeRows `
        'Program+BoundAppContainerIdentity+LaunchAuthorizationProof::RequireRegularPolicyForProcess'
)
$networkField = 'Program+BoundAppContainerIdentity::_networkTokenReader'
$networkFieldLoads = @(Field-Indexes $observeRows $networkField)
if ($regularPolicyCalls.Count -ne 1 -or $networkFieldLoads.Count -ne 1 -or
    $regularPolicyCalls[0] -ge $networkFieldLoads[0]) {
    throw 'compiled_observer_launch_policy_flow_invalid'
}
$policyIndex = [int]$regularPolicyCalls[0]
if ($policyIndex -lt 2 -or
    $observeRows[$policyIndex - 2].Name -cne 'ldarg.s' -or
    $observeRows[$policyIndex - 2].Variable -ne 4 -or
    $observeRows[$policyIndex - 1].Name -cne 'ldarg.1') {
    throw 'compiled_observer_launch_policy_arguments_invalid'
}
$delegateCall = @(
    ($networkFieldLoads[0] + 1)..($observeRows.Count - 1) |
    Where-Object { $observeRows[$_].Called -like 'System.Func*::Invoke' } |
    Select-Object -First 1
)
if ($delegateCall.Count -ne 1) { throw 'compiled_observer_network_delegate_call_missing' }
$delegateArguments = @(($networkFieldLoads[0] + 1)..($delegateCall[0] - 1))
if (@($delegateArguments | Where-Object {
        $observeRows[$_].Name -ceq 'ldarg.3'
    }).Count -ne 1 -or @($delegateArguments | Where-Object {
        $observeRows[$_].Name -ceq 'ldnull'
    }).Count) {
    throw 'compiled_observer_delegate_context_invalid'
}
$validateCalls = @(Call-Indexes $observeRows 'Program::ValidateFacts')
if ($validateCalls.Count -ne 1) { throw 'compiled_observer_validator_call_invalid' }
Require-ArgumentBeforeCall `
    $observeRows $validateCalls[0] 'ldarg.3' 'compiled_observer_validator_context_invalid'
$shaCalls = @(Call-Indexes $observeRows 'System.String::Equals')
if ($shaCalls.Count -ne 1) { throw 'compiled_aap_sha_binding_invalid' }
$shaStart = [Math]::Max(0,$shaCalls[0] - 8)
if (@($shaStart..($shaCalls[0] - 1) | Where-Object {
        $observeRows[$_].Name -ceq 'ldarg.s' -and $observeRows[$_].Variable -eq 7
    }).Count -ne 1 -or @($shaStart..($shaCalls[0] - 1) | Where-Object {
        $observeRows[$_].Integer -eq 4
    }).Count -ne 1) {
    throw 'compiled_aap_sha_binding_invalid'
}
$accessDeniedIntegers = @(
    ($shaCalls[0] + 1)..([Math]::Min($observeRows.Count - 1,$validateCalls[0] + 28)) |
    Where-Object { $observeRows[$_].Integer -eq 5 }
)
if ($accessDeniedIntegers.Count -ne 1) {
    throw 'compiled_aap_access_denied_binding_invalid'
}
$observeEnter = @(Call-Indexes $observeRows 'Program+NetworkTokenObservationContext::Enter')
$observeSteps = @($observeEnter | ForEach-Object { Nearest-Integer $observeRows $_ })
$readBaseEnter = @($observeEnter | Where-Object {
    (Nearest-Integer $observeRows $_) -eq 1
})
$bindEnter = @($observeEnter | Where-Object {
    (Nearest-Integer $observeRows $_) -eq 9
})
$getProcessIdCalls = @(Call-Indexes $observeRows 'Program::GetProcessId')
$proofConstructors = @(
    Call-Indexes `
        $observeRows `
        'Program+BoundAppContainerIdentity+ValidatedTokenFacts::.ctor'
)
$completeCalls = @(Call-Indexes $observeRows 'Program+NetworkTokenObservationContext::RequireComplete')
if (($observeSteps -join ',') -cne '1,9' -or $readBaseEnter.Count -ne 1 -or
    $bindEnter.Count -ne 1 -or $completeCalls.Count -ne 1 -or
    $regularPolicyCalls[0] -ge $readBaseEnter[0] -or
    $readBaseEnter[0] -ge $delegateCall[0]) {
    throw 'compiled_observer_bind_complete_invalid'
}
if ($validateCalls[0] -ge $bindEnter[0]) {
    throw 'compiled_validate_before_bind_invalid'
}
if ($bindEnter[0] -ge $completeCalls[0]) {
    throw 'compiled_bind_before_completion_invalid'
}
if ($proofConstructors.Count -ne 1 -or $bindEnter[0] -ge $proofConstructors[0]) {
    throw 'compiled_bind_before_proof_construction_invalid'
}
if ($getProcessIdCalls.Count -ne 1 -or $bindEnter[0] -ge $getProcessIdCalls[0]) {
    throw 'compiled_bind_before_get_process_id_invalid'
}
if ($getProcessIdCalls[0] -ge $proofConstructors[0] -or
    $proofConstructors[0] -ge $completeCalls[0]) {
    throw 'compiled_proof_before_completion_invalid'
}
if ($observeRows[$readBaseEnter[0] - 2].Name -cne 'ldarg.3' -or
    $observeRows[$readBaseEnter[0] - 1].Integer -ne 1 -or
    $observeRows[$bindEnter[0] - 2].Name -cne 'ldarg.3' -or
    $observeRows[$bindEnter[0] - 1].Integer -ne 9) {
    throw 'compiled_observer_bind_context_invalid'
}
$effectIndex = [int]$effectEnter[0]
if ($effectIndex -lt 2 -or
    $readNetworkRows[$effectIndex - 2].Name -cne 'ldarg.1' -or
    $readNetworkRows[$effectIndex - 1].Integer -ne 6) {
    throw 'compiled_network_reader_effect_context_invalid'
}
Require-ArgumentBeforeCall `
    $observeRows $completeCalls[0] 'ldarg.3' 'compiled_observer_complete_context_invalid'

$runNetwork = $program.GetMethod('RunNetworkDifferential',$static)
$runRows = @(Get-ILRows $runNetwork)
$beginCalls = @(Call-Indexes $runRows 'Program+FailureTracker::BeginNetworkTokenObservation')
$observeCalls = @(Call-Indexes $runRows 'Program+BoundAppContainerIdentity::ObserveNetworkArmToken')
if ($beginCalls.Count -ne 1 -or $observeCalls.Count -ne 1 -or
    $beginCalls[0] -ge $observeCalls[0]) {
    throw 'compiled_begin_observe_flow_invalid'
}
$storeContext = $runRows[$beginCalls[0] + 1]
$contextWindowStart = [Math]::Max($beginCalls[0] + 1,$observeCalls[0] - 12)
$contextLoads = @($contextWindowStart..($observeCalls[0] - 1) | Where-Object {
    $runRows[$_].Name -like 'ldloc*' -and
    $null -ne $storeContext.Variable -and
    $runRows[$_].Variable -eq $storeContext.Variable
})
if ($storeContext.Name -notlike 'stloc*' -or $null -eq $storeContext.Variable -or
    $contextLoads.Count -ne 1) {
    throw 'compiled_begin_observe_context_identity_invalid'
}
if (@(($beginCalls[0] + 2)..$observeCalls[0] | Where-Object {
    $runRows[$_].Called -ceq 'Program+NetworkTokenObservationContext::.ctor' -or
    $runRows[$_].Called -ceq 'Program+NetworkTokenObservationContext::Issue' -or
    $runRows[$_].Name -ceq 'ldnull' -or
    ($runRows[$_].Name -like 'stloc*' -and
        $runRows[$_].Variable -eq $storeContext.Variable)
}).Count -ne 0) {
    throw 'compiled_begin_observe_context_replaced'
}

foreach ($methodName in @('ObserveChildToken','ObserveGrandchildToken')) {
    $rows = @(Get-ILRows $bound.GetMethod($methodName,$instance))
    if (@(Field-Indexes $rows 'Program+BoundAppContainerIdentity::_tokenReader').Count -ne 1 -or
        @(Field-Indexes $rows $networkField).Count -ne 0) {
        throw ('compiled_nonnetwork_reader_invalid:' + $methodName)
    }
}
$rootRows = @(Get-ILRows $bound.GetMethod('ObserveRootTokenWithClassicBehavior',$instance))
if (@(Field-Indexes $rootRows 'Program+BoundAppContainerIdentity::_classicTokenReader').Count -ne 1 -or
    @(Field-Indexes $rootRows $networkField).Count -ne 0) {
    throw 'compiled_nonnetwork_reader_invalid:ObserveRootTokenWithClassicBehavior'
}
$classicBound = $bound.GetNestedType(
    'BoundClassicTokenObservation',[Reflection.BindingFlags]'Public,NonPublic'
)
$classicValidated = $bound.GetNestedType(
    'ValidatedClassicTokenObservation',[Reflection.BindingFlags]'Public,NonPublic'
)
if ($null -eq $classicBound -or $null -eq $classicValidated -or
    -not $classicBound.IsSealed -or -not $classicValidated.IsSealed) {
    throw 'compiled_classic_proof_surface_invalid'
}
$classicBoundConstructors = @($classicBound.GetConstructors($instance))
$classicValidatedConstructors = @($classicValidated.GetConstructors($instance))
if ($classicBoundConstructors.Count -ne 1 -or
    $classicBoundConstructors[0].GetParameters().Count -ne 6 -or
    $classicValidatedConstructors.Count -ne 1 -or
    $classicValidatedConstructors[0].GetParameters().Count -ne 5) {
    throw 'compiled_classic_proof_constructor_roster_invalid'
}
$classicDelegateCalls = @(0..($rootRows.Count - 1) | Where-Object {
    $rootRows[$_].Called -like 'System.Func*::Invoke'
})
$classicValidateCalls = @(
    Call-Indexes $rootRows `
        'Program+BoundAppContainerIdentity+BoundClassicTokenObservation::ValidateForRoot'
)
if ($classicDelegateCalls.Count -ne 1 -or $classicValidateCalls.Count -ne 1 -or
    $classicDelegateCalls[0] -ge $classicValidateCalls[0]) {
    throw 'compiled_root_classic_proof_flow_invalid'
}
$classicImportReaders = @(0..($importRows.Count - 1) | Where-Object {
    $importRows[$_].Name -ceq 'ldftn' -and
    $importRows[$_].Called -ceq 'Program::ReadTokenFactsAndObserveClassicBehavior'
})
if ($classicImportReaders.Count -ne 1) {
    throw 'compiled_imported_classic_delegate_invalid'
}
$classicReader = $program.GetMethod('ReadTokenFactsAndObserveClassicBehavior',$static)
$classicReaderRows = @(Get-ILRows $classicReader)
$classicFactsRead = @(Call-Indexes $classicReaderRows 'Program::ReadTokenFactsFromToken')
$classicEffectRead = @(Call-Indexes $classicReaderRows 'Program::ObserveClassicBehaviorWithToken')
$classicProofIssue = @(
    Call-Indexes $classicReaderRows `
        'Program+BoundAppContainerIdentity+BoundClassicTokenObservation::.ctor'
)
if ($classicFactsRead.Count -ne 1 -or $classicEffectRead.Count -ne 1 -or
    $classicProofIssue.Count -ne 1 -or
    $classicFactsRead[0] -ge $classicEffectRead[0] -or
    $classicEffectRead[0] -ge $classicProofIssue[0]) {
    throw 'compiled_classic_same_primary_source_invalid'
}
$classicFactsToken = $classicReaderRows[$classicFactsRead[0] - 2]
$classicEffectToken = $classicReaderRows[$classicEffectRead[0] - 3]
if ($classicFactsToken.Name -notlike 'ldloc*' -or
    $classicEffectToken.Name -notlike 'ldloc*' -or
    $null -eq $classicFactsToken.Variable -or
    $classicFactsToken.Variable -ne $classicEffectToken.Variable) {
    throw 'compiled_classic_same_primary_source_invalid'
}
$validateClassic = $classicBound.GetMethod('ValidateForRoot',$instance)
$validateClassicRows = @(Get-ILRows $validateClassic)
$classicIssuerCalls = @(
    Call-Indexes $validateClassicRows 'Program+BoundAppContainerIdentity::RequireProofIssuer'
)
$classicPolicyCalls = @(
    Call-Indexes $validateClassicRows `
        'Program+BoundAppContainerIdentity+LaunchAuthorizationProof::RequireRegularPolicyForProcess'
)
$classicFactValidation = @(Call-Indexes $validateClassicRows 'Program::ValidateFacts')
$classicPidCalls = @(Call-Indexes $validateClassicRows 'Program::GetProcessId')
$classicTokenIssue = @(
    Call-Indexes $validateClassicRows `
        'Program+BoundAppContainerIdentity+ValidatedTokenFacts::.ctor'
)
$classicValidatedIssue = @(
    Call-Indexes $validateClassicRows `
        'Program+BoundAppContainerIdentity+ValidatedClassicTokenObservation::.ctor'
)
if ($classicIssuerCalls.Count -ne 1 -or $classicPolicyCalls.Count -ne 1 -or
    $classicFactValidation.Count -ne 1 -or $classicPidCalls.Count -ne 1 -or
    $classicTokenIssue.Count -ne 1 -or $classicValidatedIssue.Count -ne 1 -or
    $classicIssuerCalls[0] -ge $classicPolicyCalls[0] -or
    $classicPolicyCalls[0] -ge $classicFactValidation[0] -or
    $classicFactValidation[0] -ge $classicPidCalls[0] -or
    $classicPidCalls[0] -ge $classicTokenIssue[0] -or
    $classicTokenIssue[0] -ge $classicValidatedIssue[0]) {
    throw 'compiled_root_classic_validation_flow_invalid'
}
$runBoundary = $program.GetMethod('RunBoundary',$static)
$boundaryRows = @(Get-ILRows $runBoundary)
$rootObservationCalls = @(
    Call-Indexes $boundaryRows `
        'Program+BoundAppContainerIdentity::ObserveRootTokenWithClassicBehavior'
)
$rootWireCalls = @(
    Call-Indexes $boundaryRows `
        'Program+BoundAppContainerIdentity+ValidatedClassicTokenObservation::BuildRootProcessObservation'
)
$rootPolicyWireCalls = @(
    Call-Indexes $boundaryRows `
        'Program+BoundAppContainerIdentity+ValidatedClassicTokenObservation::get_RegularLaunchPolicyBound'
)
$rootSourceWireCalls = @(
    Call-Indexes $boundaryRows `
        'Program+BoundAppContainerIdentity+ValidatedClassicTokenObservation::get_SamePrimaryTokenSourceBound'
)
if ($rootObservationCalls.Count -ne 1 -or $rootWireCalls.Count -ne 1 -or
    $rootPolicyWireCalls.Count -ne 1 -or $rootSourceWireCalls.Count -ne 1 -or
    $rootObservationCalls[0] -ge $rootWireCalls[0] -or
    $rootObservationCalls[0] -ge $rootPolicyWireCalls[0] -or
    $rootObservationCalls[0] -ge $rootSourceWireCalls[0]) {
    throw 'compiled_root_identity_proof_binding_invalid'
}
$fullNetworkCalls = @(Call-Indexes $boundaryRows 'Program::RunFullNetworkDifferential')
$aclCalls = @(Call-Indexes $boundaryRows 'Program::ValidateProtectedFileAcl')
$identityCalls = @(Call-Indexes $boundaryRows 'Program::ReadObjectIdentity')
$streamCalls = @(Call-Indexes $boundaryRows 'Program::ReadObjectStreams')
$contentCalls = @(Call-Indexes $boundaryRows 'System.IO.File::ReadAllBytes')
$deleteCalls = @(Call-Indexes $boundaryRows 'Program::DeleteTreeNoReparse')
$absenceCalls = @(Call-Indexes $boundaryRows 'System.IO.Directory::Exists')
$controlCalls = @(Call-Indexes $boundaryRows 'Program::ObserveExternalEchoControl')
if ($fullNetworkCalls.Count -ne 1 -or $controlCalls.Count -ne 2 -or
    $deleteCalls.Count -lt 1 -or $absenceCalls.Count -lt 1) {
    throw 'compiled_aap_lifecycle_surface_invalid'
}
$fullIndex = [int]$fullNetworkCalls[0]
$controlAfterIndex = [int]$controlCalls[1]
$deleteAfterFull = @($deleteCalls | Where-Object {
    $_ -gt $fullIndex -and $_ -lt $controlAfterIndex
})
if ($deleteAfterFull.Count -ne 1) { throw 'compiled_aap_delete_after_full_invalid' }
$deleteIndex = [int]$deleteAfterFull[0]
foreach ($freshCalls in @($aclCalls,$identityCalls,$streamCalls,$contentCalls)) {
    if (@($freshCalls | Where-Object { $_ -gt $fullIndex -and $_ -lt $deleteIndex }).Count -lt 2) {
        throw 'compiled_aap_post_full_revalidation_invalid'
    }
}
if (@($absenceCalls | Where-Object {
    $_ -gt $deleteIndex -and $_ -lt $controlAfterIndex
}).Count -ne 1) {
    throw 'compiled_aap_storage_absence_invalid'
}

$trackerType = $program.GetNestedType('FailureTracker',[Reflection.BindingFlags]'NonPublic')
$planType = $program.GetNestedType('NetworkArmPlan',[Reflection.BindingFlags]'NonPublic')
$stepType = $program.GetNestedType('NetworkTokenStep',[Reflection.BindingFlags]'NonPublic')
$factsType = $program.GetNestedType('TokenFacts',[Reflection.BindingFlags]'NonPublic')
$notObservedType = $program.GetNestedType('NotObservedException',[Reflection.BindingFlags]'NonPublic')
$setStage = $trackerType.GetMethod('SetStage',$instance)
$beginContext = $trackerType.GetMethod('BeginNetworkTokenObservation',$instance)
$enterContext = $contextType.GetMethod('Enter',$instance)
$substage = $trackerType.GetProperty('Substage',$instance)
$preflightPlan = $planType.GetMethod('PreflightZero',$static).Invoke($null,@())
$factsConstructor = @(
    $factsType.GetConstructors($instance) |
    Where-Object { $_.GetParameters().Count -eq 17 }
)
if ($factsConstructor.Count -ne 1) { throw 'compiled_fault_facts_constructor_invalid' }
$expectedSid = 'S-1-15-2-101-102-103-104-105-106-107-108'
function New-FaultPair {
    $tracker = [Activator]::CreateInstance($trackerType,$true)
    $null = $setStage.Invoke($tracker,[object[]]@('network_differential'))
    $tokenContext = $beginContext.Invoke($tracker,[object[]]@($preflightPlan))
    foreach ($stepName in @(
        'ReadBase','AapMembership','AapRosters','Lpac','Identity','AapEffect'
    )) {
        $step = [Enum]::Parse($stepType,$stepName,$false)
        $null = $enterContext.Invoke($tokenContext,[object[]]@($step))
    }
    return [pscustomobject]@{ Tracker=$tracker; Context=$tokenContext }
}
function New-FaultFacts([object]$Lpac,[bool]$LpacSupported,[uint32]$GroupMatches) {
    return $factsConstructor[0].Invoke([object[]]@(
        $true,$expectedSid,[uint32]1,'S-1-15-3-1|0x00000004',[uint32]9,
        $GroupMatches,'0x00000007',[uint32]4,[uint32]0,'',[uint32]0x1000,
        $false,$Lpac,$LpacSupported,$true,$null,$true
    ))
}
function Require-NotObservedMarker(
    [object]$Pair,[object]$Facts,[string]$ExpectedSubstage,[string]$Failure
) {
    try {
        $null = $validate.Invoke(
            $null,[object[]]@($Facts,$expectedSid,'network_preflight_zero',$Pair.Context)
        )
        throw $Failure
    } catch {
        $inner = $_.Exception
        while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        if ($inner.GetType() -ne $notObservedType -or
            [string]$substage.GetValue($Pair.Tracker) -cne $ExpectedSubstage) {
            throw $Failure
        }
    }
}
$lpacOptional = New-FaultPair
$null = $validate.Invoke(
    $null,[object[]]@(
        (New-FaultFacts $null $false 1),$expectedSid,
        'network_preflight_zero',$lpacOptional.Context
    )
)
if ([string]$substage.GetValue($lpacOptional.Tracker) -cne
    'network_preflight_zero_token_validate_roster') {
    throw 'compiled_optional_lpac_diagnostic_invalid'
}
$lpacTrue = New-FaultPair
try {
    $null = $validate.Invoke(
        $null,[object[]]@(
            (New-FaultFacts $true $true 1),$expectedSid,
            'network_preflight_zero',$lpacTrue.Context
        )
    )
    throw 'compiled_lpac_true_accepted'
} catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    if ($inner.GetType() -eq $notObservedType -or
        $inner.Message -cne 'network_preflight_zero_unexpected_lpac' -or
        [string]$substage.GetValue($lpacTrue.Tracker) -cne
            'network_preflight_zero_token_validate_lpac') {
        throw 'compiled_lpac_true_rejection_invalid'
    }
}
$rosterFault = New-FaultPair
Require-NotObservedMarker `
    $rosterFault (New-FaultFacts $false $true 0) `
    'network_preflight_zero_token_validate_roster' `
    'compiled_validate_roster_fault_marker_invalid'

$entry = $program.GetMethod('Entry',[Reflection.BindingFlags]'Public,Static')
$missingRoot = [IO.Path]::Combine([IO.Path]::GetDirectoryName($assemblyPath),'missing-runtime')
$arguments = [string[]]@(
    'parent','finplanbrac-context-flow',$missingRoot,$missingRoot,'QQ==',('a' * 64),
    'e30=',('b' * 64),'e30=',('c' * 64)
)
$original = [Console]::Out
$writer = [IO.StringWriter]::new([Globalization.CultureInfo]::InvariantCulture)
try {
    [Console]::SetOut($writer)
    $rc = [int]$entry.Invoke($null,[object[]](,$arguments))
} finally { [Console]::SetOut($original) }
if ($rc -ne 1) { throw 'entry_not_observed_rc_invalid' }
$document = [Text.Json.JsonDocument]::Parse($writer.ToString())
try {
    $root = $document.RootElement
    $receipt = $root.GetProperty('helper_failure_receipt')
    if ($root.GetProperty('status').GetString() -cne 'not_observed' -or
        $receipt.GetProperty('status').GetString() -cne 'not_observed' -or
        $receipt.GetProperty('failure_class').GetString() -cne 'not_observed') {
        throw 'entry_not_observed_reclassified'
    }
} finally { $document.Dispose() }
Write-Output 'compiled_context_flow_gate_ok'
'''

        def run_compiled_flow_candidate(
            source_text: str,
        ) -> subprocess.CompletedProcess[str]:
            directory = tempfile.mkdtemp(prefix="finplanbr-context-flow-")
            self.addCleanup(shutil.rmtree, directory, True)
            root = Path(directory)
            source_path = root / "Program.cs"
            assembly = root / "helper.dll"
            script_path = root / "inspect.ps1"
            source_path.write_text(source_text, encoding="utf-8")
            script_path.write_text(mutation_gate_script, encoding="utf-8")
            environment = os.environ.copy()
            environment["FPBR_SOURCE"] = os.fspath(source_path)
            environment["FPBR_ASSEMBLY"] = os.fspath(assembly)
            return subprocess.run(
                [pwsh, "-NoProfile", "-File", os.fspath(script_path)],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )

        source = PROGRAM_SOURCE.read_text(encoding="utf-8")
        gate_baseline = run_compiled_flow_candidate(source)
        self.assertEqual(gate_baseline.returncode, 0, gate_baseline.stderr)
        self.assertIn("compiled_context_flow_gate_ok", gate_baseline.stdout)

        observe_order_block = (
            '            Program.ValidateFacts(facts, CanonicalSid, "network_" '
            "+ plan.Label, context);\n"
            "            bool aapPositiveReadSha256Matches = string.Equals(\n"
            "                aapSha256,\n"
            "                expectedAapSha256,\n"
            "                StringComparison.Ordinal\n"
            "            );\n"
            "            bool aapNegativeAccessDenied = noAapError == ErrorAccessDenied;\n"
            "            if (!aapPositiveReadSha256Matches || !aapNegativeAccessDenied)\n"
            "            {\n"
            "                throw new NotObservedException(\n"
            '                    "network_regular_appcontainer_effect_not_observed"\n'
            "                );\n"
            "            }\n"
            "            context.Enter(NetworkTokenStep.Bind);\n"
            "            uint processId = GetProcessId(process);\n"
            "            if (processId == 0) ThrowLastError("
            '"GetProcessId(validated network token issue)");\n'
            "            ValidatedTokenFacts result = new(\n"
            "                _proofIssuer,\n"
            "                this,\n"
            "                facts,\n"
            "                process,\n"
            "                processId,\n"
            "                TokenObservationRole.NetworkArm,\n"
            "                plan.Label,\n"
            "                plan.Order,\n"
            "                true,\n"
            "                aapPositiveReadSha256Matches,\n"
            "                aapNegativeAccessDenied\n"
            "            );\n"
            "            context.RequireComplete();"
        )
        bind_before_validation_block = observe_order_block.replace(
            '            Program.ValidateFacts(facts, CanonicalSid, "network_" '
            "+ plan.Label, context);\n",
            "            context.Enter(NetworkTokenStep.Bind);\n"
            '            Program.ValidateFacts(facts, CanonicalSid, "network_" '
            "+ plan.Label, context);\n",
            1,
        ).replace(
            "            context.Enter(NetworkTokenStep.Bind);\n"
            "            uint processId = GetProcessId(process);\n",
            "            uint processId = GetProcessId(process);\n",
            1,
        )
        bind_after_get_process_id_block = observe_order_block.replace(
            "            context.Enter(NetworkTokenStep.Bind);\n"
            "            uint processId = GetProcessId(process);\n",
            "            uint processId = GetProcessId(process);\n"
            "            context.Enter(NetworkTokenStep.Bind);\n",
            1,
        )
        bind_after_proof_block = observe_order_block.replace(
            "            context.Enter(NetworkTokenStep.Bind);\n",
            "",
            1,
        ).replace(
            "            );\n"
            "            context.RequireComplete();",
            "            );\n"
            "            context.Enter(NetworkTokenStep.Bind);\n"
            "            context.RequireComplete();",
            1,
        )
        bind_after_completion_block = observe_order_block.replace(
            "            context.Enter(NetworkTokenStep.Bind);\n",
            "",
            1,
        ).replace(
            "            context.RequireComplete();",
            "            context.RequireComplete();\n"
            "            context.Enter(NetworkTokenStep.Bind);",
            1,
        )
        self.assertEqual(source.count(observe_order_block), 1)
        post_full_revalidation_block = (
            "            List<SortedDictionary<string, object?>> "
            "lanAppContainerArms = fullNetwork.Arms;\n"
            "            ValidateProtectedFileAcl(\n"
            "                aapProbePath,\n"
            '                new SecurityIdentifier("S-1-15-2-1"),\n'
            "                FileSystemRights.Read | FileSystemRights.Synchronize\n"
            "            );\n"
            "            ValidateProtectedFileAcl(noAapProbePath, null, 0);\n"
            "            aapObjectIdentityRevalidated = aapObjectIdentityRevalidated\n"
            "                && aapIdentityBefore == ReadObjectIdentity(aapProbePath)\n"
            "                && noAapIdentityBefore == ReadObjectIdentity(noAapProbePath)\n"
            '                && ReadObjectStreams(aapProbePath).SequenceEqual(new[] { "::$DATA" })\n'
            '                && ReadObjectStreams(noAapProbePath).SequenceEqual(new[] { "::$DATA" });\n'
            "            aapProbeContentsRevalidated = aapProbeContentsRevalidated\n"
            "                && File.ReadAllBytes(aapProbePath).SequenceEqual(aapProbeBytes)\n"
            "                && File.ReadAllBytes(noAapProbePath).SequenceEqual(aapProbeBytes);"
        )
        self.assertEqual(source.count(post_full_revalidation_block), 1)

        compiled_mutations = {
            "bind_before_validation": (
                observe_order_block,
                bind_before_validation_block,
                "compiled_validate_before_bind_invalid",
            ),
            "bind_after_get_process_id": (
                observe_order_block,
                bind_after_get_process_id_block,
                "compiled_bind_before_get_process_id_invalid",
            ),
            "bind_after_proof_construction": (
                observe_order_block,
                bind_after_proof_block,
                "compiled_bind_before_proof_construction_invalid",
            ),
            "bind_after_completion": (
                observe_order_block,
                bind_after_completion_block,
                "compiled_bind_before_completion_invalid",
            ),
            "begin_launch_policy_setter_removed": (
                "            SetSubstage(plan.TokenSubstage(NetworkTokenStep.LaunchPolicy));\n",
                "",
                "compiled_begin_launch_policy_flow_invalid",
            ),
            "read_base_marker_removed": (
                "            context.Enter(NetworkTokenStep.ReadBase);\n",
                "",
                "compiled_observer_bind_complete_invalid",
            ),
            "imported_network_delegate_ignores_context": (
                "                    ReadTokenFacts,\n"
                "                    ReadNetworkTokenFactsAndObserveClassicBehavior,\n"
                "                    ReadTokenFactsAndObserveClassicBehavior",
                "                    ReadTokenFacts,\n"
                "                    static (process, _, aap, noAap) =>\n"
                "                        ReadNetworkTokenFactsAndObserveClassicBehavior(\n"
                "                            process, null!, aap, noAap),\n"
                "                    ReadTokenFactsAndObserveClassicBehavior",
                "compiled_imported_network_delegate_invalid",
            ),
            "aap_membership_marker_after_operation": (
                "            context?.Enter(NetworkTokenStep.AapMembership);\n"
                "            bool hasAllApplicationPackages = "
                'CheckAppContainerMembership(token, "S-1-15-2-1");',
                "            bool hasAllApplicationPackages = "
                'CheckAppContainerMembership(token, "S-1-15-2-1");\n'
                "            context?.Enter(NetworkTokenStep.AapMembership);",
                "compiled_membership_marker_order_invalid",
            ),
            "identity_marker_after_first_read": (
                "            context?.Enter(NetworkTokenStep.Identity);\n"
                "            IntPtr appContainerBuffer = "
                "ReadTokenInformation(token, TokenAppContainerSid);",
                "            IntPtr appContainerBuffer = "
                "ReadTokenInformation(token, TokenAppContainerSid);\n"
                "            context?.Enter(NetworkTokenStep.Identity);",
                "compiled_identity_marker_order_invalid",
            ),
            "aap_effect_marker_after_operation": (
                "            context.Enter(NetworkTokenStep.AapEffect);\n"
                "            (string aapSha256, uint noAapError) = "
                "ObserveClassicBehaviorWithToken(\n"
                "                token,\n"
                "                aapProbePath,\n"
                "                noAapProbePath\n"
                "            );",
                "            (string aapSha256, uint noAapError) = "
                "ObserveClassicBehaviorWithToken(\n"
                "                token,\n"
                "                aapProbePath,\n"
                "                noAapProbePath\n"
                "            );\n"
                "            context.Enter(NetworkTokenStep.AapEffect);",
                "compiled_network_reader_effect_flow_invalid",
            ),
            "validate_lpac_marker_after_faults": (
                "        context?.Enter(NetworkTokenStep.ValidateLpac);\n"
                "        if (facts.IsLessPrivilegedAppContainer is true) "
                'throw new InvalidOperationException(view + "_unexpected_lpac");\n'
                "        if (facts.LpacQuerySupported != "
                "(facts.IsLessPrivilegedAppContainer is not null))\n"
                "        {\n"
                '            throw new InvalidOperationException(view + "_lpac_query_state_invalid");\n'
                "        }",
                "        if (facts.IsLessPrivilegedAppContainer is true) "
                'throw new InvalidOperationException(view + "_unexpected_lpac");\n'
                "        if (facts.LpacQuerySupported != "
                "(facts.IsLessPrivilegedAppContainer is not null))\n"
                "        {\n"
                '            throw new InvalidOperationException(view + "_lpac_query_state_invalid");\n'
                "        }\n"
                "        context?.Enter(NetworkTokenStep.ValidateLpac);",
                "compiled_validate_lpac_marker_order_invalid",
            ),
            "validate_roster_marker_after_fault": (
                "        context?.Enter(NetworkTokenStep.ValidateRoster);\n"
                "        if (facts.AllApplicationPackagesTokenGroupMatchCount\n"
                "                + facts.AllApplicationPackagesRestrictedSidMatchCount == 0)\n"
                "        {\n"
                "            throw new NotObservedException("
                'view + "_aap_sid_not_observed_in_token_rosters");\n'
                "        }",
                "        if (facts.AllApplicationPackagesTokenGroupMatchCount\n"
                "                + facts.AllApplicationPackagesRestrictedSidMatchCount == 0)\n"
                "        {\n"
                "            throw new NotObservedException("
                'view + "_aap_sid_not_observed_in_token_rosters");\n'
                "        }\n"
                "        context?.Enter(NetworkTokenStep.ValidateRoster);",
                "compiled_validate_roster_fault_marker_invalid",
            ),
            "reader_nulls_context": (
                "            TokenFacts facts = ReadTokenFactsFromToken(token, context);",
                "            TokenFacts facts = ReadTokenFactsFromToken(token, null);",
                "compiled_network_reader_context_invalid",
            ),
            "validator_nulls_context": (
                'Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label, context);',
                'Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label, null);',
                "compiled_observer_validator_context_invalid",
            ),
            "entry_reclassifies_not_observed": (
                "        catch (NotObservedException)\n"
                "        {\n"
                "            return EmitBoundaryFailure(\n"
                '                "not_observed",\n'
                "                failureTracker.Stage,\n"
                "                failureTracker.Substage,\n"
                '                "not_observed"\n'
                "            );\n"
                "        }",
                "        catch (NotObservedException error)\n"
                "        {\n"
                "            return EmitBoundaryFailure(\n"
                '                "failed",\n'
                "                failureTracker.Stage,\n"
                "                failureTracker.Substage,\n"
                "                Sanitize(error)\n"
                "            );\n"
                "        }",
                "entry_not_observed_reclassified",
            ),
            "child_consumes_network_reader_with_null": (
                "                _tokenReader(process),\n"
                "                process,\n"
                '                "child",',
                "                _networkTokenReader(\n"
                "                    process, null!, string.Empty, string.Empty\n"
                "                ).Facts,\n"
                "                process,\n"
                '                "child",',
                "compiled_nonnetwork_reader_invalid:ObserveChildToken",
            ),
            "launch_policy_requirement_removed": (
                "            context.RequirePlan(plan);\n"
                "            launchAuthorization.RequireRegularPolicyForProcess(process);\n"
                "            context.Enter(NetworkTokenStep.ReadBase);",
                "            context.RequirePlan(plan);\n"
                "            context.Enter(NetworkTokenStep.ReadBase);",
                "compiled_observer_launch_policy_flow_invalid",
            ),
            "aap_sha_match_forged": (
                "            bool aapPositiveReadSha256Matches = string.Equals(\n"
                "                aapSha256,\n"
                "                expectedAapSha256,\n"
                "                StringComparison.Ordinal\n"
                "            );",
                "            bool aapPositiveReadSha256Matches = true;",
                "compiled_aap_sha_binding_invalid",
            ),
            "aap_access_denied_forged": (
                "            bool aapNegativeAccessDenied = "
                "noAapError == ErrorAccessDenied;",
                "            bool aapNegativeAccessDenied = true;",
                "compiled_aap_access_denied_binding_invalid",
            ),
            "aap_effect_uses_different_token": (
                "            (string aapSha256, uint noAapError) = "
                "ObserveClassicBehaviorWithToken(\n"
                "                token,\n"
                "                aapProbePath,\n"
                "                noAapProbePath\n"
                "            );",
                "            (string aapSha256, uint noAapError) = "
                "ObserveClassicBehaviorWithToken(\n"
                "                IntPtr.Zero,\n"
                "                aapProbePath,\n"
                "                noAapProbePath\n"
                "            );",
                "compiled_same_token_effect_binding_invalid",
            ),
            "all_application_packages_policy_attribute_injected": (
                "0x00020009",
                "0x0002000F",
                "compiled_forbidden_aap_policy_attribute",
            ),
            "lpac_error_class_changed": (
                "error.NativeErrorCode == 87",
                "error.NativeErrorCode == ErrorAccessDenied",
                "compiled_lpac_unsupported_error_binding_invalid",
            ),
            "lpac_null_promoted_false": (
                "        => (null, false);",
                "        => (false, false);",
                "compiled_optional_lpac_diagnostic_invalid",
            ),
            "lpac_unsupported_promoted_supported": (
                "        => (null, false);",
                "        => (null, true);",
                "compiled_optional_lpac_diagnostic_invalid",
            ),
            "classic_split_primary_source": (
                "            TokenFacts facts = "
                "ReadTokenFactsFromToken(primaryToken, null);",
                "            TokenFacts facts = ReadTokenFacts(processHandle);",
                "compiled_classic_same_primary_source_invalid",
            ),
            "root_regular_policy_bypassed": (
                "                launchAuthorization."
                "RequireRegularPolicyForProcess(process);\n"
                '                Program.ValidateFacts(_facts, _owner.CanonicalSid, "root");',
                '                Program.ValidateFacts(_facts, _owner.CanonicalSid, "root");',
                "compiled_root_classic_validation_flow_invalid",
            ),
        }
        for name, (old, new, expected_failure) in compiled_mutations.items():
            with self.subTest(compiled_context_flow_mutant=name):
                self.assertEqual(source.count(old), 1)
                mutant = source.replace(old, new, 1)
                self.assertNotEqual(mutant, source, f"no-op mutant: {name}")
                result = run_compiled_flow_candidate(mutant)
                self.assertNotEqual(
                    result.returncode,
                    0,
                    f"compiled/functional mutant survived: {name}\n{result.stdout}",
                )
                self.assertNotIn("Add-Type:", result.stderr)
                self.assertIn(expected_failure, result.stderr)

        coherent_compiled_mutations = {
            "root_identity_flags_hardcoded": (
                source.replace(
                    "rootTokenObservation.RegularLaunchPolicyBound,",
                    "true,",
                    1,
                ).replace(
                    "rootTokenObservation.SamePrimaryTokenSourceBound,",
                    "true,",
                    1,
                ),
                "compiled_root_identity_proof_binding_invalid",
            ),
            "aap_delete_before_full": (
                source.replace(
                    "            DeleteTreeNoReparse(identityRoot);\n",
                    "",
                    1,
                ).replace(
                    "            FullNetworkDifferentialResult fullNetwork = "
                    "RunFullNetworkDifferential(\n",
                    "            DeleteTreeNoReparse(identityRoot);\n"
                    "            FullNetworkDifferentialResult fullNetwork = "
                    "RunFullNetworkDifferential(\n",
                    1,
                ),
                "compiled_aap_delete_after_full_invalid",
            ),
            "aap_post_full_revalidation_cached": (
                source.replace(
                    post_full_revalidation_block,
                    "            List<SortedDictionary<string, object?>> "
                    "lanAppContainerArms = fullNetwork.Arms;\n"
                    "            aapObjectIdentityRevalidated = "
                    "aapObjectIdentityRevalidated && true;\n"
                    "            aapProbeContentsRevalidated = "
                    "aapProbeContentsRevalidated && true;",
                    1,
                ),
                "compiled_aap_post_full_revalidation_invalid",
            ),
            "aap_delete_removed_storage_forged": (
                source.replace(
                    "            DeleteTreeNoReparse(identityRoot);\n"
                    "            bool aapProbeStorageRemoved = "
                    "!Directory.Exists(identityRoot);",
                    "            bool aapProbeStorageRemoved = true;",
                    1,
                ),
                "compiled_aap_delete_after_full_invalid",
            ),
        }
        for name, (mutant, expected_failure) in coherent_compiled_mutations.items():
            with self.subTest(compiled_coherent_mutant=name):
                self.assertNotEqual(mutant, source, f"no-op mutant: {name}")
                result = run_compiled_flow_candidate(mutant)
                self.assertNotEqual(
                    result.returncode,
                    0,
                    f"compiled/functional mutant survived: {name}\n{result.stdout}",
                )
                self.assertNotIn("Add-Type:", result.stderr)
                self.assertIn(expected_failure, result.stderr)

    @unittest.skipUnless(os.name == "nt", "compiled helper reflection is Windows-only")
    def test_compiled_authority_and_functional_proofs(self) -> None:
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("PowerShell 7 compiler is unavailable")
        script = r'''
$ErrorActionPreference = 'Stop'
$sourcePath = [Environment]::GetEnvironmentVariable('FPBR_SOURCE','Process')
$assemblyPath = [Environment]::GetEnvironmentVariable('FPBR_ASSEMBLY','Process')
$compiled = @(Add-Type -Path $sourcePath -OutputAssembly $assemblyPath -OutputType Library -PassThru)
$program = @($compiled | Where-Object FullName -CEQ 'Program')
if ($program.Count -ne 1) { throw 'program_type_invalid' }
$program = $program[0]
$static = [Reflection.BindingFlags] 'Public,NonPublic,Static,DeclaredOnly'
$instance = [Reflection.BindingFlags] 'Public,NonPublic,Instance'
$allStatic = @($program.GetMethods($static))
$legacy = @(
    'CreateAppContainerProfile',
    'DeleteAppContainerProfile',
    'DeriveAppContainerSidFromAppContainerName',
    'FreeSid'
)
$pinvokes = @($allStatic | Where-Object {
    @($_.GetCustomAttributes([Runtime.InteropServices.DllImportAttribute],$false)).Count -ne 0
})
if (@($pinvokes | Where-Object { $legacy -ccontains $_.Name }).Count -ne 0) {
    throw 'compiled_profile_authority_present'
}
if ($null -ne $program.GetMethod('Run', $static)) { throw 'legacy_run_compiled' }
$entry = $program.GetMethod('Entry', $static)
$runBoundary = $program.GetMethod('RunBoundary', $static)
if ($null -eq $entry -or $null -eq $runBoundary) { throw 'entry_boundary_missing' }

function Get-CalledMethodNames {
    param([Reflection.MethodInfo] $Method)
    $opcodeByValue = @{}
    foreach ($field in [Reflection.Emit.OpCodes].GetFields([Reflection.BindingFlags] 'Public,Static')) {
        $opcode = $field.GetValue($null)
        $value = [int] $opcode.Value
        if ($value -lt 0) { $value += 65536 }
        $opcodeByValue[$value] = $opcode
    }
    $bytes = $Method.GetMethodBody().GetILAsByteArray()
    $calls = @()
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $first = [int] $bytes[$offset]; $offset += 1
        if ($first -eq 0xFE) { $value = 0xFE00 -bor [int]$bytes[$offset]; $offset += 1 } else { $value = $first }
        $opcode = $opcodeByValue[$value]
        if ($null -eq $opcode) { throw 'unknown_il_opcode' }
        $operandOffset = $offset
        switch ([string]$opcode.OperandType) {
            'InlineNone' { $size = 0 }
            'ShortInlineBrTarget' { $size = 1 }
            'ShortInlineI' { $size = 1 }
            'ShortInlineVar' { $size = 1 }
            'InlineVar' { $size = 2 }
            'InlineI8' { $size = 8 }
            'InlineR' { $size = 8 }
            'ShortInlineR' { $size = 4 }
            'InlineSwitch' { $size = 4 + 4 * [BitConverter]::ToInt32($bytes,$offset) }
            default { $size = 4 }
        }
        if (($opcode.Name -ceq 'call' -or $opcode.Name -ceq 'callvirt') -and $size -eq 4) {
            $token = [BitConverter]::ToInt32($bytes,$operandOffset)
            $resolved = $Method.Module.ResolveMethod($token)
            $calls += ($resolved.DeclaringType.FullName + '::' + $resolved.Name)
        }
        $offset += $size
    }
    return @($calls)
}
$entryCalls = @(Get-CalledMethodNames $entry)
if (@($entryCalls | Where-Object { $_ -ceq 'Program::RunBoundary' }).Count -ne 1) {
    throw 'entry_does_not_call_boundary_once'
}

$bound = $program.GetNestedType('BoundAppContainerIdentity',[Reflection.BindingFlags]'NonPublic')
$tokenFactsType = $program.GetNestedType('TokenFacts',[Reflection.BindingFlags]'NonPublic')
$pathType = $program.GetNestedType('PathIdentityBinding',[Reflection.BindingFlags]'NonPublic')
$securityType = $program.GetNestedType('SecurityCapabilities',[Reflection.BindingFlags]'NonPublic')
if ($null -eq $bound -or $null -eq $tokenFactsType -or $null -eq $pathType -or $null -eq $securityType) {
    throw 'proof_types_missing'
}
$validatedToken = $bound.GetNestedType('ValidatedTokenFacts',[Reflection.BindingFlags]'Public,NonPublic')
$validatedProfile = $bound.GetNestedType('ValidatedProfileIdentity',[Reflection.BindingFlags]'Public,NonPublic')
$launchProof = $bound.GetNestedType('LaunchAuthorizationProof',[Reflection.BindingFlags]'Public,NonPublic')
$boundClassic = $bound.GetNestedType(
    'BoundClassicTokenObservation',[Reflection.BindingFlags]'Public,NonPublic'
)
$validatedClassic = $bound.GetNestedType(
    'ValidatedClassicTokenObservation',[Reflection.BindingFlags]'Public,NonPublic'
)
foreach ($proof in @($validatedToken,$validatedProfile,$launchProof,$boundClassic,$validatedClassic)) {
    if ($null -eq $proof -or -not $proof.IsSealed) { throw 'proof_type_not_sealed' }
}
if ($null -ne $launchProof.GetProperty('Pointer',$instance)) { throw 'raw_pointer_exposed' }
if ($null -ne $launchProof.GetMethod('ApplyToAttributeList',$instance)) {
    throw 'separable_apply_method_present'
}
$consume = $launchProof.GetMethod('CreateSuspendedProcess',$instance)
if ($null -eq $consume) { throw 'atomic_launch_consumer_missing' }

$pathCtor = @($pathType.GetConstructors($instance) | Where-Object { $_.GetParameters().Count -eq 4 })
$boundCtor = @($bound.GetConstructors($instance) | Where-Object { $_.GetParameters().Count -eq 7 })
if ($pathCtor.Count -ne 1 -or $boundCtor.Count -ne 1) { throw 'context_constructor_roster_invalid' }
$probePath = [IO.Path]::GetDirectoryName($assemblyPath)
$readIdentity = $program.GetMethod('ReadPathIdentityBinding',$static)
$identity = $readIdentity.Invoke($null,[object[]]@($probePath))
$profileReaderType = [Func``2].MakeGenericType([string],$pathType)
$profileReader = $readIdentity.CreateDelegate($profileReaderType)
$readToken = $program.GetMethod('ReadTokenFacts',$static)
$readNetworkToken = $program.GetMethod('ReadNetworkTokenFactsAndObserveClassicBehavior',$static)
$readClassic = $program.GetMethod('ReadTokenFactsAndObserveClassicBehavior',$static)
$tokenReader = $readToken.CreateDelegate($boundCtor[0].GetParameters()[4].ParameterType)
$networkTokenReader = $readNetworkToken.CreateDelegate(
    $boundCtor[0].GetParameters()[5].ParameterType
)
$classicReader = $readClassic.CreateDelegate($boundCtor[0].GetParameters()[6].ParameterType)
$sid = 'S-1-15-2-101-102-103-104-105-106-107-108'
$context = $boundCtor[0].Invoke(
    [object[]]@(
        [IntPtr]0x12345,$sid,$identity,$profileReader,$tokenReader,
        $networkTokenReader,$classicReader
    )
)

$factsCtor = @($tokenFactsType.GetConstructors($instance) | Where-Object { $_.GetParameters().Count -eq 17 })
if ($factsCtor.Count -ne 1) { throw 'token_facts_ctor_invalid' }
function New-Facts([string]$Sid) {
    return $factsCtor[0].Invoke([object[]]@(
        $true,$Sid,[uint32]1,'S-1-15-3-1|0x00000004',[uint32]9,
        [uint32]1,'0x00000007',[uint32]4,[uint32]0,'',[uint32]0x1000,
        $false,$false,$true,$true,$null,$true
    ))
}
$validFacts = New-Facts $sid
$wrongFacts = New-Facts 'S-1-15-2-201-202-203-204-205-206-207-208'
$validate = $bound.GetMethod('ValidateObservedToken',$instance)
$roleType = $bound.GetNestedType('TokenObservationRole',[Reflection.BindingFlags]'Public,NonPublic')
$currentProcess = [Diagnostics.Process]::GetCurrentProcess()
$currentHandle = $currentProcess.Handle
$currentPid = [uint32]$currentProcess.Id
$tokenCases = @(
    [pscustomobject]@{ Role='Root'; View='root'; Label=$null; Order=$null },
    [pscustomobject]@{ Role='Child'; View='child'; Label=$null; Order=$null },
    [pscustomobject]@{ Role='Grandchild'; View='grandchild'; Label=$null; Order=$null },
    [pscustomobject]@{ Role='NetworkArm'; View='network_preflight_zero'; Label='preflight_zero'; Order=0 },
    [pscustomobject]@{ Role='NetworkArm'; View='network_zero_1'; Label='zero_1'; Order=1 },
    [pscustomobject]@{ Role='NetworkArm'; View='network_internet_client_1'; Label='internet_client_1'; Order=2 },
    [pscustomobject]@{ Role='NetworkArm'; View='network_internet_client_2'; Label='internet_client_2'; Order=3 },
    [pscustomobject]@{ Role='NetworkArm'; View='network_zero_2'; Label='zero_2'; Order=4 }
)
foreach ($case in $tokenCases) {
    $role = [Enum]::Parse($roleType,$case.Role)
    try {
        $null = $validate.Invoke(
            $context,
            [object[]]@($wrongFacts,$currentHandle,$case.View,$role,$case.Label,$case.Order)
        )
        throw 'wrong_sid_accepted'
    } catch {
        $inner = $_.Exception
        while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        if (-not $inner.Message.EndsWith('_sid_mismatch',[StringComparison]::Ordinal)) { throw }
    }
}

$childRole = [Enum]::Parse($roleType,'Child')
$childProof = $validate.Invoke($context,[object[]]@($validFacts,$currentHandle,'child',$childRole,$null,$null))
if ([uint32]$childProof.GetType().GetProperty('ProcessId',$instance).GetValue($childProof) -ne $currentPid) {
    throw 'child_proof_pid_not_bound'
}
$wrongRoleDoc = [Text.Json.JsonDocument]::Parse('{"role":"root","pid":'+$currentPid+',"parent_pid":1}')
try {
    $null = $childProof.GetType().GetMethod('BuildProcessObservation',$instance).Invoke(
        $childProof,[object[]]@($currentHandle,$wrongRoleDoc.RootElement)
    )
    throw 'child_proof_relabel_accepted'
} catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    if ($inner.Message -cne 'validated_token_report_role_mismatch') { throw }
}
$networkRole = [Enum]::Parse($roleType,'NetworkArm')
$issuer = $bound.GetField('_proofIssuer',$instance).GetValue($context)
$validatedCtor = @($validatedToken.GetConstructors($instance) | Where-Object {
    $_.GetParameters().Count -eq 11
})
if ($validatedCtor.Count -ne 1) { throw 'validated_token_constructor_roster_invalid' }
$networkProof = $validatedCtor[0].Invoke(
    [object[]]@(
        $issuer,$context,$validFacts,$currentHandle,$currentPid,$networkRole,
        'zero_1',1,$true,$true,$true
    )
)
$networkWire = $networkProof.GetType().GetMethod('NetworkTokenWire',$instance).Invoke(
    $networkProof,[object[]]@($currentHandle)
)
if ($networkWire.ValueKind -cne [Text.Json.JsonValueKind]::Object) {
    throw 'network_proof_wire_invalid'
}
if ($networkProof.GetType().GetProperty('ArmLabel',$instance).GetValue($networkProof) -cne 'zero_1') {
    throw 'network_proof_label_not_bound'
}
if ([int]$networkProof.GetType().GetProperty('ArmOrder',$instance).GetValue($networkProof) -ne 1) {
    throw 'network_proof_order_not_bound'
}
$regularWire = $networkProof.GetType().GetMethod(
    'NetworkRegularAppContainerWire',$instance
).Invoke($networkProof,[object[]]@($currentHandle))
$regularNames = @($regularWire.EnumerateObject() | ForEach-Object Name)
$expectedRegularNames =
    'aap_negative_access_denied,aap_positive_read_sha256_matches,claim,' +
    'regular_launch_policy_bound,same_primary_token_source_bound'
if ($regularWire.ValueKind -cne [Text.Json.JsonValueKind]::Object -or
    ($regularNames -join ',') -cne $expectedRegularNames -or
    -not $regularWire.GetProperty('aap_negative_access_denied').GetBoolean() -or
    -not $regularWire.GetProperty('aap_positive_read_sha256_matches').GetBoolean() -or
    $regularWire.GetProperty('claim').GetString() -cne
        'regular_appcontainer_effect_observed_from_same_primary_token_source' -or
    -not $regularWire.GetProperty('regular_launch_policy_bound').GetBoolean() -or
    -not $regularWire.GetProperty('same_primary_token_source_bound').GetBoolean()) {
    throw 'network_regular_appcontainer_wire_invalid'
}
foreach ($invalidProofFlags in @(
    @($false,$true,$true),
    @($true,$false,$true),
    @($true,$true,$false)
)) {
    try {
        $null = $validatedCtor[0].Invoke(
            [object[]]@(
                $issuer,$context,$validFacts,$currentHandle,$currentPid,$networkRole,
                'zero_1',1,$invalidProofFlags[0],$invalidProofFlags[1],
                $invalidProofFlags[2]
            )
        )
        throw 'incomplete_network_regular_appcontainer_proof_accepted'
    } catch {
        $inner = $_.Exception
        while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        if ($inner.Message -cne 'network_regular_appcontainer_proof_incomplete') { throw }
    }
}
try {
    $null = $networkProof.GetType().GetMethod('NetworkTokenWire',$instance).Invoke(
        $networkProof,[object[]]@([IntPtr]0x2222)
    )
    throw 'network_proof_wrong_handle_accepted'
} catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    if ($inner.Message -cne 'validated_token_process_mismatch') { throw }
}

$initial = $bound.GetMethod('ObserveInitialProfileFolderIdentity',$instance).Invoke($context,[object[]]@($probePath))
$observeFinal = $bound.GetMethod('ObserveFinalProfileFolderIdentity',$instance)
$final = $observeFinal.Invoke($context,[object[]]@($probePath,$initial))
if ($final.GetType() -ne $validatedProfile) { throw 'final_profile_proof_invalid' }
$driftPath = [string]$assemblyPath
try {
    $null = $observeFinal.Invoke($context,[object[]]@($driftPath,$initial))
    throw 'final_profile_drift_accepted'
} catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    if ($inner.Message -cne 'profile_folder_identity_changed_from_prelaunch') { throw }
}
$before = $bound.GetMethod('ObserveNetworkProfileFolderBefore',$instance).Invoke($context,[object[]]@($probePath))
$after = $bound.GetMethod('ObserveNetworkProfileFolderAfter',$instance).Invoke($context,[object[]]@($probePath,$before))
if ($after.GetType() -ne $validatedProfile) { throw 'network_profile_proof_invalid' }
$beforeDrift = $bound.GetMethod('ObserveNetworkProfileFolderBefore',$instance).Invoke($context,[object[]]@($probePath))
try {
    $observeNetworkAfter = $bound.GetMethod('ObserveNetworkProfileFolderAfter',$instance)
    $null = $observeNetworkAfter.Invoke($context,[object[]]@($driftPath,$beforeDrift))
    throw 'network_profile_drift_accepted'
} catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    if ($inner.Message -cne 'network_profile_folder_identity_changed') { throw }
}

Add-Type -TypeDefinition @'
using System;
public static class LaunchProofSentinel {
    public static int Calls;
    public static int LaunchCalls;
    public static IntPtr List;
    public static IntPtr LaunchList;
    public static IntPtr Value;
    public static uint Attribute;
    public static uint LaunchFlags;
    public static void Apply(IntPtr list, uint attribute, IntPtr value, int size, string name) {
        Calls += 1; List = list; Attribute = attribute; Value = value;
        if (size <= 0 || String.IsNullOrEmpty(name)) throw new InvalidOperationException();
    }
    public static void RecordLaunch(IntPtr list, uint flags) {
        LaunchCalls += 1; LaunchList = list; LaunchFlags = flags;
    }
}
'@
$security = [Activator]::CreateInstance($securityType)
$securityType.GetField('AppContainerSid',$instance).SetValue($security,[IntPtr]0x12345)
$securityType.GetField('Capabilities',$instance).SetValue($security,[IntPtr]0)
$securityType.GetField('CapabilityCount',$instance).SetValue($security,[uint32]0)
$securityType.GetField('Reserved',$instance).SetValue($security,[uint32]0)
$proofCtor = @($launchProof.GetConstructors($instance) | Where-Object { $_.GetParameters().Count -eq 7 })
if ($proofCtor.Count -ne 1) { throw 'launch_proof_ctor_invalid' }
$actionType = [Action``5].MakeGenericType([IntPtr],[uint32],[IntPtr],[int],[string])
$action = [Delegate]::CreateDelegate($actionType,[LaunchProofSentinel].GetMethod('Apply'))
$launcherType = $bound.GetNestedType('ProcessLauncher',[Reflection.BindingFlags]'Public,NonPublic')
$launcherInvoke = $launcherType.GetMethod('Invoke')
$launcherParameterTypes = [Type[]]@($launcherInvoke.GetParameters() | ForEach-Object ParameterType)
$dynamicLauncher = [Reflection.Emit.DynamicMethod]::new(
    'LaunchSentinel',
    [bool],
    $launcherParameterTypes,
    $program.Module,
    $true
)
$startupType = $program.GetNestedType('StartupInfoEx',[Reflection.BindingFlags]'NonPublic')
$processInfoType = $program.GetNestedType('ProcessInformation',[Reflection.BindingFlags]'NonPublic')
$attributeListField = $startupType.GetField('AttributeList',$instance)
$processHandleField = $processInfoType.GetField('Process',$instance)
$recordLaunch = [LaunchProofSentinel].GetMethod('RecordLaunch')
$il = $dynamicLauncher.GetILGenerator()
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_S,[byte]8)
$il.Emit([Reflection.Emit.OpCodes]::Ldfld,$attributeListField)
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_S,[byte]5)
$il.Emit([Reflection.Emit.OpCodes]::Call,$recordLaunch)
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_S,[byte]9)
$il.Emit([Reflection.Emit.OpCodes]::Initobj,$processInfoType)
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_S,[byte]9)
$il.Emit([Reflection.Emit.OpCodes]::Ldc_I4,0x2468)
$il.Emit([Reflection.Emit.OpCodes]::Conv_I)
$il.Emit([Reflection.Emit.OpCodes]::Stfld,$processHandleField)
$il.Emit([Reflection.Emit.OpCodes]::Ldc_I4_1)
$il.Emit([Reflection.Emit.OpCodes]::Ret)
$launcher = $dynamicLauncher.CreateDelegate($launcherType)
$issuer = $bound.GetField('_proofIssuer',$instance).GetValue($context)
try {
    $null = $proofCtor[0].Invoke(
        [object[]]@(
            (New-Object object),$context,$security,[IntPtr]0,
            'SECURITY_CAPABILITIES',$action,$launcher
        )
    )
    throw 'forged_launch_proof_accepted'
} catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.Message -cne 'bound_identity_proof_issuer_invalid'){throw}
}
$proof = $proofCtor[0].Invoke(
    [object[]]@(
        $issuer,$context,$security,[IntPtr]0,
        'SECURITY_CAPABILITIES',$action,$launcher
    )
)
$startup = [Activator]::CreateInstance($startupType)
$startupType.GetField('AttributeList',$instance).SetValue($startup,[IntPtr]0x56789)
$launchArguments = [object[]]@(
    'sentinel.exe',
    [Text.StringBuilder]::new('sentinel.exe'),
    $false,
    [uint32]0x00080004,
    'C:\sentinel',
    $startup,
    $null
)
$launched = $consume.Invoke($proof,$launchArguments)
if ($launched -ne $true) { throw 'atomic_launch_consumer_failed' }
$launchedProcessInformation = $launchArguments[6]
$launchedProcess = [IntPtr]$processHandleField.GetValue($launchedProcessInformation)
if ($launchedProcess -ne [IntPtr]0x2468) {
    throw 'launch_proof_process_handle_not_bound'
}
$requireRegularPolicy = $launchProof.GetMethod('RequireRegularPolicyForProcess',$instance)
$requireRegularPolicy.Invoke($proof,[object[]]@($launchedProcess))
try {
    $requireRegularPolicy.Invoke($proof,[object[]]@([IntPtr]0x1357))
    throw 'launch_proof_wrong_process_accepted'
} catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.Message -cne 'regular_appcontainer_launch_policy_unbound'){throw}
}
if (
    [LaunchProofSentinel]::Calls -ne 1 -or
    [LaunchProofSentinel]::List -ne [IntPtr]0x56789 -or
    [LaunchProofSentinel]::Attribute -ne [uint32]0x00020009 -or
    [LaunchProofSentinel]::Value -eq [IntPtr]0 -or
    [LaunchProofSentinel]::LaunchCalls -ne 1 -or
    [LaunchProofSentinel]::LaunchList -ne [IntPtr]0x56789 -or
    [LaunchProofSentinel]::LaunchFlags -ne [uint32]0x00080004
) {
    throw 'launch_proof_atomic_consumer_invalid'
}
$launchProof.GetField('_launchedProcess',$instance).SetValue($proof,$currentHandle)
$classicCtor = @($boundClassic.GetConstructors($instance) | Where-Object {
    $_.GetParameters().Count -eq 6
})
$validatedClassicCtor = @($validatedClassic.GetConstructors($instance) | Where-Object {
    $_.GetParameters().Count -eq 5
})
if ($classicCtor.Count -ne 1 -or $validatedClassicCtor.Count -ne 1) {
    throw 'classic_proof_constructor_roster_invalid'
}
$classicSha = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
try {
    $null = $classicCtor[0].Invoke(
        [object[]]@((New-Object object),$context,$currentHandle,$validFacts,$classicSha,[uint32]5)
    )
    throw 'forged_classic_observation_accepted'
} catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.Message -cne 'bound_identity_proof_issuer_invalid'){throw}
}
$otherContext = $boundCtor[0].Invoke(
    [object[]]@(
        [IntPtr]0x23456,$sid,$identity,$profileReader,$tokenReader,
        $networkTokenReader,$classicReader
    )
)
try {
    $null = $classicCtor[0].Invoke(
        [object[]]@($issuer,$otherContext,$currentHandle,$validFacts,$classicSha,[uint32]5)
    )
    throw 'wrong_owner_classic_observation_accepted'
} catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.Message -cne 'bound_identity_proof_issuer_invalid'){throw}
}
$alternateProcess = [Diagnostics.Process]::GetCurrentProcess()
$alternateHandle = $alternateProcess.Handle
if ($alternateHandle -eq $currentHandle) { throw 'alternate_process_handle_not_distinct' }
$wrongProcessObservation = $classicCtor[0].Invoke(
    [object[]]@($issuer,$context,$currentHandle,$validFacts,$classicSha,[uint32]5)
)
$launchProof.GetField('_launchedProcess',$instance).SetValue($proof,$alternateHandle)
try {
    $null = $boundClassic.GetMethod('ValidateForRoot',$instance).Invoke(
        $wrongProcessObservation,[object[]]@($issuer,$alternateHandle,$proof)
    )
    throw 'classic_observation_wrong_process_accepted'
} catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.Message -cne 'classic_token_observation_process_mismatch'){throw}
}
$launchProof.GetField('_launchedProcess',$instance).SetValue($proof,$currentHandle)
$classicObservation = $classicCtor[0].Invoke(
    [object[]]@($issuer,$context,$currentHandle,$validFacts,$classicSha,[uint32]5)
)
$validatedRoot = $boundClassic.GetMethod('ValidateForRoot',$instance).Invoke(
    $classicObservation,[object[]]@($issuer,$currentHandle,$proof)
)
if ($validatedRoot.GetType() -ne $validatedClassic -or
    [string]$validatedClassic.GetProperty('AapSha256',$instance).GetValue($validatedRoot) -cne $classicSha -or
    [uint32]$validatedClassic.GetProperty('NoAapError',$instance).GetValue($validatedRoot) -ne 5 -or
    -not [bool]$validatedClassic.GetProperty('RegularLaunchPolicyBound',$instance).GetValue($validatedRoot) -or
    -not [bool]$validatedClassic.GetProperty('SamePrimaryTokenSourceBound',$instance).GetValue($validatedRoot)) {
    throw 'validated_classic_observation_invalid'
}
if ($null -eq $validatedClassic.GetMethod('BuildRootProcessObservation',$instance)) {
    throw 'validated_classic_root_wire_method_missing'
}
$rootReport = [Text.Json.JsonDocument]::Parse(
    '{"role":"root","pid":'+$currentPid+',"parent_pid":1}'
)
try {
    $null = $validatedClassic.GetMethod('BuildRootProcessObservation',$instance).Invoke(
        $validatedRoot,[object[]]@($currentHandle,$rootReport.RootElement)
    )
    throw 'validated_classic_nonpython_path_accepted'
} catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.Message -cne 'path_identity_leaf_mismatch'){throw}
}
try {
    $null = $validatedClassicCtor[0].Invoke(
        [object[]]@((New-Object object),$context,$childProof,$classicSha,[uint32]5)
    )
    throw 'forged_validated_classic_observation_accepted'
} catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.Message -cne 'bound_identity_proof_issuer_invalid'){throw}
}
try {
    $null = $boundClassic.GetMethod('ValidateForRoot',$instance).Invoke(
        $classicObservation,[object[]]@($issuer,$currentHandle,$proof)
    )
    throw 'classic_observation_double_consume_accepted'
} catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.Message -cne 'classic_token_observation_already_consumed'){throw}
}
try { $consume.Invoke($proof,$launchArguments); throw 'launch_proof_double_consume_accepted' } catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.Message -cne 'launch_authorization_already_consumed'){throw}
}
$proof.GetType().GetMethod('Dispose',$instance).Invoke($proof,@())
try { $consume.Invoke($proof,$launchArguments); throw 'launch_proof_use_after_dispose_accepted' } catch {
    $inner=$_.Exception; while($null -ne $inner.InnerException){$inner=$inner.InnerException}
    if($inner.GetType().FullName -cne 'System.ObjectDisposedException'){throw}
}
$alternateProcess.Dispose()
$currentProcess.Dispose()
Write-Output 'authority_and_proofs_ok'
'''
        def run_candidate(source_text: str) -> subprocess.CompletedProcess[str]:
            directory = tempfile.mkdtemp(prefix="finplanbr-helper-proof-")
            self.addCleanup(shutil.rmtree, directory, True)
            root = Path(directory)
            source_path = root / "Program.cs"
            assembly = root / "helper.dll"
            script_path = root / "inspect.ps1"
            source_path.write_text(source_text, encoding="utf-8")
            script_path.write_text(script, encoding="utf-8")
            environment = os.environ.copy()
            environment["FPBR_SOURCE"] = os.fspath(source_path)
            environment["FPBR_ASSEMBLY"] = os.fspath(assembly)
            return subprocess.run(
                [pwsh, "-NoProfile", "-File", os.fspath(script_path)],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )

        source = PROGRAM_SOURCE.read_text(encoding="utf-8")
        completed = run_candidate(source)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("authority_and_proofs_ok", completed.stdout)

        functional_mutants = {
            "selective_token_validation_bypass": (
                "            Program.ValidateFacts(facts, CanonicalSid, view);",
                "            if (!string.Equals(\n"
                "                    view,\n"
                '                    "child",\n'
                "                    StringComparison.Ordinal\n"
                "                ))\n"
                "            {\n"
                "                Program.ValidateFacts(facts, CanonicalSid, view);\n"
                "            }",
                "wrong_sid_accepted",
            ),
            "final_profile_cached_identity": (
                "            PathIdentityBinding observed = "
                "ReadFreshProfileIdentity(profileFolder);\n"
                "            RequireSamePathIdentity(\n"
                "                observed,\n"
                "                _profileFolderIdentity,\n"
                "                \"profile_folder_identity_changed_from_prelaunch\"\n"
                "            );\n"
                "            RequireSamePathIdentity(\n"
                "                observed,\n"
                "                initialIdentity.InitialBinding(),\n"
                "                \"profile_folder_identity_changed_during_boundary\"\n"
                "            );",
                "            PathIdentityBinding observed = "
                "initialIdentity.InitialBinding();",
                "final_profile_drift_accepted",
            ),
            "network_process_binding_bypass": (
                "                _owner.RequireAlive();\n"
                "                if (process == IntPtr.Zero || process != _process)",
                "                _owner.RequireAlive();\n"
                "                if (_role is TokenObservationRole.NetworkArm) return;\n"
                "                if (process == IntPtr.Zero || process != _process)",
                "network_proof_wrong_handle_accepted",
            ),
            "launch_memory_disposed_before_consumer": (
                "                    bool launched = _launcher(\n",
                "                    Dispose();\n"
                "                    bool launched = _launcher(\n",
                "Cannot access a disposed object",
            ),
            "bound_classic_proof_issuer_bypassed": (
                "            {\n"
                "                owner.RequireProofIssuer(issuer);\n"
                "                if (process == IntPtr.Zero || facts is null || "
                "string.IsNullOrEmpty(aapSha256))",
                "            {\n"
                "                if (process == IntPtr.Zero || facts is null || "
                "string.IsNullOrEmpty(aapSha256))",
                "forged_classic_observation_accepted",
            ),
            "validated_classic_proof_issuer_bypassed": (
                "            {\n"
                "                owner.RequireProofIssuer(issuer);\n"
                "                _owner = owner;\n"
                "                _token = token ?? throw new InvalidOperationException(",
                "            {\n"
                "                _owner = owner;\n"
                "                _token = token ?? throw new InvalidOperationException(",
                "forged_validated_classic_observation_accepted",
            ),
            "bound_classic_wrong_process_bypassed": (
                "                if (process == IntPtr.Zero || process != _process)\n"
                "                {\n"
                "                    throw new InvalidOperationException(\n"
                '                        "classic_token_observation_process_mismatch"\n'
                "                    );\n"
                "                }",
                "                if (process == IntPtr.Zero)\n"
                "                {\n"
                "                    throw new InvalidOperationException(\n"
                '                        "classic_token_observation_process_mismatch"\n'
                "                    );\n"
                "                }",
                "classic_observation_wrong_process_accepted",
            ),
            "bound_classic_root_relabelled": (
                "                    TokenObservationRole.Root,",
                "                    TokenObservationRole.Child,",
                "validated_token_report_role_mismatch",
            ),
            "bound_classic_double_consume_bypassed": (
                "                _consumed = true;\n"
                "                return new ValidatedClassicTokenObservation(",
                "                _consumed = false;\n"
                "                return new ValidatedClassicTokenObservation(",
                "classic_observation_double_consume_accepted",
            ),
        }
        for name, (old, new, expected_failure) in functional_mutants.items():
            with self.subTest(functional_mutant=name):
                self.assertEqual(source.count(old), 1)
                mutant = source.replace(old, new, 1)
                result = run_candidate(mutant)
                self.assertNotEqual(
                    result.returncode,
                    0,
                    f"mutant survived: {name}\n{result.stdout}",
                )
                self.assertNotIn("Add-Type:", result.stderr)
                self.assertIn(expected_failure, result.stderr)


if __name__ == "__main__":
    unittest.main()
