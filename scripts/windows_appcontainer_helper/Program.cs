#nullable enable

using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;

public static class Program
{
    private const int S_OK = 0;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorFileNotFound = 2;
    private const int ErrorHandleEof = 38;
    private const int ErrorAccessDenied = 5;
    private const uint TokenQuery = 0x0008;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenImpersonate = 0x0004;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateNoWindow = 0x08000000;
    private const uint WaitObject0 = 0x00000000;
    private const uint ProcThreadAttributeSecurityCapabilities = 0x00020009;
    private const uint ProcThreadAttributeHandleList = 0x00020002;
    private const uint ProcThreadAttributeJobList = 0x0002000D;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint Synchronize = 0x00100000;
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint StillActive = 259;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint JobObjectLimitBreakawayOk = 0x00000800;
    private const uint JobObjectLimitSilentBreakawayOk = 0x00001000;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private const int TokenElevation = 20;
    private const int TokenGroups = 2;
    private const int TokenRestrictedSids = 11;
    private const int TokenIntegrityLevel = 25;
    private const int TokenIsAppContainer = 29;
    private const int TokenCapabilities = 30;
    private const int TokenAppContainerSid = 31;
    private const int TokenIsLessPrivilegedAppContainer = 46;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint GenericWrite = 0x40000000;
    private const uint CreateNew = 1;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int FileIdInfoClass = 18;
    private const uint Th32csSnapProcess = 0x00000002;
    private const uint SeGroupEnabled = 0x00000004;
    private const uint SeGroupUseForDenyOnly = 0x00000010;
    private const uint CtmfIncludeAppContainer = 0x00000001;
    private const int SecurityIdentification = 1;
    private const int SecurityImpersonation = 2;
    private const int TokenImpersonation = 2;
    private const string HelperFormat = "finplanbr.windows-appcontainer-boundary-helper.v17";
    private const string HelperFailureReceiptFormat =
        "finplanbr.windows-appcontainer-helper-failure-receipt.v6";
    private static readonly IntPtr InvalidHandleValue = new(-1);
    private static readonly string[] NetworkFailureSubstages =
    {
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
    };

    private sealed class NotObservedException : Exception
    {
        internal NotObservedException(string message) : base(message) { }
    }

    private sealed class FailureTracker
    {
        internal string Stage { get; private set; } = "entry";
        internal string Substage { get; private set; } = "stage_entry";

        internal void SetStage(string stage)
        {
            if (!IsFailureStage(stage))
            {
                throw new InvalidOperationException("failure_stage_invalid");
            }
            Stage = stage;
            Substage = stage switch
            {
                "profile_binding" => "profile_binding_entry",
                "network_differential" => "network_differential_entry",
                _ => "stage_entry",
            };
        }

        internal void SetSubstage(string substage)
        {
            if (!IsFailureStageSubstagePair(Stage, substage))
            {
                throw new InvalidOperationException("failure_substage_invalid");
            }
            Substage = substage;
        }

        internal void SetNetworkArmSubstage(NetworkArmPlan plan, NetworkArmStep step)
        {
            if (Stage != "network_differential")
            {
                throw new InvalidOperationException("failure_network_stage_inactive");
            }
            SetSubstage(plan.Substage(step));
        }

        internal NetworkTokenObservationContext BeginNetworkTokenObservation(
            NetworkArmPlan plan
        )
        {
            if (Stage != "network_differential")
            {
                throw new InvalidOperationException("failure_network_stage_inactive");
            }
            SetSubstage(plan.TokenSubstage(NetworkTokenStep.LaunchPolicy));
            return NetworkTokenObservationContext.Issue(this, plan);
        }

        internal void SetNetworkTokenSubstage(
            NetworkArmPlan plan,
            NetworkTokenStep step
        )
        {
            if (Stage != "network_differential")
            {
                throw new InvalidOperationException("failure_network_stage_inactive");
            }
            SetSubstage(plan.TokenSubstage(step));
        }
    }

    private enum NetworkDifferentialPhase
    {
        Preflight,
        Full,
    }

    private enum NetworkArmStep
    {
        Prepare,
        Launch,
        Process,
        Report,
        Exit,
        Result,
    }

    private enum NetworkTokenStep
    {
        LaunchPolicy,
        ReadBase,
        AapMembership,
        AapRosters,
        Lpac,
        Identity,
        AapEffect,
        ValidateLpac,
        ValidateRoster,
        Bind,
    }

    private sealed class NetworkArmPlan
    {
        private NetworkArmPlan(
            NetworkDifferentialPhase phase,
            string label,
            bool internetClient,
            int order,
            string substagePrefix
        )
        {
            Phase = phase;
            Label = label;
            InternetClient = internetClient;
            Order = order;
            SubstagePrefix = substagePrefix;
        }

        internal NetworkDifferentialPhase Phase { get; }
        internal string Label { get; }
        internal bool InternetClient { get; }
        internal int Order { get; }
        private string SubstagePrefix { get; }

        internal string Substage(NetworkArmStep step) => step switch
        {
            NetworkArmStep.Prepare => SubstagePrefix,
            NetworkArmStep.Launch => SubstagePrefix + "_launch",
            NetworkArmStep.Process => SubstagePrefix + "_process",
            NetworkArmStep.Report => SubstagePrefix + "_report",
            NetworkArmStep.Exit => SubstagePrefix + "_exit",
            NetworkArmStep.Result => SubstagePrefix + "_result",
            _ => throw new InvalidOperationException("network_arm_step_invalid"),
        };

        internal string TokenSubstage(NetworkTokenStep step) => step switch
        {
            NetworkTokenStep.LaunchPolicy => SubstagePrefix + "_token_launch_policy",
            NetworkTokenStep.ReadBase => SubstagePrefix + "_token_read_base",
            NetworkTokenStep.AapMembership => SubstagePrefix + "_token_aap_membership",
            NetworkTokenStep.AapRosters => SubstagePrefix + "_token_aap_rosters",
            NetworkTokenStep.Lpac => SubstagePrefix + "_token_lpac",
            NetworkTokenStep.Identity => SubstagePrefix + "_token_identity",
            NetworkTokenStep.AapEffect => SubstagePrefix + "_token_aap_effect",
            NetworkTokenStep.ValidateLpac => SubstagePrefix + "_token_validate_lpac",
            NetworkTokenStep.ValidateRoster => SubstagePrefix + "_token_validate_roster",
            NetworkTokenStep.Bind => SubstagePrefix + "_token_bind",
            _ => throw new InvalidOperationException("network_token_step_invalid"),
        };

        internal bool Matches(
            NetworkDifferentialPhase phase,
            string label,
            bool internetClient,
            int order,
            string substagePrefix
        ) => Phase == phase
            && string.Equals(Label, label, StringComparison.Ordinal)
            && InternetClient == internetClient
            && Order == order
            && string.Equals(SubstagePrefix, substagePrefix, StringComparison.Ordinal);

        internal static NetworkArmPlan PreflightZero() => new(
            NetworkDifferentialPhase.Preflight,
            "preflight_zero",
            false,
            0,
            "network_preflight_zero"
        );

        internal static NetworkArmPlan FullZeroOne() => new(
            NetworkDifferentialPhase.Full,
            "zero_1",
            false,
            1,
            "network_arm_zero_1"
        );

        internal static NetworkArmPlan FullInternetClientOne() => new(
            NetworkDifferentialPhase.Full,
            "internet_client_1",
            true,
            2,
            "network_arm_internet_client_1"
        );

        internal static NetworkArmPlan FullInternetClientTwo() => new(
            NetworkDifferentialPhase.Full,
            "internet_client_2",
            true,
            3,
            "network_arm_internet_client_2"
        );

        internal static NetworkArmPlan FullZeroTwo() => new(
            NetworkDifferentialPhase.Full,
            "zero_2",
            false,
            4,
            "network_arm_zero_2"
        );
    }

    private sealed class NetworkTokenObservationContext
    {
        private readonly FailureTracker _failureTracker;
        private readonly NetworkArmPlan _plan;
        private NetworkTokenStep? _next = NetworkTokenStep.ReadBase;

        private NetworkTokenObservationContext(
            FailureTracker failureTracker,
            NetworkArmPlan plan
        )
        {
            _failureTracker = failureTracker;
            _plan = plan;
        }

        internal static NetworkTokenObservationContext Issue(
            FailureTracker failureTracker,
            NetworkArmPlan plan
        )
        {
            if (!string.Equals(
                    failureTracker.Substage,
                    plan.TokenSubstage(NetworkTokenStep.LaunchPolicy),
                    StringComparison.Ordinal
                ))
            {
                throw new InvalidOperationException("network_token_context_not_entered");
            }
            return new NetworkTokenObservationContext(failureTracker, plan);
        }

        internal void RequirePlan(NetworkArmPlan plan)
        {
            if (!ReferenceEquals(_plan, plan))
            {
                throw new InvalidOperationException("network_token_plan_mismatch");
            }
        }

        internal void Enter(NetworkTokenStep step)
        {
            if (_next != step)
            {
                throw new InvalidOperationException("network_token_step_order_invalid");
            }
            _failureTracker.SetNetworkTokenSubstage(_plan, step);
            _next = step switch
            {
                NetworkTokenStep.ReadBase => NetworkTokenStep.AapMembership,
                NetworkTokenStep.AapMembership => NetworkTokenStep.AapRosters,
                NetworkTokenStep.AapRosters => NetworkTokenStep.Lpac,
                NetworkTokenStep.Lpac => NetworkTokenStep.Identity,
                NetworkTokenStep.Identity => NetworkTokenStep.AapEffect,
                NetworkTokenStep.AapEffect => NetworkTokenStep.ValidateLpac,
                NetworkTokenStep.ValidateLpac => NetworkTokenStep.ValidateRoster,
                NetworkTokenStep.ValidateRoster => NetworkTokenStep.Bind,
                NetworkTokenStep.Bind => null,
                _ => throw new InvalidOperationException("network_token_step_order_invalid"),
            };
        }

        internal void RequireComplete()
        {
            if (_next is not null)
            {
                throw new InvalidOperationException("network_token_observation_incomplete");
            }
        }
    }

    private sealed class NetworkArmCursor
    {
        private readonly NetworkDifferentialPhase _phase;
        private int _next;

        internal NetworkArmCursor(NetworkDifferentialPhase phase)
        {
            if (phase is not (NetworkDifferentialPhase.Preflight or NetworkDifferentialPhase.Full))
            {
                throw new InvalidOperationException("network_phase_invalid");
            }
            _phase = phase;
        }

        internal bool TryTakeNext(out NetworkArmPlan? plan)
        {
            plan = (_phase, _next) switch
            {
                (NetworkDifferentialPhase.Preflight, 0) => NetworkArmPlan.PreflightZero(),
                (NetworkDifferentialPhase.Full, 0) => NetworkArmPlan.FullZeroOne(),
                (NetworkDifferentialPhase.Full, 1) => NetworkArmPlan.FullInternetClientOne(),
                (NetworkDifferentialPhase.Full, 2) => NetworkArmPlan.FullInternetClientTwo(),
                (NetworkDifferentialPhase.Full, 3) => NetworkArmPlan.FullZeroTwo(),
                _ => null,
            };
            if (plan is null)
            {
                return false;
            }
            _next++;
            return true;
        }
    }

    private sealed class PreflightNetworkDifferentialResult
    {
        internal PreflightNetworkDifferentialResult(
            List<NetworkArmObservation> observations
        )
        {
            if (observations.Count != 1
                || !observations[0].Plan.Matches(
                    NetworkDifferentialPhase.Preflight,
                    "preflight_zero",
                    false,
                    0,
                    "network_preflight_zero"
                ))
            {
                throw new InvalidOperationException("network_preflight_roster_invalid");
            }
            OnlyArm = observations[0].Wire;
        }

        internal SortedDictionary<string, object?> OnlyArm { get; }
    }

    private sealed class FullNetworkDifferentialResult
    {
        internal FullNetworkDifferentialResult(
            List<NetworkArmObservation> observations
        )
        {
            if (observations.Count != 4
                || !observations[0].Plan.Matches(
                    NetworkDifferentialPhase.Full,
                    "zero_1",
                    false,
                    1,
                    "network_arm_zero_1"
                )
                || !observations[1].Plan.Matches(
                    NetworkDifferentialPhase.Full,
                    "internet_client_1",
                    true,
                    2,
                    "network_arm_internet_client_1"
                )
                || !observations[2].Plan.Matches(
                    NetworkDifferentialPhase.Full,
                    "internet_client_2",
                    true,
                    3,
                    "network_arm_internet_client_2"
                )
                || !observations[3].Plan.Matches(
                    NetworkDifferentialPhase.Full,
                    "zero_2",
                    false,
                    4,
                    "network_arm_zero_2"
                ))
            {
                throw new InvalidOperationException("network_differential_roster_invalid");
            }
            Arms = observations.Select(observation => observation.Wire).ToList();
        }

        internal List<SortedDictionary<string, object?>> Arms { get; }
    }

    private sealed class NetworkArmObservation
    {
        private NetworkArmObservation(
            NetworkArmPlan plan,
            SortedDictionary<string, object?> wire
        )
        {
            Plan = plan;
            Wire = wire;
        }

        internal NetworkArmPlan Plan { get; }
        internal SortedDictionary<string, object?> Wire { get; }

        internal static NetworkArmObservation Issue(
            NetworkArmPlan plan,
            SortedDictionary<string, object?> wire
        )
        {
            if (!wire.TryGetValue("label", out object? labelValue)
                || labelValue is not string label
                || !string.Equals(label, plan.Label, StringComparison.Ordinal)
                || !wire.TryGetValue("order", out object? orderValue)
                || orderValue is not int order
                || order != plan.Order
                || !wire.TryGetValue(
                    "requested_capabilities_pointer_null",
                    out object? pointerNullValue
                )
                || pointerNullValue is not bool pointerNull
                || pointerNull != !plan.InternetClient)
            {
                throw new InvalidOperationException("network_arm_observation_binding_invalid");
            }
            return new NetworkArmObservation(plan, wire);
        }
    }

    private sealed class InteropHResultException : Exception
    {
        internal string Operation { get; }
        internal int Result { get; }

        internal InteropHResultException(string operation, int result) : base(operation)
        {
            Operation = operation;
            Result = result;
        }
    }

    private sealed class InteropWin32Exception : Win32Exception
    {
        internal string Operation { get; }

        internal InteropWin32Exception(string operation, int error) : base(error, operation)
        {
            Operation = operation;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] internal bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        internal int Cb;
        internal string? Reserved;
        internal string? Desktop;
        internal string? Title;
        internal uint X;
        internal uint Y;
        internal uint XSize;
        internal uint YSize;
        internal uint XCountChars;
        internal uint YCountChars;
        internal uint FillAttribute;
        internal uint Flags;
        internal ushort ShowWindow;
        internal ushort Reserved2Count;
        internal IntPtr Reserved2;
        internal IntPtr StandardInput;
        internal IntPtr StandardOutput;
        internal IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        internal StartupInfo StartupInfo;
        internal IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal IntPtr Process;
        internal IntPtr Thread;
        internal uint ProcessId;
        internal uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityCapabilities
    {
        internal IntPtr AppContainerSid;
        internal IntPtr Capabilities;
        internal uint CapabilityCount;
        internal uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        internal IntPtr Sid;
        internal uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenGroupsOne
    {
        internal uint GroupCount;
        internal SidAndAttributes FirstGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        internal long PerProcessUserTimeLimit;
        internal long PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSetSize;
        internal UIntPtr MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        internal ulong ReadOperationCount;
        internal ulong WriteOperationCount;
        internal ulong OtherOperationCount;
        internal ulong ReadTransferCount;
        internal ulong WriteTransferCount;
        internal ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        internal JobObjectBasicLimitInformation BasicLimitInformation;
        internal IoCounters IoInfo;
        internal UIntPtr ProcessMemoryLimit;
        internal UIntPtr JobMemoryLimit;
        internal UIntPtr PeakProcessMemoryUsed;
        internal UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        internal ulong VolumeSerialNumber;
        internal ulong FileIdLow;
        internal ulong FileIdHigh;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Win32FindStreamData
    {
        internal long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] internal string StreamName;
    }

    private sealed record AclSnapshot(
        string OwnerSid,
        bool ControllerFullControl,
        bool AppContainerReadExecute,
        bool AppContainerMutationRights,
        bool Canonical
    );

    private sealed record ObjectIdentity(string Value, uint LinkCount);

    private sealed record TokenFacts(
        bool IsAppContainer,
        string AppContainerSid,
        uint CapabilityCount,
        string CapabilityEntries,
        uint TokenGroupCount,
        uint AllApplicationPackagesTokenGroupMatchCount,
        string AllApplicationPackagesTokenGroupMatchAttributes,
        uint RestrictedSidCount,
        uint AllApplicationPackagesRestrictedSidMatchCount,
        string AllApplicationPackagesRestrictedSidMatchAttributes,
        uint IntegrityRid,
        bool IsElevated,
        bool? IsLessPrivilegedAppContainer,
        bool LpacQuerySupported,
        bool AllApplicationPackagesMembershipApiCallSucceeded,
        int? AllApplicationPackagesMembershipApiWin32Error,
        bool AllApplicationPackagesMembershipApi
    );

    private sealed record TreeFingerprint(
        string Root,
        string TreeSha256,
        int EntryCount,
        long ByteCount,
        string OwnerSid
    );

    private sealed record LoopbackSnapshot(bool TargetPresent, string RosterSha256);

    private sealed record NetworkEndpoint(JsonElement Raw, IPAddress Address, int Port);

    private sealed record PathIdentityBinding(
        string FileId128Hex,
        string IdentityFormat,
        string PathUtf8Sha256,
        string VolumeSerialHex
    );

    private sealed record ProfileFolderBoundary(
        long ComponentCount,
        bool ComponentsWin32Valid,
        bool Exact,
        bool NonemptyDescendant,
        bool PackagesAncestor,
        string Reason,
        bool ReconstructionMatches,
        bool TerminalAc
    );

    private sealed record ProfilePrelaunch(
        JsonElement Raw,
        string AppContainerSid,
        PathIdentityBinding FolderIdentity,
        ProfileFolderBoundary FolderBoundary
    );

    private sealed class BoundAppContainerIdentity : IDisposable
    {
        internal enum TokenObservationRole
        {
            Root,
            Child,
            Grandchild,
            NetworkArm,
        }

        internal sealed class ValidatedTokenFacts
        {
            private readonly BoundAppContainerIdentity _owner;
            private readonly IntPtr _process;
            private readonly TokenObservationRole _role;
            private readonly JsonElement _tokenWire;
            private readonly JsonElement? _regularAppContainerWire;

            internal ValidatedTokenFacts(
                object issuer,
                BoundAppContainerIdentity owner,
                TokenFacts facts,
                IntPtr process,
                uint processId,
                TokenObservationRole role,
                string? armLabel,
                int? armOrder,
                bool regularLaunchPolicyBound = false,
                bool aapPositiveReadSha256Matches = false,
                bool aapNegativeAccessDenied = false
            )
            {
                owner.RequireProofIssuer(issuer);
                _owner = owner;
                _process = process;
                ProcessId = processId;
                _role = role;
                ArmLabel = armLabel;
                ArmOrder = armOrder;
                _tokenWire = JsonSerializer.SerializeToElement(
                    Program.TokenDictionaryFromFacts(facts)
                );
                if (role is TokenObservationRole.NetworkArm)
                {
                    if (!regularLaunchPolicyBound
                        || !aapPositiveReadSha256Matches
                        || !aapNegativeAccessDenied)
                    {
                        throw new InvalidOperationException(
                            "network_regular_appcontainer_proof_incomplete"
                        );
                    }
                    _regularAppContainerWire = JsonSerializer.SerializeToElement(
                        new SortedDictionary<string, object?>(StringComparer.Ordinal)
                        {
                            ["aap_negative_access_denied"] = true,
                            ["aap_positive_read_sha256_matches"] = true,
                            ["claim"] =
                                "regular_appcontainer_effect_observed_from_same_primary_token_source",
                            ["regular_launch_policy_bound"] = true,
                            ["same_primary_token_source_bound"] = true,
                        }
                    );
                }
            }

            internal string? ArmLabel { get; }
            internal int? ArmOrder { get; }
            internal uint ProcessId { get; }

            private void RequireSameProcess(IntPtr process)
            {
                _owner.RequireAlive();
                if (process == IntPtr.Zero || process != _process)
                {
                    throw new InvalidOperationException("validated_token_process_mismatch");
                }
                uint currentPid = GetProcessId(process);
                if (currentPid == 0)
                {
                    ThrowLastError("GetProcessId(validated token)");
                }
                if (currentPid != ProcessId)
                {
                    throw new InvalidOperationException("validated_token_pid_mismatch");
                }
            }

            internal SortedDictionary<string, object?> BuildProcessObservation(
                IntPtr process,
                JsonElement report
            )
            {
                if (_role is TokenObservationRole.NetworkArm)
                {
                    throw new InvalidOperationException("network_token_used_as_process_token");
                }
                RequireSameProcess(process);
                string expectedRole = _role switch
                {
                    TokenObservationRole.Root => "root",
                    TokenObservationRole.Child => "child",
                    TokenObservationRole.Grandchild => "grandchild",
                    _ => throw new InvalidOperationException("validated_token_role_invalid"),
                };
                if (!string.Equals(
                        ReadReportString(report, "role"),
                        expectedRole,
                        StringComparison.Ordinal
                    ))
                {
                    throw new InvalidOperationException("validated_token_report_role_mismatch");
                }
                uint reportedPid = ReadReportPid(report, "pid");
                uint reportedParent = ReadReportPid(report, "parent_pid");
                if (reportedPid != ProcessId)
                {
                    throw new InvalidOperationException("validated_token_report_pid_mismatch");
                }
                return new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["image"] = PathIdentityObservation(
                        QueryImagePath(process),
                        "cpython_313_runtime_executable",
                        "python.exe"
                    ),
                    ["parent_pid"] = ParentProcessId(ProcessId),
                    ["pid"] = ProcessId,
                    ["reported_parent_pid"] = reportedParent,
                    ["reported_pid"] = reportedPid,
                    ["token"] = _tokenWire,
                };
            }

            internal JsonElement NetworkTokenWire(IntPtr process)
            {
                if (_role is not TokenObservationRole.NetworkArm
                    || ArmLabel is null
                    || ArmOrder is null)
                {
                    throw new InvalidOperationException("process_token_used_as_network_token");
                }
                RequireSameProcess(process);
                return _tokenWire;
            }

            internal JsonElement NetworkRegularAppContainerWire(IntPtr process)
            {
                _ = NetworkTokenWire(process);
                return _regularAppContainerWire
                    ?? throw new InvalidOperationException(
                        "network_regular_appcontainer_proof_missing"
                    );
            }

            internal (uint ReportedPid, uint ReportedParentPid) ValidateNetworkReport(
                IntPtr process,
                JsonElement report
            )
            {
                _ = NetworkTokenWire(process);
                if (!string.Equals(
                        ReadReportString(report, "role"),
                        "network-arm",
                        StringComparison.Ordinal
                    ))
                {
                    throw new InvalidOperationException("network_token_report_role_mismatch");
                }
                uint reportedPid = ReadReportPid(report, "pid");
                if (reportedPid != ProcessId)
                {
                    throw new InvalidOperationException("network_token_report_pid_mismatch");
                }
                return (reportedPid, ReadReportPid(report, "parent_pid"));
            }
        }

        internal sealed class ValidatedClassicTokenObservation
        {
            private readonly BoundAppContainerIdentity _owner;
            private readonly ValidatedTokenFacts _token;

            internal ValidatedClassicTokenObservation(
                object issuer,
                BoundAppContainerIdentity owner,
                ValidatedTokenFacts token,
                string aapSha256,
                uint noAapError
            )
            {
                owner.RequireProofIssuer(issuer);
                _owner = owner;
                _token = token ?? throw new InvalidOperationException(
                    "classic_token_observation_token_missing"
                );
                AapSha256 = aapSha256;
                NoAapError = noAapError;
            }

            internal string AapSha256 { get; }
            internal uint NoAapError { get; }
            internal bool RegularLaunchPolicyBound
            {
                get
                {
                    _owner.RequireAlive();
                    return true;
                }
            }
            internal bool SamePrimaryTokenSourceBound
            {
                get
                {
                    _owner.RequireAlive();
                    return true;
                }
            }

            internal SortedDictionary<string, object?> BuildRootProcessObservation(
                IntPtr process,
                JsonElement report
            )
            {
                _owner.RequireAlive();
                return _token.BuildProcessObservation(process, report);
            }
        }

        internal sealed class BoundClassicTokenObservation
        {
            private readonly string _aapSha256;
            private readonly TokenFacts _facts;
            private readonly uint _noAapError;
            private readonly BoundAppContainerIdentity _owner;
            private readonly IntPtr _process;
            private bool _consumed;

            internal BoundClassicTokenObservation(
                object issuer,
                BoundAppContainerIdentity owner,
                IntPtr process,
                TokenFacts facts,
                string aapSha256,
                uint noAapError
            )
            {
                owner.RequireProofIssuer(issuer);
                if (process == IntPtr.Zero || facts is null || string.IsNullOrEmpty(aapSha256))
                {
                    throw new InvalidOperationException(
                        "classic_token_observation_contract_invalid"
                    );
                }
                _owner = owner;
                _process = process;
                _facts = facts;
                _aapSha256 = aapSha256;
                _noAapError = noAapError;
            }

            internal ValidatedClassicTokenObservation ValidateForRoot(
                object issuer,
                IntPtr process,
                LaunchAuthorizationProof launchAuthorization
            )
            {
                _owner.RequireProofIssuer(issuer);
                if (_consumed)
                {
                    throw new InvalidOperationException(
                        "classic_token_observation_already_consumed"
                    );
                }
                if (process == IntPtr.Zero || process != _process)
                {
                    throw new InvalidOperationException(
                        "classic_token_observation_process_mismatch"
                    );
                }
                launchAuthorization.RequireRegularPolicyForProcess(process);
                Program.ValidateFacts(_facts, _owner.CanonicalSid, "root");
                uint processId = GetProcessId(process);
                if (processId == 0)
                {
                    ThrowLastError("GetProcessId(validated classic token observation)");
                }
                ValidatedTokenFacts token = new(
                    issuer,
                    _owner,
                    _facts,
                    process,
                    processId,
                    TokenObservationRole.Root,
                    null,
                    null
                );
                _consumed = true;
                return new ValidatedClassicTokenObservation(
                    issuer,
                    _owner,
                    token,
                    _aapSha256,
                    _noAapError
                );
            }
        }

        internal sealed class ValidatedProfileIdentity
        {
            private readonly BoundAppContainerIdentity _owner;
            private readonly PathIdentityBinding _binding;

            internal ValidatedProfileIdentity(
                object issuer,
                BoundAppContainerIdentity owner,
                PathIdentityBinding binding,
                string checkpoint,
                int ordinal
            )
            {
                owner.RequireProofIssuer(issuer);
                _owner = owner;
                _binding = binding;
                Checkpoint = checkpoint;
                Ordinal = ordinal;
            }

            internal string Checkpoint { get; }
            internal int Ordinal { get; }

            internal PathIdentityBinding NetworkBeforeBinding()
            {
                _owner.RequireAlive();
                if (Checkpoint != "network_before")
                {
                    throw new InvalidOperationException("profile_network_before_proof_invalid");
                }
                return _binding;
            }

            internal PathIdentityBinding InitialBinding()
            {
                _owner.RequireAlive();
                if (Checkpoint != "initial")
                {
                    throw new InvalidOperationException("profile_initial_proof_invalid");
                }
                return _binding;
            }

            internal PathIdentityBinding FinalWireBinding()
            {
                _owner.RequireAlive();
                if (Checkpoint != "final")
                {
                    throw new InvalidOperationException("profile_final_proof_invalid");
                }
                return _binding;
            }
        }

        internal delegate bool ProcessLauncher(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref StartupInfoEx startupInfo,
            out ProcessInformation processInformation
        );

        internal sealed class LaunchAuthorizationProof : IDisposable
        {
            private readonly ProcessLauncher _launcher;
            private readonly object _lifetimeGate = new();
            private readonly BoundAppContainerIdentity _owner;
            private readonly Action<IntPtr, uint, IntPtr, int, string> _updater;
            private readonly string _operation;
            private IntPtr _capabilityMemory;
            private IntPtr _launchedProcess;
            private IntPtr _memory;
            private bool _regularPolicyBound;
            private bool _consumed;

            internal LaunchAuthorizationProof(
                object issuer,
                BoundAppContainerIdentity owner,
                SecurityCapabilities value,
                IntPtr capabilityMemory,
                string operation,
                Action<IntPtr, uint, IntPtr, int, string> updater,
                ProcessLauncher launcher
            )
            {
                owner.RequireProofIssuer(issuer);
                if (updater is null
                    || launcher is null
                    || operation is not ("SECURITY_CAPABILITIES" or "NETWORK_SECURITY_CAPABILITIES"))
                {
                    throw new InvalidOperationException("launch_authorization_contract_invalid");
                }
                IntPtr memory = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
                try
                {
                    _owner = owner;
                    Marshal.StructureToPtr(value, memory, false);
                    _memory = memory;
                    _capabilityMemory = capabilityMemory;
                    _operation = operation;
                    _updater = updater;
                    _launcher = launcher;
                    memory = IntPtr.Zero;
                }
                finally
                {
                    if (memory != IntPtr.Zero) Marshal.FreeHGlobal(memory);
                }
            }

            internal bool CreateSuspendedProcess(
                string applicationName,
                StringBuilder commandLine,
                bool inheritHandles,
                uint creationFlags,
                string currentDirectory,
                ref StartupInfoEx startupInfo,
                out ProcessInformation processInformation
            )
            {
                lock (_lifetimeGate)
                {
                    _owner.RequireAlive();
                    if (_memory == IntPtr.Zero)
                    {
                        throw new ObjectDisposedException(nameof(LaunchAuthorizationProof));
                    }
                    if (startupInfo.AttributeList == IntPtr.Zero)
                    {
                        throw new InvalidOperationException("launch_attribute_list_missing");
                    }
                    if (_consumed)
                    {
                        throw new InvalidOperationException(
                            "launch_authorization_already_consumed"
                        );
                    }
                    _consumed = true;
                    _updater(
                        startupInfo.AttributeList,
                        ProcThreadAttributeSecurityCapabilities,
                        _memory,
                        Marshal.SizeOf<SecurityCapabilities>(),
                        _operation
                    );
                    bool launched = _launcher(
                        applicationName,
                        commandLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        inheritHandles,
                        creationFlags,
                        IntPtr.Zero,
                        currentDirectory,
                        ref startupInfo,
                        out processInformation
                    );
                    if (launched)
                    {
                        if (processInformation.Process == IntPtr.Zero)
                        {
                            throw new InvalidOperationException(
                                "regular_appcontainer_launch_process_missing"
                            );
                        }
                        _launchedProcess = processInformation.Process;
                        _regularPolicyBound = true;
                    }
                    return launched;
                }
            }

            internal void RequireRegularPolicyForProcess(IntPtr process)
            {
                lock (_lifetimeGate)
                {
                    _owner.RequireAlive();
                    if (_memory == IntPtr.Zero)
                    {
                        throw new ObjectDisposedException(nameof(LaunchAuthorizationProof));
                    }
                    if (!_consumed
                        || !_regularPolicyBound
                        || process == IntPtr.Zero
                        || process != _launchedProcess)
                    {
                        throw new InvalidOperationException(
                            "regular_appcontainer_launch_policy_unbound"
                        );
                    }
                }
            }

            public void Dispose()
            {
                lock (_lifetimeGate)
                {
                    IntPtr memory = _memory;
                    IntPtr capabilityMemory = _capabilityMemory;
                    _memory = IntPtr.Zero;
                    _capabilityMemory = IntPtr.Zero;
                    _launchedProcess = IntPtr.Zero;
                    _regularPolicyBound = false;
                    if (memory != IntPtr.Zero) Marshal.FreeHGlobal(memory);
                    if (capabilityMemory != IntPtr.Zero) Marshal.FreeHGlobal(capabilityMemory);
                }
            }
        }

        private IntPtr _sid;
        private readonly object _proofIssuer = new();
        private readonly PathIdentityBinding _profileFolderIdentity;
        private readonly Func<string, PathIdentityBinding> _profileIdentityReader;
        private readonly Func<IntPtr, TokenFacts> _tokenReader;
        private readonly Func<
            IntPtr,
            NetworkTokenObservationContext,
            string,
            string,
            (TokenFacts Facts, string AapSha256, uint NoAapError)
        > _networkTokenReader;
        private readonly Func<
            object,
            BoundAppContainerIdentity,
            IntPtr,
            string,
            string,
            BoundClassicTokenObservation
        > _classicTokenReader;
        private ValidatedProfileIdentity? _initialProfileFolderIdentity;
        private ValidatedProfileIdentity? _networkProfileFolderIdentity;
        private int _networkProfileOrdinal;

        private BoundAppContainerIdentity(
            IntPtr sid,
            string canonicalSid,
            PathIdentityBinding profileFolderIdentity,
            Func<string, PathIdentityBinding> profileIdentityReader,
            Func<IntPtr, TokenFacts> tokenReader,
            Func<
                IntPtr,
                NetworkTokenObservationContext,
                string,
                string,
                (TokenFacts Facts, string AapSha256, uint NoAapError)
            > networkTokenReader,
            Func<
                object,
                BoundAppContainerIdentity,
                IntPtr,
                string,
                string,
                BoundClassicTokenObservation
            > classicTokenReader
        )
        {
            if (sid == IntPtr.Zero)
            {
                throw new InvalidOperationException("bound_appcontainer_sid_missing");
            }
            if (profileIdentityReader is null)
            {
                throw new InvalidOperationException("profile_identity_reader_missing");
            }
            if (tokenReader is null || networkTokenReader is null || classicTokenReader is null)
            {
                throw new InvalidOperationException("token_reader_missing");
            }
            _sid = sid;
            CanonicalSid = canonicalSid;
            _profileFolderIdentity = profileFolderIdentity;
            _profileIdentityReader = profileIdentityReader;
            _tokenReader = tokenReader;
            _networkTokenReader = networkTokenReader;
            _classicTokenReader = classicTokenReader;
        }

        internal string CanonicalSid { get; }

        private void RequireAlive()
        {
            if (_sid == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(BoundAppContainerIdentity));
            }
        }

        private void RequireProofIssuer(object issuer)
        {
            RequireAlive();
            if (!ReferenceEquals(issuer, _proofIssuer))
            {
                throw new InvalidOperationException("bound_identity_proof_issuer_invalid");
            }
        }

        internal static BoundAppContainerIdentity Import(
            ProfilePrelaunch profilePrelaunch,
            FailureTracker failureTracker
        )
        {
            IntPtr sid = IntPtr.Zero;
            IntPtr roundtripSid = IntPtr.Zero;
            try
            {
                failureTracker.SetSubstage("profile_sid_import");
                if (!ConvertStringSidToSidW(profilePrelaunch.AppContainerSid, out sid)
                    || sid == IntPtr.Zero)
                {
                    throw new InvalidOperationException("profile_appcontainer_sid_import_failed");
                }
                failureTracker.SetSubstage("profile_sid_validate");
                if (!IsSupportedAppContainerSidShape(sid))
                {
                    throw new InvalidOperationException("profile_appcontainer_sid_shape_invalid");
                }
                failureTracker.SetSubstage("profile_sid_roundtrip");
                string canonicalSid = SidToString(sid);
                if (!string.Equals(
                        profilePrelaunch.AppContainerSid,
                        canonicalSid,
                        StringComparison.Ordinal
                    )
                    || !ConvertStringSidToSidW(canonicalSid, out roundtripSid)
                    || roundtripSid == IntPtr.Zero
                    || !EqualSid(sid, roundtripSid))
                {
                    throw new InvalidOperationException("profile_appcontainer_sid_roundtrip_invalid");
                }
                BoundAppContainerIdentity result = new(
                    sid,
                    canonicalSid,
                    profilePrelaunch.FolderIdentity,
                    ReadPathIdentityBinding,
                    ReadTokenFacts,
                    ReadNetworkTokenFactsAndObserveClassicBehavior,
                    ReadTokenFactsAndObserveClassicBehavior
                );
                sid = IntPtr.Zero;
                return result;
            }
            finally
            {
                if (roundtripSid != IntPtr.Zero) _ = LocalFree(roundtripSid);
                if (sid != IntPtr.Zero) _ = LocalFree(sid);
            }
        }

        internal string QueryProfileFolder()
        {
            RequireAlive();
            return AppContainerFolder(CanonicalSid);
        }

        internal LaunchAuthorizationProof BuildRootLaunchAuthorization()
        {
            RequireAlive();
            return new LaunchAuthorizationProof(
                _proofIssuer,
                this,
                new SecurityCapabilities
                {
                    AppContainerSid = _sid,
                    Capabilities = IntPtr.Zero,
                    CapabilityCount = 0,
                    Reserved = 0,
                },
                IntPtr.Zero,
                "SECURITY_CAPABILITIES",
                UpdateAttribute,
                CreateProcessW
            );
        }

        internal LaunchAuthorizationProof BuildNetworkLaunchAuthorization(
            IntPtr internetClientSid,
            bool internetClient
        )
        {
            RequireAlive();
            IntPtr capabilityMemory = IntPtr.Zero;
            try
            {
                if (internetClient)
                {
                    if (internetClientSid == IntPtr.Zero)
                    {
                        throw new InvalidOperationException("internet_client_sid_missing");
                    }
                    capabilityMemory = Marshal.AllocHGlobal(
                        Marshal.SizeOf<SidAndAttributes>()
                    );
                    Marshal.StructureToPtr(
                        new SidAndAttributes
                        {
                            Sid = internetClientSid,
                            Attributes = SeGroupEnabled,
                        },
                        capabilityMemory,
                        false
                    );
                }
                LaunchAuthorizationProof proof = new(
                    _proofIssuer,
                    this,
                    new SecurityCapabilities
                    {
                        AppContainerSid = _sid,
                        Capabilities = capabilityMemory,
                        CapabilityCount = internetClient ? 1U : 0U,
                        Reserved = 0,
                    },
                    capabilityMemory,
                    "NETWORK_SECURITY_CAPABILITIES",
                    UpdateAttribute,
                    CreateProcessW
                );
                capabilityMemory = IntPtr.Zero;
                return proof;
            }
            finally
            {
                if (capabilityMemory != IntPtr.Zero) Marshal.FreeHGlobal(capabilityMemory);
            }
        }

        private ValidatedTokenFacts ValidateObservedToken(
            TokenFacts facts,
            IntPtr process,
            string view,
            TokenObservationRole role,
            string? armLabel = null,
            int? armOrder = null
        )
        {
            RequireAlive();
            Program.ValidateFacts(facts, CanonicalSid, view);
            uint processId = GetProcessId(process);
            if (processId == 0) ThrowLastError("GetProcessId(validated token issue)");
            return new ValidatedTokenFacts(
                _proofIssuer,
                this,
                facts,
                process,
                processId,
                role,
                armLabel,
                armOrder
            );
        }

        internal ValidatedTokenFacts ObserveChildToken(IntPtr process) =>
            ValidateObservedToken(
                _tokenReader(process),
                process,
                "child",
                TokenObservationRole.Child
            );

        internal ValidatedTokenFacts ObserveGrandchildToken(IntPtr process) =>
            ValidateObservedToken(
                _tokenReader(process),
                process,
                "grandchild",
                TokenObservationRole.Grandchild
            );

        internal ValidatedTokenFacts ObserveNetworkArmToken(
            IntPtr process,
            NetworkArmPlan plan,
            NetworkTokenObservationContext context,
            LaunchAuthorizationProof launchAuthorization,
            string aapProbePath,
            string noAapProbePath,
            string expectedAapSha256
        )
        {
            if (plan is null || context is null || launchAuthorization is null)
            {
                throw new InvalidOperationException("network_token_context_invalid");
            }
            context.RequirePlan(plan);
            launchAuthorization.RequireRegularPolicyForProcess(process);
            context.Enter(NetworkTokenStep.ReadBase);
            (TokenFacts facts, string aapSha256, uint noAapError) =
                _networkTokenReader(
                    process,
                    context,
                    aapProbePath,
                    noAapProbePath
                );
            RequireAlive();
            Program.ValidateFacts(facts, CanonicalSid, "network_" + plan.Label, context);
            bool aapPositiveReadSha256Matches = string.Equals(
                aapSha256,
                expectedAapSha256,
                StringComparison.Ordinal
            );
            bool aapNegativeAccessDenied = noAapError == ErrorAccessDenied;
            if (!aapPositiveReadSha256Matches || !aapNegativeAccessDenied)
            {
                throw new NotObservedException(
                    "network_regular_appcontainer_effect_not_observed"
                );
            }
            context.Enter(NetworkTokenStep.Bind);
            uint processId = GetProcessId(process);
            if (processId == 0) ThrowLastError("GetProcessId(validated network token issue)");
            ValidatedTokenFacts result = new(
                _proofIssuer,
                this,
                facts,
                process,
                processId,
                TokenObservationRole.NetworkArm,
                plan.Label,
                plan.Order,
                true,
                aapPositiveReadSha256Matches,
                aapNegativeAccessDenied
            );
            context.RequireComplete();
            return result;
        }

        internal ValidatedClassicTokenObservation ObserveRootTokenWithClassicBehavior(
            IntPtr process,
            LaunchAuthorizationProof launchAuthorization,
            string aapProbePath,
            string noAapProbePath
        )
        {
            BoundClassicTokenObservation observation = _classicTokenReader(
                    _proofIssuer,
                    this,
                    process,
                    aapProbePath,
                    noAapProbePath
                );
            return observation.ValidateForRoot(
                _proofIssuer,
                process,
                launchAuthorization
            );
        }

        private PathIdentityBinding ReadFreshProfileIdentity(string profileFolder)
        {
            RequireAlive();
            return _profileIdentityReader(profileFolder)
                ?? throw new InvalidOperationException("profile_identity_reader_returned_null");
        }

        internal ValidatedProfileIdentity ObserveInitialProfileFolderIdentity(
            string profileFolder
        )
        {
            if (_initialProfileFolderIdentity is not null)
            {
                throw new InvalidOperationException("profile_folder_identity_already_observed");
            }
            PathIdentityBinding observed = ReadFreshProfileIdentity(profileFolder);
            RequireSamePathIdentity(
                observed,
                _profileFolderIdentity,
                "profile_folder_identity_prelaunch_mismatch"
            );
            ValidatedProfileIdentity validated = new(
                _proofIssuer,
                this,
                observed,
                "initial",
                0
            );
            _initialProfileFolderIdentity = validated;
            return validated;
        }

        internal ValidatedProfileIdentity ObserveNetworkProfileFolderBefore(
            string profileFolder
        )
        {
            if (_networkProfileFolderIdentity is not null)
            {
                throw new InvalidOperationException("network_profile_checkpoint_already_open");
            }
            PathIdentityBinding observed = ReadFreshProfileIdentity(profileFolder);
            RequireSamePathIdentity(
                observed,
                _profileFolderIdentity,
                "network_profile_folder_identity_mismatch"
            );
            if (_initialProfileFolderIdentity is not null)
            {
                RequireSamePathIdentity(
                    observed,
                    _initialProfileFolderIdentity.InitialBinding(),
                    "network_profile_folder_identity_mismatch"
                );
            }
            _networkProfileOrdinal++;
            ValidatedProfileIdentity proof = new(
                _proofIssuer,
                this,
                observed,
                "network_before",
                _networkProfileOrdinal
            );
            _networkProfileFolderIdentity = proof;
            return proof;
        }

        internal ValidatedProfileIdentity ObserveNetworkProfileFolderAfter(
            string profileFolder,
            ValidatedProfileIdentity before
        )
        {
            if (_networkProfileFolderIdentity is null
                || !ReferenceEquals(before, _networkProfileFolderIdentity)
                || before.Checkpoint != "network_before")
            {
                throw new InvalidOperationException("network_profile_checkpoint_missing");
            }
            PathIdentityBinding observed = ReadFreshProfileIdentity(profileFolder);
            RequireSamePathIdentity(
                observed,
                _profileFolderIdentity,
                "network_profile_folder_identity_changed"
            );
            RequireSamePathIdentity(
                observed,
                before.NetworkBeforeBinding(),
                "network_profile_folder_identity_changed"
            );
            ValidatedProfileIdentity proof = new(
                _proofIssuer,
                this,
                observed,
                "network_after",
                before.Ordinal
            );
            _networkProfileFolderIdentity = null;
            return proof;
        }

        internal ValidatedProfileIdentity ObserveFinalProfileFolderIdentity(
            string profileFolder,
            ValidatedProfileIdentity initialIdentity
        )
        {
            if (_initialProfileFolderIdentity is null
                || !ReferenceEquals(initialIdentity, _initialProfileFolderIdentity))
            {
                throw new InvalidOperationException("profile_folder_identity_initial_missing");
            }
            PathIdentityBinding observed = ReadFreshProfileIdentity(profileFolder);
            RequireSamePathIdentity(
                observed,
                _profileFolderIdentity,
                "profile_folder_identity_changed_from_prelaunch"
            );
            RequireSamePathIdentity(
                observed,
                initialIdentity.InitialBinding(),
                "profile_folder_identity_changed_during_boundary"
            );
            return new ValidatedProfileIdentity(
                _proofIssuer,
                this,
                observed,
                "final",
                0
            );
        }

        public void Dispose()
        {
            IntPtr sid = _sid;
            _sid = IntPtr.Zero;
            if (sid != IntPtr.Zero) _ = LocalFree(sid);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        internal uint Size;
        internal uint Usage;
        internal uint ProcessId;
        internal UIntPtr DefaultHeapId;
        internal uint ModuleId;
        internal uint Threads;
        internal uint ParentProcessId;
        internal int BasePriority;
        internal uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] internal string ExeFile;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int GetAppContainerFolderPath(string appContainerSid, out IntPtr path);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength
    );

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EqualSid(IntPtr sid1, IntPtr sid2);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(IntPtr sid);

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        ExactSpelling = true,
        SetLastError = true
    )]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSidToSidW(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateToken(IntPtr existingToken, int impersonationLevel, out IntPtr duplicateToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        IntPtr existingToken,
        uint desiredAccess,
        IntPtr tokenAttributes,
        int impersonationLevel,
        int tokenType,
        out IntPtr duplicateToken
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CheckTokenMembershipEx(
        IntPtr token,
        IntPtr sid,
        uint flags,
        [MarshalAs(UnmanagedType.Bool)] out bool isMember
    );

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidIdentifierAuthority(IntPtr sid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        int attributeCount,
        int flags,
        ref UIntPtr size
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        UIntPtr attribute,
        IntPtr value,
        UIntPtr size,
        IntPtr previousValue,
        IntPtr returnSize
    );

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        ref SecurityAttributes securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        IntPtr file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        IntPtr information,
        uint informationLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        IntPtr file,
        out ByHandleFileInformation information
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        IntPtr file,
        int informationClass,
        out FileIdInfo information,
        uint size
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(
        string fileName,
        int informationLevel,
        out Win32FindStreamData findStreamData,
        uint flags
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextStreamW(
        IntPtr findStream,
        out Win32FindStreamData findStreamData
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr findFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        IntPtr job,
        int informationClass,
        IntPtr information,
        uint informationLength,
        out uint returnLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(
        IntPtr process,
        IntPtr job,
        [MarshalAs(UnmanagedType.Bool)] out bool result
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll")]
    private static extern uint GetProcessId(IntPtr process);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr process,
        uint flags,
        StringBuilder imageName,
        ref uint size
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreatePipe(
        out IntPtr readPipe,
        out IntPtr writePipe,
        ref SecurityAttributes pipeAttributes,
        uint size
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetHandleInformation(IntPtr handle, out uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(
        IntPtr file,
        byte[] buffer,
        uint bytesToWrite,
        out uint bytesWritten,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("Firewallapi.dll")]
    private static extern uint NetworkIsolationGetAppContainerConfig(out uint count, out IntPtr entries);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcessHeap();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool HeapFree(IntPtr heap, uint flags, IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr processHandle, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("ole32.dll")]
    private static extern void CoTaskMemFree(IntPtr memory);

    private static int Main(string[] arguments) => Entry(arguments);

    public static int Entry(string[] arguments)
    {
        FailureTracker failureTracker = new();
        try
        {
            failureTracker.SetStage("entry");
            if (!OperatingSystem.IsWindows())
            {
                throw new NotObservedException("windows_required");
            }
            if (arguments.Length != 10
                || !string.Equals(arguments[0], "parent", StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "usage_parent_moniker_python_runtime_work_probe_endpoint_profile"
                );
            }

            string moniker = arguments[1];
            string pythonRuntimeSourceRoot = Path.GetFullPath(arguments[2]);
            string workRoot = Path.GetFullPath(arguments[3]);
            string probeSourceBase64 = arguments[4];
            string probeSourceSha256 = arguments[5];
            string networkEndpointBase64 = arguments[6];
            string networkEndpointSha256 = arguments[7];
            string profilePrelaunchBase64 = arguments[8];
            string profilePrelaunchSha256 = arguments[9];
            if (!moniker.StartsWith("finplanbrac-", StringComparison.Ordinal)
                || moniker.Length > 64
                || moniker.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                throw new ArgumentException("invalid_moniker");
            }
            string suspendedImage = Path.Combine(pythonRuntimeSourceRoot, "python.exe");
            if (!Directory.Exists(pythonRuntimeSourceRoot) || !File.Exists(suspendedImage))
            {
                throw new NotObservedException("cpython_3_13_runtime_unavailable");
            }
            if (!Directory.Exists(workRoot))
            {
                throw new InvalidOperationException("work_root_missing");
            }
            if ((File.GetAttributes(suspendedImage) & FileAttributes.ReparsePoint) != 0
                || probeSourceBase64.Length == 0
                || probeSourceSha256.Length != 64)
            {
                throw new InvalidOperationException("suspended_image_reparse");
            }
            return RunBoundary(
                moniker,
                pythonRuntimeSourceRoot,
                workRoot,
                probeSourceBase64,
                probeSourceSha256,
                networkEndpointBase64,
                networkEndpointSha256,
                profilePrelaunchBase64,
                profilePrelaunchSha256,
                failureTracker
            );
        }
        catch (NotObservedException)
        {
            return EmitBoundaryFailure(
                "not_observed",
                failureTracker.Stage,
                failureTracker.Substage,
                "not_observed"
            );
        }
        catch (Exception error)
        {
            return EmitBoundaryFailure(
                "failed",
                failureTracker.Stage,
                failureTracker.Substage,
                Sanitize(error)
            );
        }
    }

    private static int RunBoundary(
        string moniker,
        string runtimeSourceRoot,
        string workRoot,
        string probeSourceBase64,
        string expectedProbeSha256,
        string networkEndpointBase64,
        string expectedNetworkEndpointSha256,
        string profilePrelaunchBase64,
        string expectedProfilePrelaunchSha256,
        FailureTracker failureTracker
    )
    {
        byte[] probeBytes;
        try
        {
            probeBytes = Convert.FromBase64String(probeSourceBase64);
        }
        catch (FormatException error)
        {
            throw new InvalidOperationException("probe_source_base64_invalid", error);
        }
        string probeDigest = Sha256(probeBytes);
        if (!string.Equals(probeDigest, expectedProbeSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("probe_source_digest_mismatch");
        }
        failureTracker.SetStage("network_differential");
        failureTracker.SetSubstage("network_endpoint_bind");
        NetworkEndpoint networkEndpoint = ParseNetworkEndpoint(
            networkEndpointBase64,
            expectedNetworkEndpointSha256
        );
        failureTracker.SetStage("profile_binding");
        failureTracker.SetSubstage("profile_prelaunch_parse");
        ProfilePrelaunch profilePrelaunch = ParseProfilePrelaunch(
            profilePrelaunchBase64,
            expectedProfilePrelaunchSha256,
            moniker
        );

        BoundAppContainerIdentity? boundIdentity = null;
        BoundAppContainerIdentity.LaunchAuthorizationProof? boundSecurityCapabilities = null;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleListMemory = IntPtr.Zero;
        IntPtr jobListMemory = IntPtr.Zero;
        IntPtr job = IntPtr.Zero;
        IntPtr permittedRead = IntPtr.Zero;
        IntPtr permittedWrite = IntPtr.Zero;
        IntPtr decoyRead = IntPtr.Zero;
        IntPtr decoyWrite = IntPtr.Zero;
        ProcessInformation rootProcess = default;
        IntPtr childProcess = IntPtr.Zero;
        IntPtr grandchildProcess = IntPtr.Zero;
        TcpListener? loopbackListener = null;
        List<FileStream> protectedFileLocks = new();
        bool attributeListDeleted = false;
        bool jobHandleClosed = false;
        bool listenerHandlesClosed = false;
        bool pipeHandlesClosed = false;
        bool processHandlesClosed = false;
        bool threadHandleClosed = false;
        bool processesExited = false;
        bool runtimeAndSourceRemoved = false;
        string? profileFolder = null;
        string? runtimeRoot = null;
        string? sourceRoot = null;
        string? identityRoot = null;

        try
        {
            boundIdentity = BoundAppContainerIdentity.Import(profilePrelaunch, failureTracker);
            failureTracker.SetSubstage("profile_folder_query");
            string observedProfileFolder = boundIdentity.QueryProfileFolder();
            failureTracker.SetSubstage("profile_folder_canonical");
            profileFolder = RequireCanonicalWindowsPath(
                observedProfileFolder,
                "profile_folder_path_noncanonical"
            );
            failureTracker.SetSubstage("profile_localappdata_canonical");
            string localAppData = RequireCanonicalWindowsPath(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "local_appdata_path_noncanonical"
            );
            failureTracker.SetSubstage("profile_ancestry");
            if (!profileFolder.StartsWith(
                localAppData.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase
            ))
            {
                throw new InvalidOperationException("profile_folder_outside_local_appdata");
            }
            failureTracker.SetSubstage("profile_boundary_compare");
            ProfileFolderBoundary observedProfileBoundary = ObserveProfileFolderBoundary(
                profileFolder,
                localAppData
            );
            if (!observedProfileBoundary.Exact
                || observedProfileBoundary != profilePrelaunch.FolderBoundary)
            {
                throw new InvalidOperationException("profile_folder_boundary_mismatch");
            }
            failureTracker.SetStage("profile_storage");
            if (!Directory.Exists(profileFolder))
            {
                throw new NotObservedException("appcontainer_profile_storage_missing");
            }
            BoundAppContainerIdentity.ValidatedProfileIdentity initialProfileIdentity =
                boundIdentity.ObserveInitialProfileFolderIdentity(profileFolder);

            failureTracker.SetStage("runtime_copy_acl");
            runtimeRoot = Path.Combine(workRoot, "runtime");
            sourceRoot = Path.Combine(workRoot, "source");
            EnsureNewDirectory(runtimeRoot);
            EnsureNewDirectory(sourceRoot);
            CopyClosedPythonRuntime(runtimeSourceRoot, runtimeRoot);
            string probePath = Path.Combine(sourceRoot, "windows_appcontainer_child_probe.py");
            WriteNewFile(probePath, probeBytes);
            string protectedRoot = Path.Combine(sourceRoot, "protected");
            EnsureNewDirectory(protectedRoot);
            foreach (string name in new[]
            {
                "delete.txt",
                "denied-read.txt",
                "hardlink-source.txt",
                "overwrite.txt",
                "rename.txt",
                "rights.txt",
                "stream.txt",
                "symlink-source.txt",
            })
            {
                WriteNewFile(Path.Combine(protectedRoot, name), RandomNumberGenerator.GetBytes(32));
            }
            EnsureNewDirectory(Path.Combine(protectedRoot, "directory-target"));

            identityRoot = Path.Combine(workRoot, "identity");
            EnsureNewDirectory(identityRoot);
            byte[] aapProbeBytes = RandomNumberGenerator.GetBytes(32);
            string aapProbeSha256 = Sha256(aapProbeBytes);
            string aapProbePath = Path.Combine(identityRoot, "aap-positive.bin");
            string noAapProbePath = Path.Combine(identityRoot, "aap-negative.bin");
            WriteNewFile(aapProbePath, aapProbeBytes);
            WriteNewFile(noAapProbePath, aapProbeBytes);
            ObjectIdentity aapIdentityBefore = ReadObjectIdentity(aapProbePath);
            ObjectIdentity noAapIdentityBefore = ReadObjectIdentity(noAapProbePath);
            ApplyAllApplicationPackagesReadAcl(aapProbePath);
            ApplyNoApplicationPackagesReadAcl(noAapProbePath);
            ApplyReadOnlyRuntimeAcl(identityRoot, boundIdentity.CanonicalSid);

            byte[] permittedCanary = SHA256.HashData(
                Encoding.ASCII.GetBytes("finplanbr-permitted-handle-v1\0" + moniker)
            );
            byte[] decoyCanary = SHA256.HashData(
                Encoding.ASCII.GetBytes("finplanbr-decoy-handle-v1\0" + moniker)
            );
            string permittedCanarySha256 = Sha256(permittedCanary);
            string decoyCanarySha256 = Sha256(decoyCanary);
            CreateCanaryPipe(permittedCanary, out permittedRead, out permittedWrite);
            CreateCanaryPipe(decoyCanary, out decoyRead, out decoyWrite);
            CloseOwnedHandle(ref permittedWrite);
            CloseOwnedHandle(ref decoyWrite);

            failureTracker.SetStage("listeners_controls");
            LoopbackSnapshot exemptionBefore = ReadLoopbackSnapshot(boundIdentity.CanonicalSid);
            int firewallBefore = CountFirewallObjects(moniker);
            IPAddress loopbackAddress = IPAddress.Loopback;
            IPAddress lanAddress = networkEndpoint.Address;
            int lanPort = networkEndpoint.Port;
            loopbackListener = new TcpListener(loopbackAddress, 0);
            try
            {
                loopbackListener.Start(4);
            }
            catch (SocketException error)
            {
                throw new NotObservedException(
                    "loopback_listener_unavailable_" + error.ErrorCode.ToString()
                );
            }
            byte[] loopbackControlNonce = RandomNumberGenerator.GetBytes(32);
            SortedDictionary<string, object?> loopbackControl = ObserveNetworkControl(
                loopbackListener,
                loopbackAddress,
                loopbackControlNonce,
                0
            );
            int loopbackPort = ((IPEndPoint)loopbackListener.LocalEndpoint).Port;

            failureTracker.SetStage("runtime_copy_acl");
            string requestPath = Path.Combine(sourceRoot, "request.json");
            string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            SortedDictionary<string, object?> childRequest = new(StringComparer.Ordinal)
            {
                ["appcontainer_sid"] = boundIdentity.CanonicalSid,
                ["decoy_canary_sha256"] = decoyCanarySha256,
                ["decoy_handle"] = decoyRead.ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["format"] = "finplanbr.windows-appcontainer-child-request.v3",
                ["lan_host"] = lanAddress.ToString(),
                ["lan_port"] = lanPort,
                ["loopback_host"] = loopbackAddress.ToString(),
                ["loopback_port"] = loopbackPort,
                ["nonce"] = nonce,
                ["permitted_canary_sha256"] = permittedCanarySha256,
                ["permitted_handle"] = permittedRead.ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["probe_source"] = probePath,
                ["protected_root"] = protectedRoot,
                ["request_path"] = requestPath,
                ["runtime_root"] = runtimeRoot,
                ["scratch_root"] = profileFolder,
                ["source_root"] = sourceRoot,
            };
            WriteNewFile(requestPath, CanonicalJsonLine(childRequest));
            ApplyReadOnlyFileAcl(requestPath, boundIdentity.CanonicalSid);
            ApplyReadOnlyFileAcl(probePath, boundIdentity.CanonicalSid);
            ApplyReadOnlyRuntimeAcl(runtimeRoot, boundIdentity.CanonicalSid);
            ApplyProtectedDirectoryAcl(protectedRoot);
            ApplyReadOnlyRuntimeAcl(sourceRoot, boundIdentity.CanonicalSid);
            ApplyReadOnlyRuntimeAcl(workRoot, boundIdentity.CanonicalSid);

            failureTracker.SetStage("fingerprint_initial");
            SortedDictionary<string, object?> runtimeBefore = FingerprintTree(
                runtimeRoot,
                boundIdentity.CanonicalSid,
                "external_rx_runtime_copy",
                "runtime"
            );
            SortedDictionary<string, object?> sourceBefore = FingerprintTree(
                sourceRoot,
                boundIdentity.CanonicalSid,
                "protected_probe_source_copy",
                "source"
            );
            string protectedBefore = TreeContentSha256(protectedRoot);
            protectedFileLocks.AddRange(LockAllFiles(runtimeRoot));
            JsonElement positiveControlReport = RunPositiveFilesystemControl(
                Path.Combine(runtimeRoot, "python.exe"),
                probePath,
                requestPath,
                profileFolder
            );
            protectedFileLocks.AddRange(LockNamedFiles(probePath, requestPath));

            failureTracker.SetStage("job_attributes");
            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
            {
                ThrowLastError("CreateJobObjectW");
            }
            ConfigureKillOnCloseJob(job);
            uint observedJobLimitFlags = ReadJobLimitFlags(job);

            failureTracker.SetStage("network_differential");
            failureTracker.SetSubstage("network_preflight_prepare");
            PreflightNetworkDifferentialResult preflight = RunNetworkPreflight(
                Path.Combine(runtimeRoot, "python.exe"),
                probePath,
                profileFolder,
                boundIdentity,
                job,
                lanAddress,
                childRequest,
                failureTracker,
                aapProbePath,
                noAapProbePath,
                aapProbeSha256
            );
            SortedDictionary<string, object?> preflightZeroCapability = preflight.OnlyArm;
            failureTracker.SetStage("network_differential");
            failureTracker.SetSubstage("network_control_before");
            SortedDictionary<string, object?> lanControlBefore = ObserveExternalEchoControl(
                lanAddress,
                lanPort,
                RandomNumberGenerator.GetBytes(32),
                0
            );

            failureTracker.SetStage("job_attributes");
            UIntPtr attributeListSize = UIntPtr.Zero;
            bool firstInitialize = InitializeProcThreadAttributeList(IntPtr.Zero, 3, 0, ref attributeListSize);
            int firstInitializeError = Marshal.GetLastWin32Error();
            if (firstInitialize || firstInitializeError != ErrorInsufficientBuffer || attributeListSize == UIntPtr.Zero)
            {
                throw new InteropWin32Exception(
                    "InitializeProcThreadAttributeList(size)",
                    firstInitializeError
                );
            }
            attributeList = Marshal.AllocHGlobal(checked((int)attributeListSize.ToUInt64()));
            if (!InitializeProcThreadAttributeList(attributeList, 3, 0, ref attributeListSize))
            {
                ThrowLastError("InitializeProcThreadAttributeList");
            }
            boundSecurityCapabilities = boundIdentity.BuildRootLaunchAuthorization();
            handleListMemory = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(handleListMemory, permittedRead);
            UpdateAttribute(
                attributeList,
                ProcThreadAttributeHandleList,
                handleListMemory,
                IntPtr.Size,
                "HANDLE_LIST"
            );
            jobListMemory = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(jobListMemory, job);
            UpdateAttribute(
                attributeList,
                ProcThreadAttributeJobList,
                jobListMemory,
                IntPtr.Size,
                "JOB_LIST"
            );

            failureTracker.SetStage("root_launch");
            string pythonImage = Path.Combine(runtimeRoot, "python.exe");
            string command = string.Join(" ", new[]
            {
                Quote(pythonImage),
                "-I",
                "-B",
                Quote(probePath),
                Quote(requestPath),
                "root",
            });
            StartupInfoEx startup = new();
            startup.StartupInfo.Cb = Marshal.SizeOf<StartupInfoEx>();
            startup.AttributeList = attributeList;
            if (!boundSecurityCapabilities.CreateSuspendedProcess(
                pythonImage,
                new StringBuilder(command),
                true,
                CreateSuspended | CreateUnicodeEnvironment | ExtendedStartupInfoPresent | CreateNoWindow,
                profileFolder,
                ref startup,
                out rootProcess
            ))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ErrorAccessDenied)
                {
                    throw new NotObservedException("appcontainer_cpython_creation_access_denied");
                }
                throw new InteropWin32Exception("CreateProcessW", error);
            }
            failureTracker.SetStage("lineage");
            BoundAppContainerIdentity.ValidatedClassicTokenObservation rootTokenObservation =
                boundIdentity.ObserveRootTokenWithClassicBehavior(
                    rootProcess.Process,
                    boundSecurityCapabilities,
                    aapProbePath,
                    noAapProbePath
                );
            string observedAapSha256 = rootTokenObservation.AapSha256;
            uint observedNoAapError = rootTokenObservation.NoAapError;
            ValidateProtectedFileAcl(
                aapProbePath,
                new SecurityIdentifier("S-1-15-2-1"),
                FileSystemRights.Read | FileSystemRights.Synchronize
            );
            ValidateProtectedFileAcl(noAapProbePath, null, 0);
            bool aapObjectIdentityRevalidated = aapIdentityBefore == ReadObjectIdentity(aapProbePath)
                && noAapIdentityBefore == ReadObjectIdentity(noAapProbePath)
                && aapIdentityBefore.LinkCount == 1
                && noAapIdentityBefore.LinkCount == 1
                && ReadObjectStreams(aapProbePath).SequenceEqual(new[] { "::$DATA" })
                && ReadObjectStreams(noAapProbePath).SequenceEqual(new[] { "::$DATA" });
            bool aapPositiveReadSha256Matches = string.Equals(
                observedAapSha256,
                aapProbeSha256,
                StringComparison.Ordinal
            );
            bool aapNegativeAccessDenied = observedNoAapError == ErrorAccessDenied;
            bool aapProbeContentsRevalidated = File.ReadAllBytes(aapProbePath).SequenceEqual(aapProbeBytes)
                && File.ReadAllBytes(noAapProbePath).SequenceEqual(aapProbeBytes);
            failureTracker.SetStage("root_launch");
            if (!IsMember(rootProcess.Process, job))
            {
                throw new InvalidOperationException("root_not_preassigned_to_job");
            }
            uint previousSuspendCount = ResumeThread(rootProcess.Thread);
            if (previousSuspendCount == uint.MaxValue)
            {
                ThrowLastError("ResumeThread");
            }
            if (previousSuspendCount != 1)
            {
                throw new InvalidOperationException("resume_thread_count_invalid");
            }

            failureTracker.SetStage("root_report");
            JsonElement rootReport = WaitForChildReport(
                Path.Combine(profileFolder, "root.json"),
                "root",
                rootProcess.Process
            );
            JsonElement childReport = WaitForChildReport(
                Path.Combine(profileFolder, "child.json"),
                "child"
            );
            JsonElement grandchildReport = WaitForChildReport(
                Path.Combine(profileFolder, "grandchild.json"),
                "grandchild"
            );
            failureTracker.SetStage("lineage");
            uint childPid = ReadReportPid(rootReport, "child_pid");
            uint grandchildPid = ReadReportPid(rootReport, "grandchild_pid");
            childProcess = OpenObservedProcess(childPid);
            grandchildProcess = OpenObservedProcess(grandchildPid);
            BoundAppContainerIdentity.ValidatedTokenFacts childToken =
                boundIdentity.ObserveChildToken(childProcess);
            BoundAppContainerIdentity.ValidatedTokenFacts grandchildToken =
                boundIdentity.ObserveGrandchildToken(grandchildProcess);
            bool rootMember = IsMember(rootProcess.Process, job);
            bool childMember = IsMember(childProcess, job);
            bool grandchildMember = IsMember(grandchildProcess, job);

            failureTracker.SetStage("network_differential");
            failureTracker.SetSubstage("network_full_snapshot");
            LoopbackSnapshot exemptionDuring = ReadLoopbackSnapshot(boundIdentity.CanonicalSid);
            failureTracker.SetSubstage("network_full_firewall_snapshot");
            int firewallDuring = CountFirewallObjects(moniker);
            failureTracker.SetSubstage("network_full_listener_snapshot");
            bool sawLoopback = loopbackListener.Pending();
            DrainPending(loopbackListener);
            failureTracker.SetSubstage("network_full_prepare");
            FullNetworkDifferentialResult fullNetwork = RunFullNetworkDifferential(
                pythonImage,
                probePath,
                profileFolder,
                boundIdentity,
                job,
                lanAddress,
                childRequest,
                failureTracker,
                aapProbePath,
                noAapProbePath,
                aapProbeSha256
            );
            List<SortedDictionary<string, object?>> lanAppContainerArms = fullNetwork.Arms;
            ValidateProtectedFileAcl(
                aapProbePath,
                new SecurityIdentifier("S-1-15-2-1"),
                FileSystemRights.Read | FileSystemRights.Synchronize
            );
            ValidateProtectedFileAcl(noAapProbePath, null, 0);
            aapObjectIdentityRevalidated = aapObjectIdentityRevalidated
                && aapIdentityBefore == ReadObjectIdentity(aapProbePath)
                && noAapIdentityBefore == ReadObjectIdentity(noAapProbePath)
                && ReadObjectStreams(aapProbePath).SequenceEqual(new[] { "::$DATA" })
                && ReadObjectStreams(noAapProbePath).SequenceEqual(new[] { "::$DATA" });
            aapProbeContentsRevalidated = aapProbeContentsRevalidated
                && File.ReadAllBytes(aapProbePath).SequenceEqual(aapProbeBytes)
                && File.ReadAllBytes(noAapProbePath).SequenceEqual(aapProbeBytes);
            DeleteTreeNoReparse(identityRoot);
            bool aapProbeStorageRemoved = !Directory.Exists(identityRoot);
            failureTracker.SetStage("network_differential");
            failureTracker.SetSubstage("network_control_after");
            SortedDictionary<string, object?> lanControlAfter = ObserveExternalEchoControl(
                lanAddress,
                lanPort,
                RandomNumberGenerator.GetBytes(32),
                5
            );

            failureTracker.SetStage("fingerprint_final_cleanup");
            SortedDictionary<string, object?> runtimeAfter = FingerprintTree(
                runtimeRoot,
                boundIdentity.CanonicalSid,
                "external_rx_runtime_copy",
                "runtime"
            );
            SortedDictionary<string, object?> sourceAfter = FingerprintTree(
                sourceRoot,
                boundIdentity.CanonicalSid,
                "protected_probe_source_copy",
                "source"
            );
            string protectedAfter = TreeContentSha256(protectedRoot);

            bool permittedParentOpen = GetHandleInformation(permittedRead, out _);
            bool decoyParentOpen = GetHandleInformation(decoyRead, out _);
            SortedDictionary<string, object?> rootObservation =
                rootTokenObservation.BuildRootProcessObservation(
                    rootProcess.Process,
                    rootReport
                );
            SortedDictionary<string, object?> childObservation = childToken.BuildProcessObservation(
                childProcess,
                childReport
            );
            SortedDictionary<string, object?> grandchildObservation =
                grandchildToken.BuildProcessObservation(
                grandchildProcess,
                grandchildReport
            );
            JsonElement rootHandles = RequireProperty(rootReport, "handles");
            JsonElement rootFilesystem = RequireProperty(rootReport, "filesystem");
            JsonElement rootNetwork = RequireProperty(rootReport, "network");
            JsonElement breakaway = RequireProperty(rootReport, "breakaway");
            bool breakawayCreated = ReadReportBool(breakaway, "created");
            int? breakawayError = ReadNullableInt(breakaway, "winerror");

            CloseOwnedHandle(ref job);
            jobHandleClosed = true;
            bool killedRoot = WaitForKilled(rootProcess.Process);
            bool killedChild = WaitForKilled(childProcess);
            bool killedGrandchild = WaitForKilled(grandchildProcess);
            processesExited = killedRoot && killedChild && killedGrandchild;

            loopbackListener.Stop();
            loopbackListener = null;
            listenerHandlesClosed = true;
            LoopbackSnapshot exemptionAfter = ReadLoopbackSnapshot(boundIdentity.CanonicalSid);
            int firewallAfter = CountFirewallObjects(moniker);

            foreach (FileStream stream in protectedFileLocks)
            {
                stream.Dispose();
            }
            protectedFileLocks.Clear();
            CloseOwnedHandle(ref permittedRead);
            CloseOwnedHandle(ref decoyRead);
            pipeHandlesClosed = true;
            CloseOwnedHandle(ref rootProcess.Thread);
            threadHandleClosed = true;
            CloseOwnedHandle(ref childProcess);
            CloseOwnedHandle(ref grandchildProcess);
            CloseOwnedHandle(ref rootProcess.Process);
            processHandlesClosed = true;

            DeleteProcThreadAttributeList(attributeList);
            Marshal.FreeHGlobal(attributeList);
            attributeList = IntPtr.Zero;
            attributeListDeleted = true;
            boundSecurityCapabilities.Dispose();
            boundSecurityCapabilities = null;
            FreeHGlobal(ref handleListMemory);
            FreeHGlobal(ref jobListMemory);

            DeleteTreeNoReparse(runtimeRoot);
            DeleteTreeNoReparse(sourceRoot);
            runtimeAndSourceRemoved = !Directory.Exists(runtimeRoot) && !Directory.Exists(sourceRoot);
            BoundAppContainerIdentity.ValidatedProfileIdentity profileIdentityAfter =
                boundIdentity.ObserveFinalProfileFolderIdentity(
                    profileFolder,
                    initialProfileIdentity
                );
            PathIdentityBinding finalProfileIdentity =
                profileIdentityAfter.FinalWireBinding();

            SortedDictionary<string, object?> raw = new(StringComparer.Ordinal)
            {
                ["cleanup"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["acl_restore_not_required"] = true,
                    ["attribute_list_deleted"] = attributeListDeleted,
                    ["firewall_objects_absent"] = firewallBefore == 0 && firewallDuring == 0 && firewallAfter == 0,
                    ["job_handle_closed"] = jobHandleClosed,
                    ["listener_handles_closed"] = listenerHandlesClosed,
                    ["loopback_config_restored"] = exemptionBefore == exemptionAfter,
                    ["no_foreign_named_objects"] = firewallBefore == 0 && firewallDuring == 0 && firewallAfter == 0,
                    ["pipe_handles_closed"] = pipeHandlesClosed,
                    ["process_handles_closed"] = processHandlesClosed,
                    ["processes_exited"] = processesExited,
                    ["profile_cleanup_deferred_to_wrapper"] = true,
                    ["runtime_and_source_removed"] = runtimeAndSourceRemoved,
                    ["thread_handle_closed"] = threadHandleClosed,
                    ["work_root_empty"] = !Directory.EnumerateFileSystemEntries(workRoot).Any(),
                },
                ["filesystem"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["operations"] = CombineFilesystemOperations(
                        RequireProperty(RequireProperty(positiveControlReport, "filesystem"), "operations"),
                        RequireProperty(rootFilesystem, "operations")
                    ),
                    ["protected_tree_unchanged"] = string.Equals(protectedBefore, protectedAfter, StringComparison.Ordinal),
                    ["scratch_positive_root_under_profile"] = true,
                },
                ["fingerprints"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["probe_source_sha256"] = probeDigest,
                    ["runtime_after"] = runtimeAfter,
                    ["runtime_before"] = runtimeBefore,
                    ["source_after"] = sourceAfter,
                    ["source_before"] = sourceBefore,
                },
                ["format"] = "finplanbr.windows-appcontainer-boundary-observations.v9",
                ["handles"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["decoy"] = RequireProperty(rootHandles, "decoy"),
                    ["decoy_parent_open_during"] = decoyParentOpen,
                    ["handle_list_attribute_applied"] = true,
                    ["handle_list_count"] = 1,
                    ["permitted"] = RequireProperty(rootHandles, "permitted"),
                    ["permitted_parent_open_during"] = permittedParentOpen,
                },
                ["identity"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["aap_acl_pair_only_semantic_difference"] = "allow_read_s-1-15-2-1",
                    ["aap_acl_pair_revalidated"] = true,
                    ["aap_negative_access_denied"] = aapNegativeAccessDenied,
                    ["aap_negative_win32_error"] = observedNoAapError,
                    ["aap_object_identity_revalidated"] = aapObjectIdentityRevalidated,
                    ["aap_positive_read_sha256_matches"] = aapPositiveReadSha256Matches,
                    ["aap_probe_contents_revalidated"] = aapProbeContentsRevalidated,
                    ["aap_probe_storage_removed"] = aapProbeStorageRemoved,
                    ["aap_sid"] = "S-1-15-2-1",
                    ["claim"] = "aap_acl_effect_observed_for_this_token_run",
                    ["regular_launch_policy_bound"] =
                        rootTokenObservation.RegularLaunchPolicyBound,
                    ["same_primary_token_source_bound"] =
                        rootTokenObservation.SamePrimaryTokenSourceBound,
                },
                ["job"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["breakaway_created"] = breakawayCreated,
                    ["breakaway_flags_absent"] = (
                        observedJobLimitFlags
                        & (JobObjectLimitBreakawayOk | JobObjectLimitSilentBreakawayOk)
                    ) == 0,
                    ["breakaway_winerror"] = breakawayError ?? 0,
                    ["child_member"] = childMember,
                    ["grandchild_member"] = grandchildMember,
                    ["job_handle_was_last_job_handle"] = true,
                    ["job_limit_flags"] = observedJobLimitFlags,
                    ["job_list_attribute_applied"] = true,
                    ["kill_on_close_child"] = killedChild,
                    ["kill_on_close_grandchild"] = killedGrandchild,
                    ["kill_on_close_root"] = killedRoot,
                    ["root_member"] = rootMember,
                },
                ["network"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["endpoint"] = networkEndpoint.Raw,
                    ["execution_order"] = new[]
                    {
                        "preflight_zero",
                        "full_trust_before",
                        "zero_1",
                        "internet_client_1",
                        "internet_client_2",
                        "zero_2",
                        "full_trust_after",
                    },
                    ["exemption_after"] = exemptionAfter.TargetPresent,
                    ["exemption_before"] = exemptionBefore.TargetPresent,
                    ["exemption_digest_after"] = exemptionAfter.RosterSha256,
                    ["exemption_digest_before"] = exemptionBefore.RosterSha256,
                    ["exemption_digest_during"] = exemptionDuring.RosterSha256,
                    ["exemption_during"] = exemptionDuring.TargetPresent,
                    ["firewall_named_objects_after"] = firewallAfter,
                    ["firewall_named_objects_before"] = firewallBefore,
                    ["firewall_named_objects_during"] = firewallDuring,
                    ["lan_appcontainer_arms"] = lanAppContainerArms,
                    ["lan_full_trust_controls"] = new[] { lanControlBefore, lanControlAfter },
                    ["lan_host"] = lanAddress.ToString(),
                    ["lan_host_is_non_loopback"] = !IPAddress.IsLoopback(lanAddress),
                    ["lan_port"] = lanPort,
                    ["listener_saw_appcontainer_loopback"] = sawLoopback,
                    ["listeners_closed"] = listenerHandlesClosed,
                    ["loopback_full_trust_control"] = loopbackControl,
                    ["loopback_zero_capability_attempt"] = RequireProperty(rootNetwork, "loopback"),
                    ["preflight_selected_capability_name"] = "internetClient",
                    ["preflight_selected_capability_sid"] = "S-1-15-3-1",
                    ["preflight_zero_capability"] = preflightZeroCapability,
                },
                ["processes"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["child"] = childObservation,
                    ["grandchild"] = grandchildObservation,
                    ["root"] = rootObservation,
                },
                ["profile"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["appcontainer_sid_prelaunch_bound"] = boundIdentity.CanonicalSid,
                    ["folder_declared_entire_scratch"] = true,
                    ["folder_file_id_128_hex"] = finalProfileIdentity.FileId128Hex,
                    ["folder_identity_format"] = finalProfileIdentity.IdentityFormat,
                    ["folder_identity_matched_prelaunch"] = true,
                    ["folder_identity_revalidated_after_boundary"] = true,
                    ["folder_outside_runtime_and_source"] = !IsUnder(profileFolder, runtimeRoot) && !IsUnder(profileFolder, sourceRoot),
                    ["folder_path_utf8_sha256"] = finalProfileIdentity.PathUtf8Sha256,
                    ["folder_present_during_boundary"] = Directory.Exists(profileFolder),
                    ["folder_under_local_appdata"] = true,
                    ["folder_volume_serial_hex"] = finalProfileIdentity.VolumeSerialHex,
                    ["moniker"] = moniker,
                    ["precreated_by_wrapper"] = true,
                    ["prelaunch_created_hresult"] = 0,
                    ["prelaunch_ownership_established"] = true,
                    ["prelaunch_receipt_sha256"] = expectedProfilePrelaunchSha256,
                    ["prelaunch_sid_reconciled"] = true,
                },
                ["request"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["create_suspended"] = true,
                    ["inherit_handles"] = true,
                    ["python_flags"] = new[] { "-I", "-B" },
                    ["requested_capabilities_pointer_null"] = true,
                    ["requested_capability_count"] = 0,
                    ["resume_thread_count"] = 1,
                    ["startup_attribute_count"] = 3,
                    ["startup_attributes"] = new[] { "handle_list", "job_list", "security_capabilities" },
                },
                ["runtime"] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["child"] = RequireProperty(childReport, "runtime"),
                    ["grandchild"] = RequireProperty(grandchildReport, "runtime"),
                    ["root"] = RequireProperty(rootReport, "runtime"),
                },
            };
            return EmitBoundaryObservations(raw);
        }
        finally
        {
            foreach (FileStream stream in protectedFileLocks)
            {
                try { stream.Dispose(); } catch { }
            }
            if (loopbackListener is not null) try { loopbackListener.Stop(); } catch { }
            if (job != IntPtr.Zero) CloseOwnedHandle(ref job);
            if (rootProcess.Process != IntPtr.Zero)
            {
                _ = TerminateProcess(rootProcess.Process, 125);
                _ = WaitForSingleObject(rootProcess.Process, 5000);
            }
            if (childProcess != IntPtr.Zero) _ = TerminateProcess(childProcess, 125);
            if (grandchildProcess != IntPtr.Zero) _ = TerminateProcess(grandchildProcess, 125);
            CloseOwnedHandle(ref rootProcess.Thread);
            CloseOwnedHandle(ref rootProcess.Process);
            CloseOwnedHandle(ref childProcess);
            CloseOwnedHandle(ref grandchildProcess);
            CloseOwnedHandle(ref permittedRead);
            CloseOwnedHandle(ref permittedWrite);
            CloseOwnedHandle(ref decoyRead);
            CloseOwnedHandle(ref decoyWrite);
            if (attributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            boundSecurityCapabilities?.Dispose();
            FreeHGlobal(ref handleListMemory);
            FreeHGlobal(ref jobListMemory);
            if (runtimeRoot is not null) TryDeleteTree(runtimeRoot);
            if (sourceRoot is not null) TryDeleteTree(sourceRoot);
            if (identityRoot is not null) TryDeleteTree(identityRoot);
            boundIdentity?.Dispose();
        }
    }

    private static string Sha256(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private static byte[] CanonicalJsonLine(object value)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(value);
        byte[] framed = new byte[payload.Length + 1];
        Buffer.BlockCopy(payload, 0, framed, 0, payload.Length);
        framed[^1] = (byte)'\n';
        return framed;
    }

    private static NetworkEndpoint ParseNetworkEndpoint(
        string encoded,
        string expectedSha256
    )
    {
        if (encoded.Length is < 4 or > 65_536 || !IsLowerSha256(expectedSha256))
        {
            throw new InvalidOperationException("network_endpoint_encoding_invalid");
        }
        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(encoded);
        }
        catch (FormatException error)
        {
            throw new InvalidOperationException("network_endpoint_base64_invalid", error);
        }
        if (!string.Equals(Convert.ToBase64String(payload), encoded, StringComparison.Ordinal)
            || payload.Length is < 2 or > 32_768
            || payload.Any(value => value > 0x7f)
            || !string.Equals(Sha256(payload), expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("network_endpoint_binding_invalid");
        }
        string[] expectedNames =
        {
            "busybox_sha256",
            "distro_name",
            "distro_running_before",
            "endpoint_class",
            "guest_boot_id",
            "guest_interface",
            "guest_ipv4",
            "guest_prefix_length",
            "host_launcher_creation_time_100ns",
            "host_launcher_pid",
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
            "netns_inode",
            "startup_nonce_sha256",
            "startup_script_sha256",
            "watchdog_pid",
            "watchdog_starttime_ticks",
            "windows_interface_ip_absent_before",
            "wsl_version",
        };
        try
        {
            using JsonDocument document = JsonDocument.Parse(
                payload,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8,
                }
            );
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.EnumerateObject().Select(property => property.Name).SequenceEqual(expectedNames)
                || !JsonSerializer.SerializeToUtf8Bytes(root).SequenceEqual(payload))
            {
                throw new InvalidOperationException("network_endpoint_canonical_shape_invalid");
            }
            foreach (string name in new[]
            {
                "busybox_sha256",
                "listener_command_sha256",
                "startup_nonce_sha256",
                "startup_script_sha256",
            })
            {
                if (!IsLowerSha256(ReadEndpointString(root, name)))
                {
                    throw new InvalidOperationException("network_endpoint_digest_invalid");
                }
            }
            if (!string.Equals(
                    ReadEndpointString(root, "endpoint_class"),
                    "existing_running_wsl2_nat_guest_eth0.v1",
                    StringComparison.Ordinal
                )
                || !string.Equals(
                    ReadEndpointString(root, "distro_name"),
                    "docker-desktop",
                    StringComparison.Ordinal
                )
                || !string.Equals(
                    ReadEndpointString(root, "guest_interface"),
                    "eth0",
                    StringComparison.Ordinal
                )
                || ReadEndpointInt64(root, "wsl_version") != 2)
            {
                throw new InvalidOperationException("network_endpoint_class_invalid");
            }
            foreach (string name in new[]
            {
                "distro_running_before",
                "listener_port_absent_before_start",
                "listener_port_observed_before",
                "listener_process_absent_before_start",
                "listener_process_observed_before",
                "windows_interface_ip_absent_before",
            })
            {
                if (!ReadEndpointBoolean(root, name))
                {
                    throw new InvalidOperationException("network_endpoint_precondition_false");
                }
            }
            string addressText = ReadEndpointString(root, "guest_ipv4");
            if (!IPAddress.TryParse(addressText, out IPAddress? address)
                || address.AddressFamily != AddressFamily.InterNetwork
                || !string.Equals(address.ToString(), addressText, StringComparison.Ordinal)
                || IPAddress.IsLoopback(address)
                || address.Equals(IPAddress.Any)
                || address.Equals(IPAddress.None))
            {
                throw new InvalidOperationException("network_endpoint_address_invalid");
            }
            long prefix = ReadEndpointInt64(root, "guest_prefix_length");
            long port = ReadEndpointInt64(root, "listener_port");
            long timeout = ReadEndpointInt64(root, "listener_watchdog_timeout_seconds");
            long listenerPid = ReadEndpointInt64(root, "listener_pid");
            long watchdogPid = ReadEndpointInt64(root, "watchdog_pid");
            if (prefix is < 1 or > 32
                || port is < 49_152 or > 65_535
                || timeout is < 30 or > 600
                || listenerPid < 2
                || watchdogPid < 2
                || listenerPid == watchdogPid)
            {
                throw new InvalidOperationException("network_endpoint_numeric_invalid");
            }
            foreach (string name in new[]
            {
                "host_launcher_creation_time_100ns",
                "host_launcher_pid",
                "listener_socket_inode",
                "listener_starttime_ticks",
                "watchdog_starttime_ticks",
            })
            {
                if (ReadEndpointInt64(root, name) < 1)
                {
                    throw new InvalidOperationException("network_endpoint_identity_invalid");
                }
            }
            string bootId = ReadEndpointString(root, "guest_boot_id");
            string netns = ReadEndpointString(root, "netns_inode");
            if (!Guid.TryParseExact(bootId, "D", out Guid parsedBootId)
                || !string.Equals(parsedBootId.ToString("D"), bootId, StringComparison.Ordinal)
                || !netns.StartsWith("net:[", StringComparison.Ordinal)
                || !netns.EndsWith("]", StringComparison.Ordinal)
                || !netns[5..^1].All(char.IsAsciiDigit))
            {
                throw new InvalidOperationException("network_endpoint_namespace_invalid");
            }
            return new NetworkEndpoint(root.Clone(), address, checked((int)port));
        }
        catch (JsonException error)
        {
            throw new InvalidOperationException("network_endpoint_json_invalid", error);
        }
    }

    private static ProfilePrelaunch ParseProfilePrelaunch(
        string encoded,
        string expectedSha256,
        string expectedMoniker
    )
    {
        if (encoded.Length is < 4 or > 65_536 || !IsLowerSha256(expectedSha256))
        {
            throw new InvalidOperationException("profile_prelaunch_encoding_invalid");
        }
        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(encoded);
        }
        catch (FormatException error)
        {
            throw new InvalidOperationException("profile_prelaunch_base64_invalid", error);
        }
        if (!string.Equals(Convert.ToBase64String(payload), encoded, StringComparison.Ordinal)
            || payload.Length is < 2 or > 32_768
            || payload.Any(value => value > 0x7f)
            || !string.Equals(Sha256(payload), expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("profile_prelaunch_binding_invalid");
        }
        string[] expectedNames =
        {
            "appcontainer_sid",
            "created_hresult",
            "folder_boundary_component_count",
            "folder_boundary_components_win32_valid",
            "folder_boundary_exact",
            "folder_boundary_nonempty_descendant",
            "folder_boundary_packages_ancestor",
            "folder_boundary_reason",
            "folder_boundary_reconstruction_matches",
            "folder_boundary_terminal_ac",
            "folder_exists",
            "folder_file_id_128_hex",
            "folder_handle_delete_share_denied",
            "folder_handle_held",
            "folder_identity_format",
            "folder_path_utf8_sha256",
            "folder_reparse_free",
            "folder_volume_serial_hex",
            "format",
            "moniker",
            "ownership_established",
            "sid_reconciled",
        };
        try
        {
            using JsonDocument document = JsonDocument.Parse(
                payload,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 4,
                }
            );
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.EnumerateObject().Select(property => property.Name).SequenceEqual(expectedNames)
                || !JsonSerializer.SerializeToUtf8Bytes(root).SequenceEqual(payload))
            {
                throw new InvalidOperationException("profile_prelaunch_canonical_shape_invalid");
            }
            long componentCount = ReadEndpointInt64(root, "folder_boundary_component_count");
            _ = ReadEndpointBoolean(root, "folder_boundary_terminal_ac");
            if (!string.Equals(
                    ReadEndpointString(root, "format"),
                    "finplanbr.windows-appcontainer-profile-prelaunch.v4",
                    StringComparison.Ordinal
                )
                || !string.Equals(
                    ReadEndpointString(root, "moniker"),
                    expectedMoniker,
                    StringComparison.Ordinal
                )
                || ReadEndpointInt64(root, "created_hresult") != 0
                || componentCount is < 1 or > uint.MaxValue
                || !ReadEndpointBoolean(root, "folder_boundary_components_win32_valid")
                || !ReadEndpointBoolean(root, "folder_boundary_exact")
                || !ReadEndpointBoolean(root, "folder_boundary_nonempty_descendant")
                || !ReadEndpointBoolean(root, "folder_boundary_packages_ancestor")
                || !string.Equals(
                    ReadEndpointString(root, "folder_boundary_reason"),
                    "observed",
                    StringComparison.Ordinal
                )
                || !ReadEndpointBoolean(root, "folder_boundary_reconstruction_matches")
                || !ReadEndpointBoolean(root, "folder_exists")
                || !ReadEndpointBoolean(root, "folder_handle_delete_share_denied")
                || !ReadEndpointBoolean(root, "folder_handle_held")
                || !ReadEndpointBoolean(root, "folder_reparse_free")
                || !ReadEndpointBoolean(root, "ownership_established")
                || !ReadEndpointBoolean(root, "sid_reconciled"))
            {
                throw new InvalidOperationException("profile_prelaunch_ownership_invalid");
            }
            string sid = ReadEndpointString(root, "appcontainer_sid");
            if (!sid.StartsWith("S-1-", StringComparison.Ordinal)
                || !sid.Skip(4).All(character => char.IsAsciiDigit(character) || character == '-'))
            {
                throw new InvalidOperationException("profile_prelaunch_sid_invalid");
            }
            string fileId = ReadEndpointString(root, "folder_file_id_128_hex");
            string identityFormat = ReadEndpointString(root, "folder_identity_format");
            string pathSha256 = ReadEndpointString(root, "folder_path_utf8_sha256");
            string volumeSerial = ReadEndpointString(root, "folder_volume_serial_hex");
            if (!IsLowerHex(fileId, 32)
                || !string.Equals(
                    identityFormat,
                    "windows-file-id-info.v1",
                    StringComparison.Ordinal
                )
                || !IsLowerSha256(pathSha256)
                || !IsLowerHex(volumeSerial, 16))
            {
                throw new InvalidOperationException("profile_prelaunch_folder_identity_invalid");
            }
            return new ProfilePrelaunch(
                root.Clone(),
                sid,
                new PathIdentityBinding(fileId, identityFormat, pathSha256, volumeSerial),
                new ProfileFolderBoundary(
                    componentCount,
                    ReadEndpointBoolean(root, "folder_boundary_components_win32_valid"),
                    ReadEndpointBoolean(root, "folder_boundary_exact"),
                    ReadEndpointBoolean(root, "folder_boundary_nonempty_descendant"),
                    ReadEndpointBoolean(root, "folder_boundary_packages_ancestor"),
                    ReadEndpointString(root, "folder_boundary_reason"),
                    ReadEndpointBoolean(root, "folder_boundary_reconstruction_matches"),
                    ReadEndpointBoolean(root, "folder_boundary_terminal_ac")
                )
            );
        }
        catch (JsonException error)
        {
            throw new InvalidOperationException("profile_prelaunch_json_invalid", error);
        }
    }

    private static bool IsLowerSha256(string value) => value.Length == 64
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsLowerHex(string value, int length) => value.Length == length
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsWin32ProfileComponent(string value)
    {
        if (value.Length == 0
            || value is "." or ".."
            || value.EndsWith(' ')
            || value.EndsWith('.'))
        {
            return false;
        }
        const string invalid = "<>:\"/\\|?*";
        for (int index = 0; index < value.Length; index += 1)
        {
            char character = value[index];
            if (invalid.Contains(character) || char.IsControl(character))
            {
                return false;
            }
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                {
                    return false;
                }
                index += 1;
            }
            else if (char.IsLowSurrogate(character))
            {
                return false;
            }
        }
        string stem = value.Split('.', 2)[0];
        if (new[] { "aux", "con", "conin$", "conout$", "nul", "prn" }.Contains(
                stem,
                StringComparer.OrdinalIgnoreCase
            ))
        {
            return false;
        }
        return stem.Length != 4
            || !(stem.StartsWith("com", StringComparison.OrdinalIgnoreCase)
                || stem.StartsWith("lpt", StringComparison.OrdinalIgnoreCase))
            || stem[3] is not (>= '1' and <= '9') and not '\u00b9' and not '\u00b2' and not '\u00b3';
    }

    private static ProfileFolderBoundary ObserveProfileFolderBoundary(
        string folder,
        string localAppData
    )
    {
        string packagesRoot = Path.GetFullPath(Path.Combine(localAppData, "Packages"));
        string packagesPrefix = packagesRoot.TrimEnd(Path.DirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        bool sameAsPackages = string.Equals(
            folder,
            packagesRoot,
            StringComparison.OrdinalIgnoreCase
        );
        bool belowPackages = folder.StartsWith(
            packagesPrefix,
            StringComparison.OrdinalIgnoreCase
        );
        bool packagesAncestor = sameAsPackages || belowPackages;
        string relative = belowPackages ? folder[packagesPrefix.Length..] : string.Empty;
        string[] components = relative.Length == 0
            ? Array.Empty<string>()
            : relative.Split(Path.DirectorySeparatorChar);
        long componentCount = components.LongLength;
        bool nonempty = packagesAncestor && componentCount >= 1;
        bool componentsValid = nonempty && components.All(IsWin32ProfileComponent);
        bool terminalAc = nonempty && string.Equals(
            components[^1],
            "AC",
            StringComparison.OrdinalIgnoreCase
        );
        string reconstructed = components.Aggregate(packagesRoot, Path.Combine);
        bool reconstructionMatches = nonempty && string.Equals(
            folder,
            reconstructed,
            StringComparison.OrdinalIgnoreCase
        );
        bool exact = packagesAncestor && nonempty && componentsValid && reconstructionMatches;
        string reason = !packagesAncestor
            ? "packages_ancestor_mismatch"
            : !nonempty
                ? "empty_descendant"
                : !componentsValid
                    ? "components_win32_invalid"
                    : !reconstructionMatches
                        ? "reconstruction_mismatch"
                        : "observed";
        return new ProfileFolderBoundary(
            componentCount,
            componentsValid,
            exact,
            nonempty,
            packagesAncestor,
            reason,
            reconstructionMatches,
            terminalAc
        );
    }

    private static string RequireCanonicalWindowsPath(string value, string reason)
    {
        bool driveLetter = value.Length >= 3
            && ((value[0] is >= 'A' and <= 'Z') || (value[0] is >= 'a' and <= 'z'))
            && value[1] == ':'
            && value[2] == Path.DirectorySeparatorChar;
        if (!driveLetter
            || value.Contains('\0')
            || value.Contains(Path.AltDirectorySeparatorChar)
            || value.EndsWith(Path.DirectorySeparatorChar)
            || !string.Equals(Path.GetFullPath(value), value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(reason);
        }
        return value;
    }

    private static string ReadEndpointString(JsonElement root, string name)
    {
        JsonElement value = RequireProperty(root, name);
        if (value.ValueKind != JsonValueKind.String || value.GetString() is not string text || text.Length == 0)
        {
            throw new InvalidOperationException("network_endpoint_string_invalid");
        }
        return text;
    }

    private static bool ReadEndpointBoolean(JsonElement root, string name)
    {
        JsonElement value = RequireProperty(root, name);
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidOperationException("network_endpoint_boolean_invalid");
        }
        return value.GetBoolean();
    }

    private static long ReadEndpointInt64(JsonElement root, string name)
    {
        JsonElement value = RequireProperty(root, name);
        if (!value.TryGetInt64(out long result))
        {
            throw new InvalidOperationException("network_endpoint_integer_invalid");
        }
        return result;
    }

    private static void EnsureNewDirectory(string path)
    {
        if (Directory.Exists(path) || File.Exists(path))
        {
            throw new InvalidOperationException("destination_preexisting");
        }
        Directory.CreateDirectory(path);
        if (!Directory.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("directory_creation_identity_invalid");
        }
    }

    private static void WriteNewFile(string path, byte[] value)
    {
        using FileStream stream = new(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            65_536,
            FileOptions.WriteThrough
        );
        stream.Write(value, 0, value.Length);
        stream.Flush(true);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("new_file_is_reparse");
        }
    }

    private static void CopyClosedPythonRuntime(string sourceRoot, string destinationRoot)
    {
        foreach (string fileName in new[]
        {
            "python.exe",
            "python3.dll",
            "python313.dll",
            "vcruntime140.dll",
            "vcruntime140_1.dll",
        })
        {
            string source = Path.Combine(sourceRoot, fileName);
            if (!File.Exists(source) || (File.GetAttributes(source) & FileAttributes.ReparsePoint) != 0)
            {
                throw new NotObservedException("cpython_runtime_member_missing_or_reparse");
            }
            CopyNewFile(source, Path.Combine(destinationRoot, fileName));
        }
        foreach (string directoryName in new[] { "DLLs", "Lib" })
        {
            string source = Path.Combine(sourceRoot, directoryName);
            string destination = Path.Combine(destinationRoot, directoryName);
            if (!Directory.Exists(source) || (File.GetAttributes(source) & FileAttributes.ReparsePoint) != 0)
            {
                throw new NotObservedException("cpython_runtime_directory_missing_or_reparse");
            }
            CopyRuntimeDirectory(source, destination);
        }
        WriteNewFile(
            Path.Combine(destinationRoot, "python313._pth"),
            new UTF8Encoding(false).GetBytes("Lib\nDLLs\n")
        );
    }

    private static void CopyRuntimeDirectory(string source, string destination)
    {
        EnsureNewDirectory(destination);
        foreach (string directory in Directory.EnumerateDirectories(source).OrderBy(item => item, StringComparer.Ordinal))
        {
            string name = Path.GetFileName(directory);
            if (string.Equals(name, "__pycache__", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "site-packages", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            {
                throw new NotObservedException("cpython_runtime_tree_contains_reparse");
            }
            CopyRuntimeDirectory(directory, Path.Combine(destination, name));
        }
        foreach (string file in Directory.EnumerateFiles(source).OrderBy(item => item, StringComparer.Ordinal))
        {
            string extension = Path.GetExtension(file);
            if (string.Equals(extension, ".pyc", StringComparison.OrdinalIgnoreCase)
                || string.Equals(extension, ".pyo", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
            {
                throw new NotObservedException("cpython_runtime_tree_contains_reparse");
            }
            CopyNewFile(file, Path.Combine(destination, Path.GetFileName(file)));
        }
    }

    private static void CopyNewFile(string source, string destination)
    {
        using FileStream input = new(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        using FileStream output = new(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            65_536,
            FileOptions.SequentialScan
        );
        input.CopyTo(output, 65_536);
        output.Flush(true);
        if ((File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("runtime_copy_is_reparse");
        }
    }

    private static void ApplyProtectedDirectoryAcl(string path)
    {
        SecurityIdentifier? currentUser = WindowsIdentity.GetCurrent().User;
        if (currentUser is null)
        {
            throw new InvalidOperationException("current_user_sid_missing");
        }
        DirectoryInfo directory = new(path);
        DirectorySecurity security = FileSystemAclExtensions.GetAccessControl(
            directory,
            AccessControlSections.Access
        );
        security.SetAccessRuleProtection(true, false);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
        {
            security.RemoveAccessRuleSpecific(rule);
        }
        InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier("S-1-3-4"),
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Deny
        ));
        foreach (SecurityIdentifier principal in new[]
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            currentUser,
        })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                principal,
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow
            ));
        }
        FileSystemAclExtensions.SetAccessControl(directory, security);
        DirectorySecurity observed = FileSystemAclExtensions.GetAccessControl(
            directory,
            AccessControlSections.Access | AccessControlSections.Owner
        );
        if (!observed.AreAccessRulesProtected || !observed.AreAccessRulesCanonical)
        {
            throw new InvalidOperationException("protected_directory_acl_invalid");
        }
    }

    private static void CreateCanaryPipe(byte[] canary, out IntPtr readPipe, out IntPtr writePipe)
    {
        SecurityAttributes attributes = new()
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            SecurityDescriptor = IntPtr.Zero,
            InheritHandle = true,
        };
        if (!CreatePipe(out readPipe, out writePipe, ref attributes, 0))
        {
            ThrowLastError("CreatePipe");
        }
        if (!SetHandleInformation(readPipe, HandleFlagInherit, HandleFlagInherit))
        {
            ThrowLastError("SetHandleInformation(pipe_read)");
        }
        if (!SetHandleInformation(writePipe, HandleFlagInherit, 0))
        {
            ThrowLastError("SetHandleInformation(pipe_write)");
        }
        if (!WriteFile(writePipe, canary, checked((uint)canary.Length), out uint written, IntPtr.Zero)
            || written != canary.Length)
        {
            ThrowLastError("WriteFile(pipe_canary)");
        }
    }

    private static LoopbackSnapshot ReadLoopbackSnapshot(string targetSid)
    {
        uint result = NetworkIsolationGetAppContainerConfig(out uint count, out IntPtr entries);
        if (result != 0)
        {
            throw new NotObservedException(
                "network_isolation_config_query_unavailable_"
                + result.ToString(System.Globalization.CultureInfo.InvariantCulture)
            );
        }
        List<string> sids = new();
        List<IntPtr> allocatedSids = new();
        int? freeError = null;
        try
        {
            int stride = Marshal.SizeOf<SidAndAttributes>();
            if (count > 0 && entries == IntPtr.Zero)
            {
                throw new InvalidOperationException("network_isolation_config_null_entries");
            }
            for (uint index = 0; index < count; index++)
            {
                IntPtr itemAddress = IntPtr.Add(entries, checked((int)index * stride));
                SidAndAttributes item = Marshal.PtrToStructure<SidAndAttributes>(itemAddress);
                allocatedSids.Add(item.Sid);
            }
            foreach (IntPtr sid in allocatedSids)
            {
                sids.Add(SidToString(sid));
            }
        }
        finally
        {
            foreach (IntPtr sid in allocatedSids)
            {
                if (sid != IntPtr.Zero && !HeapFree(GetProcessHeap(), 0, sid))
                {
                    freeError ??= Marshal.GetLastWin32Error();
                }
            }
            if (entries != IntPtr.Zero && !HeapFree(GetProcessHeap(), 0, entries))
            {
                freeError ??= Marshal.GetLastWin32Error();
            }
        }
        if (freeError.HasValue)
        {
            throw new InteropWin32Exception("HeapFree(NetworkIsolationGetAppContainerConfig)", freeError.Value);
        }
        sids.Sort(StringComparer.Ordinal);
        string roster = string.Join("\n", sids) + "\n";
        return new LoopbackSnapshot(
            sids.Contains(targetSid, StringComparer.Ordinal),
            Sha256(Encoding.ASCII.GetBytes(roster))
        );
    }

    private static int CountFirewallObjects(string moniker)
    {
        Type? policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
        if (policyType is null)
        {
            throw new NotObservedException("firewall_policy_api_unavailable");
        }
        object? policy = null;
        object? rules = null;
        int count = 0;
        try
        {
            policy = Activator.CreateInstance(policyType)
                ?? throw new NotObservedException("firewall_policy_creation_unavailable");
            rules = policyType.InvokeMember(
                "Rules",
                BindingFlags.GetProperty,
                null,
                policy,
                null,
                System.Globalization.CultureInfo.InvariantCulture
            );
            if (rules is not IEnumerable enumerable)
            {
                throw new NotObservedException("firewall_rule_enumeration_unavailable");
            }
            foreach (object rule in enumerable)
            {
                try
                {
                    string? name = rule.GetType().InvokeMember(
                        "Name",
                        BindingFlags.GetProperty,
                        null,
                        rule,
                        null,
                        System.Globalization.CultureInfo.InvariantCulture
                    ) as string;
                    if (name is not null && name.Contains(moniker, StringComparison.Ordinal))
                    {
                        count++;
                    }
                }
                finally
                {
                    if (Marshal.IsComObject(rule)) _ = Marshal.FinalReleaseComObject(rule);
                }
            }
            return count;
        }
        catch (NotObservedException)
        {
            throw;
        }
        catch (Exception error)
        {
            throw new NotObservedException("firewall_policy_query_unavailable_" + error.GetType().Name);
        }
        finally
        {
            if (rules is not null && Marshal.IsComObject(rules)) _ = Marshal.FinalReleaseComObject(rules);
            if (policy is not null && Marshal.IsComObject(policy)) _ = Marshal.FinalReleaseComObject(policy);
        }
    }

    private static IPAddress SelectLanAddress()
    {
        foreach (IPAddress address in Dns.GetHostAddresses(Dns.GetHostName()))
        {
            if (address.AddressFamily == AddressFamily.InterNetwork
                && !IPAddress.IsLoopback(address)
                && !address.Equals(IPAddress.Any)
                && !address.Equals(IPAddress.None))
            {
                return address;
            }
        }
        throw new NotObservedException("non_loopback_lan_address_unavailable");
    }

    private static SortedDictionary<string, object?> ObserveNetworkControl(
        TcpListener listener,
        IPAddress address,
        byte[] nonce,
        int order
    )
    {
        bool connected = false;
        bool accepted = false;
        bool matches = false;
        int? errorCode = null;
        string? receivedNonceSha256 = null;
        try
        {
            using TcpClient client = new(address.AddressFamily);
            client.SendTimeout = 2000;
            client.ReceiveTimeout = 2000;
            client.Connect(address, ((IPEndPoint)listener.LocalEndpoint).Port);
            connected = client.Connected;
            using NetworkStream clientStream = client.GetStream();
            clientStream.Write(nonce, 0, nonce.Length);
            using TcpClient server = listener.AcceptTcpClient();
            accepted = true;
            server.ReceiveTimeout = 2000;
            using NetworkStream serverStream = server.GetStream();
            byte[] observed = new byte[nonce.Length];
            int offset = 0;
            while (offset < observed.Length)
            {
                int read = serverStream.Read(observed, offset, observed.Length - offset);
                if (read == 0) break;
                offset += read;
            }
            matches = offset == nonce.Length && observed.SequenceEqual(nonce);
            receivedNonceSha256 = offset == 0 ? null : Sha256(observed[..offset]);
        }
        catch (SocketException error)
        {
            errorCode = error.ErrorCode;
        }
        catch (IOException error) when (error.InnerException is SocketException socketError)
        {
            errorCode = socketError.ErrorCode;
        }
        return new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["accepted"] = accepted,
            ["connected"] = connected,
            ["host"] = address.ToString(),
            ["nonce_matches"] = matches,
            ["nonce_sha256"] = Sha256(nonce),
            ["order"] = order,
            ["port"] = ((IPEndPoint)listener.LocalEndpoint).Port,
            ["received_nonce_sha256"] = receivedNonceSha256,
            ["winerror"] = errorCode,
        };
    }

    private static SortedDictionary<string, object?> ObserveExternalEchoControl(
        IPAddress address,
        int port,
        byte[] nonce,
        int order
    )
    {
        bool connected = false;
        bool accepted = false;
        bool matches = false;
        int? errorCode = null;
        string? receivedNonceSha256 = null;
        try
        {
            using TcpClient client = new(AddressFamily.InterNetwork);
            client.SendTimeout = 2500;
            client.ReceiveTimeout = 2500;
            client.Connect(address, port);
            connected = client.Connected;
            using NetworkStream stream = client.GetStream();
            stream.Write(nonce, 0, nonce.Length);
            client.Client.Shutdown(SocketShutdown.Send);
            byte[] observed = new byte[nonce.Length + 1];
            int offset = 0;
            while (offset < observed.Length)
            {
                int read = stream.Read(observed, offset, observed.Length - offset);
                if (read == 0) break;
                offset += read;
            }
            accepted = offset > 0;
            matches = offset == nonce.Length && observed[..offset].SequenceEqual(nonce);
            receivedNonceSha256 = offset == 0 ? null : Sha256(observed[..offset]);
        }
        catch (SocketException error)
        {
            errorCode = error.ErrorCode;
        }
        catch (IOException error) when (error.InnerException is SocketException socketError)
        {
            errorCode = socketError.ErrorCode;
        }
        catch (IOException)
        {
            errorCode = 1;
        }
        return new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["accepted"] = accepted,
            ["connected"] = connected,
            ["host"] = address.ToString(),
            ["nonce_matches"] = matches,
            ["nonce_sha256"] = Sha256(nonce),
            ["order"] = order,
            ["port"] = port,
            ["received_nonce_sha256"] = receivedNonceSha256,
            ["winerror"] = errorCode,
        };
    }

    private static SortedDictionary<string, object?> ObserveListenerNonce(
        TcpListener listener,
        byte[] expectedNonce
    )
    {
        Stopwatch timer = Stopwatch.StartNew();
        while (!listener.Pending() && timer.Elapsed < TimeSpan.FromMilliseconds(2500))
        {
            Thread.Sleep(10);
        }
        bool accepted = false;
        bool matches = false;
        string? receivedSha256 = null;
        if (listener.Pending())
        {
            using TcpClient server = listener.AcceptTcpClient();
            accepted = true;
            server.ReceiveTimeout = 2500;
            using NetworkStream stream = server.GetStream();
            byte[] observed = new byte[expectedNonce.Length];
            int offset = 0;
            try
            {
                while (offset < observed.Length)
                {
                    int read = stream.Read(observed, offset, observed.Length - offset);
                    if (read == 0) break;
                    offset += read;
                }
            }
            catch (IOException) { }
            receivedSha256 = offset == 0 ? null : Sha256(observed[..offset]);
            matches = offset == expectedNonce.Length && observed.SequenceEqual(expectedNonce);
        }
        if (listener.Pending())
        {
            matches = false;
            DrainPending(listener);
        }
        return new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["accepted"] = accepted,
            ["nonce_matches"] = matches,
            ["received_nonce_sha256"] = receivedSha256,
        };
    }

    private static string EnvironmentFingerprint()
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        List<string> entries = new();
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            entries.Add((string)entry.Key + "\0" + (string?)entry.Value + "\0");
        }
        entries.Sort(StringComparer.Ordinal);
        foreach (string entry in entries)
        {
            hash.AppendData(Encoding.UTF8.GetBytes(entry));
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static PreflightNetworkDifferentialResult RunNetworkPreflight(
        string pythonImage,
        string probePath,
        string profileFolder,
        BoundAppContainerIdentity boundIdentity,
        IntPtr job,
        IPAddress lanAddress,
        SortedDictionary<string, object?> baseRequest,
        FailureTracker failureTracker,
        string aapProbePath,
        string noAapProbePath,
        string expectedAapSha256
    ) => new(RunNetworkDifferential(
        pythonImage,
        probePath,
        profileFolder,
        boundIdentity,
        job,
        lanAddress,
        baseRequest,
        failureTracker,
        NetworkDifferentialPhase.Preflight,
        aapProbePath,
        noAapProbePath,
        expectedAapSha256
    ));

    private static FullNetworkDifferentialResult RunFullNetworkDifferential(
        string pythonImage,
        string probePath,
        string profileFolder,
        BoundAppContainerIdentity boundIdentity,
        IntPtr job,
        IPAddress lanAddress,
        SortedDictionary<string, object?> baseRequest,
        FailureTracker failureTracker,
        string aapProbePath,
        string noAapProbePath,
        string expectedAapSha256
    ) => new(RunNetworkDifferential(
        pythonImage,
        probePath,
        profileFolder,
        boundIdentity,
        job,
        lanAddress,
        baseRequest,
        failureTracker,
        NetworkDifferentialPhase.Full,
        aapProbePath,
        noAapProbePath,
        expectedAapSha256
    ));

    private static List<NetworkArmObservation> RunNetworkDifferential(
        string pythonImage,
        string probePath,
        string profileFolder,
        BoundAppContainerIdentity boundIdentity,
        IntPtr job,
        IPAddress lanAddress,
        SortedDictionary<string, object?> baseRequest,
        FailureTracker failureTracker,
        NetworkDifferentialPhase phase,
        string aapProbePath,
        string noAapProbePath,
        string expectedAapSha256
    )
    {
        const string internetClientSidText = "S-1-15-3-1";
        const int armTimeoutMilliseconds = 10_000;
        NetworkArmCursor cursor = new(phase);
        const string requestLeaf = "network-arm-request.json";
        string requestPath = Path.Combine(profileFolder, requestLeaf);
        string reportPath = Path.Combine(profileFolder, "network-arm.json");
        string failurePath = Path.Combine(profileFolder, "failure.json");
        string command = string.Join(" ", new[]
        {
            Quote(pythonImage),
            "-I",
            "-B",
            Quote(probePath),
            Quote(requestPath),
            "network-arm",
        });
        string commandSha256 = Sha256(Encoding.UTF8.GetBytes(command));
        failureTracker.SetSubstage(
            phase == NetworkDifferentialPhase.Preflight
                ? "network_preflight_profile_before"
                : "network_full_profile_before"
        );
        BoundAppContainerIdentity.ValidatedProfileIdentity validatedProfileIdentity =
            boundIdentity.ObserveNetworkProfileFolderBefore(profileFolder);
        PathIdentityBinding profileFolderIdentity =
            validatedProfileIdentity.NetworkBeforeBinding();
        IntPtr internetClientSid = IntPtr.Zero;
        List<NetworkArmObservation> observations = new();
        try
        {
            failureTracker.SetSubstage(
                phase == NetworkDifferentialPhase.Preflight
                    ? "network_preflight_capability_import"
                    : "network_full_capability_import"
            );
            if (!ConvertStringSidToSidW(internetClientSidText, out internetClientSid)
                || internetClientSid == IntPtr.Zero)
            {
                throw new NotObservedException("internet_client_capability_sid_unavailable");
            }
            failureTracker.SetSubstage(
                phase == NetworkDifferentialPhase.Preflight
                    ? "network_preflight_request_setup"
                    : "network_full_request_setup"
            );
            using FileStream requestStream = new(
                requestPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.Read,
                65_536,
                FileOptions.WriteThrough
            );
            PathIdentityBinding requestIdentity = ReadHandleIdentityBinding(
                requestStream.SafeFileHandle.DangerousGetHandle()
            );
            while (cursor.TryTakeNext(out NetworkArmPlan? plan))
            {
                if (plan is null)
                {
                    throw new InvalidOperationException("network_arm_plan_missing");
                }
                string label = plan.Label;
                bool internetClient = plan.InternetClient;
                int order = plan.Order;
                failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Prepare);
                byte[] nonce = Encoding.ASCII.GetBytes(
                    Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant()
                );
                SortedDictionary<string, object?> request = new(baseRequest, StringComparer.Ordinal)
                {
                    ["nonce"] = Encoding.ASCII.GetString(nonce),
                    ["request_path"] = requestPath,
                    ["scratch_root"] = profileFolder,
                };
                byte[] requestBytes = CanonicalJsonLine(request);
                string requestSha256 = Sha256(requestBytes);
                requestStream.Position = 0;
                requestStream.SetLength(0);
                requestStream.Write(requestBytes, 0, requestBytes.Length);
                requestStream.Flush(true);
                File.Delete(reportPath);
                File.Delete(failurePath);

                IntPtr attributeList = IntPtr.Zero;
                BoundAppContainerIdentity.LaunchAuthorizationProof?
                    boundSecurityCapabilities = null;
                IntPtr jobMemory = IntPtr.Zero;
                ProcessInformation process = default;
                try
                {
                    UIntPtr attributeListSize = UIntPtr.Zero;
                    bool firstInitialize = InitializeProcThreadAttributeList(
                        IntPtr.Zero,
                        2,
                        0,
                        ref attributeListSize
                    );
                    int firstInitializeError = Marshal.GetLastWin32Error();
                    if (firstInitialize
                        || firstInitializeError != ErrorInsufficientBuffer
                        || attributeListSize == UIntPtr.Zero)
                    {
                        throw new InteropWin32Exception(
                            "InitializeProcThreadAttributeList(network,size)",
                            firstInitializeError
                        );
                    }
                    attributeList = Marshal.AllocHGlobal(
                        checked((int)attributeListSize.ToUInt64())
                    );
                    if (!InitializeProcThreadAttributeList(
                        attributeList,
                        2,
                        0,
                        ref attributeListSize
                    ))
                    {
                        ThrowLastError("InitializeProcThreadAttributeList(network)");
                    }
                    boundSecurityCapabilities =
                        boundIdentity.BuildNetworkLaunchAuthorization(
                            internetClientSid,
                            internetClient
                        );
                    jobMemory = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(jobMemory, job);
                    UpdateAttribute(
                        attributeList,
                        ProcThreadAttributeJobList,
                        jobMemory,
                        IntPtr.Size,
                        "NETWORK_JOB_LIST"
                    );
                    StartupInfoEx startup = new();
                    startup.StartupInfo.Cb = Marshal.SizeOf<StartupInfoEx>();
                    startup.AttributeList = attributeList;
                    string environmentSha256 = EnvironmentFingerprint();
                    failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Launch);
                    if (!boundSecurityCapabilities.CreateSuspendedProcess(
                        pythonImage,
                        new StringBuilder(command),
                        false,
                        CreateSuspended
                            | CreateUnicodeEnvironment
                            | ExtendedStartupInfoPresent
                            | CreateNoWindow,
                        profileFolder,
                        ref startup,
                        out process
                    ))
                    {
                        int error = Marshal.GetLastWin32Error();
                        throw new NotObservedException(
                            "network_arm_create_process_unavailable_"
                            + error.ToString(System.Globalization.CultureInfo.InvariantCulture)
                        );
                    }
                    NetworkTokenObservationContext tokenContext =
                        failureTracker.BeginNetworkTokenObservation(plan);
                    BoundAppContainerIdentity.ValidatedTokenFacts token =
                        boundIdentity.ObserveNetworkArmToken(
                            process.Process,
                            plan,
                            tokenContext,
                            boundSecurityCapabilities,
                            aapProbePath,
                            noAapProbePath,
                            expectedAapSha256
                        );
                    failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Process);
                    bool jobMember = IsMember(process.Process, job);
                    SortedDictionary<string, object?> imageIdentity = PathIdentityObservation(
                        QueryImagePath(process.Process),
                        "cpython_313_runtime_executable",
                        "python.exe"
                    );
                    uint parentPid = ParentProcessId(process.ProcessId);
                    uint previousSuspendCount = ResumeThread(process.Thread);
                    if (previousSuspendCount != 1)
                    {
                        throw new InvalidOperationException("network_arm_resume_thread_count_invalid");
                    }
                    failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Report);
                    JsonElement report = WaitForChildReport(
                        reportPath,
                        "network-arm",
                        process.Process
                    );
                    failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Exit);
                    if (WaitForSingleObject(process.Process, armTimeoutMilliseconds) != WaitObject0
                        || !GetExitCodeProcess(process.Process, out uint exitCode)
                        || exitCode != 0)
                    {
                        throw new NotObservedException("network_arm_process_did_not_exit_cleanly");
                    }
                    failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Result);
                    JsonElement attempt = RequireProperty(report, "network");
                    if (string.Equals(label, "preflight_zero", StringComparison.Ordinal))
                    {
                        failureTracker.SetSubstage("network_preflight_zero_expectation");
                        bool preflightConnected = ReadReportBool(attempt, "connected");
                        bool preflightEchoMatches = ReadReportBool(attempt, "echo_matches");
                        int? preflightWinError = ReadNullableInt(attempt, "winerror");
                        int? preflightDiagnosisResult = ReadNullableInt(
                            attempt,
                            "diagnosis_result"
                        );
                        int? preflightDiagnosisType = ReadNullableInt(attempt, "diagnosis_type");
                        JsonElement preflightEchoDigest = RequireProperty(
                            attempt,
                            "echo_nonce_sha256"
                        );
                        if (preflightConnected
                            || preflightEchoMatches
                            || preflightWinError is null or 0
                            || preflightDiagnosisResult != 0
                            || preflightDiagnosisType != 2
                            || preflightEchoDigest.ValueKind != JsonValueKind.Null)
                        {
                            throw new NotObservedException(
                                "network_preflight_internet_client_not_selected"
                            );
                        }
                        failureTracker.SetNetworkArmSubstage(plan, NetworkArmStep.Result);
                    }
                    (uint reportedPid, uint reportedParentPid) =
                        token.ValidateNetworkReport(process.Process, report);
                    string reportedRequestSha256 = ReadReportString(
                        report,
                        "request_sha256"
                    );
                    SortedDictionary<string, object?> arm = new(StringComparer.Ordinal)
                    {
                        ["attempt"] = attempt,
                        ["command_line_sha256"] = commandSha256,
                        ["create_suspended"] = true,
                        ["current_directory_file_id_128_hex"] = profileFolderIdentity.FileId128Hex,
                        ["current_directory_identity_format"] = profileFolderIdentity.IdentityFormat,
                        ["current_directory_path_utf8_sha256"] = profileFolderIdentity.PathUtf8Sha256,
                        ["current_directory_volume_serial_hex"] = profileFolderIdentity.VolumeSerialHex,
                        ["environment_sha256"] = environmentSha256,
                        ["image"] = imageIdentity,
                        ["job_member"] = jobMember,
                        ["label"] = token.ArmLabel,
                        ["order"] = token.ArmOrder,
                        ["parent_pid"] = parentPid,
                        ["pid"] = token.ProcessId,
                        ["reported_parent_pid"] = reportedParentPid,
                        ["reported_pid"] = reportedPid,
                        ["reported_request_sha256"] = reportedRequestSha256,
                        ["request_file_id_128_hex"] = requestIdentity.FileId128Hex,
                        ["request_identity_format"] = requestIdentity.IdentityFormat,
                        ["request_leaf"] = requestLeaf,
                        ["request_parent_file_id_128_hex"] = profileFolderIdentity.FileId128Hex,
                        ["request_parent_identity_format"] = profileFolderIdentity.IdentityFormat,
                        ["request_parent_path_utf8_sha256"] = profileFolderIdentity.PathUtf8Sha256,
                        ["request_parent_volume_serial_hex"] = profileFolderIdentity.VolumeSerialHex,
                        ["request_path_utf8_sha256"] = requestIdentity.PathUtf8Sha256,
                        ["request_sha256"] = requestSha256,
                        ["request_volume_serial_hex"] = requestIdentity.VolumeSerialHex,
                        ["requested_capabilities_pointer_null"] = !internetClient,
                        ["requested_capability_sids"] = internetClient
                            ? new[] { internetClientSidText }
                            : Array.Empty<string>(),
                        ["resume_thread_count"] = 1,
                        ["startup_attribute_count"] = 2,
                        ["startup_attributes"] = new[]
                        {
                            "job_list",
                            "security_capabilities",
                        },
                        ["regular_appcontainer"] =
                            token.NetworkRegularAppContainerWire(process.Process),
                        ["timeout_milliseconds"] = armTimeoutMilliseconds,
                        ["target_host"] = lanAddress.ToString(),
                        ["target_port"] = (int)baseRequest["lan_port"]!,
                        ["token"] = token.NetworkTokenWire(process.Process),
                    };
                    observations.Add(NetworkArmObservation.Issue(plan, arm));
                }
                finally
                {
                    if (process.Process != IntPtr.Zero
                        && WaitForSingleObject(process.Process, 0) != WaitObject0)
                    {
                        _ = TerminateProcess(process.Process, 126);
                        _ = WaitForSingleObject(process.Process, 5000);
                    }
                    CloseOwnedHandle(ref process.Thread);
                    CloseOwnedHandle(ref process.Process);
                    if (attributeList != IntPtr.Zero)
                    {
                        DeleteProcThreadAttributeList(attributeList);
                        Marshal.FreeHGlobal(attributeList);
                    }
                    boundSecurityCapabilities?.Dispose();
                    FreeHGlobal(ref jobMemory);
                }
            }
            failureTracker.SetSubstage(
                phase == NetworkDifferentialPhase.Preflight
                    ? "network_preflight_profile_after"
                    : "network_full_profile_after"
            );
            BoundAppContainerIdentity.ValidatedProfileIdentity finalNetworkProfileIdentity =
                boundIdentity.ObserveNetworkProfileFolderAfter(
                    profileFolder,
                    validatedProfileIdentity
                );
            if (finalNetworkProfileIdentity.Checkpoint != "network_after"
                || finalNetworkProfileIdentity.Ordinal != validatedProfileIdentity.Ordinal)
            {
                throw new InvalidOperationException("network_profile_checkpoint_mismatch");
            }
        }
        finally
        {
            try { File.Delete(requestPath); } catch { }
            try { File.Delete(reportPath); } catch { }
            try { File.Delete(failurePath); } catch { }
            if (internetClientSid != IntPtr.Zero) _ = LocalFree(internetClientSid);
        }
        return observations;
    }

    private static PathIdentityBinding ReadPathIdentityBinding(string path)
    {
        SecurityAttributes attributes = new()
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            SecurityDescriptor = IntPtr.Zero,
            InheritHandle = false,
        };
        IntPtr handle = CreateFileW(
            path,
            0,
            FileShareRead | FileShareWrite | FileShareDelete,
            ref attributes,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero
        );
        if (handle == InvalidHandleValue)
        {
            ThrowLastError("CreateFileW(path_identity)");
        }
        try
        {
            return ReadHandleIdentityBinding(handle);
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    private static PathIdentityBinding ReadHandleIdentityBinding(IntPtr handle)
    {
        if (!BitConverter.IsLittleEndian)
        {
            throw new InvalidOperationException("file_identity_byte_order_unsupported");
        }
        if (!GetFileInformationByHandleEx(
            handle,
            FileIdInfoClass,
            out FileIdInfo fileId,
            checked((uint)Marshal.SizeOf<FileIdInfo>())
        ))
        {
            ThrowLastError("GetFileInformationByHandleEx(path_identity)");
        }
        byte[] identifier = new byte[16];
        Buffer.BlockCopy(BitConverter.GetBytes(fileId.FileIdLow), 0, identifier, 0, 8);
        Buffer.BlockCopy(BitConverter.GetBytes(fileId.FileIdHigh), 0, identifier, 8, 8);
        const int maximumPathCharacters = 32_768;
        StringBuilder finalPathBuffer = new(maximumPathCharacters);
        uint finalPathLength = GetFinalPathNameByHandleW(
            handle,
            finalPathBuffer,
            maximumPathCharacters,
            0
        );
        if (finalPathLength == 0 || finalPathLength >= maximumPathCharacters)
        {
            ThrowLastError("GetFinalPathNameByHandleW(path_identity)");
        }
        string finalPath = finalPathBuffer.ToString();
        if (finalPath.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            finalPath = "\\\\" + finalPath[8..];
        }
        else if (finalPath.StartsWith("\\\\?\\", StringComparison.Ordinal))
        {
            finalPath = finalPath[4..];
        }
        if (string.IsNullOrEmpty(finalPath)
            || finalPath.IndexOf('\0') >= 0
            || finalPath.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("final_handle_path_invalid");
        }
        string canonicalPath = finalPath.Replace('/', '\\').ToLowerInvariant();
        return new PathIdentityBinding(
            Convert.ToHexString(identifier).ToLowerInvariant(),
            "windows-file-id-info.v1",
            Sha256(Encoding.UTF8.GetBytes(canonicalPath)),
            fileId.VolumeSerialNumber.ToString(
                "x16",
                System.Globalization.CultureInfo.InvariantCulture
            )
        );
    }

    private static void RequireSamePathIdentity(
        PathIdentityBinding observed,
        PathIdentityBinding expected,
        string reason
    )
    {
        if (observed != expected)
        {
            throw new InvalidOperationException(reason);
        }
    }

    private static ObjectIdentity ReadObjectIdentity(string path)
    {
        SecurityAttributes attributes = new()
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            SecurityDescriptor = IntPtr.Zero,
            InheritHandle = false,
        };
        IntPtr handle = CreateFileW(
            path,
            0,
            FileShareRead | FileShareWrite | FileShareDelete,
            ref attributes,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero
        );
        if (handle == InvalidHandleValue)
        {
            ThrowLastError("CreateFileW(fingerprint_identity)");
        }
        try
        {
            if (!GetFileInformationByHandleEx(
                handle,
                FileIdInfoClass,
                out FileIdInfo fileId,
                checked((uint)Marshal.SizeOf<FileIdInfo>())
            ))
            {
                ThrowLastError("GetFileInformationByHandleEx(FileIdInfo)");
            }
            if (!GetFileInformationByHandle(handle, out ByHandleFileInformation basic))
            {
                ThrowLastError("GetFileInformationByHandle");
            }
            string identity = string.Concat(
                fileId.VolumeSerialNumber.ToString("x16", System.Globalization.CultureInfo.InvariantCulture),
                ":",
                fileId.FileIdLow.ToString("x16", System.Globalization.CultureInfo.InvariantCulture),
                fileId.FileIdHigh.ToString("x16", System.Globalization.CultureInfo.InvariantCulture)
            );
            return new ObjectIdentity(identity, basic.NumberOfLinks);
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    private static List<string> ReadObjectStreams(string path)
    {
        List<string> streams = new();
        IntPtr find = FindFirstStreamW(path, 0, out Win32FindStreamData data, 0);
        if (find == InvalidHandleValue)
        {
            int error = Marshal.GetLastWin32Error();
            if (error is ErrorFileNotFound or ErrorHandleEof)
            {
                return streams;
            }
            throw new NotObservedException(
                "stream_enumeration_unavailable_"
                + error.ToString(System.Globalization.CultureInfo.InvariantCulture)
            );
        }
        try
        {
            streams.Add(data.StreamName);
            while (FindNextStreamW(find, out data))
            {
                streams.Add(data.StreamName);
            }
            int error = Marshal.GetLastWin32Error();
            if (error != ErrorHandleEof)
            {
                throw new InteropWin32Exception("FindNextStreamW", error);
            }
        }
        finally
        {
            _ = FindClose(find);
        }
        streams.Sort(StringComparer.Ordinal);
        if (streams.Count != streams.Distinct(StringComparer.Ordinal).Count()
            || streams.Any(item => string.IsNullOrEmpty(item)))
        {
            throw new InvalidOperationException("stream_roster_invalid");
        }
        return streams;
    }

    private static AclSnapshot ReadAclSnapshot(string path, bool isDirectory, string appContainerSid)
    {
        FileSystemSecurity security = isDirectory
            ? FileSystemAclExtensions.GetAccessControl(
                new DirectoryInfo(path),
                AccessControlSections.Access | AccessControlSections.Owner
            )
            : FileSystemAclExtensions.GetAccessControl(
                new FileInfo(path),
                AccessControlSections.Access | AccessControlSections.Owner
            );
        SecurityIdentifier? owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null)
        {
            throw new InvalidOperationException("fingerprint_owner_missing");
        }
        bool controllerFull = false;
        bool appContainerReadExecute = false;
        bool appContainerMutation = false;
        string? currentUserSid = WindowsIdentity.GetCurrent().User?.Value;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(
            true,
            true,
            typeof(SecurityIdentifier)
        ))
        {
            if (rule.IdentityReference is not SecurityIdentifier sid
                || rule.AccessControlType != AccessControlType.Allow)
            {
                continue;
            }
            if (string.Equals(sid.Value, currentUserSid, StringComparison.Ordinal)
                && (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl)
            {
                controllerFull = true;
            }
            if (string.Equals(sid.Value, appContainerSid, StringComparison.Ordinal))
            {
                appContainerReadExecute = appContainerReadExecute
                    || (rule.FileSystemRights & FileSystemRights.ReadAndExecute)
                        == FileSystemRights.ReadAndExecute;
                const FileSystemRights mutation = FileSystemRights.Write
                    | FileSystemRights.Delete
                    | FileSystemRights.DeleteSubdirectoriesAndFiles
                    | FileSystemRights.ChangePermissions
                    | FileSystemRights.TakeOwnership;
                appContainerMutation = appContainerMutation
                    || (rule.FileSystemRights & mutation) != 0;
            }
        }
        return new AclSnapshot(
            owner.Value,
            controllerFull,
            appContainerReadExecute,
            appContainerMutation,
            security.AreAccessRulesCanonical
        );
    }

    private static SortedDictionary<string, object?> FingerprintTree(
        string root,
        string appContainerSid,
        string rootRole,
        string expectedRootLeaf
    )
    {
        if (!Directory.Exists(root))
        {
            throw new InvalidOperationException("fingerprint_root_missing");
        }
        List<string> entries = Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)
            .OrderBy(item => Path.GetRelativePath(root, item), StringComparer.Ordinal)
            .ToList();
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using IncrementalHash identityHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long byteCount = 0;
        int alternateStreamCount = 0;
        bool allFilesSingleLink = true;
        bool allEntriesOwnerMatch = true;
        bool allEntriesControllerFull = true;
        bool allEntriesMutationAbsent = true;
        bool declaredReadEntriesReadable = true;
        AclSnapshot rootAcl = ReadAclSnapshot(root, true, appContainerSid);
        if (!rootAcl.Canonical)
        {
            throw new InvalidOperationException("fingerprint_acl_invalid");
        }
        List<string> identityEntries = new() { root };
        identityEntries.AddRange(entries);
        foreach (string entry in identityEntries)
        {
            FileAttributes attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("fingerprint_tree_contains_reparse");
            }
            bool isDirectory = (attributes & FileAttributes.Directory) != 0;
            string relative = string.Equals(entry, root, StringComparison.OrdinalIgnoreCase)
                ? "."
                : Path.GetRelativePath(root, entry).Replace('\\', '/');
            ObjectIdentity identity = ReadObjectIdentity(entry);
            List<string> streams = ReadObjectStreams(entry);
            if (!isDirectory && !streams.Contains("::$DATA", StringComparer.Ordinal))
            {
                throw new NotObservedException("default_stream_not_observed");
            }
            int namedStreams = streams.Count(item => !string.Equals(item, "::$DATA", StringComparison.Ordinal));
            alternateStreamCount = checked(alternateStreamCount + namedStreams);
            if (!isDirectory && identity.LinkCount != 1)
            {
                allFilesSingleLink = false;
            }
            identityHash.AppendData(Encoding.UTF8.GetBytes(
                (isDirectory ? "D" : "F")
                + "\0"
                + relative
                + "\0"
                + identity.Value
                + "\0"
                + identity.LinkCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
                + "\0"
                + string.Join("\0", streams)
                + "\0"
            ));
            AclSnapshot acl = string.Equals(entry, root, StringComparison.OrdinalIgnoreCase)
                ? rootAcl
                : ReadAclSnapshot(entry, isDirectory, appContainerSid);
            allEntriesOwnerMatch = allEntriesOwnerMatch
                && string.Equals(acl.OwnerSid, rootAcl.OwnerSid, StringComparison.Ordinal);
            allEntriesControllerFull = allEntriesControllerFull && acl.ControllerFullControl;
            allEntriesMutationAbsent = allEntriesMutationAbsent && !acl.AppContainerMutationRights;
            bool declaredReadExecute = appContainerSid == "S-1-0-0"
                || relative == "."
                || !(string.Equals(relative, "protected", StringComparison.Ordinal)
                    || relative.StartsWith("protected/", StringComparison.Ordinal));
            if (declaredReadExecute && appContainerSid != "S-1-0-0")
            {
                declaredReadEntriesReadable = declaredReadEntriesReadable
                    && acl.AppContainerReadExecute;
            }
        }
        foreach (string entry in entries)
        {
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("fingerprint_tree_contains_reparse");
            }
            string relative = Path.GetRelativePath(root, entry).Replace('\\', '/');
            if (Directory.Exists(entry))
            {
                hash.AppendData(Encoding.UTF8.GetBytes("D\0" + relative + "\0"));
                continue;
            }
            byte[] content = File.ReadAllBytes(entry);
            byteCount = checked(byteCount + content.LongLength);
            hash.AppendData(Encoding.UTF8.GetBytes(
                "F\0" + relative + "\0" + content.LongLength.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\0"
            ));
            hash.AppendData(SHA256.HashData(content));
        }
        DirectorySecurity security = FileSystemAclExtensions.GetAccessControl(
            new DirectoryInfo(root),
            AccessControlSections.Access | AccessControlSections.Owner
        );
        SecurityIdentifier? owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        SecurityIdentifier? controller = WindowsIdentity.GetCurrent().User;
        if (owner is null || !security.AreAccessRulesProtected || !security.AreAccessRulesCanonical)
        {
            throw new InvalidOperationException("fingerprint_acl_invalid");
        }
        bool controllerFull = false;
        bool appContainerReadExecute = false;
        bool appContainerMutation = false;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
        {
            if (rule.IdentityReference is not SecurityIdentifier sid || rule.AccessControlType != AccessControlType.Allow)
            {
                continue;
            }
            if (string.Equals(sid.Value, WindowsIdentity.GetCurrent().User?.Value, StringComparison.Ordinal)
                && (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl)
            {
                controllerFull = true;
            }
            if (string.Equals(sid.Value, appContainerSid, StringComparison.Ordinal))
            {
                appContainerReadExecute =
                    (rule.FileSystemRights & FileSystemRights.ReadAndExecute) == FileSystemRights.ReadAndExecute;
                const FileSystemRights mutation = FileSystemRights.Write
                    | FileSystemRights.Delete
                    | FileSystemRights.DeleteSubdirectoriesAndFiles
                    | FileSystemRights.ChangePermissions
                    | FileSystemRights.TakeOwnership;
                appContainerMutation = (rule.FileSystemRights & mutation) != 0;
            }
        }
        SortedDictionary<string, object?> rootIdentity = PathIdentityObservation(
            root,
            rootRole,
            expectedRootLeaf
        );
        return new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["all_entries_appcontainer_mutation_rights_absent"] = allEntriesMutationAbsent,
            ["all_entries_controller_full_control"] = allEntriesControllerFull,
            ["all_entries_owner_matches_root"] = allEntriesOwnerMatch,
            ["all_files_single_link"] = allFilesSingleLink,
            ["alternate_stream_count"] = alternateStreamCount,
            ["appcontainer_mutation_rights_absent"] = !appContainerMutation,
            ["appcontainer_read_execute"] = appContainerReadExecute,
            ["byte_count"] = byteCount,
            ["controller_full_control"] = controllerFull,
            ["dacl_protected"] = security.AreAccessRulesProtected,
            ["declared_read_execute_entries_appcontainer_read_execute"] = declaredReadEntriesReadable,
            ["entry_count"] = entries.Count,
            ["object_identity_sha256"] = Convert.ToHexString(
                identityHash.GetHashAndReset()
            ).ToLowerInvariant(),
            ["owner_matches_controller"] = controller is not null
                && string.Equals(owner.Value, controller.Value, StringComparison.Ordinal),
            ["reparse_free"] = true,
            ["root_identity"] = rootIdentity,
            ["tree_sha256"] = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant(),
        };
    }

    private static string TreeContentSha256(string root)
    {
        SortedDictionary<string, object?> value = FingerprintTree(
            root,
            "S-1-0-0",
            "internal_content_digest_only",
            Path.GetFileName(Path.GetFullPath(root))
        );
        return (string)(value["tree_sha256"] ?? throw new InvalidOperationException("tree_hash_missing"));
    }

    private static IEnumerable<FileStream> LockAllFiles(string root)
    {
        List<FileStream> streams = new();
        try
        {
            foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .OrderBy(item => item, StringComparer.Ordinal))
            {
                streams.Add(new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read));
            }
            return streams;
        }
        catch
        {
            foreach (FileStream stream in streams) stream.Dispose();
            throw;
        }
    }

    private static IEnumerable<FileStream> LockNamedFiles(params string[] paths)
    {
        List<FileStream> streams = new();
        try
        {
            foreach (string path in paths.OrderBy(item => item, StringComparer.Ordinal))
            {
                streams.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
            }
            return streams;
        }
        catch
        {
            foreach (FileStream stream in streams) stream.Dispose();
            throw;
        }
    }

    private static void ConfigureKillOnCloseJob(IntPtr job)
    {
        JobObjectExtendedLimitInformation limits = new();
        limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf<JobObjectExtendedLimitInformation>());
        try
        {
            Marshal.StructureToPtr(limits, buffer, false);
            if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformationClass,
                buffer,
                checked((uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>())
            ))
            {
                ThrowLastError("SetInformationJobObject");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static uint ReadJobLimitFlags(IntPtr job)
    {
        int size = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.Copy(new byte[size], 0, buffer, size);
            if (!QueryInformationJobObject(
                job,
                JobObjectExtendedLimitInformationClass,
                buffer,
                checked((uint)size),
                out uint returned
            ))
            {
                ThrowLastError("QueryInformationJobObject");
            }
            if (returned != size)
            {
                throw new InvalidOperationException("job_limit_query_size_mismatch");
            }
            JobObjectExtendedLimitInformation observed =
                Marshal.PtrToStructure<JobObjectExtendedLimitInformation>(buffer);
            return observed.BasicLimitInformation.LimitFlags;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void UpdateAttribute(
        IntPtr attributeList,
        uint attribute,
        IntPtr value,
        int size,
        string name
    )
    {
        if (!UpdateProcThreadAttribute(
            attributeList,
            0,
            new UIntPtr(attribute),
            value,
            new UIntPtr(checked((uint)size)),
            IntPtr.Zero,
            IntPtr.Zero
        ))
        {
            ThrowLastError("UpdateProcThreadAttribute(" + name + ")");
        }
    }

    private static bool IsMember(IntPtr process, IntPtr job)
    {
        if (!IsProcessInJob(process, job, out bool member))
        {
            ThrowLastError("IsProcessInJob");
        }
        return member;
    }

    private static JsonElement RunPositiveFilesystemControl(
        string pythonImage,
        string probePath,
        string requestPath,
        string scratchRoot
    )
    {
        ProcessStartInfo start = new()
        {
            CreateNoWindow = true,
            FileName = pythonImage,
            UseShellExecute = false,
            WorkingDirectory = scratchRoot,
        };
        foreach (string argument in new[] { "-I", "-B", probePath, requestPath, "positive-control" })
        {
            start.ArgumentList.Add(argument);
        }
        using Process process = Process.Start(start)
            ?? throw new NotObservedException("filesystem_positive_control_launch_failed");
        if (!process.WaitForExit(30_000))
        {
            try { process.Kill(true); } catch { }
            throw new NotObservedException("filesystem_positive_control_timeout");
        }
        if (process.ExitCode != 0)
        {
            throw new NotObservedException(
                "filesystem_positive_control_exit_"
                + process.ExitCode.ToString(System.Globalization.CultureInfo.InvariantCulture)
            );
        }
        return WaitForChildReport(
            Path.Combine(scratchRoot, "positive-control.json"),
            "positive-control"
        );
    }

    private static SortedDictionary<string, object?> CombineFilesystemOperations(
        JsonElement positiveOperations,
        JsonElement negativeOperations
    )
    {
        SortedDictionary<string, object?> result = new(StringComparer.Ordinal);
        foreach (string operation in new[]
        {
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
        })
        {
            JsonElement positivePair = RequireProperty(positiveOperations, operation);
            JsonElement negativePair = RequireProperty(negativeOperations, operation);
            JsonElement positive = RequireProperty(positivePair, "positive");
            JsonElement negative = RequireProperty(negativePair, "negative");
            if (positive.ValueKind != JsonValueKind.Object || negative.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidOperationException("filesystem_control_pair_invalid");
            }
            result[operation] = new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["negative"] = negative,
                ["positive"] = positive,
            };
        }
        return result;
    }

    private static JsonElement WaitForChildReport(
        string path,
        string expectedRole,
        IntPtr process = default
    )
    {
        Stopwatch timer = Stopwatch.StartNew();
        while (timer.Elapsed < TimeSpan.FromSeconds(45))
        {
            string failurePath = Path.Combine(Path.GetDirectoryName(path) ?? "", "failure.json");
            if (File.Exists(failurePath))
            {
                try
                {
                    using JsonDocument failure = JsonDocument.Parse(File.ReadAllBytes(failurePath));
                    string reason = failure.RootElement.GetProperty("reason").GetString() ?? "unknown";
                    throw new NotObservedException("child_probe_" + NormalizeOperation(reason));
                }
                catch (JsonException)
                {
                    throw new InvalidOperationException("child_failure_report_invalid");
                }
            }
            if (File.Exists(path))
            {
                try
                {
                    byte[] payload = File.ReadAllBytes(path);
                    if (payload.Length is > 0 and <= 1_048_576
                        && payload[^1] == (byte)'\n'
                        && payload.Count(value => value == (byte)'\n') == 1
                        && !payload.Contains((byte)'\r')
                        && !payload.Contains((byte)0))
                    {
                        using JsonDocument document = JsonDocument.Parse(payload);
                        JsonElement root = document.RootElement;
                        if (root.ValueKind == JsonValueKind.Object
                            && ValidateJsonPropertyUniqueness(root)
                            && CanonicalJsonLine(root).SequenceEqual(payload)
                            && string.Equals(
                                ReadReportString(root, "format"),
                                "finplanbr.windows-appcontainer-child-observations.v4",
                                StringComparison.Ordinal
                            )
                            && string.Equals(
                                ReadReportString(root, "role"),
                                expectedRole,
                                StringComparison.Ordinal
                            ))
                        {
                            return root.Clone();
                        }
                    }
                }
                catch (IOException) { }
                catch (JsonException) { }
            }
            if (process != IntPtr.Zero && WaitForSingleObject(process, 0) == WaitObject0)
            {
                uint exitCode = GetExitCodeProcess(process, out uint observed) ? observed : uint.MaxValue;
                throw new NotObservedException(
                    "child_process_exited_"
                    + exitCode.ToString(System.Globalization.CultureInfo.InvariantCulture)
                );
            }
            Thread.Sleep(20);
        }
        throw new NotObservedException("child_report_timeout");
    }

    private static bool ValidateJsonPropertyUniqueness(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            HashSet<string> names = new(StringComparer.Ordinal);
            foreach (JsonProperty property in value.EnumerateObject())
            {
                if (!names.Add(property.Name) || !ValidateJsonPropertyUniqueness(property.Value))
                {
                    return false;
                }
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in value.EnumerateArray())
            {
                if (!ValidateJsonPropertyUniqueness(item)) return false;
            }
        }
        return true;
    }

    private static uint ReadReportPid(JsonElement report, string name)
    {
        JsonElement value = RequireProperty(report, name);
        if (!value.TryGetUInt32(out uint result) || result == 0)
        {
            throw new InvalidOperationException("child_report_pid_invalid");
        }
        return result;
    }

    private static IntPtr OpenObservedProcess(uint processId)
    {
        IntPtr process = OpenProcess(Synchronize | ProcessQueryLimitedInformation, false, processId);
        if (process == IntPtr.Zero)
        {
            ThrowLastError("OpenProcess(descendant)");
        }
        return process;
    }

    private static JsonElement RequireProperty(JsonElement value, string name)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(name, out JsonElement property))
        {
            throw new InvalidOperationException("child_report_property_missing_" + name);
        }
        return property.Clone();
    }

    private static bool ReadReportBool(JsonElement value, string name)
    {
        JsonElement property = RequireProperty(value, name);
        if (property.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidOperationException("child_report_boolean_invalid");
        }
        return property.GetBoolean();
    }

    private static int? ReadNullableInt(JsonElement value, string name)
    {
        JsonElement property = RequireProperty(value, name);
        if (property.ValueKind == JsonValueKind.Null) return null;
        if (!property.TryGetInt32(out int result))
        {
            throw new InvalidOperationException("child_report_integer_invalid");
        }
        return result;
    }

    private static string ReadReportString(JsonElement value, string name)
    {
        JsonElement property = RequireProperty(value, name);
        if (property.ValueKind != JsonValueKind.String
            || property.GetString() is not string result
            || result.Length == 0)
        {
            throw new InvalidOperationException("child_report_string_invalid");
        }
        return result;
    }

    private static void DrainPending(TcpListener listener)
    {
        while (listener.Pending())
        {
            using TcpClient connection = listener.AcceptTcpClient();
        }
    }

    private static bool WaitForKilled(IntPtr process)
    {
        if (WaitForSingleObject(process, 10_000) != WaitObject0) return false;
        return GetExitCodeProcess(process, out uint code) && code != StillActive;
    }

    private static SortedDictionary<string, object?> PathIdentityObservation(
        string path,
        string role,
        string expectedLeaf
    )
    {
        string leaf = Path.GetFileName(Path.GetFullPath(path));
        if (!string.Equals(leaf, expectedLeaf, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("path_identity_leaf_mismatch");
        }
        PathIdentityBinding identity = ReadPathIdentityBinding(path);
        return new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["file_id_128_hex"] = identity.FileId128Hex,
            ["identity_format"] = identity.IdentityFormat,
            ["leaf"] = expectedLeaf,
            ["path_utf8_sha256"] = identity.PathUtf8Sha256,
            ["role"] = role,
            ["volume_serial_hex"] = identity.VolumeSerialHex,
        };
    }

    private static string QueryImagePath(IntPtr process)
    {
        uint size = 32_768;
        StringBuilder path = new(checked((int)size));
        if (!QueryFullProcessImageNameW(process, 0, path, ref size) || size == 0)
        {
            ThrowLastError("QueryFullProcessImageNameW");
        }
        return Path.GetFullPath(path.ToString());
    }

    private static uint ParentProcessId(uint processId)
    {
        IntPtr snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == InvalidHandleValue)
        {
            ThrowLastError("CreateToolhelp32Snapshot");
        }
        try
        {
            ProcessEntry32 entry = new() { Size = checked((uint)Marshal.SizeOf<ProcessEntry32>()) };
            if (!Process32FirstW(snapshot, ref entry))
            {
                ThrowLastError("Process32FirstW");
            }
            do
            {
                if (entry.ProcessId == processId) return entry.ParentProcessId;
                entry.Size = checked((uint)Marshal.SizeOf<ProcessEntry32>());
            }
            while (Process32NextW(snapshot, ref entry));
            throw new InvalidOperationException("process_parent_not_found");
        }
        finally
        {
            _ = CloseHandle(snapshot);
        }
    }

    private static bool IsUnder(string path, string root)
    {
        string fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
    }

    private static void FreeHGlobal(ref IntPtr memory)
    {
        if (memory != IntPtr.Zero) Marshal.FreeHGlobal(memory);
        memory = IntPtr.Zero;
    }

    private static void DeleteTreeNoReparse(string root)
    {
        if (!Directory.Exists(root)) return;
        foreach (string entry in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("cleanup_tree_contains_reparse");
            }
        }
        Directory.Delete(root, true);
    }

    private static void TryDeleteTree(string root)
    {
        try { DeleteTreeNoReparse(root); } catch { }
    }

    private static int EmitBoundaryObservations(SortedDictionary<string, object?> raw)
    {
        SortedDictionary<string, object?> report = new(StringComparer.Ordinal)
        {
            ["authority"] = "none",
            ["evidence_authentication"] = "not_implemented",
            ["format"] = HelperFormat,
            ["helper_failure_receipt"] = null,
            ["raw_observations"] = raw,
            ["reason"] = "raw_observations_complete",
            ["release_authorized"] = false,
            ["status"] = "observations_complete",
        };
        Console.Out.WriteLine(JsonSerializer.Serialize(report));
        return 0;
    }

    private static int EmitBoundaryFailure(
        string status,
        string stage,
        string substage,
        string failureClass
    )
    {
        if (status is not ("failed" or "not_observed")
            || !IsFailureStage(stage)
            || !IsFailureStageSubstagePair(stage, substage)
            || !IsFailureClass(failureClass)
            || (status == "not_observed") != (failureClass == "not_observed"))
        {
            throw new InvalidOperationException("helper_failure_receipt_invalid");
        }
        SortedDictionary<string, object?> failureReceipt = new(StringComparer.Ordinal)
        {
            ["failure_class"] = failureClass,
            ["format"] = HelperFailureReceiptFormat,
            ["stage"] = stage,
            ["status"] = status,
            ["substage"] = substage,
        };
        SortedDictionary<string, object?> report = new(StringComparer.Ordinal)
        {
            ["authority"] = "none",
            ["evidence_authentication"] = "not_implemented",
            ["format"] = HelperFormat,
            ["helper_failure_receipt"] = failureReceipt,
            ["raw_observations"] = null,
            ["reason"] = status == "not_observed" ? "helper_not_observed" : "helper_failed",
            ["release_authorized"] = false,
            ["status"] = status,
        };
        Console.Out.WriteLine(JsonSerializer.Serialize(report));
        return 1;
    }

    private static TokenFacts ReadTokenFacts(IntPtr processHandle)
    {
        if (!OpenProcessToken(processHandle, TokenQuery | TokenDuplicate, out IntPtr token))
        {
            ThrowLastError("OpenProcessToken");
        }
        try
        {
            return ReadTokenFactsFromToken(token, null);
        }
        finally
        {
            _ = CloseHandle(token);
        }
    }

    private static (TokenFacts Facts, string AapSha256, uint NoAapError)
        ReadNetworkTokenFactsAndObserveClassicBehavior(
        IntPtr processHandle,
        NetworkTokenObservationContext context,
        string aapProbePath,
        string noAapProbePath
    )
    {
        if (!OpenProcessToken(processHandle, TokenQuery | TokenDuplicate, out IntPtr token))
        {
            ThrowLastError("OpenProcessToken(network)");
        }
        try
        {
            TokenFacts facts = ReadTokenFactsFromToken(token, context);
            context.Enter(NetworkTokenStep.AapEffect);
            (string aapSha256, uint noAapError) = ObserveClassicBehaviorWithToken(
                token,
                aapProbePath,
                noAapProbePath
            );
            return (facts, aapSha256, noAapError);
        }
        finally
        {
            _ = CloseHandle(token);
        }
    }

    private static TokenFacts ReadTokenFactsFromToken(
        IntPtr token,
        NetworkTokenObservationContext? context
    )
    {
            bool isAppContainer = ReadDwordTokenInformation(token, TokenIsAppContainer) != 0;
            bool elevated = ReadDwordTokenInformation(token, TokenElevation) != 0;
            context?.Enter(NetworkTokenStep.AapMembership);
            bool hasAllApplicationPackages = CheckAppContainerMembership(token, "S-1-15-2-1");
            context?.Enter(NetworkTokenStep.AapRosters);
            (uint tokenGroupCount, uint aapTokenGroupMatchCount, string aapTokenGroupMatchAttributes) =
                ReadTargetSidMatches(token, TokenGroups, "S-1-15-2-1");
            (uint restrictedSidCount, uint aapRestrictedSidMatchCount, string aapRestrictedSidMatchAttributes) =
                ReadTargetSidMatches(token, TokenRestrictedSids, "S-1-15-2-1");
            bool? lpac;
            bool lpacQuerySupported;
            context?.Enter(NetworkTokenStep.Lpac);
            try
            {
                lpac = ReadDwordTokenInformation(token, TokenIsLessPrivilegedAppContainer) != 0;
                lpacQuerySupported = true;
            }
            catch (InteropWin32Exception error) when (error.NativeErrorCode == 87)
            {
                (lpac, lpacQuerySupported) = UnsupportedLpacQueryDiagnostic();
            }
            context?.Enter(NetworkTokenStep.Identity);
            IntPtr appContainerBuffer = ReadTokenInformation(token, TokenAppContainerSid);
            IntPtr capabilitiesBuffer = IntPtr.Zero;
            IntPtr integrityBuffer = IntPtr.Zero;
            try
            {
                IntPtr appContainerSid = Marshal.ReadIntPtr(appContainerBuffer);
                string sid = SidToString(appContainerSid);
                capabilitiesBuffer = ReadTokenInformation(token, TokenCapabilities);
                uint capabilityCount = unchecked((uint)Marshal.ReadInt32(capabilitiesBuffer));
                string capabilityEntries = GroupEntryCsv(capabilitiesBuffer);
                integrityBuffer = ReadTokenInformation(token, TokenIntegrityLevel);
                IntPtr integritySid = Marshal.ReadIntPtr(integrityBuffer);
                IntPtr countPointer = GetSidSubAuthorityCount(integritySid);
                if (countPointer == IntPtr.Zero)
                {
                    throw new InvalidOperationException("integrity_sid_has_no_subauthority_count");
                }
                byte count = Marshal.ReadByte(countPointer);
                if (count == 0)
                {
                    throw new InvalidOperationException("integrity_sid_has_no_subauthority");
                }
                IntPtr ridPointer = GetSidSubAuthority(integritySid, (uint)(count - 1));
                if (ridPointer == IntPtr.Zero)
                {
                    throw new InvalidOperationException("integrity_sid_rid_missing");
                }
                uint integrityRid = unchecked((uint)Marshal.ReadInt32(ridPointer));
                return new TokenFacts(
                    isAppContainer,
                    sid,
                    capabilityCount,
                    capabilityEntries,
                    tokenGroupCount,
                    aapTokenGroupMatchCount,
                    aapTokenGroupMatchAttributes,
                    restrictedSidCount,
                    aapRestrictedSidMatchCount,
                    aapRestrictedSidMatchAttributes,
                    integrityRid,
                    elevated,
                    lpac,
                    lpacQuerySupported,
                    true,
                    null,
                    hasAllApplicationPackages
                );
            }
            finally
            {
                Marshal.FreeHGlobal(appContainerBuffer);
                if (capabilitiesBuffer != IntPtr.Zero) Marshal.FreeHGlobal(capabilitiesBuffer);
                if (integrityBuffer != IntPtr.Zero) Marshal.FreeHGlobal(integrityBuffer);
            }
        }

    private static (bool? Result, bool Supported) UnsupportedLpacQueryDiagnostic()
        => (null, false);

    private static BoundAppContainerIdentity.BoundClassicTokenObservation
        ReadTokenFactsAndObserveClassicBehavior(
        object issuer,
        BoundAppContainerIdentity owner,
        IntPtr processHandle,
        string aapProbePath,
        string noAapProbePath
    )
    {
        if (!OpenProcessToken(processHandle, TokenQuery | TokenDuplicate, out IntPtr primaryToken))
        {
            ThrowLastError("OpenProcessToken(impersonation)");
        }
        try
        {
            TokenFacts facts = ReadTokenFactsFromToken(primaryToken, null);
            (string aapSha256, uint noAapError) = ObserveClassicBehaviorWithToken(
                primaryToken,
                aapProbePath,
                noAapProbePath
            );
            return new BoundAppContainerIdentity.BoundClassicTokenObservation(
                issuer,
                owner,
                processHandle,
                facts,
                aapSha256,
                noAapError
            );
        }
        finally
        {
            CloseOwnedHandle(ref primaryToken);
        }
    }

    private static (string AapSha256, uint NoAapError) ObserveClassicBehaviorWithToken(
        IntPtr primaryToken,
        string aapProbePath,
        string noAapProbePath
    )
    {
        IntPtr impersonationToken = IntPtr.Zero;
        bool impersonating = false;
        try
        {
            if (!DuplicateTokenEx(
                primaryToken,
                TokenQuery | TokenImpersonate,
                IntPtr.Zero,
                SecurityImpersonation,
                TokenImpersonation,
                out impersonationToken
            ))
            {
                ThrowLastError("DuplicateTokenEx(SecurityImpersonation)");
            }
            if (!ImpersonateLoggedOnUser(impersonationToken))
            {
                ThrowLastError("ImpersonateLoggedOnUser");
            }
            impersonating = true;

            byte[] observedAap = File.ReadAllBytes(aapProbePath);
            string observedAapSha256 = Convert.ToHexString(SHA256.HashData(observedAap)).ToLowerInvariant();
            SecurityAttributes attributes = new()
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = IntPtr.Zero,
                InheritHandle = false,
            };
            IntPtr unexpectedHandle = CreateFileW(
                noAapProbePath,
                GenericRead,
                FileShareRead,
                ref attributes,
                OpenExisting,
                FileAttributeNormal,
                IntPtr.Zero
            );
            uint noAapError;
            if (unexpectedHandle != InvalidHandleValue)
            {
                _ = CloseHandle(unexpectedHandle);
                throw new InvalidOperationException("no_aap_file_unexpectedly_readable");
            }
            noAapError = unchecked((uint)Marshal.GetLastWin32Error());
            return (observedAapSha256, noAapError);
        }
        finally
        {
            int revertError = impersonating && !RevertToSelf() ? Marshal.GetLastWin32Error() : 0;
            CloseOwnedHandle(ref impersonationToken);
            if (revertError != 0)
            {
                throw new InteropWin32Exception("RevertToSelf", revertError);
            }
        }
    }

    private static uint ReadDwordTokenInformation(IntPtr token, int informationClass)
    {
        IntPtr buffer = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            if (!GetTokenInformation(token, informationClass, buffer, sizeof(uint), out uint returned))
            {
                ThrowLastError("GetTokenInformation(dword," + informationClass + ")");
            }
            if (returned != sizeof(uint))
            {
                throw new InvalidOperationException("token_dword_information_length_invalid");
            }
            return unchecked((uint)Marshal.ReadInt32(buffer));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool CheckAppContainerMembership(IntPtr token, string expectedSid)
    {
        if (!DuplicateToken(token, SecurityIdentification, out IntPtr duplicate))
        {
            ThrowLastError("DuplicateToken");
        }
        IntPtr sid = IntPtr.Zero;
        try
        {
            if (!ConvertStringSidToSidW(expectedSid, out sid))
            {
                ThrowLastError("ConvertStringSidToSidW");
            }
            bool apiCallSucceeded = CheckTokenMembershipEx(
                duplicate,
                sid,
                CtmfIncludeAppContainer,
                out bool isMember
            );
            return RequireObservedAppContainerMembership(apiCallSucceeded, isMember);
        }
        finally
        {
            if (sid != IntPtr.Zero)
            {
                _ = LocalFree(sid);
            }
            _ = CloseHandle(duplicate);
        }
    }

    private static bool RequireObservedAppContainerMembership(
        bool apiCallSucceeded,
        bool isMember
    )
    {
        if (!apiCallSucceeded)
        {
            throw new NotObservedException("check_token_membership_ex_unavailable");
        }
        return isMember;
    }

    private static (uint TotalCount, uint TargetMatchCount, string TargetMatchAttributes)
        ReadTargetSidMatches(IntPtr token, int informationClass, string targetSidText)
    {
        IntPtr groups = ReadTokenInformation(token, informationClass);
        IntPtr targetSid = IntPtr.Zero;
        try
        {
            if (!ConvertStringSidToSidW(targetSidText, out targetSid))
            {
                ThrowLastError("ConvertStringSidToSidW(target)");
            }
            uint count = unchecked((uint)Marshal.ReadInt32(groups));
            int offset = Marshal.OffsetOf<TokenGroupsOne>(nameof(TokenGroupsOne.FirstGroup)).ToInt32();
            int stride = Marshal.SizeOf<SidAndAttributes>();
            List<uint> attributes = new();
            for (uint index = 0; index < count; index++)
            {
                IntPtr itemPointer = IntPtr.Add(groups, checked(offset + (int)index * stride));
                SidAndAttributes item = Marshal.PtrToStructure<SidAndAttributes>(itemPointer);
                if (EqualSid(item.Sid, targetSid))
                {
                    attributes.Add(item.Attributes);
                }
            }
            attributes.Sort();
            string csv = string.Join(",", attributes.Select(item =>
                "0x" + item.ToString("x8", System.Globalization.CultureInfo.InvariantCulture)
            ));
            return (count, checked((uint)attributes.Count), csv);
        }
        finally
        {
            if (targetSid != IntPtr.Zero) _ = LocalFree(targetSid);
            Marshal.FreeHGlobal(groups);
        }
    }

    private static string GroupEntryCsv(IntPtr groups)
    {
        uint count = unchecked((uint)Marshal.ReadInt32(groups));
        int offset = Marshal.OffsetOf<TokenGroupsOne>(nameof(TokenGroupsOne.FirstGroup)).ToInt32();
        int stride = Marshal.SizeOf<SidAndAttributes>();
        List<string> sids = new();
        for (uint index = 0; index < count; index++)
        {
            IntPtr itemPointer = IntPtr.Add(groups, checked(offset + (int)index * stride));
            SidAndAttributes item = Marshal.PtrToStructure<SidAndAttributes>(itemPointer);
            sids.Add(
                SidToString(item.Sid)
                + "|0x"
                + item.Attributes.ToString("x8", System.Globalization.CultureInfo.InvariantCulture)
            );
        }
        sids.Sort(StringComparer.Ordinal);
        return string.Join(",", sids);
    }

    private static IntPtr ReadTokenInformation(IntPtr token, int informationClass)
    {
        _ = GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out uint required);
        int error = Marshal.GetLastWin32Error();
        if (required == 0 || error != ErrorInsufficientBuffer)
        {
            throw new InteropWin32Exception("GetTokenInformation(size," + informationClass + ")", error);
        }
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)required));
        if (!GetTokenInformation(token, informationClass, buffer, required, out uint returned))
        {
            int secondError = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw new InteropWin32Exception("GetTokenInformation(data," + informationClass + ")", secondError);
        }
        if (returned > required)
        {
            Marshal.FreeHGlobal(buffer);
            throw new InvalidOperationException("token_information_length_grew");
        }
        return buffer;
    }

    private static void ValidateFacts(
        TokenFacts facts,
        string expectedSid,
        string view,
        NetworkTokenObservationContext? context = null
    )
    {
        if (!facts.IsAppContainer) throw new InvalidOperationException(view + "_not_appcontainer");
        if (!string.Equals(facts.AppContainerSid, expectedSid, StringComparison.Ordinal)) throw new InvalidOperationException(view + "_sid_mismatch");
        if (facts.IntegrityRid != 0x1000) throw new InvalidOperationException(view + "_integrity_not_low");
        if (facts.IsElevated) throw new InvalidOperationException(view + "_token_elevated");
        context?.Enter(NetworkTokenStep.ValidateLpac);
        if (facts.IsLessPrivilegedAppContainer is true) throw new InvalidOperationException(view + "_unexpected_lpac");
        if (facts.LpacQuerySupported != (facts.IsLessPrivilegedAppContainer is not null))
        {
            throw new InvalidOperationException(view + "_lpac_query_state_invalid");
        }
        if (!facts.AllApplicationPackagesMembershipApiCallSucceeded
            || facts.AllApplicationPackagesMembershipApiWin32Error is not null)
        {
            throw new InvalidOperationException(view + "_aap_membership_state_invalid");
        }
        context?.Enter(NetworkTokenStep.ValidateRoster);
        if (facts.AllApplicationPackagesTokenGroupMatchCount
                + facts.AllApplicationPackagesRestrictedSidMatchCount == 0)
        {
            throw new NotObservedException(view + "_aap_sid_not_observed_in_token_rosters");
        }
    }

    private static bool IsSupportedAppContainerSidShape(IntPtr sid)
    {
        if (sid == IntPtr.Zero || !IsValidSid(sid) || Marshal.ReadByte(sid) != 1)
        {
            return false;
        }
        IntPtr authority = GetSidIdentifierAuthority(sid);
        IntPtr countPointer = GetSidSubAuthorityCount(sid);
        if (authority == IntPtr.Zero || countPointer == IntPtr.Zero)
        {
            return false;
        }
        for (int index = 0; index < 5; index++)
        {
            if (Marshal.ReadByte(authority, index) != 0)
            {
                return false;
            }
        }
        if (Marshal.ReadByte(authority, 5) != 15)
        {
            return false;
        }
        byte subAuthorityCount = Marshal.ReadByte(countPointer);
        if (subAuthorityCount is not (8 or 12))
        {
            return false;
        }
        IntPtr baseRid = GetSidSubAuthority(sid, 0);
        return baseRid != IntPtr.Zero && unchecked((uint)Marshal.ReadInt32(baseRid)) == 2;
    }

    private static string SidToString(IntPtr sid)
    {
        IntPtr textPointer = IntPtr.Zero;
        if (sid == IntPtr.Zero || !ConvertSidToStringSidW(sid, out textPointer))
        {
            ThrowLastError("ConvertSidToStringSidW");
        }
        try
        {
            return Marshal.PtrToStringUni(textPointer) ?? throw new InvalidOperationException("SID string is null");
        }
        finally
        {
            _ = LocalFree(textPointer);
        }
    }

    private static string AppContainerFolder(string sid)
    {
        int result = GetAppContainerFolderPath(sid, out IntPtr pathPointer);
        RequireHResult(result, "GetAppContainerFolderPath");
        try
        {
            return Marshal.PtrToStringUni(pathPointer) ?? throw new InvalidOperationException("profile folder is null");
        }
        finally
        {
            CoTaskMemFree(pathPointer);
        }
    }

    private static void ApplyReadOnlyRuntimeAcl(string path, string appContainerSid)
    {
        SecurityIdentifier? currentUser = WindowsIdentity.GetCurrent().User;
        if (currentUser is null)
        {
            throw new InvalidOperationException("current_user_sid_missing");
        }
        string userSid = currentUser.Value;
        DirectoryInfo directory = new(path);
        DirectorySecurity security = FileSystemAclExtensions.GetAccessControl(
            directory,
            AccessControlSections.Access
        );
        security.SetAccessRuleProtection(true, false);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
        {
            security.RemoveAccessRuleSpecific(rule);
        }
        InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier("S-1-3-4"),
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Deny
        ));
        foreach (SecurityIdentifier principal in new[]
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            currentUser,
        })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                principal,
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow
            ));
        }
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(appContainerSid),
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow
        ));
        FileSystemAclExtensions.SetAccessControl(directory, security);
        DirectorySecurity observed = FileSystemAclExtensions.GetAccessControl(
            directory,
            AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group
        );
        IdentityReference? observedOwner = observed.GetOwner(typeof(SecurityIdentifier));
        if (observedOwner is not SecurityIdentifier observedOwnerSid
            || !string.Equals(observedOwnerSid.Value, userSid, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("runtime_acl_owner_mismatch");
        }
        if (!observed.AreAccessRulesProtected || !observed.AreAccessRulesCanonical)
        {
            throw new InvalidOperationException("runtime_acl_not_protected_canonical");
        }
        List<string> expectedRules = new()
        {
            AclRuleKey(
                new SecurityIdentifier("S-1-3-4"),
                FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
                AccessControlType.Deny,
                inheritance,
                PropagationFlags.None
            ),
            AclRuleKey(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow, inheritance, PropagationFlags.None),
            AclRuleKey(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow, inheritance, PropagationFlags.None),
            AclRuleKey(currentUser, FileSystemRights.FullControl, AccessControlType.Allow, inheritance, PropagationFlags.None),
            AclRuleKey(new SecurityIdentifier(appContainerSid), FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, AccessControlType.Allow, inheritance, PropagationFlags.None),
        };
        ValidateAclRules(observed, expectedRules, "runtime");
    }

    private static void ApplyReadOnlyFileAcl(string path, string appContainerSid)
    {
        ApplyProtectedFileAcl(
            path,
            new SecurityIdentifier(appContainerSid),
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize
        );
    }

    private static void ApplyAllApplicationPackagesReadAcl(string path)
    {
        ApplyProtectedFileAcl(
            path,
            new SecurityIdentifier("S-1-15-2-1"),
            FileSystemRights.Read | FileSystemRights.Synchronize
        );
    }

    private static void ApplyNoApplicationPackagesReadAcl(string path)
    {
        ApplyProtectedFileAcl(path, null, 0);
    }

    private static void ApplyProtectedFileAcl(
        string path,
        SecurityIdentifier? additionalPrincipal,
        FileSystemRights additionalRights
    )
    {
        SecurityIdentifier? currentUser = WindowsIdentity.GetCurrent().User;
        if (currentUser is null)
        {
            throw new InvalidOperationException("current_user_sid_missing");
        }
        FileInfo file = new(path);
        FileSecurity security = FileSystemAclExtensions.GetAccessControl(file, AccessControlSections.Access);
        security.SetAccessRuleProtection(true, false);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
        {
            security.RemoveAccessRuleSpecific(rule);
        }
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier("S-1-3-4"),
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
            AccessControlType.Deny
        ));
        foreach (SecurityIdentifier principal in new[]
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            currentUser,
        })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                principal,
                FileSystemRights.FullControl,
                AccessControlType.Allow
            ));
        }
        if (additionalPrincipal is not null)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                additionalPrincipal,
                additionalRights,
                AccessControlType.Allow
            ));
        }
        FileSystemAclExtensions.SetAccessControl(file, security);
        ValidateProtectedFileAcl(path, additionalPrincipal, additionalRights);
    }

    private static void ValidateProtectedFileAcl(
        string path,
        SecurityIdentifier? additionalPrincipal,
        FileSystemRights additionalRights
    )
    {
        SecurityIdentifier? currentUser = WindowsIdentity.GetCurrent().User;
        if (currentUser is null)
        {
            throw new InvalidOperationException("current_user_sid_missing");
        }
        FileInfo file = new(path);
        FileSecurity observed = FileSystemAclExtensions.GetAccessControl(
            file,
            AccessControlSections.Access | AccessControlSections.Owner
        );
        if (!observed.AreAccessRulesProtected)
        {
            throw new InvalidOperationException("protected_file_acl_inheritance_enabled");
        }
        if (!observed.AreAccessRulesCanonical)
        {
            throw new InvalidOperationException("protected_file_acl_not_canonical");
        }
        IdentityReference? observedOwner = observed.GetOwner(typeof(SecurityIdentifier));
        if (observedOwner is not SecurityIdentifier observedOwnerSid
            || !string.Equals(observedOwnerSid.Value, currentUser.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("protected_file_acl_owner_mismatch");
        }
        List<string> expectedRules = new()
        {
            AclRuleKey(
                new SecurityIdentifier("S-1-3-4"),
                FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
                AccessControlType.Deny,
                InheritanceFlags.None,
                PropagationFlags.None
            ),
            AclRuleKey(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow, InheritanceFlags.None, PropagationFlags.None),
            AclRuleKey(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow, InheritanceFlags.None, PropagationFlags.None),
            AclRuleKey(currentUser, FileSystemRights.FullControl, AccessControlType.Allow, InheritanceFlags.None, PropagationFlags.None),
        };
        if (additionalPrincipal is not null)
        {
            expectedRules.Add(AclRuleKey(additionalPrincipal, additionalRights, AccessControlType.Allow, InheritanceFlags.None, PropagationFlags.None));
        }
        ValidateAclRules(observed, expectedRules, "protected_file");
    }

    private static void ValidateAclRules(
        FileSystemSecurity security,
        List<string> expectedRules,
        string boundary
    )
    {
        List<string> observedRules = new();
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.IsInherited || rule.IdentityReference is not SecurityIdentifier sid)
            {
                throw new InvalidOperationException(boundary + "_acl_inherited_or_unresolved_rule");
            }
            observedRules.Add(AclRuleKey(
                sid,
                rule.FileSystemRights,
                rule.AccessControlType,
                rule.InheritanceFlags,
                rule.PropagationFlags
            ));
        }
        observedRules.Sort(StringComparer.Ordinal);
        expectedRules.Sort(StringComparer.Ordinal);
        if (!observedRules.SequenceEqual(expectedRules, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(boundary + "_acl_roster_mismatch");
        }
    }

    private static string AclRuleKey(
        SecurityIdentifier sid,
        FileSystemRights rights,
        AccessControlType type,
        InheritanceFlags inheritance,
        PropagationFlags propagation
    ) => string.Join("|", new[]
    {
        sid.Value,
        unchecked((uint)rights).ToString("x8", System.Globalization.CultureInfo.InvariantCulture),
        ((int)type).ToString(System.Globalization.CultureInfo.InvariantCulture),
        ((int)inheritance).ToString(System.Globalization.CultureInfo.InvariantCulture),
        ((int)propagation).ToString(System.Globalization.CultureInfo.InvariantCulture),
    });

    private static string Quote(string argument)
    {
        if (argument.IndexOf('\0') >= 0) throw new InvalidOperationException("NUL in process argument");
        StringBuilder quoted = new();
        quoted.Append('\"');
        int backslashes = 0;
        foreach (char character in argument)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '\"')
            {
                quoted.Append('\\', backslashes * 2 + 1);
                quoted.Append('\"');
                backslashes = 0;
                continue;
            }
            quoted.Append('\\', backslashes);
            backslashes = 0;
            quoted.Append(character);
        }
        quoted.Append('\\', backslashes * 2);
        quoted.Append('\"');
        return quoted.ToString();
    }

    private static void CloseOwnedHandle(ref IntPtr handle)
    {
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
        {
            _ = CloseHandle(handle);
        }
        handle = IntPtr.Zero;
    }

    private static void ThrowLastError(string operation)
    {
        int error = Marshal.GetLastWin32Error();
        throw new InteropWin32Exception(operation, error);
    }

    private static void RequireHResult(int result, string operation)
    {
        if (result != S_OK)
        {
            throw new InteropHResultException(operation, result);
        }
    }

    private static string Sanitize(Exception error)
    {
        return error switch
        {
            InteropWin32Exception => "internal_interop_win32_failure",
            Win32Exception => "internal_win32_failure",
            InteropHResultException => "internal_interop_hresult_failure",
            UnauthorizedAccessException => "internal_access_failure",
            IOException => "internal_io_failure",
            JsonException => "internal_json_failure",
            ArgumentException => "internal_argument_failure",
            InvalidOperationException => "internal_invariant_failure",
            _ => "internal_unexpected_failure",
        };
    }

    private static bool IsFailureStage(string stage) => stage is
        "entry"
        or "profile_binding"
        or "profile_storage"
        or "runtime_copy_acl"
        or "fingerprint_initial"
        or "listeners_controls"
        or "job_attributes"
        or "root_launch"
        or "root_report"
        or "lineage"
        or "network_differential"
        or "fingerprint_final_cleanup";

    private static bool IsFailureStageSubstagePair(string stage, string substage)
    {
        if (!IsFailureStage(stage))
        {
            return false;
        }
        if (stage != "profile_binding")
        {
            if (stage != "network_differential")
            {
                return substage == "stage_entry";
            }
            return Array.IndexOf(NetworkFailureSubstages, substage) >= 0;
        }
        return substage is
            "profile_binding_entry"
            or "profile_prelaunch_parse"
            or "profile_sid_import"
            or "profile_sid_validate"
            or "profile_sid_roundtrip"
            or "profile_folder_query"
            or "profile_folder_canonical"
            or "profile_localappdata_canonical"
            or "profile_ancestry"
            or "profile_boundary_compare";
    }

    private static bool IsFailureClass(string failureClass) => failureClass is
        "not_observed"
        or "internal_interop_win32_failure"
        or "internal_win32_failure"
        or "internal_interop_hresult_failure"
        or "internal_access_failure"
        or "internal_io_failure"
        or "internal_json_failure"
        or "internal_argument_failure"
        or "internal_invariant_failure"
        or "internal_unexpected_failure";

    private static string NormalizeOperation(string value)
    {
        StringBuilder normalized = new();
        foreach (char character in value)
        {
            normalized.Append(char.IsAsciiLetterOrDigit(character) ? char.ToLowerInvariant(character) : '_');
        }
        return normalized.ToString().Trim('_');
    }

    private static SortedDictionary<string, object?> TokenDictionaryFromFacts(
        TokenFacts facts
    )
    {
        return new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
        ["appcontainer_sid"] = facts.AppContainerSid,
        ["all_application_packages_membership_api"] = facts.AllApplicationPackagesMembershipApi,
        ["all_application_packages_membership_api_call_succeeded"] = facts.AllApplicationPackagesMembershipApiCallSucceeded,
        ["all_application_packages_membership_api_win32_error"] = facts.AllApplicationPackagesMembershipApiWin32Error,
        ["all_application_packages_restricted_sid_match_attributes"] = facts.AllApplicationPackagesRestrictedSidMatchAttributes,
        ["all_application_packages_restricted_sid_match_count"] = facts.AllApplicationPackagesRestrictedSidMatchCount,
        ["all_application_packages_token_group_match_attributes"] = facts.AllApplicationPackagesTokenGroupMatchAttributes,
        ["all_application_packages_token_group_match_count"] = facts.AllApplicationPackagesTokenGroupMatchCount,
        ["capability_count"] = facts.CapabilityCount,
        ["capability_entries"] = facts.CapabilityEntries,
        ["integrity_rid"] = facts.IntegrityRid,
        ["is_appcontainer"] = facts.IsAppContainer,
        ["is_elevated"] = facts.IsElevated,
        ["less_privileged_appcontainer_query_result"] =
            facts.IsLessPrivilegedAppContainer,
        ["less_privileged_appcontainer_query_supported"] = facts.LpacQuerySupported,
        ["restricted_sid_count"] = facts.RestrictedSidCount,
        ["token_group_count"] = facts.TokenGroupCount,
        };
    }
}
