using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

// This probe intentionally targets the Windows PowerShell 5.1 compiler. It has
// no package dependencies and reports only token facts required by the parent.
public static class TokenProbe
{
    private const uint TokenQuery = 0x0008;
    private const uint TokenDuplicate = 0x0002;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorInvalidParameter = 87;
    private const int TokenGroups = 2;
    private const int TokenElevation = 20;
    private const int TokenIntegrityLevel = 25;
    private const int TokenIsAppContainer = 29;
    private const int TokenCapabilities = 30;
    private const int TokenAppContainerSid = 31;
    private const int TokenIsLessPrivilegedAppContainer = 46;
    private const uint SeGroupEnabled = 0x00000004;
    private const uint SeGroupUseForDenyOnly = 0x00000010;
    private const uint CtmfIncludeAppContainer = 0x00000001;
    private const int SecurityIdentification = 1;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

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

    private sealed class NativeFailure : Exception
    {
        internal readonly int Code;

        internal NativeFailure(int code)
        {
            Code = code;
        }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr token,
        int informationClass,
        IntPtr information,
        uint informationLength,
        out uint returnLength
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr text);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSidToSidW(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateToken(IntPtr existingToken, int impersonationLevel, out IntPtr duplicateToken);

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
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

    public static int Main(string[] arguments)
    {
        if (arguments.Length != 3
            || String.IsNullOrEmpty(arguments[0])
            || String.IsNullOrEmpty(arguments[1])
            || String.IsNullOrEmpty(arguments[2]))
        {
            Console.Error.WriteLine("token_probe_usage_invalid");
            return 2;
        }

        try
        {
            string report = Observe(arguments[0], arguments[1], arguments[2]);
            Console.Out.WriteLine(report);
            return 0;
        }
        catch
        {
            Console.Error.WriteLine("token_probe_failed");
            return 1;
        }
    }

    private static string Observe(string expectedSid, string aapProbePath, string noAapProbePath)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery | TokenDuplicate, out token))
        {
            throw new NativeFailure(Marshal.GetLastWin32Error());
        }

        try
        {
            bool isAppContainer = ReadDword(token, TokenIsAppContainer) != 0;
            bool elevated = ReadDword(token, TokenElevation) != 0;
            bool allApplicationPackagesMembershipApi = CheckAppContainerMembership(token, "S-1-15-2-1");
            bool? lpac;
            bool lpacQuerySupported;
            try
            {
                lpac = ReadDword(token, TokenIsLessPrivilegedAppContainer) != 0;
                lpacQuerySupported = true;
            }
            catch (NativeFailure failure)
            {
                if (failure.Code != ErrorInvalidParameter)
                {
                    throw;
                }
                lpac = null;
                lpacQuerySupported = false;
            }

            IntPtr appContainer = ReadInformation(token, TokenAppContainerSid);
            IntPtr capabilities = IntPtr.Zero;
            IntPtr integrity = IntPtr.Zero;
            try
            {
                IntPtr appContainerSidPointer = Marshal.ReadIntPtr(appContainer);
                string appContainerSid = SidText(appContainerSidPointer);
                if (!String.Equals(appContainerSid, expectedSid, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException();
                }

                capabilities = ReadInformation(token, TokenCapabilities);
                uint capabilityCount = unchecked((uint)Marshal.ReadInt32(capabilities));
                string capabilityEntries = GroupEntryCsv(capabilities);

                integrity = ReadInformation(token, TokenIntegrityLevel);
                IntPtr integritySid = Marshal.ReadIntPtr(integrity);
                IntPtr countPointer = GetSidSubAuthorityCount(integritySid);
                if (countPointer == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                byte count = Marshal.ReadByte(countPointer);
                if (count == 0)
                {
                    throw new InvalidOperationException();
                }
                IntPtr ridPointer = GetSidSubAuthority(integritySid, (uint)(count - 1));
                if (ridPointer == IntPtr.Zero)
                {
                    throw new InvalidOperationException();
                }
                uint integrityRid = unchecked((uint)Marshal.ReadInt32(ridPointer));
                string aapFileSha256 = Sha256(File.ReadAllBytes(aapProbePath));
                int noAapFileError = ReadMustBeDenied(noAapProbePath);

                return "{"
                    + "\"all_application_packages_file_sha256\":" + JsonString(aapFileSha256)
                    + ",\"appcontainer_sid\":" + JsonString(appContainerSid)
                    + ",\"capability_count\":" + capabilityCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    + ",\"capability_entries\":" + JsonString(capabilityEntries)
                    + ",\"all_application_packages_membership_api\":" + JsonBoolean(allApplicationPackagesMembershipApi)
                    + ",\"integrity_rid\":" + integrityRid.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    + ",\"is_appcontainer\":" + JsonBoolean(isAppContainer)
                    + ",\"is_elevated\":" + JsonBoolean(elevated)
                    + ",\"is_lpac\":" + JsonNullableBoolean(lpac)
                    + ",\"lpac_query_supported\":" + JsonBoolean(lpacQuerySupported)
                    + ",\"no_all_application_packages_file_error\":" + noAapFileError.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    + "}";
            }
            finally
            {
                Marshal.FreeHGlobal(appContainer);
                if (capabilities != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(capabilities);
                }
                if (integrity != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(integrity);
                }
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static uint ReadDword(IntPtr token, int informationClass)
    {
        IntPtr value = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            uint returned;
            if (!GetTokenInformation(token, informationClass, value, sizeof(uint), out returned))
            {
                throw new NativeFailure(Marshal.GetLastWin32Error());
            }
            if (returned != sizeof(uint))
            {
                throw new InvalidOperationException();
            }
            return unchecked((uint)Marshal.ReadInt32(value));
        }
        finally
        {
            Marshal.FreeHGlobal(value);
        }
    }

    private static IntPtr ReadInformation(IntPtr token, int informationClass)
    {
        uint required;
        GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out required);
        int firstError = Marshal.GetLastWin32Error();
        if (required == 0 || firstError != ErrorInsufficientBuffer)
        {
            throw new NativeFailure(firstError);
        }
        IntPtr value = Marshal.AllocHGlobal(checked((int)required));
        uint returned;
        if (!GetTokenInformation(token, informationClass, value, required, out returned))
        {
            int secondError = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(value);
            throw new NativeFailure(secondError);
        }
        if (returned > required)
        {
            Marshal.FreeHGlobal(value);
            throw new InvalidOperationException();
        }
        return value;
    }

    private static bool HasEnabledGroup(IntPtr token, string expectedSid)
    {
        IntPtr groups = ReadInformation(token, TokenGroups);
        try
        {
            uint count = unchecked((uint)Marshal.ReadInt32(groups));
            int offset = Marshal.OffsetOf(typeof(TokenGroupsOne), "FirstGroup").ToInt32();
            int stride = Marshal.SizeOf(typeof(SidAndAttributes));
            for (uint index = 0; index < count; index++)
            {
                IntPtr pointer = IntPtr.Add(groups, checked(offset + (int)index * stride));
                SidAndAttributes item = (SidAndAttributes)Marshal.PtrToStructure(pointer, typeof(SidAndAttributes));
                if ((item.Attributes & SeGroupEnabled) != 0
                    && (item.Attributes & SeGroupUseForDenyOnly) == 0
                    && String.Equals(SidText(item.Sid), expectedSid, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(groups);
        }
    }

    private static bool CheckAppContainerMembership(IntPtr token, string expectedSid)
    {
        IntPtr duplicate;
        if (!DuplicateToken(token, SecurityIdentification, out duplicate))
        {
            throw new NativeFailure(Marshal.GetLastWin32Error());
        }
        IntPtr sid = IntPtr.Zero;
        try
        {
            if (!ConvertStringSidToSidW(expectedSid, out sid))
            {
                throw new NativeFailure(Marshal.GetLastWin32Error());
            }
            bool isMember;
            if (!CheckTokenMembershipEx(duplicate, sid, CtmfIncludeAppContainer, out isMember))
            {
                throw new NativeFailure(Marshal.GetLastWin32Error());
            }
            return isMember;
        }
        finally
        {
            if (sid != IntPtr.Zero)
            {
                LocalFree(sid);
            }
            CloseHandle(duplicate);
        }
    }

    private static string GroupEntryCsv(IntPtr groups)
    {
        uint count = unchecked((uint)Marshal.ReadInt32(groups));
        int offset = Marshal.OffsetOf(typeof(TokenGroupsOne), "FirstGroup").ToInt32();
        int stride = Marshal.SizeOf(typeof(SidAndAttributes));
        List<string> entries = new List<string>();
        for (uint index = 0; index < count; index++)
        {
            IntPtr pointer = IntPtr.Add(groups, checked(offset + (int)index * stride));
            SidAndAttributes item = (SidAndAttributes)Marshal.PtrToStructure(pointer, typeof(SidAndAttributes));
            entries.Add(
                SidText(item.Sid)
                + "|0x"
                + item.Attributes.ToString("x8", System.Globalization.CultureInfo.InvariantCulture)
            );
        }
        entries.Sort(StringComparer.Ordinal);
        return String.Join(",", entries.ToArray());
    }

    private static string SidText(IntPtr sid)
    {
        IntPtr text;
        if (sid == IntPtr.Zero || !ConvertSidToStringSidW(sid, out text))
        {
            throw new NativeFailure(Marshal.GetLastWin32Error());
        }
        try
        {
            string value = Marshal.PtrToStringUni(text);
            if (value == null)
            {
                throw new InvalidOperationException();
            }
            return value;
        }
        finally
        {
            LocalFree(text);
        }
    }

    private static string JsonString(string value)
    {
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    private static string JsonBoolean(bool value)
    {
        return value ? "true" : "false";
    }

    private static string JsonNullableBoolean(bool? value)
    {
        return value.HasValue ? JsonBoolean(value.Value) : "null";
    }

    private static string Sha256(byte[] value)
    {
        using (SHA256 hash = SHA256.Create())
        {
            byte[] digest = hash.ComputeHash(value);
            char[] text = new char[digest.Length * 2];
            const string alphabet = "0123456789abcdef";
            for (int index = 0; index < digest.Length; index++)
            {
                text[index * 2] = alphabet[digest[index] >> 4];
                text[index * 2 + 1] = alphabet[digest[index] & 15];
            }
            return new string(text);
        }
    }

    private static int ReadMustBeDenied(string path)
    {
        IntPtr handle = CreateFileW(
            path,
            GenericRead,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileAttributeNormal,
            IntPtr.Zero
        );
        if (handle != InvalidHandleValue)
        {
            CloseHandle(handle);
            throw new InvalidOperationException();
        }
        int error = Marshal.GetLastWin32Error();
        if (error != 5)
        {
            throw new NativeFailure(error);
        }
        return error;
    }
}
