#!/usr/bin/env python3
"""Fail-closed Windows host trust lease for the AppContainer diagnostic.

The lease authenticates only the two PowerShell process hosts used by the
diagnostic.  It is not a general Windows trust framework and establishes no
release or evidence authority.
"""

from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import re
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from types import TracebackType
from typing import Protocol

HOST_TRUST_FORMAT = "finplanbr.windows-powershell-host-trust.v1"
HOST_TRUST_POLICY = "microsoft-signed-protected-path-current-token-read-only.v1"
SIGNATURE_POLICY = "winverifytrust-generic-v2-cache-only-no-revocation-microsoft-publisher.v1"
OWNER_POLICY = "system-trustedinstaller-or-administrators.v1"

POWERSHELL_7_ROLE = "powershell_7"
WINDOWS_POWERSHELL_ROLE = "windows_powershell_5_1"

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){3}\Z", re.ASCII)
STORE_POWERSHELL_PATTERN = re.compile(
    r"Microsoft\.PowerShell_(?P<version>[0-9]+(?:\.[0-9]+){3})_"
    r"(?P<architecture>x64|x86|arm64)__8wekyb3d8bbwe\Z",
    re.ASCII,
)
POWERSHELL_PACKAGE_FAMILY = "Microsoft.PowerShell_8wekyb3d8bbwe"
POWERSHELL_PACKAGE_NAME = "Microsoft.PowerShell"
MICROSOFT_PACKAGE_PUBLISHER = (
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
)
MICROSOFT_PACKAGE_PUBLISHER_ID = "8wekyb3d8bbwe"

TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
ALLOWED_OWNER_SIDS = frozenset(
    {
        "S-1-5-18",  # LocalSystem
        "S-1-5-32-544",  # BUILTIN\Administrators
        TRUSTED_INSTALLER_SID,
    }
)
ALLOWED_SIGNER_COMMON_NAMES = frozenset({"Microsoft Corporation", "Microsoft Windows"})

_CLOSED_REASONS = frozenset(
    {
        "host_access_check_indeterminate",
        "host_chain_identity_unstable",
        "host_chain_mutable_by_current_token",
        "host_chain_owner_untrusted",
        "host_chain_reparse",
        "host_file_version_invalid",
        "host_hash_changed",
        "host_lock_failed",
        "host_path_changed",
        "host_path_unexpected",
        "host_publisher_invalid",
        "host_signature_invalid",
        "host_trust_unavailable",
        "powershell_7_not_found",
        "powershell_7_path_ambiguous",
        "windows_powershell_5_1_not_found",
    }
)

# File access and sharing constants from WinNT.h/fileapi.h.
_FILE_READ_DATA = 0x0001
_FILE_WRITE_DATA = 0x0002
_FILE_APPEND_DATA = 0x0004
_FILE_READ_EA = 0x0008
_FILE_WRITE_EA = 0x0010
_FILE_EXECUTE = 0x0020
_FILE_DELETE_CHILD = 0x0040
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_WRITE_ATTRIBUTES = 0x0100
_DELETE = 0x00010000
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_SYNCHRONIZE = 0x00100000
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_ERROR_ACCESS_DENIED = 5

_MUTATION_RIGHTS = (
    _GENERIC_WRITE,
    _FILE_WRITE_DATA,
    _FILE_APPEND_DATA,
    _FILE_WRITE_EA,
    _FILE_WRITE_ATTRIBUTES,
    _FILE_DELETE_CHILD,
    _DELETE,
    _WRITE_DAC,
    _WRITE_OWNER,
)


class _GUID(ctypes.Structure):
    _fields_ = (
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    )


class _FILETIME(ctypes.Structure):
    _fields_ = (("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD))


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", _FILETIME),
        ("ftLastAccessTime", _FILETIME),
        ("ftLastWriteTime", _FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    )


class _FILE_ID_128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _FILE_ID_INFO(ctypes.Structure):
    _fields_ = (("volume_serial_number", ctypes.c_ulonglong), ("file_id", _FILE_ID_128))


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = (
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_GUID)),
    )


class _WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = (
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", wintypes.HANDLE),
    )


class _WINTRUST_DATA_UNION(ctypes.Union):
    _fields_ = (
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("pCatalog", ctypes.POINTER(_WINTRUST_CATALOG_INFO)),
        ("value", ctypes.c_void_p),
    )


class _WINTRUST_DATA(ctypes.Structure):
    _anonymous_ = ("union",)
    _fields_ = (
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("union", _WINTRUST_DATA_UNION),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    )


class _CRYPT_PROVIDER_CERT_PREFIX(ctypes.Structure):
    _fields_ = (("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p))


class _CATALOG_INFO(ctypes.Structure):
    _fields_ = (("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260))


class _PACKAGE_VERSION_PARTS(ctypes.Structure):
    _fields_ = (
        ("revision", wintypes.WORD),
        ("build", wintypes.WORD),
        ("minor", wintypes.WORD),
        ("major", wintypes.WORD),
    )


class _PACKAGE_VERSION(ctypes.Union):
    _anonymous_ = ("parts",)
    _fields_ = (("value", ctypes.c_uint64), ("parts", _PACKAGE_VERSION_PARTS))


class _PACKAGE_ID(ctypes.Structure):
    _fields_ = (
        ("reserved", wintypes.UINT),
        ("processorArchitecture", wintypes.UINT),
        ("version", _PACKAGE_VERSION),
        ("name", wintypes.LPWSTR),
        ("publisher", wintypes.LPWSTR),
        ("resourceId", wintypes.LPWSTR),
        ("publisherId", wintypes.LPWSTR),
    )


class _VS_FIXEDFILEINFO(ctypes.Structure):
    _fields_ = (
        ("dwSignature", wintypes.DWORD),
        ("dwStrucVersion", wintypes.DWORD),
        ("dwFileVersionMS", wintypes.DWORD),
        ("dwFileVersionLS", wintypes.DWORD),
        ("dwProductVersionMS", wintypes.DWORD),
        ("dwProductVersionLS", wintypes.DWORD),
        ("dwFileFlagsMask", wintypes.DWORD),
        ("dwFileFlags", wintypes.DWORD),
        ("dwFileOS", wintypes.DWORD),
        ("dwFileType", wintypes.DWORD),
        ("dwFileSubtype", wintypes.DWORD),
        ("dwFileDateMS", wintypes.DWORD),
        ("dwFileDateLS", wintypes.DWORD),
    )


class HostTrustFailure(Exception):
    """A closed, redacted host trust failure."""

    def __init__(self, status: str, reason: str) -> None:
        if status not in {"failed", "not_observed"} or reason not in _CLOSED_REASONS:
            raise ValueError("host trust failure is not canonical")
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class HostIdentity:
    """Closed wire identity for one locked process host."""

    role: str
    path: str
    sha256: str
    file_version: str
    file_id: str
    publisher: str
    signer_common_name: str
    ancestor_count: int
    installation_profile: str
    package_full_name: str | None
    package_publisher: str | None
    package_version: str | None

    def __post_init__(self) -> None:
        if self.role not in {POWERSHELL_7_ROLE, WINDOWS_POWERSHELL_ROLE}:
            raise ValueError("invalid host identity role")
        if (
            not _is_absolute_windows_path(self.path)
            or SHA256_PATTERN.fullmatch(self.sha256) is None
            or VERSION_PATTERN.fullmatch(self.file_version) is None
            or re.fullmatch(r"[0-9a-f]{16}:[0-9a-f]{32}", self.file_id, re.ASCII) is None
            or self.publisher != "Microsoft Corporation"
            or self.signer_common_name not in ALLOWED_SIGNER_COMMON_NAMES
            or type(self.ancestor_count) is not int
            or not 1 <= self.ancestor_count <= 64
            or self.installation_profile
            not in {"powershell_7_msi", "powershell_7_msix", "windows_inbox"}
        ):
            raise ValueError("invalid host identity")
        package_values = (self.package_full_name, self.package_publisher, self.package_version)
        if self.role == WINDOWS_POWERSHELL_ROLE and self.installation_profile != "windows_inbox":
            raise ValueError("invalid Windows PowerShell host identity")
        if self.role == POWERSHELL_7_ROLE and self.installation_profile == "windows_inbox":
            raise ValueError("invalid PowerShell 7 host identity")
        if self.installation_profile == "powershell_7_msix":
            package_match = STORE_POWERSHELL_PATTERN.fullmatch(str(self.package_full_name))
            if (
                not all(isinstance(value, str) for value in package_values)
                or self.package_publisher != MICROSOFT_PACKAGE_PUBLISHER
                or VERSION_PATTERN.fullmatch(str(self.package_version)) is None
                or package_match is None
                or package_match.group("version") != self.package_version
                or PureWindowsPath(self.path).parent.name != self.package_full_name
            ):
                raise ValueError("invalid MSIX host identity")
        elif any(value is not None for value in package_values):
            raise ValueError("non-MSIX host has package identity")

    def to_wire(self) -> dict[str, object]:
        return {
            "ancestor_count": self.ancestor_count,
            "current_token_mutation_access": "denied",
            "file_id": self.file_id,
            "file_version": self.file_version,
            "installation_profile": self.installation_profile,
            "owner_policy": OWNER_POLICY,
            "package_full_name": self.package_full_name,
            "package_publisher": self.package_publisher,
            "package_version": self.package_version,
            "path": self.path,
            "publisher": self.publisher,
            "role": self.role,
            "sha256": self.sha256,
            "signature_policy": SIGNATURE_POLICY,
            "signer_common_name": self.signer_common_name,
        }


class PowerShellHostLease(Protocol):
    powershell_7: HostIdentity
    windows_powershell_5_1: HostIdentity

    def __enter__(self) -> PowerShellHostLease: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...

    def revalidate(self) -> None: ...

    def to_wire(self) -> dict[str, object]: ...


HostAcquirer = Callable[[], PowerShellHostLease]


@dataclass(frozen=True)
class _ComponentSnapshot:
    path: Path
    final_path: str
    normalized_path: str
    file_id: str
    owner_sid: str
    is_directory: bool


@dataclass
class _LockedComponent:
    baseline: _ComponentSnapshot
    handle: int


@dataclass(frozen=True)
class _RegisteredPackage:
    full_name: str
    path: Path
    version: str
    publisher: str
    processor_architecture: int


@dataclass(frozen=True)
class _PowerShell7Discovery:
    path: Path
    installation_profile: str
    package: _RegisteredPackage | None


def _fail(reason: str, *, not_observed: bool = False) -> HostTrustFailure:
    return HostTrustFailure("not_observed" if not_observed else "failed", reason)


def _is_absolute_windows_path(value: str) -> bool:
    path = PureWindowsPath(value)
    return path.is_absolute() and bool(path.drive) and path.root == "\\"


def _strip_extended_prefix(value: str) -> str:
    if value.startswith("\\\\?\\UNC\\"):
        return "\\\\" + value[8:]
    if value.startswith("\\\\?\\"):
        return value[4:]
    return value


def _normalize_windows_path(value: str) -> str:
    stripped = _strip_extended_prefix(value)
    if not _is_absolute_windows_path(stripped):
        raise _fail("host_path_unexpected")
    return ntpath.normcase(ntpath.normpath(stripped))


def _path_components(path: Path) -> tuple[Path, ...]:
    pure = PureWindowsPath(os.fspath(path))
    if not pure.is_absolute() or not pure.drive or pure.root != "\\":
        raise _fail("host_path_unexpected")
    current = Path(pure.anchor)
    components = [current]
    for part in pure.parts[1:]:
        current /= part
        components.append(current)
    return tuple(components)


def _handle_value(handle: object) -> int | None:
    return ctypes.cast(handle, ctypes.c_void_p).value  # type: ignore[arg-type]


def _invalid_handle_value() -> int:
    return int(ctypes.c_void_p(-1).value)


def _close_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close = kernel32.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    close(handle)


def _try_open_handle(path: Path, desired_access: int, share_mode: int) -> tuple[int | None, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    ctypes.set_last_error(0)
    raw_handle = create_file(
        os.fspath(path),
        desired_access,
        share_mode,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    handle = _handle_value(raw_handle)
    if handle in {None, _invalid_handle_value()}:
        return None, ctypes.get_last_error()
    return int(handle), 0


def _open_handle(path: Path, desired_access: int, share_mode: int, *, reason: str) -> int:
    handle, _error = _try_open_handle(path, desired_access, share_mode)
    if handle is None:
        raise _fail(reason)
    return handle


def _query_handle_information(handle: int) -> _BY_HANDLE_FILE_INFORMATION:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = (wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION))
    get_information.restype = wintypes.BOOL
    information = _BY_HANDLE_FILE_INFORMATION()
    if not get_information(handle, ctypes.byref(information)):
        raise _fail("host_chain_identity_unstable")
    return information


def _query_file_id(handle: int) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    get_information.restype = wintypes.BOOL
    information = _FILE_ID_INFO()
    if not get_information(handle, 18, ctypes.byref(information), ctypes.sizeof(information)):
        raise _fail("host_chain_identity_unstable")
    identifier = bytes(information.file_id.identifier)
    if not any(identifier):
        raise _fail("host_chain_identity_unstable")
    return (
        f"{int(information.volume_serial_number):016x}:"
        f"{identifier.hex()}"
    )


def _query_final_path(handle: int) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    get_final_path.restype = wintypes.DWORD
    required = get_final_path(handle, None, 0, 0)
    if required == 0 or required > 32_767:
        raise _fail("host_path_changed")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = get_final_path(handle, buffer, len(buffer), 0)
    if written == 0 or written >= len(buffer):
        raise _fail("host_path_changed")
    final_path = _strip_extended_prefix(buffer.value)
    _normalize_windows_path(final_path)
    return final_path


def _query_owner_sid(handle: int) -> str:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_security_info = advapi32.GetSecurityInfo
    get_security_info.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    get_security_info.restype = wintypes.DWORD
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = get_security_info(
        handle,
        1,  # SE_FILE_OBJECT
        0x00000001,  # OWNER_SECURITY_INFORMATION
        ctypes.byref(owner),
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if result != 0 or not owner.value or not descriptor.value:
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        raise _fail("host_chain_owner_untrusted")
    try:
        convert_sid = advapi32.ConvertSidToStringSidW
        convert_sid.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
        convert_sid.restype = wintypes.BOOL
        sid_text = wintypes.LPWSTR()
        if not convert_sid(owner, ctypes.byref(sid_text)) or not sid_text.value:
            raise _fail("host_chain_owner_untrusted")
        try:
            return sid_text.value
        finally:
            kernel32.LocalFree(sid_text)
    finally:
        kernel32.LocalFree(descriptor)


def _probe_current_token_mutation_access(path: Path, *, volume_root: bool) -> None:
    share_all = _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
    rights = _MUTATION_RIGHTS
    if volume_root:
        # A standard Windows volume root can grant FILE_ADD_SUBDIRECTORY without
        # granting any ability to replace the already-existing protected Windows
        # or Program Files child.  The anchor is still locked and checked for
        # DELETE_CHILD, direct mutation, owner, identity, and reparse state.
        rights = tuple(
            right
            for right in rights
            if right not in {_GENERIC_WRITE, _FILE_WRITE_DATA, _FILE_APPEND_DATA}
        )
    for desired_access in rights:
        handle, error = _try_open_handle(path, desired_access, share_all)
        if handle is not None:
            _close_handle(handle)
            raise _fail("host_chain_mutable_by_current_token")
        if error != _ERROR_ACCESS_DENIED:
            raise _fail("host_access_check_indeterminate")


def _inspect_component(path: Path, *, is_directory: bool) -> _ComponentSnapshot:
    share_all = _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
    handle = _open_handle(
        path,
        _FILE_READ_ATTRIBUTES | _READ_CONTROL,
        share_all,
        reason="host_path_unexpected",
    )
    try:
        information = _query_handle_information(handle)
        observed_directory = bool(information.dwFileAttributes & _FILE_ATTRIBUTE_DIRECTORY)
        if information.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise _fail("host_chain_reparse")
        if observed_directory is not is_directory:
            raise _fail("host_path_unexpected")
        final_path = _query_final_path(handle)
        normalized = _normalize_windows_path(final_path)
        if normalized != _normalize_windows_path(os.fspath(path)):
            raise _fail("host_path_changed")
        owner_sid = _query_owner_sid(handle)
        if owner_sid not in ALLOWED_OWNER_SIDS:
            raise _fail("host_chain_owner_untrusted")
        snapshot = _ComponentSnapshot(
            path=path,
            final_path=final_path,
            normalized_path=normalized,
            file_id=_query_file_id(handle),
            owner_sid=owner_sid,
            is_directory=is_directory,
        )
        _probe_current_token_mutation_access(path, volume_root=len(_path_components(path)) == 1)
        return snapshot
    finally:
        _close_handle(handle)


def _lock_component(baseline: _ComponentSnapshot) -> _LockedComponent:
    desired_access = _FILE_READ_ATTRIBUTES | _READ_CONTROL
    if not baseline.is_directory:
        desired_access = _GENERIC_READ | _READ_CONTROL
    handle = _open_handle(
        baseline.path,
        desired_access,
        _FILE_SHARE_READ,
        reason="host_lock_failed",
    )
    try:
        information = _query_handle_information(handle)
        if information.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise _fail("host_chain_reparse")
        if bool(information.dwFileAttributes & _FILE_ATTRIBUTE_DIRECTORY) is not baseline.is_directory:
            raise _fail("host_chain_identity_unstable")
        if _query_file_id(handle) != baseline.file_id:
            raise _fail("host_chain_identity_unstable")
        if _normalize_windows_path(_query_final_path(handle)) != baseline.normalized_path:
            raise _fail("host_path_changed")
        if _query_owner_sid(handle) != baseline.owner_sid:
            raise _fail("host_chain_owner_untrusted")
        return _LockedComponent(baseline=baseline, handle=handle)
    except Exception:
        _close_handle(handle)
        raise


def _sha256_file(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as exc:
        raise _fail("host_hash_changed") from exc
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise _fail("host_hash_changed")
    return digest


def _file_version(path: Path) -> str:
    version_dll = ctypes.WinDLL("version", use_last_error=True)
    get_size = version_dll.GetFileVersionInfoSizeW
    get_size.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD))
    get_size.restype = wintypes.DWORD
    ignored = wintypes.DWORD()
    size = get_size(os.fspath(path), ctypes.byref(ignored))
    if size == 0 or size > 16 * 1024 * 1024:
        raise _fail("host_file_version_invalid")
    buffer = ctypes.create_string_buffer(size)
    get_information = version_dll.GetFileVersionInfoW
    get_information.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p)
    get_information.restype = wintypes.BOOL
    if not get_information(os.fspath(path), 0, size, buffer):
        raise _fail("host_file_version_invalid")
    query = version_dll.VerQueryValueW
    query.argtypes = (
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.UINT),
    )
    query.restype = wintypes.BOOL
    value = ctypes.c_void_p()
    value_size = wintypes.UINT()
    if not query(buffer, "\\", ctypes.byref(value), ctypes.byref(value_size)):
        raise _fail("host_file_version_invalid")
    if value_size.value < ctypes.sizeof(_VS_FIXEDFILEINFO) or not value.value:
        raise _fail("host_file_version_invalid")
    fixed = ctypes.cast(value, ctypes.POINTER(_VS_FIXEDFILEINFO)).contents
    if fixed.dwSignature != 0xFEEF04BD:
        raise _fail("host_file_version_invalid")
    components = (
        int(fixed.dwFileVersionMS) >> 16,
        int(fixed.dwFileVersionMS) & 0xFFFF,
        int(fixed.dwFileVersionLS) >> 16,
        int(fixed.dwFileVersionLS) & 0xFFFF,
    )
    result = ".".join(str(component) for component in components)
    if VERSION_PATTERN.fullmatch(result) is None:
        raise _fail("host_file_version_invalid")
    return result


def _certificate_attribute(cert_context: int, oid: bytes) -> str:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    get_name = crypt32.CertGetNameStringW
    get_name.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
    )
    get_name.restype = wintypes.DWORD
    oid_pointer = ctypes.cast(ctypes.c_char_p(oid), ctypes.c_void_p)
    required = get_name(cert_context, 3, 0, oid_pointer, None, 0)  # CERT_NAME_ATTR_TYPE
    if required <= 1 or required > 1024:
        raise _fail("host_publisher_invalid")
    buffer = ctypes.create_unicode_buffer(required)
    written = get_name(cert_context, 3, 0, oid_pointer, buffer, len(buffer))
    if written != required or not buffer.value:
        raise _fail("host_publisher_invalid")
    return buffer.value


def _generic_verify_action() -> _GUID:
    return _GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )


def _new_trust_data() -> _WINTRUST_DATA:
    trust_data = _WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    trust_data.dwUIChoice = 2  # WTD_UI_NONE
    trust_data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
    trust_data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
    trust_data.dwProvFlags = 0x1000 | 0x0010 | 0x2000  # cache-only, no revocation, no MD2/MD4
    return trust_data


def _microsoft_signer_from_state(wintrust: object, state_handle: object) -> str:
    provider_from_state = wintrust.WTHelperProvDataFromStateData  # type: ignore[attr-defined]
    provider_from_state.argtypes = (wintypes.HANDLE,)
    provider_from_state.restype = ctypes.c_void_p
    get_signer = wintrust.WTHelperGetProvSignerFromChain  # type: ignore[attr-defined]
    get_signer.argtypes = (ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    get_signer.restype = ctypes.c_void_p
    get_certificate = wintrust.WTHelperGetProvCertFromChain  # type: ignore[attr-defined]
    get_certificate.argtypes = (ctypes.c_void_p, wintypes.DWORD)
    get_certificate.restype = ctypes.POINTER(_CRYPT_PROVIDER_CERT_PREFIX)

    provider = provider_from_state(state_handle)
    signer = get_signer(provider, 0, False, 0) if provider else None
    certificate = get_certificate(signer, 0) if signer else None
    if not certificate or not certificate.contents.pCert:
        raise _fail("host_signature_invalid")
    common_name = _certificate_attribute(certificate.contents.pCert, b"2.5.4.3")
    organization = _certificate_attribute(certificate.contents.pCert, b"2.5.4.10")
    if organization != "Microsoft Corporation" or common_name not in ALLOWED_SIGNER_COMMON_NAMES:
        raise _fail("host_publisher_invalid")
    return common_name


def _verify_microsoft_catalog(path: Path, handle: int) -> str:
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    acquire = wintrust.CryptCATAdminAcquireContext2
    acquire.argtypes = (
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(_GUID),
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    acquire.restype = wintypes.BOOL
    calculate_hash = wintrust.CryptCATAdminCalcHashFromFileHandle2
    calculate_hash.argtypes = (
        ctypes.c_void_p,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
    )
    calculate_hash.restype = wintypes.BOOL
    enumerate_catalog = wintrust.CryptCATAdminEnumCatalogFromHash
    enumerate_catalog.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    )
    enumerate_catalog.restype = ctypes.c_void_p
    catalog_information = wintrust.CryptCATCatalogInfoFromContext
    catalog_information.argtypes = (ctypes.c_void_p, ctypes.POINTER(_CATALOG_INFO), wintypes.DWORD)
    catalog_information.restype = wintypes.BOOL
    release_catalog = wintrust.CryptCATAdminReleaseCatalogContext
    release_catalog.argtypes = (ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD)
    release_catalog.restype = wintypes.BOOL
    release_context = wintrust.CryptCATAdminReleaseContext
    release_context.argtypes = (ctypes.c_void_p, wintypes.DWORD)
    release_context.restype = wintypes.BOOL

    admin = ctypes.c_void_p()
    if not acquire(ctypes.byref(admin), None, None, None, 0) or not admin.value:
        raise _fail("host_signature_invalid")
    catalog: int | None = None
    try:
        hash_size = wintypes.DWORD()
        if not calculate_hash(admin, handle, ctypes.byref(hash_size), None, 0):
            raise _fail("host_signature_invalid")
        if not 16 <= hash_size.value <= 128:
            raise _fail("host_signature_invalid")
        hash_buffer = (ctypes.c_ubyte * hash_size.value)()
        if not calculate_hash(admin, handle, ctypes.byref(hash_size), hash_buffer, 0):
            raise _fail("host_signature_invalid")
        raw_catalog = enumerate_catalog(admin, hash_buffer, hash_size.value, 0, None)
        catalog = _handle_value(raw_catalog)
        if catalog is None:
            raise _fail("host_signature_invalid")
        catalog_info = _CATALOG_INFO(cbStruct=ctypes.sizeof(_CATALOG_INFO))
        if not catalog_information(catalog, ctypes.byref(catalog_info), 0) or not catalog_info.wszCatalogFile:
            raise _fail("host_signature_invalid")

        member_tag = bytes(hash_buffer).hex().upper()
        catalog_subject = _WINTRUST_CATALOG_INFO(
            cbStruct=ctypes.sizeof(_WINTRUST_CATALOG_INFO),
            dwCatalogVersion=0,
            pcwszCatalogFilePath=catalog_info.wszCatalogFile,
            pcwszMemberTag=member_tag,
            pcwszMemberFilePath=os.fspath(path),
            hMemberFile=handle,
            pbCalculatedFileHash=ctypes.cast(hash_buffer, ctypes.POINTER(ctypes.c_ubyte)),
            cbCalculatedFileHash=hash_size.value,
            pcCatalogContext=None,
            hCatAdmin=admin,
        )
        trust_data = _new_trust_data()
        trust_data.dwUnionChoice = 2  # WTD_CHOICE_CATALOG
        trust_data.pCatalog = ctypes.pointer(catalog_subject)
        action = _generic_verify_action()
        verify = wintrust.WinVerifyTrust
        verify.argtypes = (wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p)
        verify.restype = ctypes.c_long
        result = verify(None, ctypes.byref(action), ctypes.byref(trust_data))
        try:
            if result != 0 or not _handle_value(trust_data.hWVTStateData):
                raise _fail("host_signature_invalid")
            return _microsoft_signer_from_state(wintrust, trust_data.hWVTStateData)
        finally:
            if _handle_value(trust_data.hWVTStateData):
                trust_data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
                verify(None, ctypes.byref(action), ctypes.byref(trust_data))
    finally:
        if catalog is not None:
            release_catalog(admin, catalog, 0)
        release_context(admin, 0)


def _verify_microsoft_authenticode(path: Path, handle: int) -> str:
    # First verify an embedded Authenticode signature.  Windows inbox binaries
    # such as powershell.exe can instead be signed by an OS catalog, in which
    # case the second route binds the same open member handle and calculated hash.
    action = _generic_verify_action()
    file_info = _WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(_WINTRUST_FILE_INFO),
        pcwszFilePath=os.fspath(path),
        hFile=handle,
        pgKnownSubject=None,
    )
    trust_data = _new_trust_data()
    trust_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
    trust_data.pFile = ctypes.pointer(file_info)

    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    verify = wintrust.WinVerifyTrust
    verify.argtypes = (wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p)
    verify.restype = ctypes.c_long
    result = verify(None, ctypes.byref(action), ctypes.byref(trust_data))
    try:
        if result == 0 and _handle_value(trust_data.hWVTStateData):
            return _microsoft_signer_from_state(wintrust, trust_data.hWVTStateData)
    finally:
        if _handle_value(trust_data.hWVTStateData):
            trust_data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
            verify(None, ctypes.byref(action), ctypes.byref(trust_data))
    return _verify_microsoft_catalog(path, handle)


def _get_system_directory() -> Path:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_directory = kernel32.GetSystemDirectoryW
    get_directory.argtypes = (wintypes.LPWSTR, wintypes.UINT)
    get_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32_768)
    written = get_directory(buffer, len(buffer))
    if written == 0 or written >= len(buffer):
        raise _fail("host_trust_unavailable")
    path = Path(buffer.value)
    if not _is_absolute_windows_path(os.fspath(path)):
        raise _fail("host_trust_unavailable")
    return path


def _get_program_files() -> Path:
    # FOLDERID_ProgramFiles: 905e63b6-c1bf-494e-b29c-65b732d3d21a.
    folder_id = _GUID(
        0x905E63B6,
        0xC1BF,
        0x494E,
        (ctypes.c_ubyte * 8)(0xB2, 0x9C, 0x65, 0xB7, 0x32, 0xD3, 0xD2, 0x1A),
    )
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    get_folder = shell32.SHGetKnownFolderPath
    get_folder.argtypes = (ctypes.POINTER(_GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(wintypes.LPWSTR))
    get_folder.restype = ctypes.c_long
    allocated = wintypes.LPWSTR()
    result = get_folder(ctypes.byref(folder_id), 0, None, ctypes.byref(allocated))
    if result != 0 or not allocated.value:
        raise _fail("host_trust_unavailable")
    try:
        path = Path(allocated.value)
    finally:
        ole32.CoTaskMemFree(allocated)
    if not _is_absolute_windows_path(os.fspath(path)):
        raise _fail("host_trust_unavailable")
    return path


def _package_family_name(full_name: str) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_family = kernel32.PackageFamilyNameFromFullName
    get_family.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(wintypes.UINT), wintypes.LPWSTR)
    get_family.restype = ctypes.c_long
    length = wintypes.UINT()
    if get_family(full_name, ctypes.byref(length), None) != 122 or not 1 < length.value <= 256:
        raise _fail("host_path_unexpected")
    buffer = ctypes.create_unicode_buffer(length.value)
    if get_family(full_name, ctypes.byref(length), buffer) != 0 or not buffer.value:
        raise _fail("host_path_unexpected")
    return buffer.value


def _package_path(full_name: str) -> Path:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_path = kernel32.GetPackagePathByFullName
    get_path.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(wintypes.UINT), wintypes.LPWSTR)
    get_path.restype = ctypes.c_long
    length = wintypes.UINT()
    if get_path(full_name, ctypes.byref(length), None) != 122 or not 1 < length.value <= 32_768:
        raise _fail("host_path_unexpected")
    buffer = ctypes.create_unicode_buffer(length.value)
    if get_path(full_name, ctypes.byref(length), buffer) != 0 or not buffer.value:
        raise _fail("host_path_unexpected")
    path = Path(buffer.value)
    if not _is_absolute_windows_path(os.fspath(path)):
        raise _fail("host_path_unexpected")
    return path


def _registered_package(full_name: str) -> tuple[_RegisteredPackage, str]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    package_id_from_name = kernel32.PackageIdFromFullName
    package_id_from_name.argtypes = (
        wintypes.LPCWSTR,
        wintypes.UINT,
        ctypes.POINTER(wintypes.UINT),
        ctypes.c_void_p,
    )
    package_id_from_name.restype = ctypes.c_long
    length = wintypes.UINT()
    if package_id_from_name(full_name, 0x00000100, ctypes.byref(length), None) != 122:
        raise _fail("host_path_unexpected")
    if not ctypes.sizeof(_PACKAGE_ID) <= length.value <= 65_536:
        raise _fail("host_path_unexpected")
    buffer = ctypes.create_string_buffer(length.value)
    if package_id_from_name(full_name, 0x00000100, ctypes.byref(length), buffer) != 0:
        raise _fail("host_path_unexpected")
    package_id = ctypes.cast(buffer, ctypes.POINTER(_PACKAGE_ID)).contents
    name = package_id.name or ""
    publisher = package_id.publisher or ""
    publisher_id = package_id.publisherId or ""
    resource_id = package_id.resourceId or ""
    version = (
        f"{int(package_id.version.major)}.{int(package_id.version.minor)}."
        f"{int(package_id.version.build)}.{int(package_id.version.revision)}"
    )
    if name != POWERSHELL_PACKAGE_NAME or publisher_id != MICROSOFT_PACKAGE_PUBLISHER_ID:
        raise _fail("host_publisher_invalid")
    if publisher != MICROSOFT_PACKAGE_PUBLISHER:
        raise _fail("host_publisher_invalid")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise _fail("host_file_version_invalid")
    package = _RegisteredPackage(
        full_name=full_name,
        path=_package_path(full_name),
        version=version,
        publisher=publisher,
        processor_architecture=int(package_id.processorArchitecture),
    )
    return package, resource_id


def _registered_powershell_packages() -> tuple[_RegisteredPackage, ...]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_packages = kernel32.GetPackagesByPackageFamily
    get_packages.argtypes = (
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.UINT),
        wintypes.LPWSTR,
    )
    get_packages.restype = ctypes.c_long
    count = wintypes.UINT()
    buffer_length = wintypes.UINT()
    result = get_packages(
        POWERSHELL_PACKAGE_FAMILY,
        ctypes.byref(count),
        None,
        ctypes.byref(buffer_length),
        None,
    )
    if result not in {0, 122}:
        raise _fail("powershell_7_not_found", not_observed=True)
    if count.value == 0:
        return ()
    if count.value > 64 or buffer_length.value == 0 or buffer_length.value > 32_768:
        raise _fail("host_path_unexpected")
    names = (wintypes.LPWSTR * count.value)()
    buffer = ctypes.create_unicode_buffer(buffer_length.value)
    if (
        get_packages(
            POWERSHELL_PACKAGE_FAMILY,
            ctypes.byref(count),
            names,
            ctypes.byref(buffer_length),
            buffer,
        )
        != 0
    ):
        raise _fail("host_path_unexpected")
    full_names = tuple(name for name in names[: count.value] if name)
    if len(full_names) != count.value or len(set(full_names)) != len(full_names):
        raise _fail("host_path_unexpected")
    packages: list[_RegisteredPackage] = []
    for full_name in full_names:
        if _package_family_name(full_name) != POWERSHELL_PACKAGE_FAMILY:
            raise _fail("host_path_unexpected")
        package, resource_id = _registered_package(full_name)
        if resource_id == "":
            packages.append(package)
    return tuple(packages)


def _discover_windows_powershell() -> Path:
    candidate = _get_system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not os.path.lexists(candidate):
        raise _fail("windows_powershell_5_1_not_found", not_observed=True)
    return candidate


def _discover_powershell_7() -> _PowerShell7Discovery:
    program_files = _get_program_files()
    msi_candidate = program_files / "PowerShell" / "7" / "pwsh.exe"
    if os.path.lexists(msi_candidate):
        return _PowerShell7Discovery(
            path=msi_candidate,
            installation_profile="powershell_7_msi",
            package=None,
        )

    packages = _registered_powershell_packages()
    candidates: list[tuple[tuple[int, int, int, int], _RegisteredPackage]] = []
    windows_apps = program_files / "WindowsApps"
    for package in packages:
        match = STORE_POWERSHELL_PATTERN.fullmatch(package.full_name)
        expected_architecture = {0: "x86", 9: "x64", 12: "arm64"}.get(package.processor_architecture)
        if (
            match is None
            or expected_architecture is None
            or match.group("architecture") != expected_architecture
            or match.group("version") != package.version
            or int(package.version.split(".", 1)[0]) != 7
        ):
            raise _fail("host_path_unexpected")
        try:
            relative = PureWindowsPath(os.fspath(package.path)).relative_to(
                PureWindowsPath(os.fspath(windows_apps))
            )
        except ValueError as exc:
            raise _fail("host_path_unexpected") from exc
        if len(relative.parts) != 1 or relative.parts[0] != package.full_name:
            raise _fail("host_path_unexpected")
        candidate = package.path / "pwsh.exe"
        if not os.path.lexists(candidate):
            raise _fail("host_path_unexpected")
        candidates.append((tuple(int(part) for part in package.version.split(".")), package))
    if not candidates:
        raise _fail("powershell_7_not_found", not_observed=True)
    highest = max(version for version, _package in candidates)
    selected = [package for version, package in candidates if version == highest]
    if len(selected) != 1:
        raise _fail("powershell_7_path_ambiguous", not_observed=True)
    package = selected[0]
    return _PowerShell7Discovery(
        path=package.path / "pwsh.exe",
        installation_profile="powershell_7_msix",
        package=package,
    )


def _expected_host_path(
    role: str,
    path: Path,
    *,
    program_files: Path,
    system_directory: Path,
    powershell_7_discovery: _PowerShell7Discovery | None = None,
) -> bool:
    normalized = _normalize_windows_path(os.fspath(path))
    if role == WINDOWS_POWERSHELL_ROLE:
        expected = system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        return normalized == _normalize_windows_path(os.fspath(expected))
    if role != POWERSHELL_7_ROLE:
        return False
    msi = program_files / "PowerShell" / "7" / "pwsh.exe"
    if powershell_7_discovery is None:
        return normalized == _normalize_windows_path(os.fspath(msi))
    if powershell_7_discovery.installation_profile == "powershell_7_msi":
        return (
            powershell_7_discovery.package is None
            and normalized == _normalize_windows_path(os.fspath(msi))
            and normalized == _normalize_windows_path(os.fspath(powershell_7_discovery.path))
        )
    if powershell_7_discovery.installation_profile != "powershell_7_msix":
        return False
    package = powershell_7_discovery.package
    return (
        package is not None
        and normalized == _normalize_windows_path(os.fspath(powershell_7_discovery.path))
        and normalized == _normalize_windows_path(os.fspath(package.path / "pwsh.exe"))
    )


class TrustedPowerShellHosts:
    """Acquire and hold both protected PowerShell host chains."""

    def __init__(self) -> None:
        self._locked: dict[str, _LockedComponent] = {}
        self._host_components: dict[str, tuple[str, ...]] = {}
        self._powershell_7_discovery: _PowerShell7Discovery | None = None
        self.powershell_7: HostIdentity
        self.windows_powershell_5_1: HostIdentity

    def __enter__(self) -> TrustedPowerShellHosts:
        if os.name != "nt":
            raise _fail("host_trust_unavailable", not_observed=True)
        try:
            self._acquire()
        except Exception:
            self._close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self._close()

    def _acquire(self) -> None:
        system_directory = _get_system_directory()
        program_files = _get_program_files()
        powershell_7_discovery = _discover_powershell_7()
        self._powershell_7_discovery = powershell_7_discovery
        host_paths = {
            POWERSHELL_7_ROLE: powershell_7_discovery.path,
            WINDOWS_POWERSHELL_ROLE: _discover_windows_powershell(),
        }
        for role, path in host_paths.items():
            if not _expected_host_path(
                role,
                path,
                program_files=program_files,
                system_directory=system_directory,
                powershell_7_discovery=powershell_7_discovery,
            ):
                raise _fail("host_path_unexpected")

        component_paths: dict[str, tuple[Path, bool]] = {}
        for role, host_path in host_paths.items():
            components = _path_components(host_path)
            normalized_components: list[str] = []
            for index, component in enumerate(components):
                normalized = _normalize_windows_path(os.fspath(component))
                component_paths.setdefault(normalized, (component, index != len(components) - 1))
                normalized_components.append(normalized)
            self._host_components[role] = tuple(normalized_components)

        baselines: dict[str, _ComponentSnapshot] = {}
        for normalized, (component, is_directory) in component_paths.items():
            baselines[normalized] = _inspect_component(component, is_directory=is_directory)
        for normalized in component_paths:
            self._locked[normalized] = _lock_component(baselines[normalized])

        self.powershell_7 = self._build_identity(POWERSHELL_7_ROLE, host_paths[POWERSHELL_7_ROLE])
        self.windows_powershell_5_1 = self._build_identity(
            WINDOWS_POWERSHELL_ROLE,
            host_paths[WINDOWS_POWERSHELL_ROLE],
        )
        if int(self.powershell_7.file_version.split(".", 1)[0]) != 7:
            raise _fail("host_file_version_invalid")
        self.revalidate()

    def _build_identity(self, role: str, path: Path) -> HostIdentity:
        components = self._host_components[role]
        executable = self._locked[components[-1]]
        digest = _sha256_file(executable.baseline.path)
        version = _file_version(executable.baseline.path)
        signer = _verify_microsoft_authenticode(executable.baseline.path, executable.handle)
        package = None
        installation_profile = "windows_inbox"
        if role == POWERSHELL_7_ROLE:
            discovery = self._powershell_7_discovery
            if discovery is None:
                raise _fail("host_chain_identity_unstable")
            package = discovery.package
            installation_profile = discovery.installation_profile
            if package is not None and version.split(".")[:3] != package.version.split(".")[:3]:
                raise _fail("host_file_version_invalid")
        return HostIdentity(
            role=role,
            path=executable.baseline.final_path,
            sha256=digest,
            file_version=version,
            file_id=executable.baseline.file_id,
            publisher="Microsoft Corporation",
            signer_common_name=signer,
            ancestor_count=len(components) - 1,
            installation_profile=installation_profile,
            package_full_name=None if package is None else package.full_name,
            package_publisher=None if package is None else package.publisher,
            package_version=None if package is None else package.version,
        )

    def _identity_for_role(self, role: str) -> HostIdentity:
        return self.powershell_7 if role == POWERSHELL_7_ROLE else self.windows_powershell_5_1

    def revalidate(self) -> None:
        if not self._locked:
            raise _fail("host_chain_identity_unstable")
        for locked in self._locked.values():
            information = _query_handle_information(locked.handle)
            if (
                information.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT
                or _query_file_id(locked.handle) != locked.baseline.file_id
                or _normalize_windows_path(_query_final_path(locked.handle)) != locked.baseline.normalized_path
                or _query_owner_sid(locked.handle) != locked.baseline.owner_sid
            ):
                raise _fail("host_chain_identity_unstable")
        for role in (POWERSHELL_7_ROLE, WINDOWS_POWERSHELL_ROLE):
            identity = self._identity_for_role(role)
            executable = self._locked[self._host_components[role][-1]].baseline.path
            if _sha256_file(executable) != identity.sha256:
                raise _fail("host_hash_changed")
            if _file_version(executable) != identity.file_version:
                raise _fail("host_file_version_invalid")

    def to_wire(self) -> dict[str, object]:
        return {
            "format": HOST_TRUST_FORMAT,
            "policy": HOST_TRUST_POLICY,
            POWERSHELL_7_ROLE: self.powershell_7.to_wire(),
            WINDOWS_POWERSHELL_ROLE: self.windows_powershell_5_1.to_wire(),
        }

    def _close(self) -> None:
        for locked in reversed(tuple(self._locked.values())):
            _close_handle(locked.handle)
        self._locked.clear()


def acquire_trusted_powershell_hosts() -> TrustedPowerShellHosts:
    """Return the production host-trust context manager with no path override."""

    return TrustedPowerShellHosts()
