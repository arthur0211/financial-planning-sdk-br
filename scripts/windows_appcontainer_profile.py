"""Wrapper-owned AppContainer profile lease for the Windows boundary probe.

The lease deliberately distinguishes creation from discovery.  Only an exact
``S_OK`` from ``CreateAppContainerProfile`` establishes ownership and therefore
authorizes deletion.  All public observations omit the profile path because it
contains the current user's local-app-data path.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import ntpath
import os
import re
import secrets
import time
import unicodedata
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from typing import Final, NoReturn, Protocol, cast, final

PRELAUNCH_FORMAT: Final = "finplanbr.windows-appcontainer-profile-prelaunch.v4"
RECEIPT_FORMAT: Final = "finplanbr.windows-appcontainer-profile-receipt.v4"
FOLDER_IDENTITY_FORMAT: Final = "windows-file-id-info.v1"

S_OK: Final = 0
ERROR_ALREADY_EXISTS: Final = 183
HRESULT_ALREADY_EXISTS: Final = 0x800700B7
MAX_DELETE_ATTEMPTS: Final = 3
MAX_FOLDER_POLLS: Final = 4
DELETE_RETRY_DELAYS_SECONDS: Final = (0.025, 0.05)
FOLDER_POLL_DELAY_SECONDS: Final = 0.025

FILE_READ_ATTRIBUTES: Final = 0x00000080
FILE_SHARE_READ: Final = 0x00000001
FILE_SHARE_WRITE: Final = 0x00000002
FILE_SHARE_DELETE: Final = 0x00000004
OPEN_EXISTING: Final = 3
FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
PROFILE_DIRECTORY_SHARE_MODE: Final = FILE_SHARE_READ | FILE_SHARE_WRITE
PROFILE_DIRECTORY_FLAGS: Final = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
RESIDUAL_RACE_CLAIM: Final = "not_prevented"

MONIKER_PATTERN: Final = re.compile(r"finplanbrac-[0-9a-f]{24}\Z", re.ASCII)
SID_PATTERN: Final = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\Z", re.ASCII)
SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
VOLUME_SERIAL_PATTERN: Final = re.compile(r"[0-9a-f]{16}\Z", re.ASCII)
FILE_ID_128_PATTERN: Final = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
CHILD_LEAF_PATTERN: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII
)
PROFILE_FOLDER_BOUNDARY_REASONS: Final = frozenset(
    {
        "components_win32_invalid",
        "empty_descendant",
        "observed",
        "packages_ancestor_mismatch",
        "reconstruction_mismatch",
    }
)
_INVALID_WIN32_LEAF_CHARACTERS: Final = frozenset('<>:"/\\|?*')
_RESERVED_WIN32_LEAF_STEMS: Final = frozenset(
    {"aux", "con", "conin$", "conout$", "nul", "prn"}
)
_RESERVED_WIN32_NUMBERED_STEM: Final = re.compile(
    r"(?:com|lpt)(?:[1-9]|[\N{SUPERSCRIPT ONE}\N{SUPERSCRIPT TWO}\N{SUPERSCRIPT THREE}])\Z",
    re.IGNORECASE,
)

_DISPLAY_NAME: Final = "Financial Planning SDK BR boundary probe"
_DESCRIPTION: Final = "Ephemeral local full-boundary observation"
_RECREATE_DISPLAY_NAME: Final = "Financial Planning SDK BR cleanup proof"
_RECREATE_DESCRIPTION: Final = "Ephemeral cleanup verification"
_OWNED_PROFILE_BINDING_ISSUER: Final = object()


class ProfileLeaseFailure(RuntimeError):
    """The lease could not establish the closed AppContainer profile boundary."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.receipt: dict[str, object] | None = None


@dataclass(frozen=True)
class ProfileDirectoryIdentity:
    """Raw identity read from one retained directory handle."""

    canonical_path: str
    file_id_128_hex: str
    is_directory: bool
    is_reparse_point: bool
    volume_serial_hex: str


@dataclass(frozen=True)
class _BoundDirectoryIdentity:
    canonical_path: str
    file_id_128_hex: str
    path_utf8_sha256: str
    volume_serial_hex: str


@dataclass(frozen=True)
class _ProfileFolderBoundaryObservation:
    component_count: int
    components_win32_valid: bool
    exact: bool
    nonempty_descendant: bool
    packages_ancestor: bool
    reason: str
    reconstruction_matches: bool
    terminal_ac: bool


@dataclass(frozen=True, slots=True)
class CanonicalProfilePrelaunch:
    """One immutable canonical serialization and its digest."""

    bytes_value: bytes
    sha256: str

    def __post_init__(self) -> None:
        if type(self.bytes_value) is not bytes:
            raise ProfileLeaseFailure("profile_prelaunch_bytes_type_invalid")
        if type(self.sha256) is not str or SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ProfileLeaseFailure("profile_prelaunch_digest_invalid")
        if hashlib.sha256(self.bytes_value).hexdigest() != self.sha256:
            raise ProfileLeaseFailure("profile_prelaunch_digest_mismatch")


@final
@dataclass(frozen=True, slots=True, init=False)
class OwnedProfileBinding:
    """Immutable prelaunch binding issued only after same-process reconciliation."""

    appcontainer_sid: str
    created_hresult: int
    folder_boundary_component_count: int
    folder_boundary_components_win32_valid: bool
    folder_boundary_exact: bool
    folder_boundary_nonempty_descendant: bool
    folder_boundary_packages_ancestor: bool
    folder_boundary_reason: str
    folder_boundary_reconstruction_matches: bool
    folder_boundary_terminal_ac: bool
    folder_exists: bool
    folder_file_id_128_hex: str
    folder_handle_delete_share_denied: bool
    folder_handle_held: bool
    folder_identity_format: str
    folder_path_utf8_sha256: str
    folder_reparse_free: bool
    folder_volume_serial_hex: str
    format: str
    moniker: str
    ownership_established: bool
    sid_reconciled: bool
    _canonical_bytes: bytes
    _canonical_sha256: str

    def __init__(self) -> None:
        raise TypeError("OwnedProfileBinding is factory-issued")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("OwnedProfileBinding is sealed")

    @classmethod
    def _issue(
        cls,
        issuer: object,
        *,
        appcontainer_sid: str,
        created_hresult: int,
        folder_boundary_component_count: int,
        folder_boundary_components_win32_valid: bool,
        folder_boundary_exact: bool,
        folder_boundary_nonempty_descendant: bool,
        folder_boundary_packages_ancestor: bool,
        folder_boundary_reason: str,
        folder_boundary_reconstruction_matches: bool,
        folder_boundary_terminal_ac: bool,
        folder_exists: bool,
        folder_file_id_128_hex: str,
        folder_handle_delete_share_denied: bool,
        folder_handle_held: bool,
        folder_identity_format: str,
        folder_path_utf8_sha256: str,
        folder_reparse_free: bool,
        folder_volume_serial_hex: str,
        format: str,
        moniker: str,
        ownership_established: bool,
        sid_reconciled: bool,
    ) -> OwnedProfileBinding:
        if (
            issuer is not _OWNED_PROFILE_BINDING_ISSUER
            or type(appcontainer_sid) is not str
            or SID_PATTERN.fullmatch(appcontainer_sid) is None
            or type(created_hresult) is not int
            or created_hresult != S_OK
            or type(folder_boundary_component_count) is not int
            or not 1 <= folder_boundary_component_count <= 0xFFFFFFFF
            or type(folder_boundary_terminal_ac) is not bool
            or folder_boundary_reason != "observed"
            or type(folder_file_id_128_hex) is not str
            or FILE_ID_128_PATTERN.fullmatch(folder_file_id_128_hex) is None
            or folder_identity_format != FOLDER_IDENTITY_FORMAT
            or type(folder_path_utf8_sha256) is not str
            or SHA256_PATTERN.fullmatch(folder_path_utf8_sha256) is None
            or type(folder_volume_serial_hex) is not str
            or VOLUME_SERIAL_PATTERN.fullmatch(folder_volume_serial_hex) is None
            or format != PRELAUNCH_FORMAT
            or _validate_moniker(moniker) != moniker
            or any(
                type(value) is not bool or value is not True
                for value in (
                    folder_boundary_components_win32_valid,
                    folder_boundary_exact,
                    folder_boundary_nonempty_descendant,
                    folder_boundary_packages_ancestor,
                    folder_boundary_reconstruction_matches,
                    folder_exists,
                    folder_handle_delete_share_denied,
                    folder_handle_held,
                    folder_reparse_free,
                    ownership_established,
                    sid_reconciled,
                )
            )
        ):
            raise ProfileLeaseFailure("profile_owned_binding_issue_invalid")
        binding = object.__new__(cls)
        values: dict[str, object] = {
            "appcontainer_sid": appcontainer_sid,
            "created_hresult": created_hresult,
            "folder_boundary_component_count": folder_boundary_component_count,
            "folder_boundary_components_win32_valid": (
                folder_boundary_components_win32_valid
            ),
            "folder_boundary_exact": folder_boundary_exact,
            "folder_boundary_nonempty_descendant": (
                folder_boundary_nonempty_descendant
            ),
            "folder_boundary_packages_ancestor": folder_boundary_packages_ancestor,
            "folder_boundary_reason": folder_boundary_reason,
            "folder_boundary_reconstruction_matches": (
                folder_boundary_reconstruction_matches
            ),
            "folder_boundary_terminal_ac": folder_boundary_terminal_ac,
            "folder_exists": folder_exists,
            "folder_file_id_128_hex": folder_file_id_128_hex,
            "folder_handle_delete_share_denied": folder_handle_delete_share_denied,
            "folder_handle_held": folder_handle_held,
            "folder_identity_format": folder_identity_format,
            "folder_path_utf8_sha256": folder_path_utf8_sha256,
            "folder_reparse_free": folder_reparse_free,
            "folder_volume_serial_hex": folder_volume_serial_hex,
            "format": format,
            "moniker": moniker,
            "ownership_established": ownership_established,
            "sid_reconciled": sid_reconciled,
        }
        for name, value in values.items():
            object.__setattr__(binding, name, value)
        canonical_bytes = binding._serialize_current_fields()
        object.__setattr__(binding, "_canonical_bytes", canonical_bytes)
        object.__setattr__(
            binding,
            "_canonical_sha256",
            hashlib.sha256(canonical_bytes).hexdigest(),
        )
        return binding

    def _wire_dict(self) -> dict[str, object]:
        return {
            "appcontainer_sid": self.appcontainer_sid,
            "created_hresult": self.created_hresult,
            "folder_boundary_component_count": self.folder_boundary_component_count,
            "folder_boundary_components_win32_valid": (
                self.folder_boundary_components_win32_valid
            ),
            "folder_boundary_exact": self.folder_boundary_exact,
            "folder_boundary_nonempty_descendant": (
                self.folder_boundary_nonempty_descendant
            ),
            "folder_boundary_packages_ancestor": self.folder_boundary_packages_ancestor,
            "folder_boundary_reason": self.folder_boundary_reason,
            "folder_boundary_reconstruction_matches": (
                self.folder_boundary_reconstruction_matches
            ),
            "folder_boundary_terminal_ac": self.folder_boundary_terminal_ac,
            "folder_exists": self.folder_exists,
            "folder_file_id_128_hex": self.folder_file_id_128_hex,
            "folder_handle_delete_share_denied": (
                self.folder_handle_delete_share_denied
            ),
            "folder_handle_held": self.folder_handle_held,
            "folder_identity_format": self.folder_identity_format,
            "folder_path_utf8_sha256": self.folder_path_utf8_sha256,
            "folder_reparse_free": self.folder_reparse_free,
            "folder_volume_serial_hex": self.folder_volume_serial_hex,
            "format": self.format,
            "moniker": self.moniker,
            "ownership_established": self.ownership_established,
            "sid_reconciled": self.sid_reconciled,
        }

    def _serialize_current_fields(self) -> bytes:
        return json.dumps(
            self._wire_dict(),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

    def current_wire(self) -> tuple[bytes, str]:
        """Revalidate the immutable typed fields and return one bytes/digest pair."""

        if type(self) is not OwnedProfileBinding:
            raise ProfileLeaseFailure("profile_binding_type_invalid")
        current_bytes = self._serialize_current_fields()
        current_sha256 = hashlib.sha256(current_bytes).hexdigest()
        if (
            type(self._canonical_bytes) is not bytes
            or type(self._canonical_sha256) is not str
            or current_bytes != self._canonical_bytes
            or current_sha256 != self._canonical_sha256
        ):
            raise ProfileLeaseFailure("profile_binding_snapshot_drift")
        payload = CanonicalProfilePrelaunch(current_bytes, current_sha256)
        return payload.bytes_value, payload.sha256


class ProfileNative(Protocol):
    """Small injectable native surface; tests never call live Windows APIs."""

    def create_profile(
        self, moniker: str, display_name: str, description: str
    ) -> tuple[int, str | None]: ...

    def delete_profile(self, moniker: str) -> int: ...

    def derive_sid(self, moniker: str) -> str: ...

    def folder_exists(self, path: str) -> bool: ...

    def folder_is_directory(self, path: str) -> bool: ...

    def get_folder_path(self, sid: str) -> str: ...

    def get_local_app_data_path(self) -> str: ...

    def path_chain_reparse_free(self, path: str) -> bool: ...

    def open_profile_directory(
        self,
        path: str,
        *,
        creation_disposition: int,
        desired_access: int,
        flags_and_attributes: int,
        share_mode: int,
    ) -> object: ...

    def read_profile_directory_identity(self, handle: object) -> ProfileDirectoryIdentity: ...

    def close_profile_directory(self, handle: object) -> None: ...


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _FILE_ID_128(ctypes.Structure):
    _fields_ = [("Identifier", ctypes.c_ubyte * 16)]


class _FILE_ID_INFO(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_ulonglong),
        ("FileId", _FILE_ID_128),
    ]


class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [
        ("FileAttributes", wintypes.DWORD),
        ("ReparseTag", wintypes.DWORD),
    ]


_FOLDERID_LOCAL_APP_DATA: Final = _GUID(
    0xF1B32785,
    0x6FBA,
    0x4FCF,
    (ctypes.c_ubyte * 8)(0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91),
)


def _normalize_hresult(value: int) -> int:
    if type(value) is not int:
        raise ProfileLeaseFailure("native_hresult_type_invalid")
    return value & 0xFFFFFFFF


def _validate_moniker(moniker: str) -> str:
    if type(moniker) is not str or MONIKER_PATTERN.fullmatch(moniker) is None:
        raise ProfileLeaseFailure("profile_moniker_invalid")
    return moniker


def _validate_sid(value: object, reason: str) -> str:
    if type(value) is not str or len(value) > 184 or SID_PATTERN.fullmatch(value) is None:
        raise ProfileLeaseFailure(reason)
    return value


def _canonical_windows_path(value: str, reason: str) -> str:
    if type(value) is not str or not value or "\x00" in value or "/" in value:
        raise ProfileLeaseFailure(reason)
    if value.startswith(("\\\\", "\\\\?\\", "\\??\\")):
        raise ProfileLeaseFailure(reason)
    drive, tail = ntpath.splitdrive(value)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\"):
        raise ProfileLeaseFailure(reason)
    normalized = ntpath.normpath(value)
    if normalized != value or normalized.endswith("\\"):
        raise ProfileLeaseFailure(reason)
    return normalized


def _same_windows_path(left: str, right: str) -> bool:
    return ntpath.normcase(left) == ntpath.normcase(right)


def _win32_profile_leaf_valid(value: str) -> bool:
    """Accept one ordinary Win32 directory leaf, including OS-selected Unicode."""

    if not value or value in {".", ".."} or value.endswith((" ", ".")):
        return False
    if any(
        character in _INVALID_WIN32_LEAF_CHARACTERS
        or unicodedata.category(character) in {"Cc", "Cs"}
        for character in value
    ):
        return False
    stem = value.split(".", 1)[0].casefold()
    return stem not in _RESERVED_WIN32_LEAF_STEMS and (
        _RESERVED_WIN32_NUMBERED_STEM.fullmatch(stem) is None
    )


def _profile_folder_boundary_observation(
    folder: str, local_app_data: str
) -> _ProfileFolderBoundaryObservation:
    r"""Classify a canonical nonempty descendant of ``LocalAppData\Packages``.

    ``GetAppContainerFolderPath`` is queried with the reconciled SID and is the
    authority for the relative shape.  Every returned component must be an
    ordinary Win32 directory leaf, but neither depth nor an ``AC`` terminal is
    a security predicate.  The closed observations retain which structural
    predicate failed without publishing that user-profile path.
    """

    packages_root = ntpath.join(local_app_data, "Packages")
    packages_prefix = packages_root + "\\"
    packages_ancestor = bool(
        _same_windows_path(folder, packages_root)
        or (
            len(folder) > len(packages_prefix)
            and _same_windows_path(folder[: len(packages_prefix)], packages_prefix)
        )
    )
    relative = (
        folder[len(packages_prefix) :]
        if packages_ancestor and not _same_windows_path(folder, packages_root)
        else ""
    )
    components = relative.split("\\") if relative else []
    component_count = len(components)
    nonempty_descendant = packages_ancestor and component_count >= 1
    terminal_ac = bool(nonempty_descendant and components[-1].casefold() == "ac")
    components_win32_valid = bool(
        nonempty_descendant
        and all(_win32_profile_leaf_valid(component) for component in components)
    )
    reconstruction_matches = bool(
        nonempty_descendant
        and _same_windows_path(
            folder, ntpath.join(packages_root, *components)
        )
    )
    exact = bool(
        packages_ancestor
        and nonempty_descendant
        and components_win32_valid
        and reconstruction_matches
    )
    if not packages_ancestor:
        reason = "packages_ancestor_mismatch"
    elif not nonempty_descendant:
        reason = "empty_descendant"
    elif not components_win32_valid:
        reason = "components_win32_invalid"
    elif not reconstruction_matches:
        reason = "reconstruction_mismatch"
    else:
        reason = "observed"
    return _ProfileFolderBoundaryObservation(
        component_count=component_count,
        components_win32_valid=components_win32_valid,
        exact=exact,
        nonempty_descendant=nonempty_descendant,
        packages_ancestor=packages_ancestor,
        reason=reason,
        reconstruction_matches=reconstruction_matches,
        terminal_ac=terminal_ac,
    )


def _profile_folder_boundary_exact(folder: str, local_app_data: str) -> bool:
    """Compatibility predicate backed by the closed boundary observation."""

    return _profile_folder_boundary_observation(folder, local_app_data).exact


def _bind_directory_identity(
    value: object, expected_folder: str
) -> _BoundDirectoryIdentity:
    if type(value) is not ProfileDirectoryIdentity:
        raise ProfileLeaseFailure("profile_directory_identity_type_invalid")
    identity = value
    canonical_path = _canonical_windows_path(
        identity.canonical_path, "profile_directory_canonical_path_invalid"
    )
    if not _same_windows_path(canonical_path, expected_folder):
        raise ProfileLeaseFailure("profile_directory_handle_path_mismatch")
    if type(identity.is_directory) is not bool or identity.is_directory is not True:
        raise ProfileLeaseFailure("profile_directory_handle_not_directory")
    if type(identity.is_reparse_point) is not bool or identity.is_reparse_point is not False:
        raise ProfileLeaseFailure("profile_directory_handle_is_reparse")
    if VOLUME_SERIAL_PATTERN.fullmatch(identity.volume_serial_hex) is None:
        raise ProfileLeaseFailure("profile_directory_volume_serial_invalid")
    if FILE_ID_128_PATTERN.fullmatch(identity.file_id_128_hex) is None:
        raise ProfileLeaseFailure("profile_directory_file_id_invalid")
    canonical_identity_path = ntpath.normcase(canonical_path)
    path_sha256 = hashlib.sha256(canonical_identity_path.encode("utf-8")).hexdigest()
    if SHA256_PATTERN.fullmatch(path_sha256) is None:
        raise ProfileLeaseFailure("profile_directory_path_digest_invalid")
    return _BoundDirectoryIdentity(
        canonical_path=canonical_identity_path,
        file_id_128_hex=identity.file_id_128_hex,
        path_utf8_sha256=path_sha256,
        volume_serial_hex=identity.volume_serial_hex,
    )


class _WindowsProfileNative:
    """ctypes binding kept lazy so importing and fake-native tests are inert."""

    _INVALID_FILE_ATTRIBUTES: Final = 0xFFFFFFFF
    _FILE_ATTRIBUTE_DIRECTORY: Final = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x00000400
    _ERROR_FILE_NOT_FOUND: Final = 2
    _ERROR_PATH_NOT_FOUND: Final = 3
    _FILE_ATTRIBUTE_TAG_INFO_CLASS: Final = 9
    _FILE_ID_INFO_CLASS: Final = 18

    def __init__(self) -> None:
        if os.name != "nt":
            raise ProfileLeaseFailure("windows_required")
        self._userenv = ctypes.WinDLL("userenv.dll", use_last_error=True)
        self._advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
        self._shell32 = ctypes.WinDLL("shell32.dll", use_last_error=True)

        self._create = self._userenv.CreateAppContainerProfile
        self._create.argtypes = (
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
        )
        self._create.restype = ctypes.c_long

        self._delete = self._userenv.DeleteAppContainerProfile
        self._delete.argtypes = (wintypes.LPCWSTR,)
        self._delete.restype = ctypes.c_long

        self._derive = self._userenv.DeriveAppContainerSidFromAppContainerName
        self._derive.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID))
        self._derive.restype = ctypes.c_long

        self._get_folder = self._userenv.GetAppContainerFolderPath
        self._get_folder.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID))
        self._get_folder.restype = ctypes.c_long

        self._convert_sid = self._advapi32.ConvertSidToStringSidW
        self._convert_sid.argtypes = (wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID))
        self._convert_sid.restype = wintypes.BOOL

        self._free_sid = self._advapi32.FreeSid
        self._free_sid.argtypes = (wintypes.LPVOID,)
        self._free_sid.restype = wintypes.LPVOID

        self._local_free = self._kernel32.LocalFree
        self._local_free.argtypes = (wintypes.LPVOID,)
        self._local_free.restype = wintypes.LPVOID

        self._get_attributes = self._kernel32.GetFileAttributesW
        self._get_attributes.argtypes = (wintypes.LPCWSTR,)
        self._get_attributes.restype = wintypes.DWORD

        self._create_file = self._kernel32.CreateFileW
        self._create_file.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        self._create_file.restype = wintypes.HANDLE

        self._get_file_information = self._kernel32.GetFileInformationByHandleEx
        self._get_file_information.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        )
        self._get_file_information.restype = wintypes.BOOL

        self._get_final_path = self._kernel32.GetFinalPathNameByHandleW
        self._get_final_path.argtypes = (
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        self._get_final_path.restype = wintypes.DWORD

        self._close_handle = self._kernel32.CloseHandle
        self._close_handle.argtypes = (wintypes.HANDLE,)
        self._close_handle.restype = wintypes.BOOL

        self._co_task_mem_free = self._ole32.CoTaskMemFree
        self._co_task_mem_free.argtypes = (wintypes.LPVOID,)
        self._co_task_mem_free.restype = None

        self._known_folder = self._shell32.SHGetKnownFolderPath
        self._known_folder.argtypes = (
            ctypes.POINTER(_GUID),
            wintypes.DWORD,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.LPVOID),
        )
        self._known_folder.restype = ctypes.c_long

    def _sid_text(self, sid_pointer: wintypes.LPVOID) -> str:
        text_pointer = wintypes.LPVOID()
        if not sid_pointer.value or not self._convert_sid(sid_pointer, ctypes.byref(text_pointer)):
            raise ProfileLeaseFailure("profile_sid_string_failed")
        try:
            if not text_pointer.value:
                raise ProfileLeaseFailure("profile_sid_string_failed")
            return _validate_sid(ctypes.wstring_at(text_pointer.value), "profile_sid_invalid")
        finally:
            if text_pointer.value:
                self._local_free(text_pointer)

    def create_profile(
        self, moniker: str, display_name: str, description: str
    ) -> tuple[int, str | None]:
        sid_pointer = wintypes.LPVOID()
        result = _normalize_hresult(
            int(
                self._create(
                    moniker,
                    display_name,
                    description,
                    None,
                    0,
                    ctypes.byref(sid_pointer),
                )
            )
        )
        try:
            if result != S_OK:
                return result, None
            if not sid_pointer.value:
                return result, None
            try:
                return result, self._sid_text(sid_pointer)
            except BaseException:
                # Preserve the ownership-establishing S_OK for the lease even
                # when the returned SID cannot be converted or validated.
                return result, None
        finally:
            if sid_pointer.value:
                self._free_sid(sid_pointer)

    def delete_profile(self, moniker: str) -> int:
        return _normalize_hresult(int(self._delete(moniker)))

    def derive_sid(self, moniker: str) -> str:
        sid_pointer = wintypes.LPVOID()
        result = _normalize_hresult(int(self._derive(moniker, ctypes.byref(sid_pointer))))
        try:
            if result != S_OK or not sid_pointer.value:
                raise ProfileLeaseFailure("profile_sid_derivation_failed")
            return self._sid_text(sid_pointer)
        finally:
            if sid_pointer.value:
                self._free_sid(sid_pointer)

    def get_folder_path(self, sid: str) -> str:
        path_pointer = wintypes.LPVOID()
        result = _normalize_hresult(int(self._get_folder(sid, ctypes.byref(path_pointer))))
        try:
            if result != S_OK or not path_pointer.value:
                raise ProfileLeaseFailure("profile_folder_query_failed")
            return ctypes.wstring_at(path_pointer.value)
        finally:
            if path_pointer.value:
                self._co_task_mem_free(path_pointer)

    def get_local_app_data_path(self) -> str:
        path_pointer = wintypes.LPVOID()
        result = _normalize_hresult(
            int(self._known_folder(ctypes.byref(_FOLDERID_LOCAL_APP_DATA), 0, None, ctypes.byref(path_pointer)))
        )
        try:
            if result != S_OK or not path_pointer.value:
                raise ProfileLeaseFailure("local_app_data_query_failed")
            return ctypes.wstring_at(path_pointer.value)
        finally:
            if path_pointer.value:
                self._co_task_mem_free(path_pointer)

    def _attributes(self, path: str) -> int | None:
        ctypes.set_last_error(0)
        attributes = int(self._get_attributes(path))
        if attributes != self._INVALID_FILE_ATTRIBUTES:
            return attributes
        error = ctypes.get_last_error()
        if error in {self._ERROR_FILE_NOT_FOUND, self._ERROR_PATH_NOT_FOUND}:
            return None
        raise ProfileLeaseFailure("profile_folder_attributes_failed")

    def folder_exists(self, path: str) -> bool:
        return self._attributes(path) is not None

    def folder_is_directory(self, path: str) -> bool:
        attributes = self._attributes(path)
        return attributes is not None and bool(attributes & self._FILE_ATTRIBUTE_DIRECTORY)

    def path_chain_reparse_free(self, path: str) -> bool:
        current = path
        while True:
            attributes = self._attributes(current)
            if attributes is None or attributes & self._FILE_ATTRIBUTE_REPARSE_POINT:
                return False
            parent = ntpath.dirname(current)
            if parent == current:
                return True
            current = parent

    @staticmethod
    def _handle_value(handle: object) -> int:
        if type(handle) is not int or handle <= 0:
            raise ProfileLeaseFailure("profile_directory_handle_invalid")
        return handle

    def open_profile_directory(
        self,
        path: str,
        *,
        creation_disposition: int,
        desired_access: int,
        flags_and_attributes: int,
        share_mode: int,
    ) -> object:
        if (
            creation_disposition != OPEN_EXISTING
            or desired_access != FILE_READ_ATTRIBUTES
            or flags_and_attributes != PROFILE_DIRECTORY_FLAGS
            or share_mode != PROFILE_DIRECTORY_SHARE_MODE
            or share_mode & FILE_SHARE_DELETE
        ):
            raise ProfileLeaseFailure("profile_directory_open_contract_invalid")
        ctypes.set_last_error(0)
        handle = self._create_file(
            path,
            desired_access,
            share_mode,
            None,
            creation_disposition,
            flags_and_attributes,
            None,
        )
        value = int(handle) if handle is not None else 0
        invalid_handle = ctypes.c_void_p(-1).value
        if value == 0 or value == invalid_handle:
            raise ProfileLeaseFailure("profile_directory_open_failed")
        return value

    def _final_handle_path(self, handle: int) -> str:
        required = int(self._get_final_path(handle, None, 0, 0))
        if required <= 0 or required > 32_767:
            raise ProfileLeaseFailure("profile_directory_final_path_query_failed")
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = int(self._get_final_path(handle, buffer, len(buffer), 0))
        if written <= 0 or written >= len(buffer):
            raise ProfileLeaseFailure("profile_directory_final_path_query_failed")
        value = buffer.value
        if value.startswith("\\\\?\\UNC\\"):
            raise ProfileLeaseFailure("profile_directory_final_path_unc_invalid")
        if value.startswith("\\\\?\\"):
            value = value[4:]
        return value

    def read_profile_directory_identity(self, handle: object) -> ProfileDirectoryIdentity:
        value = self._handle_value(handle)
        file_id = _FILE_ID_INFO()
        if not self._get_file_information(
            value,
            self._FILE_ID_INFO_CLASS,
            ctypes.byref(file_id),
            ctypes.sizeof(file_id),
        ):
            raise ProfileLeaseFailure("profile_directory_file_id_query_failed")
        attributes = _FILE_ATTRIBUTE_TAG_INFO()
        if not self._get_file_information(
            value,
            self._FILE_ATTRIBUTE_TAG_INFO_CLASS,
            ctypes.byref(attributes),
            ctypes.sizeof(attributes),
        ):
            raise ProfileLeaseFailure("profile_directory_attribute_query_failed")
        return ProfileDirectoryIdentity(
            canonical_path=self._final_handle_path(value),
            file_id_128_hex=bytes(file_id.FileId.Identifier).hex(),
            is_directory=bool(attributes.FileAttributes & self._FILE_ATTRIBUTE_DIRECTORY),
            is_reparse_point=bool(
                attributes.FileAttributes & self._FILE_ATTRIBUTE_REPARSE_POINT
            ),
            volume_serial_hex=f"{int(file_id.VolumeSerialNumber):016x}",
        )

    def close_profile_directory(self, handle: object) -> None:
        value = self._handle_value(handle)
        if not self._close_handle(value):
            raise ProfileLeaseFailure("profile_directory_handle_close_failed")


class AppContainerProfileLease:
    """Own exactly one freshly created AppContainer profile until ``close``."""

    def __init__(
        self,
        moniker: str,
        *,
        native: ProfileNative | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._moniker = _validate_moniker(moniker)
        self._native = _WindowsProfileNative() if native is None else native
        self._sleeper = sleeper
        self._started = False
        self._closed = False
        self._owned = False
        self._sid: str | None = None
        self._profile_folder: str | None = None
        self._profile_directory_handle: object | None = None
        self._profile_directory_identity: _BoundDirectoryIdentity | None = None
        self._owned_binding: OwnedProfileBinding | None = None
        self._receipt = self._new_receipt()

    def _new_receipt(self) -> dict[str, object]:
        return {
            "cleanup_attempted": False,
            "cleanup_complete": False,
            "closed": False,
            "delete_attempt_hresults": [],
            "delete_succeeded": False,
            "delete_suppressed_due_identity_uncertainty": False,
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
            "folder_identity_drift_detected": False,
            "folder_identity_format": FOLDER_IDENTITY_FORMAT,
            "folder_identity_revalidated_before_release": False,
            "folder_path_utf8_sha256": None,
            "folder_volume_serial_hex": None,
            "format": RECEIPT_FORMAT,
            "moniker": self._moniker,
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
            "residual_race_after_handle_release": RESIDUAL_RACE_CLAIM,
        }

    def _record_folder_boundary(
        self,
        boundary: _ProfileFolderBoundaryObservation,
        *,
        prefix: str = "",
    ) -> None:
        self._receipt[f"{prefix}folder_boundary_component_count"] = (
            boundary.component_count
        )
        self._receipt[f"{prefix}folder_boundary_components_win32_valid"] = (
            boundary.components_win32_valid
        )
        self._receipt[f"{prefix}folder_boundary_exact"] = boundary.exact
        self._receipt[f"{prefix}folder_boundary_nonempty_descendant"] = (
            boundary.nonempty_descendant
        )
        self._receipt[f"{prefix}folder_boundary_packages_ancestor"] = (
            boundary.packages_ancestor
        )
        self._receipt[f"{prefix}folder_boundary_reason"] = boundary.reason
        self._receipt[f"{prefix}folder_boundary_reconstruction_matches"] = (
            boundary.reconstruction_matches
        )
        self._receipt[f"{prefix}folder_boundary_terminal_ac"] = boundary.terminal_ac

    def _observe_folder(
        self, sid: str
    ) -> tuple[str, _ProfileFolderBoundaryObservation, bool, bool]:
        folder = _canonical_windows_path(
            self._native.get_folder_path(sid), "profile_folder_path_invalid"
        )
        self._profile_folder = folder
        local_app_data = _canonical_windows_path(
            self._native.get_local_app_data_path(), "local_app_data_path_invalid"
        )
        boundary = _profile_folder_boundary_observation(folder, local_app_data)
        exists = self._native.folder_exists(folder) and self._native.folder_is_directory(folder)
        reparse_free = exists and self._native.path_chain_reparse_free(folder)
        return folder, boundary, exists, reparse_free

    def _open_and_bind_profile_directory(
        self, folder: str
    ) -> _BoundDirectoryIdentity:
        handle = self._native.open_profile_directory(
            folder,
            creation_disposition=OPEN_EXISTING,
            desired_access=FILE_READ_ATTRIBUTES,
            flags_and_attributes=PROFILE_DIRECTORY_FLAGS,
            share_mode=PROFILE_DIRECTORY_SHARE_MODE,
        )
        self._profile_directory_handle = handle
        identity = _bind_directory_identity(
            self._native.read_profile_directory_identity(handle), folder
        )
        self._profile_directory_identity = identity
        self._receipt["folder_file_id_128_hex"] = identity.file_id_128_hex
        self._receipt["folder_path_utf8_sha256"] = identity.path_utf8_sha256
        self._receipt["folder_volume_serial_hex"] = identity.volume_serial_hex
        return identity

    def _raise_post_creation_failure(self, cause: BaseException) -> NoReturn:
        reason = (
            cause.reason
            if isinstance(cause, ProfileLeaseFailure)
            else "profile_post_creation_validation_failed"
        )
        receipt = self.close()
        failure = ProfileLeaseFailure(reason)
        failure.receipt = receipt
        raise failure from cause

    def start(self) -> AppContainerProfileLease:
        if self._closed:
            raise ProfileLeaseFailure("profile_lease_closed")
        if self._started:
            raise ProfileLeaseFailure("profile_lease_already_started")

        create_result, created_sid = self._native.create_profile(
            self._moniker, _DISPLAY_NAME, _DESCRIPTION
        )
        create_result = _normalize_hresult(create_result)
        if create_result == HRESULT_ALREADY_EXISTS:
            raise ProfileLeaseFailure("profile_preexisting")
        if create_result != S_OK:
            raise ProfileLeaseFailure("profile_creation_failed")

        try:
            # Ownership is established before every subsequent fallible validation.
            self._owned = True
            self._receipt["owned"] = True
            self._receipt["ownership_established"] = True
            created_sid = _validate_sid(created_sid, "profile_created_sid_invalid")
            self._sid = created_sid
            derived_sid = _validate_sid(
                self._native.derive_sid(self._moniker), "profile_derived_sid_invalid"
            )
            sid_reconciled = created_sid == derived_sid
            folder, boundary, folder_exists, reparse_free = self._observe_folder(
                created_sid
            )
            self._record_folder_boundary(boundary)
            if not sid_reconciled:
                raise ProfileLeaseFailure("profile_sid_reconciliation_failed")
            if not boundary.exact:
                raise ProfileLeaseFailure("profile_folder_boundary_failed")
            if not folder_exists:
                raise ProfileLeaseFailure("profile_folder_missing")
            if not reparse_free:
                raise ProfileLeaseFailure("profile_folder_reparse_boundary_failed")
            identity = self._open_and_bind_profile_directory(folder)
            self._owned_binding = OwnedProfileBinding._issue(
                _OWNED_PROFILE_BINDING_ISSUER,
                appcontainer_sid=created_sid,
                created_hresult=create_result,
                folder_boundary_component_count=boundary.component_count,
                folder_boundary_components_win32_valid=(
                    boundary.components_win32_valid
                ),
                folder_boundary_exact=boundary.exact,
                folder_boundary_nonempty_descendant=boundary.nonempty_descendant,
                folder_boundary_packages_ancestor=boundary.packages_ancestor,
                folder_boundary_reason=boundary.reason,
                folder_boundary_reconstruction_matches=(
                    boundary.reconstruction_matches
                ),
                folder_boundary_terminal_ac=boundary.terminal_ac,
                folder_exists=folder_exists,
                folder_file_id_128_hex=identity.file_id_128_hex,
                folder_handle_delete_share_denied=True,
                folder_handle_held=True,
                folder_identity_format=FOLDER_IDENTITY_FORMAT,
                folder_path_utf8_sha256=identity.path_utf8_sha256,
                folder_reparse_free=reparse_free,
                folder_volume_serial_hex=identity.volume_serial_hex,
                format=PRELAUNCH_FORMAT,
                moniker=self._moniker,
                ownership_established=True,
                sid_reconciled=sid_reconciled,
            )
            self._started = True
            return self
        except BaseException as exc:
            self._raise_post_creation_failure(exc)

    def _delete_with_retry(self) -> list[int]:
        results: list[int] = []
        for attempt in range(MAX_DELETE_ATTEMPTS):
            result = _normalize_hresult(self._native.delete_profile(self._moniker))
            results.append(result)
            if result == S_OK:
                break
            if attempt < MAX_DELETE_ATTEMPTS - 1:
                self._sleeper(DELETE_RETRY_DELAYS_SECONDS[attempt])
        return results

    def _folder_absent(self, folder: str | None) -> bool:
        if folder is None:
            return False
        for attempt in range(MAX_FOLDER_POLLS):
            if not self._native.folder_exists(folder):
                return True
            if attempt < MAX_FOLDER_POLLS - 1:
                self._sleeper(FOLDER_POLL_DELAY_SECONDS)
        return False

    def _release_profile_directory_for_cleanup(self) -> bool:
        handle = self._profile_directory_handle
        baseline = self._profile_directory_identity
        if handle is None:
            if baseline is None:
                return True
            self._receipt["delete_suppressed_due_identity_uncertainty"] = True
            return False

        identity_allows_delete = False
        if baseline is None:
            self._receipt["delete_suppressed_due_identity_uncertainty"] = True
        else:
            try:
                raw_identity = self._native.read_profile_directory_identity(handle)
            except BaseException:
                self._receipt["delete_suppressed_due_identity_uncertainty"] = True
            else:
                try:
                    current = _bind_directory_identity(
                        raw_identity,
                        self._profile_folder
                        if self._profile_folder is not None
                        else baseline.canonical_path,
                    )
                except BaseException:
                    self._receipt["folder_identity_drift_detected"] = True
                    self._receipt["delete_suppressed_due_identity_uncertainty"] = True
                else:
                    if current == baseline:
                        self._receipt["folder_identity_revalidated_before_release"] = True
                        identity_allows_delete = True
                    else:
                        self._receipt["folder_identity_drift_detected"] = True
                        self._receipt["delete_suppressed_due_identity_uncertainty"] = True

        self._receipt["profile_directory_handle_release_attempted"] = True
        try:
            self._native.close_profile_directory(handle)
        except BaseException:
            self._receipt["delete_suppressed_due_identity_uncertainty"] = True
            identity_allows_delete = False
        else:
            self._profile_directory_handle = None
            self._receipt["profile_directory_handle_released"] = True

        if not self._receipt["profile_directory_handle_released"]:
            return False
        return identity_allows_delete

    def _close_owned(self) -> None:
        if not self._release_profile_directory_for_cleanup():
            return
        self._receipt["cleanup_attempted"] = True
        first_results = self._delete_with_retry()
        self._receipt["delete_attempt_hresults"] = first_results
        first_delete_succeeded = bool(first_results and first_results[-1] == S_OK)
        self._receipt["delete_succeeded"] = first_delete_succeeded
        if not first_delete_succeeded:
            return

        first_folder_absent = self._folder_absent(self._profile_folder)
        self._receipt["first_folder_absent"] = first_folder_absent
        if not first_folder_absent:
            return

        self._receipt["recreate_attempted"] = True
        recreate_result, recreated_sid = self._native.create_profile(
            self._moniker, _RECREATE_DISPLAY_NAME, _RECREATE_DESCRIPTION
        )
        recreate_result = _normalize_hresult(recreate_result)
        self._receipt["recreate_created_hresult"] = recreate_result
        if recreate_result != S_OK:
            # A concurrent ERROR_ALREADY_EXISTS is not wrapper-owned; never delete it.
            return

        self._receipt["recreate_succeeded"] = True
        try:
            recreated_sid = _validate_sid(recreated_sid, "profile_recreated_sid_invalid")
            self._receipt["recreated_sid"] = recreated_sid
            derived_sid = _validate_sid(
                self._native.derive_sid(self._moniker), "profile_recreated_derived_sid_invalid"
            )
            sid_matches = recreated_sid == derived_sid == self._sid
            self._receipt["recreated_sid_matches"] = sid_matches
            _, boundary, folder_exists, reparse_free = self._observe_folder(recreated_sid)
            self._record_folder_boundary(boundary, prefix="recreate_")
            self._receipt["recreate_folder_exists"] = folder_exists
            self._receipt["recreate_folder_reparse_free"] = reparse_free
        finally:
            # The recreate S_OK independently establishes ownership even if validation fails.
            final_results = self._delete_with_retry()
            self._receipt["final_delete_attempt_hresults"] = final_results
            final_delete_succeeded = bool(final_results and final_results[-1] == S_OK)
            self._receipt["final_delete_succeeded"] = final_delete_succeeded
            final_absent = final_delete_succeeded and self._folder_absent(self._profile_folder)
            self._receipt["final_folder_absent"] = final_absent

        self._receipt["cleanup_complete"] = bool(
            self._receipt["delete_succeeded"]
            and self._receipt["first_folder_absent"]
            and self._receipt["recreate_succeeded"]
            and self._receipt["recreated_sid_matches"]
            and self._receipt["recreate_folder_boundary_exact"]
            and self._receipt["recreate_folder_exists"]
            and self._receipt["recreate_folder_reparse_free"]
            and self._receipt["final_delete_succeeded"]
            and self._receipt["final_folder_absent"]
        )

    def close(self) -> dict[str, object]:
        if self._closed:
            return self.receipt
        try:
            if self._owned:
                self._close_owned()
        except BaseException:
            # Cleanup is best effort at this layer; the closed receipt remains fail-closed.
            self._receipt["cleanup_complete"] = False
        finally:
            self._closed = True
            self._receipt["closed"] = True
        return self.receipt

    def child_path_utf8_sha256(self, leaf: str) -> str:
        """Hash one strict child path without disclosing the retained profile path."""

        if (
            not self._started
            or self._closed
            or self._profile_directory_handle is None
            or self._profile_directory_identity is None
        ):
            raise ProfileLeaseFailure("profile_directory_handle_not_held")
        if type(leaf) is not str or CHILD_LEAF_PATTERN.fullmatch(leaf) is None:
            raise ProfileLeaseFailure("profile_child_leaf_invalid")
        child_path = ntpath.normcase(
            ntpath.join(self._profile_directory_identity.canonical_path, leaf)
        )
        return hashlib.sha256(child_path.encode("utf-8")).hexdigest()

    @property
    def owned_profile_binding(self) -> OwnedProfileBinding:
        if not self._started or self._closed or self._owned_binding is None:
            raise ProfileLeaseFailure("profile_prelaunch_unavailable")
        self._owned_binding.current_wire()
        return self._owned_binding

    @property
    def receipt(self) -> dict[str, object]:
        receipt = dict(self._receipt)
        receipt["delete_attempt_hresults"] = list(
            cast(list[int], self._receipt["delete_attempt_hresults"])
        )
        receipt["final_delete_attempt_hresults"] = list(
            cast(list[int], self._receipt["final_delete_attempt_hresults"])
        )
        return receipt

    def __enter__(self) -> AppContainerProfileLease:
        if not self._started:
            try:
                self.start()
            except BaseException:
                self.close()
                raise
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def new_appcontainer_moniker(
    *, nonce_factory: Callable[[int], str] = secrets.token_hex
) -> str:
    """Generate the one accepted lowercase CSPRNG-backed moniker shape."""

    try:
        nonce = nonce_factory(12)
    except Exception as exc:
        raise ProfileLeaseFailure("profile_moniker_generation_failed") from exc
    if type(nonce) is not str:
        raise ProfileLeaseFailure("profile_moniker_generation_failed")
    return _validate_moniker("finplanbrac-" + nonce)


def acquire_appcontainer_profile(
    moniker: str,
    *,
    native: ProfileNative | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> AppContainerProfileLease:
    """Create and validate a fresh profile, cleaning any partly started owned lease."""

    lease = AppContainerProfileLease(moniker, native=native, sleeper=sleeper)
    try:
        return lease.start()
    except ProfileLeaseFailure as exc:
        exc.receipt = lease.close()
        raise
