from __future__ import annotations

import hashlib
import json
import ntpath
import unittest
from dataclasses import FrozenInstanceError

from scripts import windows_appcontainer_profile as profile

MONIKER = "finplanbrac-" + "ab" * 12
SID = "S-1-15-2-101-102-103-104-105-106-107-108"
OTHER_SID = "S-1-15-2-201-202-203-204-205-206-207-208"
LOCAL_APP_DATA = r"C:\Users\synthetic-user\AppData\Local"
PRELAUNCH_KEYS = [
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
]
RECEIPT_KEYS = [
    "cleanup_attempted",
    "cleanup_complete",
    "closed",
    "delete_attempt_hresults",
    "delete_succeeded",
    "delete_suppressed_due_identity_uncertainty",
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
]


class _FakeNative:
    def __init__(
        self,
        *,
        create_results: list[tuple[int, str | None]] | None = None,
        delete_results: list[int] | None = None,
        derived_sids: list[str] | None = None,
        residual_delete_calls: set[int] | None = None,
        folder_path: str | None = None,
        fail_once: dict[str, BaseException] | None = None,
        file_id_128_hex: str = "11" * 16,
        identity_is_directory: bool = True,
        identity_is_reparse_point: bool = False,
        reparse_free: bool = True,
        volume_serial_hex: str = "22" * 8,
    ) -> None:
        self.create_results = list(
            create_results
            if create_results is not None
            else [(profile.S_OK, SID), (profile.S_OK, SID)]
        )
        self.delete_results = list(
            delete_results if delete_results is not None else [profile.S_OK, profile.S_OK]
        )
        self.derived_sids = list(derived_sids if derived_sids is not None else [SID, SID])
        self.residual_delete_calls = residual_delete_calls or set()
        self.folder_path = folder_path or rf"{LOCAL_APP_DATA}\Packages\{MONIKER}\AC"
        self.fail_once = dict(fail_once or {})
        self.file_id_128_hex = file_id_128_hex
        self.identity_is_directory = identity_is_directory
        self.identity_is_reparse_point = identity_is_reparse_point
        self.reparse_free = reparse_free
        self.volume_serial_hex = volume_serial_hex
        self.folder_present = False
        self.handle_held = False
        self.create_calls: list[tuple[str, str, str]] = []
        self.delete_calls: list[str] = []
        self.derive_calls: list[str] = []
        self.folder_queries: list[str] = []
        self.folder_sid_queries: list[str] = []
        self.handle_identity_reads = 0
        self.handle_open_calls: list[tuple[str, int, int, int, int]] = []
        self.handle_release_calls = 0

    def _maybe_fail(self, operation: str) -> None:
        failure = self.fail_once.pop(operation, None)
        if failure is not None:
            raise failure

    def create_profile(
        self, moniker: str, display_name: str, description: str
    ) -> tuple[int, str | None]:
        self.create_calls.append((moniker, display_name, description))
        if not self.create_results:
            raise AssertionError("unexpected create")
        result = self.create_results.pop(0)
        if result[0] == profile.S_OK:
            self.folder_present = True
        return result

    def delete_profile(self, moniker: str) -> int:
        if self.handle_held:
            raise OSError("profile directory delete sharing denied")
        self.delete_calls.append(moniker)
        if not self.delete_results:
            raise AssertionError("unexpected delete")
        result = self.delete_results.pop(0)
        call_number = len(self.delete_calls)
        if result == profile.S_OK and call_number not in self.residual_delete_calls:
            self.folder_present = False
        return result

    def derive_sid(self, moniker: str) -> str:
        self.derive_calls.append(moniker)
        self._maybe_fail("derive_sid")
        if not self.derived_sids:
            raise AssertionError("unexpected derive")
        return self.derived_sids.pop(0)

    def folder_exists(self, path: str) -> bool:
        self.folder_queries.append(path)
        self._maybe_fail("folder_exists")
        return self.folder_present

    def folder_is_directory(self, _path: str) -> bool:
        self._maybe_fail("folder_is_directory")
        return self.folder_present

    def get_folder_path(self, sid: str) -> str:
        self.folder_sid_queries.append(sid)
        self._maybe_fail("get_folder_path")
        return self.folder_path

    def get_local_app_data_path(self) -> str:
        self._maybe_fail("get_local_app_data_path")
        return LOCAL_APP_DATA

    def path_chain_reparse_free(self, _path: str) -> bool:
        self._maybe_fail("path_chain_reparse_free")
        return self.reparse_free

    def open_profile_directory(
        self,
        path: str,
        *,
        creation_disposition: int,
        desired_access: int,
        flags_and_attributes: int,
        share_mode: int,
    ) -> object:
        self._maybe_fail("open_profile_directory")
        self.handle_open_calls.append(
            (
                path,
                creation_disposition,
                desired_access,
                flags_and_attributes,
                share_mode,
            )
        )
        self.handle_held = True
        return 700

    def read_profile_directory_identity(
        self, _handle: object
    ) -> profile.ProfileDirectoryIdentity:
        self.handle_identity_reads += 1
        self._maybe_fail("read_profile_directory_identity")
        return profile.ProfileDirectoryIdentity(
            canonical_path=self.folder_path,
            file_id_128_hex=self.file_id_128_hex,
            is_directory=self.identity_is_directory,
            is_reparse_point=self.identity_is_reparse_point,
            volume_serial_hex=self.volume_serial_hex,
        )

    def close_profile_directory(self, _handle: object) -> None:
        self.handle_release_calls += 1
        self._maybe_fail("close_profile_directory")
        self.handle_held = False

    def watcher_recreate_result(self) -> int:
        if self.handle_held or self.folder_present:
            return profile.HRESULT_ALREADY_EXISTS
        return profile.S_OK


def _lease(fake: _FakeNative) -> profile.AppContainerProfileLease:
    return profile.AppContainerProfileLease(MONIKER, native=fake, sleeper=lambda _seconds: None)


def _prelaunch_wire(
    lease: profile.AppContainerProfileLease,
) -> tuple[profile.OwnedProfileBinding, dict[str, object], bytes, str]:
    binding = lease.owned_profile_binding
    payload, digest = binding.current_wire()
    parsed = json.loads(payload)
    if type(parsed) is not dict:
        raise AssertionError("profile prelaunch JSON must be an object")
    return binding, parsed, payload, digest


class WindowsAppContainerProfileTests(unittest.TestCase):
    def test_success_is_canonical_and_proves_delete_recreate_delete(self) -> None:
        fake = _FakeNative()
        lease = _lease(fake).start()

        binding, prelaunch, payload, digest = _prelaunch_wire(lease)
        self.assertIs(type(binding), profile.OwnedProfileBinding)
        self.assertIs(lease.owned_profile_binding, binding)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
        with self.assertRaises(FrozenInstanceError):
            binding.appcontainer_sid = OTHER_SID  # type: ignore[misc]
        with self.assertRaises(TypeError):
            profile.OwnedProfileBinding()
        with self.assertRaisesRegex(
            profile.ProfileLeaseFailure, "profile_owned_binding_issue_invalid"
        ):
            profile.OwnedProfileBinding._issue(object(), **prelaunch)  # type: ignore[arg-type]
        self.assertEqual(list(prelaunch), PRELAUNCH_KEYS)
        self.assertEqual(prelaunch["format"], profile.PRELAUNCH_FORMAT)
        self.assertEqual(prelaunch["created_hresult"], 0)
        self.assertEqual(prelaunch["appcontainer_sid"], SID)
        self.assertTrue(prelaunch["ownership_established"])
        self.assertTrue(prelaunch["sid_reconciled"])
        self.assertEqual(prelaunch["folder_boundary_component_count"], 2)
        self.assertTrue(prelaunch["folder_boundary_components_win32_valid"])
        self.assertTrue(prelaunch["folder_boundary_exact"])
        self.assertTrue(prelaunch["folder_boundary_nonempty_descendant"])
        self.assertTrue(prelaunch["folder_boundary_packages_ancestor"])
        self.assertEqual(prelaunch["folder_boundary_reason"], "observed")
        self.assertTrue(prelaunch["folder_boundary_reconstruction_matches"])
        self.assertTrue(prelaunch["folder_boundary_terminal_ac"])
        self.assertTrue(prelaunch["folder_exists"])
        self.assertTrue(prelaunch["folder_reparse_free"])
        self.assertTrue(prelaunch["folder_handle_delete_share_denied"])
        self.assertTrue(prelaunch["folder_handle_held"])
        self.assertEqual(prelaunch["folder_identity_format"], profile.FOLDER_IDENTITY_FORMAT)
        self.assertEqual(prelaunch["folder_file_id_128_hex"], "11" * 16)
        self.assertEqual(prelaunch["folder_volume_serial_hex"], "22" * 8)
        expected_path_sha256 = hashlib.sha256(
            ntpath.normcase(fake.folder_path).encode("utf-8")
        ).hexdigest()
        self.assertEqual(prelaunch["folder_path_utf8_sha256"], expected_path_sha256)
        self.assertNotIn("folder", prelaunch)
        canonical = json.dumps(prelaunch, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        self.assertEqual(json.loads(canonical), prelaunch)

        receipt = lease.close()

        self.assertEqual(list(receipt), RECEIPT_KEYS)
        self.assertEqual(receipt["format"], profile.RECEIPT_FORMAT)
        self.assertTrue(receipt["closed"])
        self.assertTrue(receipt["owned"])
        self.assertTrue(receipt["ownership_established"])
        self.assertTrue(receipt["cleanup_attempted"])
        self.assertTrue(receipt["cleanup_complete"])
        for key in (
            "delete_succeeded",
            "first_folder_absent",
            "recreate_succeeded",
            "recreated_sid_matches",
            "recreate_folder_boundary_exact",
            "recreate_folder_exists",
            "recreate_folder_reparse_free",
            "final_delete_succeeded",
            "final_folder_absent",
        ):
            self.assertTrue(receipt[key], key)
        self.assertEqual(receipt["folder_boundary_reason"], "observed")
        self.assertEqual(receipt["recreate_folder_boundary_reason"], "observed")
        self.assertEqual(receipt["delete_attempt_hresults"], [profile.S_OK])
        self.assertEqual(receipt["final_delete_attempt_hresults"], [profile.S_OK])
        self.assertTrue(receipt["first_folder_absent"])
        self.assertTrue(receipt["final_folder_absent"])
        self.assertTrue(receipt["recreated_sid_matches"])
        self.assertTrue(receipt["folder_identity_revalidated_before_release"])
        self.assertTrue(receipt["profile_directory_handle_release_attempted"])
        self.assertTrue(receipt["profile_directory_handle_released"])
        self.assertFalse(receipt["folder_identity_drift_detected"])
        self.assertFalse(receipt["delete_suppressed_due_identity_uncertainty"])
        self.assertEqual(receipt["folder_file_id_128_hex"], prelaunch["folder_file_id_128_hex"])
        self.assertEqual(receipt["folder_path_utf8_sha256"], prelaunch["folder_path_utf8_sha256"])
        self.assertEqual(receipt["folder_volume_serial_hex"], prelaunch["folder_volume_serial_hex"])
        self.assertEqual(receipt["residual_race_after_handle_release"], "not_prevented")
        self.assertNotIn("folder_path", receipt)
        receipt_canonical = json.dumps(
            receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
        self.assertNotIn("synthetic-user", receipt_canonical)
        self.assertEqual(json.loads(receipt_canonical), receipt)
        self.assertEqual(fake.delete_calls, [MONIKER, MONIKER])
        self.assertFalse(fake.folder_present)
        self.assertFalse(fake.handle_held)
        self.assertEqual(fake.handle_identity_reads, 2)
        self.assertEqual(fake.handle_release_calls, 1)
        self.assertEqual(
            fake.handle_open_calls,
            [
                (
                    fake.folder_path,
                    profile.OPEN_EXISTING,
                    profile.FILE_READ_ATTRIBUTES,
                    profile.PROFILE_DIRECTORY_FLAGS,
                    profile.PROFILE_DIRECTORY_SHARE_MODE,
                )
            ],
        )
        self.assertEqual(profile.PROFILE_DIRECTORY_SHARE_MODE & profile.FILE_SHARE_DELETE, 0)

    def test_owned_binding_is_issued_only_after_same_process_sid_reconciliation(self) -> None:
        fake = _FakeNative(derived_sids=[OTHER_SID, SID])
        lease = _lease(fake)

        with self.assertRaisesRegex(
            profile.ProfileLeaseFailure, "profile_sid_reconciliation_failed"
        ) as captured:
            lease.start()

        self.assertIsNotNone(captured.exception.receipt)
        assert captured.exception.receipt is not None
        self.assertTrue(captured.exception.receipt["cleanup_complete"])
        with self.assertRaisesRegex(
            profile.ProfileLeaseFailure, "profile_prelaunch_unavailable"
        ):
            _ = lease.owned_profile_binding
        self.assertEqual(fake.derive_calls, [MONIKER, MONIKER])

    def test_owned_binding_is_sealed_and_unavailable_after_close(self) -> None:
        lease = _lease(_FakeNative()).start()
        binding = lease.owned_profile_binding

        with self.assertRaisesRegex(TypeError, "sealed"):
            type("ForgedOwnedProfileBinding", (profile.OwnedProfileBinding,), {})

        lease.close()
        with self.assertRaisesRegex(
            profile.ProfileLeaseFailure, "profile_prelaunch_unavailable"
        ):
            _ = lease.owned_profile_binding
        payload, digest = binding.current_wire()
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())

    def test_owned_binding_detects_low_level_field_drift_without_rebaseline(self) -> None:
        lease = _lease(_FakeNative()).start()
        binding = lease.owned_profile_binding

        object.__setattr__(binding, "appcontainer_sid", OTHER_SID)
        with self.assertRaisesRegex(
            profile.ProfileLeaseFailure, "profile_binding_snapshot_drift"
        ):
            binding.current_wire()

        lease.close()

    def test_already_exists_never_establishes_ownership_or_deletes(self) -> None:
        fake = _FakeNative(
            create_results=[(profile.HRESULT_ALREADY_EXISTS - (1 << 32), None)],
            delete_results=[],
            derived_sids=[],
        )
        lease = _lease(fake)

        with self.assertRaisesRegex(profile.ProfileLeaseFailure, "profile_preexisting"):
            lease.start()
        receipt = lease.close()

        self.assertTrue(receipt["closed"])
        self.assertFalse(receipt["owned"])
        self.assertFalse(receipt["ownership_established"])
        self.assertFalse(receipt["cleanup_attempted"])
        self.assertFalse(receipt["cleanup_complete"])
        self.assertEqual(receipt["delete_attempt_hresults"], [])
        self.assertEqual(receipt["final_delete_attempt_hresults"], [])
        self.assertEqual(fake.delete_calls, [])

    def test_acquire_failure_exposes_closed_non_owned_receipt(self) -> None:
        fake = _FakeNative(
            create_results=[(profile.HRESULT_ALREADY_EXISTS, None)],
            delete_results=[],
            derived_sids=[],
        )

        with self.assertRaises(profile.ProfileLeaseFailure) as captured:
            profile.acquire_appcontainer_profile(
                MONIKER, native=fake, sleeper=lambda _seconds: None
            )

        self.assertEqual(captured.exception.reason, "profile_preexisting")
        self.assertIsNotNone(captured.exception.receipt)
        assert captured.exception.receipt is not None
        self.assertTrue(captured.exception.receipt["closed"])
        self.assertFalse(captured.exception.receipt["owned"])
        self.assertEqual(fake.delete_calls, [])

    def test_failed_delete_is_retried_before_recreate(self) -> None:
        access_denied = 0x80070005
        fake = _FakeNative(
            delete_results=[access_denied, profile.S_OK, profile.S_OK]
        )
        lease = _lease(fake).start()

        receipt = lease.close()

        self.assertTrue(receipt["cleanup_complete"])
        self.assertEqual(receipt["delete_attempt_hresults"], [access_denied, profile.S_OK])
        self.assertEqual(receipt["final_delete_attempt_hresults"], [profile.S_OK])
        self.assertEqual(fake.delete_calls, [MONIKER, MONIKER, MONIKER])

    def test_persistent_delete_failure_is_bounded_and_never_recreates(self) -> None:
        access_denied = 0x80070005
        fake = _FakeNative(
            create_results=[(profile.S_OK, SID)],
            delete_results=[access_denied] * profile.MAX_DELETE_ATTEMPTS,
            derived_sids=[SID],
        )
        lease = _lease(fake).start()

        receipt = lease.close()

        self.assertFalse(receipt["cleanup_complete"])
        self.assertEqual(
            receipt["delete_attempt_hresults"],
            [access_denied] * profile.MAX_DELETE_ATTEMPTS,
        )
        self.assertFalse(receipt["delete_succeeded"])
        self.assertFalse(receipt["recreate_attempted"])
        self.assertEqual(len(fake.delete_calls), profile.MAX_DELETE_ATTEMPTS)

    def test_every_prehandle_post_s_ok_oserror_is_closed_and_leaves_no_residual(self) -> None:
        operations = (
            "derive_sid",
            "get_folder_path",
            "get_local_app_data_path",
            "folder_exists",
            "folder_is_directory",
            "path_chain_reparse_free",
            "open_profile_directory",
        )
        for operation in operations:
            with self.subTest(operation=operation):
                fake = _FakeNative(fail_once={operation: OSError("injected")})

                with self.assertRaises(profile.ProfileLeaseFailure) as captured:
                    profile.acquire_appcontainer_profile(
                        MONIKER, native=fake, sleeper=lambda _seconds: None
                    )

                self.assertEqual(
                    captured.exception.reason, "profile_post_creation_validation_failed"
                )
                self.assertIsInstance(captured.exception.__cause__, OSError)
                self.assertIsNotNone(captured.exception.receipt)
                assert captured.exception.receipt is not None
                self.assertTrue(captured.exception.receipt["closed"])
                self.assertTrue(captured.exception.receipt["owned"])
                self.assertGreaterEqual(len(fake.delete_calls), 1)
                self.assertFalse(fake.folder_present)
                self.assertFalse(fake.handle_held)

    def test_interrupt_and_system_exit_are_preserved_only_as_closed_failure_causes(self) -> None:
        for injected in (KeyboardInterrupt(), SystemExit(73)):
            with self.subTest(injected=type(injected).__name__):
                fake = _FakeNative(fail_once={"derive_sid": injected})

                with self.assertRaises(profile.ProfileLeaseFailure) as captured:
                    profile.acquire_appcontainer_profile(
                        MONIKER, native=fake, sleeper=lambda _seconds: None
                    )

                self.assertIs(captured.exception.__cause__, injected)
                self.assertIsNotNone(captured.exception.receipt)
                assert captured.exception.receipt is not None
                self.assertTrue(captured.exception.receipt["closed"])
                self.assertTrue(captured.exception.receipt["cleanup_attempted"])
                self.assertFalse(fake.folder_present)

    def test_held_handle_denies_watcher_delete_and_recreate_until_close(self) -> None:
        fake = _FakeNative()
        lease = _lease(fake).start()

        self.assertTrue(fake.handle_held)
        with self.assertRaises(OSError):
            fake.delete_profile(MONIKER)
        self.assertEqual(fake.watcher_recreate_result(), profile.HRESULT_ALREADY_EXISTS)
        self.assertEqual(fake.delete_calls, [])

        receipt = lease.close()

        self.assertTrue(receipt["cleanup_complete"])
        self.assertFalse(fake.handle_held)
        self.assertEqual(fake.delete_calls, [MONIKER, MONIKER])

    def test_pre_release_identity_drift_releases_handle_and_suppresses_foreign_delete(self) -> None:
        fake = _FakeNative()
        lease = _lease(fake).start()
        fake.file_id_128_hex = "33" * 16

        receipt = lease.close()

        self.assertTrue(receipt["closed"])
        self.assertTrue(receipt["folder_identity_drift_detected"])
        self.assertFalse(receipt["folder_identity_revalidated_before_release"])
        self.assertTrue(receipt["delete_suppressed_due_identity_uncertainty"])
        self.assertTrue(receipt["profile_directory_handle_released"])
        self.assertFalse(receipt["cleanup_attempted"])
        self.assertFalse(receipt["cleanup_complete"])
        self.assertEqual(receipt["delete_attempt_hresults"], [])
        self.assertEqual(fake.delete_calls, [])
        self.assertTrue(fake.folder_present)
        self.assertFalse(fake.handle_held)

    def test_pre_release_identity_query_error_suppresses_delete(self) -> None:
        fake = _FakeNative()
        lease = _lease(fake).start()
        fake.fail_once["read_profile_directory_identity"] = OSError("injected")

        receipt = lease.close()

        self.assertFalse(receipt["folder_identity_drift_detected"])
        self.assertFalse(receipt["folder_identity_revalidated_before_release"])
        self.assertTrue(receipt["delete_suppressed_due_identity_uncertainty"])
        self.assertTrue(receipt["profile_directory_handle_released"])
        self.assertEqual(fake.delete_calls, [])
        self.assertTrue(fake.folder_present)

    def test_identity_query_error_after_handle_open_closes_handle_without_deleting(self) -> None:
        fake = _FakeNative(
            fail_once={"read_profile_directory_identity": OSError("injected")}
        )

        with self.assertRaises(profile.ProfileLeaseFailure) as captured:
            profile.acquire_appcontainer_profile(
                MONIKER, native=fake, sleeper=lambda _seconds: None
            )

        self.assertIsNotNone(captured.exception.receipt)
        assert captured.exception.receipt is not None
        receipt = captured.exception.receipt
        self.assertTrue(receipt["profile_directory_handle_release_attempted"])
        self.assertTrue(receipt["profile_directory_handle_released"])
        self.assertTrue(receipt["delete_suppressed_due_identity_uncertainty"])
        self.assertEqual(fake.delete_calls, [])
        self.assertTrue(fake.folder_present)
        self.assertFalse(fake.handle_held)

    def test_handle_release_error_suppresses_all_profile_deletes(self) -> None:
        fake = _FakeNative()
        lease = _lease(fake).start()
        fake.fail_once["close_profile_directory"] = OSError("injected")

        receipt = lease.close()

        self.assertTrue(receipt["folder_identity_revalidated_before_release"])
        self.assertTrue(receipt["profile_directory_handle_release_attempted"])
        self.assertFalse(receipt["profile_directory_handle_released"])
        self.assertTrue(receipt["delete_suppressed_due_identity_uncertainty"])
        self.assertEqual(fake.delete_calls, [])
        self.assertTrue(fake.folder_present)

    def test_handle_identity_must_report_directory_and_non_reparse(self) -> None:
        for options in (
            {"identity_is_directory": False},
            {"identity_is_reparse_point": True},
        ):
            with self.subTest(options=options):
                fake = _FakeNative(**options)  # type: ignore[arg-type]
                with self.assertRaises(profile.ProfileLeaseFailure) as captured:
                    profile.acquire_appcontainer_profile(
                        MONIKER, native=fake, sleeper=lambda _seconds: None
                    )
                self.assertIsNotNone(captured.exception.receipt)
                assert captured.exception.receipt is not None
                self.assertTrue(captured.exception.receipt["closed"])
                self.assertTrue(
                    captured.exception.receipt[
                        "delete_suppressed_due_identity_uncertainty"
                    ]
                )
                self.assertEqual(fake.delete_calls, [])
                self.assertFalse(fake.handle_held)

    def test_recreated_sid_mismatch_fails_closed_but_deletes_owned_recreation(self) -> None:
        fake = _FakeNative(
            create_results=[(profile.S_OK, SID), (profile.S_OK, OTHER_SID)],
            derived_sids=[SID, OTHER_SID],
        )
        lease = _lease(fake).start()

        receipt = lease.close()

        self.assertFalse(receipt["cleanup_complete"])
        self.assertTrue(receipt["recreate_succeeded"])
        self.assertEqual(receipt["recreated_sid"], OTHER_SID)
        self.assertFalse(receipt["recreated_sid_matches"])
        self.assertTrue(receipt["final_delete_succeeded"])
        self.assertTrue(receipt["final_folder_absent"])
        self.assertEqual(fake.delete_calls, [MONIKER, MONIKER])

    def test_residual_folder_stops_before_recreate(self) -> None:
        fake = _FakeNative(
            create_results=[(profile.S_OK, SID)],
            delete_results=[profile.S_OK],
            derived_sids=[SID],
            residual_delete_calls={1},
        )
        lease = _lease(fake).start()

        receipt = lease.close()

        self.assertFalse(receipt["cleanup_complete"])
        self.assertTrue(receipt["delete_succeeded"])
        self.assertFalse(receipt["first_folder_absent"])
        self.assertFalse(receipt["recreate_attempted"])
        self.assertEqual(len(fake.folder_queries), 1 + profile.MAX_FOLDER_POLLS)
        self.assertEqual(len(fake.create_calls), 1)
        self.assertEqual(fake.delete_calls, [MONIKER])

    def test_outside_folder_fails_start_and_owned_profile_is_cleaned(self) -> None:
        wrong_folder = rf"{LOCAL_APP_DATA}\Outside\other\nested\AC"
        fake = _FakeNative(folder_path=wrong_folder)

        with self.assertRaises(profile.ProfileLeaseFailure) as captured:
            profile.acquire_appcontainer_profile(
                MONIKER, native=fake, sleeper=lambda _seconds: None
            )

        self.assertEqual(captured.exception.reason, "profile_folder_boundary_failed")
        self.assertIsNotNone(captured.exception.receipt)
        assert captured.exception.receipt is not None
        self.assertTrue(captured.exception.receipt["owned"])
        self.assertEqual(fake.delete_calls, [MONIKER, MONIKER])

    def test_noncanonical_traversal_fails_before_shape_admission_and_is_cleaned(self) -> None:
        fake = _FakeNative(
            folder_path=rf"{LOCAL_APP_DATA}\Packages\one\..\Outside"
        )

        with self.assertRaises(profile.ProfileLeaseFailure) as captured:
            profile.acquire_appcontainer_profile(
                MONIKER,
                native=fake,
                sleeper=lambda _seconds: None,
            )

        self.assertEqual(captured.exception.reason, "profile_folder_path_invalid")
        self.assertIsNotNone(captured.exception.receipt)
        assert captured.exception.receipt is not None
        self.assertTrue(captured.exception.receipt["owned"])
        self.assertTrue(captured.exception.receipt["closed"])
        self.assertTrue(captured.exception.receipt["delete_succeeded"])
        self.assertFalse(captured.exception.receipt["cleanup_complete"])
        self.assertFalse(captured.exception.receipt["recreate_attempted"])
        self.assertEqual(fake.delete_calls, [MONIKER])
        self.assertFalse(fake.folder_present)

    def test_sid_bound_win32_leaf_need_not_match_old_ascii_grammar_or_moniker(self) -> None:
        api_selected_component = "OS selected + profile ü"
        fake = _FakeNative(
            folder_path=rf"{LOCAL_APP_DATA}\Packages\{api_selected_component}\AC"
        )

        lease = _lease(fake).start()
        try:
            _, prelaunch, _, _ = _prelaunch_wire(lease)
            self.assertTrue(prelaunch["folder_boundary_exact"])
            self.assertNotIn(api_selected_component, json.dumps(prelaunch, sort_keys=True))
            self.assertEqual(fake.folder_queries[0], fake.folder_path)
            self.assertEqual(fake.folder_sid_queries[0], SID)
        finally:
            lease.close()

    def test_profile_leaf_rejects_invalid_win32_names(self) -> None:
        invalid_components = (
            "",
            ".",
            "..",
            "two:streams",
            "bad<leaf",
            "bad>leaf",
            'bad"leaf',
            "bad|leaf",
            "bad?leaf",
            "bad*leaf",
            "bad\x00leaf",
            "bad\x1fleaf",
            "bad\x7fleaf",
            "trailing.",
            "trailing ",
            "CON",
            "con.txt",
            "NUL.log",
            "COM1",
            "lpt9.data",
            "COM¹",
            "CONIN$",
        )
        for component in invalid_components:
            with self.subTest(component=component):
                self.assertFalse(profile._win32_profile_leaf_valid(component))
        for component in (
            "-bad",
            "bad component",
            "profile+leaf",
            "perfil-ç",
            "profile-📁",
        ):
            with self.subTest(valid_component=component):
                self.assertTrue(profile._win32_profile_leaf_valid(component))

    def test_profile_boundary_accepts_one_two_and_three_component_shapes(self) -> None:
        valid_paths = (
            (rf"{LOCAL_APP_DATA}\Packages\{MONIKER}", 1, False),
            (rf"{LOCAL_APP_DATA}\Packages\{MONIKER}\AC", 2, True),
            (rf"{LOCAL_APP_DATA}\Packages\vendor\{MONIKER}\scratch", 3, False),
        )
        for folder_path, component_count, terminal_ac in valid_paths:
            with self.subTest(component_count=component_count, terminal_ac=terminal_ac):
                observation = profile._profile_folder_boundary_observation(
                    folder_path, LOCAL_APP_DATA
                )
                self.assertTrue(observation.exact)
                self.assertTrue(observation.nonempty_descendant)
                self.assertTrue(observation.components_win32_valid)
                self.assertTrue(observation.reconstruction_matches)
                self.assertEqual(observation.component_count, component_count)
                self.assertEqual(observation.terminal_ac, terminal_ac)
                self.assertEqual(observation.reason, "observed")

    def test_profile_boundary_rejects_outside_empty_traversal_ads_and_reserved(self) -> None:
        invalid_paths = {
            rf"{LOCAL_APP_DATA}\Outside\leaf\AC": "packages_ancestor_mismatch",
            rf"{LOCAL_APP_DATA}\Packages": "empty_descendant",
            rf"{LOCAL_APP_DATA}\PackagesBackup\leaf": "packages_ancestor_mismatch",
            rf"{LOCAL_APP_DATA}\Packages\one\..\Outside": "components_win32_invalid",
            rf"{LOCAL_APP_DATA}\Packages\two:streams\AC": "components_win32_invalid",
            rf"{LOCAL_APP_DATA}\Packages\CON.txt\AC": "components_win32_invalid",
            rf"{LOCAL_APP_DATA}\Packages\trailing.\AC": "components_win32_invalid",
        }
        for folder_path, reason in invalid_paths.items():
            with self.subTest(reason=reason):
                observation = profile._profile_folder_boundary_observation(
                    folder_path, LOCAL_APP_DATA
                )
                self.assertFalse(observation.exact)
                self.assertEqual(observation.reason, reason)
        self.assertFalse(profile._win32_profile_leaf_valid("nested\\leaf"))
        self.assertFalse(profile._win32_profile_leaf_valid("nested/leaf"))

    def test_historical_v3_relative_depth_rc1_shape_is_accepted_by_v4(self) -> None:
        fake = _FakeNative(folder_path=rf"{LOCAL_APP_DATA}\Packages\{MONIKER}")

        lease = _lease(fake).start()
        _, prelaunch, _, _ = _prelaunch_wire(lease)
        self.assertEqual(prelaunch["folder_boundary_component_count"], 1)
        self.assertFalse(prelaunch["folder_boundary_terminal_ac"])
        self.assertTrue(prelaunch["folder_boundary_exact"])
        self.assertEqual(prelaunch["folder_boundary_reason"], "observed")

        receipt = lease.close()
        self.assertTrue(receipt["cleanup_complete"])
        self.assertEqual(receipt["recreate_folder_boundary_component_count"], 1)
        self.assertFalse(receipt["recreate_folder_boundary_terminal_ac"])
        self.assertFalse(fake.folder_present)

    def test_invalid_component_failure_leaves_no_residual_or_false_cleanup(self) -> None:
        fake = _FakeNative(folder_path=rf"{LOCAL_APP_DATA}\Packages\CON\AC")

        with self.assertRaises(profile.ProfileLeaseFailure) as captured:
            profile.acquire_appcontainer_profile(
                MONIKER, native=fake, sleeper=lambda _seconds: None
            )

        self.assertEqual(captured.exception.reason, "profile_folder_boundary_failed")
        receipt = captured.exception.receipt
        self.assertIsNotNone(receipt)
        assert receipt is not None
        self.assertTrue(receipt["closed"])
        self.assertTrue(receipt["owned"])
        self.assertTrue(receipt["cleanup_attempted"])
        self.assertFalse(receipt["cleanup_complete"])
        self.assertFalse(receipt["folder_boundary_exact"])
        self.assertEqual(
            receipt["folder_boundary_reason"], "components_win32_invalid"
        )
        self.assertFalse(receipt["recreate_folder_boundary_exact"])
        self.assertEqual(
            receipt["recreate_folder_boundary_reason"],
            "components_win32_invalid",
        )
        for key in (
            "delete_succeeded",
            "first_folder_absent",
            "recreate_succeeded",
            "recreated_sid_matches",
            "recreate_folder_exists",
            "recreate_folder_reparse_free",
            "final_delete_succeeded",
            "final_folder_absent",
        ):
            self.assertTrue(receipt[key], key)
        self.assertIsNone(receipt["folder_file_id_128_hex"])
        self.assertIsNone(receipt["folder_path_utf8_sha256"])
        self.assertIsNone(receipt["folder_volume_serial_hex"])
        self.assertEqual(fake.delete_calls, [MONIKER, MONIKER])
        self.assertFalse(fake.folder_present)

    def test_s_ok_with_missing_sid_still_establishes_cleanup_ownership(self) -> None:
        fake = _FakeNative(
            create_results=[(profile.S_OK, None)],
            delete_results=[profile.S_OK],
            derived_sids=[],
        )

        with self.assertRaises(profile.ProfileLeaseFailure) as captured:
            profile.acquire_appcontainer_profile(
                MONIKER, native=fake, sleeper=lambda _seconds: None
            )

        self.assertEqual(captured.exception.reason, "profile_created_sid_invalid")
        self.assertIsNotNone(captured.exception.receipt)
        assert captured.exception.receipt is not None
        self.assertTrue(captured.exception.receipt["owned"])
        self.assertTrue(captured.exception.receipt["cleanup_attempted"])
        self.assertEqual(fake.delete_calls, [MONIKER])

    def test_invalid_moniker_is_rejected_before_native_use(self) -> None:
        fake = _FakeNative()

        with self.assertRaisesRegex(profile.ProfileLeaseFailure, "profile_moniker_invalid"):
            profile.AppContainerProfileLease("finplanbrac-ABC", native=fake)

        self.assertEqual(fake.create_calls, [])
        self.assertEqual(fake.delete_calls, [])

    def test_new_moniker_requires_exact_lowercase_nonce_shape(self) -> None:
        self.assertEqual(
            profile.new_appcontainer_moniker(nonce_factory=lambda _count: "12" * 12),
            "finplanbrac-" + "12" * 12,
        )
        with self.assertRaisesRegex(profile.ProfileLeaseFailure, "profile_moniker_invalid"):
            profile.new_appcontainer_moniker(nonce_factory=lambda _count: "AB" * 12)
        with self.assertRaisesRegex(
            profile.ProfileLeaseFailure, "profile_moniker_generation_failed"
        ):
            profile.new_appcontainer_moniker(nonce_factory=lambda _count: None)  # type: ignore[arg-type]

    def test_child_path_hash_uses_held_canonical_profile_path_without_emitting_it(self) -> None:
        fake = _FakeNative()
        lease = _lease(fake).start()
        leaf = "network-arm-request.json"
        expected = hashlib.sha256(
            ntpath.normcase(ntpath.join(fake.folder_path, leaf)).encode("utf-8")
        ).hexdigest()

        self.assertEqual(lease.child_path_utf8_sha256(leaf), expected)
        self.assertNotIn(fake.folder_path, lease.child_path_utf8_sha256(leaf))

        lease.close()
        with self.assertRaisesRegex(
            profile.ProfileLeaseFailure, "profile_directory_handle_not_held"
        ):
            lease.child_path_utf8_sha256(leaf)

    def test_child_path_hash_rejects_separators_ads_controls_and_non_ascii(self) -> None:
        fake = _FakeNative()
        lease = _lease(fake).start()
        try:
            for leaf in (
                "..",
                ".",
                "nested\\request.json",
                "nested/request.json",
                "request.json:stream",
                " request.json",
                "request\x00.json",
                "requêst.json",
            ):
                with self.subTest(leaf=leaf):
                    with self.assertRaisesRegex(
                        profile.ProfileLeaseFailure, "profile_child_leaf_invalid"
                    ):
                        lease.child_path_utf8_sha256(leaf)
        finally:
            lease.close()

    def test_context_manager_cleans_owned_profile_when_start_validation_fails(self) -> None:
        fake = _FakeNative(reparse_free=False)
        lease = _lease(fake)

        with self.assertRaisesRegex(
            profile.ProfileLeaseFailure, "profile_folder_reparse_boundary_failed"
        ):
            with lease:
                self.fail("unreachable")

        self.assertTrue(lease.receipt["closed"])
        self.assertTrue(lease.receipt["owned"])
        self.assertEqual(fake.delete_calls, [MONIKER, MONIKER])

    def test_close_is_idempotent(self) -> None:
        fake = _FakeNative()
        lease = _lease(fake).start()

        first = lease.close()
        second = lease.close()

        self.assertEqual(first, second)
        self.assertEqual(fake.delete_calls, [MONIKER, MONIKER])


if __name__ == "__main__":
    unittest.main()
