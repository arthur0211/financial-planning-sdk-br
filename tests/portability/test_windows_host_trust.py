from __future__ import annotations

import inspect
import os
import unittest
from pathlib import Path
from unittest import mock

from scripts import run_windows_appcontainer_spike as spike
from scripts import windows_host_trust as trust


def _information(*, attributes: int, index: int = 1) -> trust._BY_HANDLE_FILE_INFORMATION:
    information = trust._BY_HANDLE_FILE_INFORMATION()
    information.dwFileAttributes = attributes
    information.dwVolumeSerialNumber = 1
    information.nFileIndexHigh = 0
    information.nFileIndexLow = index
    return information


class WindowsHostTrustContractTests(unittest.TestCase):
    def test_production_entrypoints_expose_no_host_or_runner_override(self) -> None:
        public_parameters = set(inspect.signature(spike.run_spike).parameters)
        acquire_parameters = set(inspect.signature(trust.acquire_trusted_powershell_hosts).parameters)
        self.assertEqual(public_parameters, {"temp_root", "timeout_seconds"})
        self.assertEqual(acquire_parameters, set())
        self.assertNotIn("pwsh", public_parameters)
        self.assertNotIn("windows_powershell", public_parameters)
        self.assertNotIn("runner", public_parameters)

    def test_host_identity_rejects_path_hash_version_publisher_signature_and_package_tamper(self) -> None:
        valid = {
            "role": trust.POWERSHELL_7_ROLE,
            "path": r"C:\Program Files\PowerShell\7\pwsh.exe",
            "sha256": "a" * 64,
            "file_version": "7.6.4.0",
            "file_id": "0000000000000001:" + "b" * 32,
            "publisher": "Microsoft Corporation",
            "signer_common_name": "Microsoft Corporation",
            "ancestor_count": 4,
            "installation_profile": "powershell_7_msi",
            "package_full_name": None,
            "package_publisher": None,
            "package_version": None,
        }
        mutations = (
            ("path", r"relative\pwsh.exe"),
            ("sha256", "0" * 63),
            ("file_version", "7.6"),
            ("file_id", "00000001:" + "b" * 16),
            ("publisher", "Attacker Corporation"),
            ("signer_common_name", "Microsoft Corporation Evil"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                candidate = dict(valid)
                candidate[field] = value
                with self.assertRaises(ValueError):
                    trust.HostIdentity(**candidate)  # type: ignore[arg-type]

        msix = dict(valid)
        msix_full_name = "Microsoft.PowerShell_7.6.4.0_x64__8wekyb3d8bbwe"
        msix.update(
            path=rf"C:\Program Files\WindowsApps\{msix_full_name}\pwsh.exe",
            installation_profile="powershell_7_msix",
            package_full_name=msix_full_name,
            package_publisher=trust.MICROSOFT_PACKAGE_PUBLISHER,
            package_version="7.6.4.0",
        )
        trust.HostIdentity(**msix)  # type: ignore[arg-type]
        for field, value in (
            ("package_full_name", "Microsoft.PowerShell_7.6.4.0_x64__attacker"),
            ("package_publisher", "CN=Attacker"),
            ("package_version", "7.6"),
            ("package_version", "7.6.5.0"),
        ):
            with self.subTest(field=field):
                candidate = dict(msix)
                candidate[field] = value
                with self.assertRaises(ValueError):
                    trust.HostIdentity(**candidate)  # type: ignore[arg-type]

    def test_windowsapps_folder_name_spoof_is_not_discovered_without_appmodel_registration(self) -> None:
        program_files = Path(r"C:\Program Files")
        spoof = (
            program_files
            / "WindowsApps"
            / "Microsoft.PowerShell_99.0.0.0_x64__8wekyb3d8bbwe"
            / "pwsh.exe"
        )

        def only_spoof_exists(path: object) -> bool:
            return trust._normalize_windows_path(os.fspath(path)) == trust._normalize_windows_path(
                os.fspath(spoof)
            )

        with (
            mock.patch.object(trust, "_get_program_files", return_value=program_files),
            mock.patch.object(trust, "_registered_powershell_packages", return_value=()) as registered,
            mock.patch.object(trust.os.path, "lexists", side_effect=only_spoof_exists),
        ):
            with self.assertRaises(trust.HostTrustFailure) as failure:
                trust._discover_powershell_7()
        self.assertEqual(failure.exception.status, "not_observed")
        self.assertEqual(failure.exception.reason, "powershell_7_not_found")
        registered.assert_called_once_with()

    def test_registered_package_path_must_match_appmodel_full_name_exactly(self) -> None:
        program_files = Path(r"C:\Program Files")
        full_name = "Microsoft.PowerShell_7.6.4.0_x64__8wekyb3d8bbwe"
        package = trust._RegisteredPackage(
            full_name=full_name,
            path=program_files / "WindowsApps" / (full_name + "-spoof"),
            version="7.6.4.0",
            publisher=trust.MICROSOFT_PACKAGE_PUBLISHER,
            processor_architecture=9,
        )
        with (
            mock.patch.object(trust, "_get_program_files", return_value=program_files),
            mock.patch.object(trust, "_registered_powershell_packages", return_value=(package,)),
            mock.patch.object(trust.os.path, "lexists", return_value=False),
        ):
            with self.assertRaises(trust.HostTrustFailure) as failure:
                trust._discover_powershell_7()
        self.assertEqual(failure.exception.reason, "host_path_unexpected")

    def test_registered_appmodel_package_binds_full_name_path_publisher_and_version(self) -> None:
        program_files = Path(r"C:\Program Files")
        full_name = "Microsoft.PowerShell_7.6.4.0_x64__8wekyb3d8bbwe"
        package = trust._RegisteredPackage(
            full_name=full_name,
            path=program_files / "WindowsApps" / full_name,
            version="7.6.4.0",
            publisher=trust.MICROSOFT_PACKAGE_PUBLISHER,
            processor_architecture=9,
        )

        def package_executable_exists(path: object) -> bool:
            return trust._normalize_windows_path(os.fspath(path)) == trust._normalize_windows_path(
                os.fspath(package.path / "pwsh.exe")
            )

        with (
            mock.patch.object(trust, "_get_program_files", return_value=program_files),
            mock.patch.object(trust, "_registered_powershell_packages", return_value=(package,)),
            mock.patch.object(trust.os.path, "lexists", side_effect=package_executable_exists),
        ):
            discovery = trust._discover_powershell_7()
        self.assertEqual(discovery.package, package)
        self.assertEqual(discovery.path, package.path / "pwsh.exe")
        self.assertEqual(discovery.installation_profile, "powershell_7_msix")


class WindowsHostTrustPrimitiveTests(unittest.TestCase):
    def test_reparse_component_is_rejected_before_owner_or_acl_checks(self) -> None:
        path = Path(r"C:\Windows")
        information = _information(
            attributes=trust._FILE_ATTRIBUTE_DIRECTORY | trust._FILE_ATTRIBUTE_REPARSE_POINT
        )
        with (
            mock.patch.object(trust, "_open_handle", return_value=41),
            mock.patch.object(trust, "_query_handle_information", return_value=information),
            mock.patch.object(trust, "_query_owner_sid") as owner,
            mock.patch.object(trust, "_probe_current_token_mutation_access") as access,
            mock.patch.object(trust, "_close_handle") as close,
        ):
            with self.assertRaises(trust.HostTrustFailure) as failure:
                trust._inspect_component(path, is_directory=True)
        self.assertEqual(failure.exception.reason, "host_chain_reparse")
        owner.assert_not_called()
        access.assert_not_called()
        close.assert_called_once_with(41)

    def test_untrusted_owner_is_rejected_before_acl_probe(self) -> None:
        path = Path(r"C:\Windows")
        information = _information(attributes=trust._FILE_ATTRIBUTE_DIRECTORY)
        with (
            mock.patch.object(trust, "_open_handle", return_value=42),
            mock.patch.object(trust, "_query_handle_information", return_value=information),
            mock.patch.object(trust, "_query_final_path", return_value=os.fspath(path)),
            mock.patch.object(trust, "_query_owner_sid", return_value="S-1-5-21-123"),
            mock.patch.object(trust, "_probe_current_token_mutation_access") as access,
            mock.patch.object(trust, "_close_handle"),
        ):
            with self.assertRaises(trust.HostTrustFailure) as failure:
                trust._inspect_component(path, is_directory=True)
        self.assertEqual(failure.exception.reason, "host_chain_owner_untrusted")
        access.assert_not_called()

    def test_delete_write_dac_and_write_owner_access_each_fail_closed(self) -> None:
        path = Path(r"C:\Windows")
        for granted_right in (trust._DELETE, trust._WRITE_DAC, trust._WRITE_OWNER):
            with self.subTest(granted_right=granted_right):

                def try_open(
                    _path: Path,
                    desired_access: int,
                    _share_mode: int,
                    *,
                    expected: int = granted_right,
                ) -> tuple[int | None, int]:
                    return (71, 0) if desired_access == expected else (None, 5)

                with (
                    mock.patch.object(trust, "_try_open_handle", side_effect=try_open),
                    mock.patch.object(trust, "_close_handle") as close,
                ):
                    with self.assertRaises(trust.HostTrustFailure) as failure:
                        trust._probe_current_token_mutation_access(path, volume_root=False)
                self.assertEqual(failure.exception.reason, "host_chain_mutable_by_current_token")
                close.assert_called_once_with(71)

    def test_indeterminate_access_check_does_not_normalize_to_denied(self) -> None:
        with mock.patch.object(trust, "_try_open_handle", return_value=(None, 1234)):
            with self.assertRaises(trust.HostTrustFailure) as failure:
                trust._probe_current_token_mutation_access(Path(r"C:\Windows"), volume_root=False)
        self.assertEqual(failure.exception.reason, "host_access_check_indeterminate")

    def test_lock_rejects_file_id_change_and_closes_new_handle(self) -> None:
        path = Path(r"C:\Windows\System32\powershell.exe")
        baseline = trust._ComponentSnapshot(
            path=path,
            final_path=os.fspath(path),
            normalized_path=trust._normalize_windows_path(os.fspath(path)),
            file_id="0000000000000001:00000000000000000000000000000001",
            owner_sid="S-1-5-18",
            is_directory=False,
        )
        changed = _information(attributes=0, index=2)
        with (
            mock.patch.object(trust, "_open_handle", return_value=91),
            mock.patch.object(trust, "_query_handle_information", return_value=changed),
            mock.patch.object(
                trust,
                "_query_file_id",
                return_value="0000000000000001:00000000000000000000000000000002",
            ),
            mock.patch.object(trust, "_close_handle") as close,
        ):
            with self.assertRaises(trust.HostTrustFailure) as failure:
                trust._lock_component(baseline)
        self.assertEqual(failure.exception.reason, "host_chain_identity_unstable")
        close.assert_called_once_with(91)

    def test_signature_failure_propagates_as_closed_host_failure(self) -> None:
        path = Path(r"C:\Program Files\PowerShell\7\pwsh.exe")
        normalized = trust._normalize_windows_path(os.fspath(path))
        snapshot = trust._ComponentSnapshot(
            path=path,
            final_path=os.fspath(path),
            normalized_path=normalized,
            file_id="0000000000000001:00000000000000000000000000000001",
            owner_sid="S-1-5-18",
            is_directory=False,
        )
        lease = trust.TrustedPowerShellHosts()
        lease._host_components[trust.POWERSHELL_7_ROLE] = (normalized,)
        lease._locked[normalized] = trust._LockedComponent(snapshot, 101)
        lease._powershell_7_discovery = trust._PowerShell7Discovery(
            path=path,
            installation_profile="powershell_7_msi",
            package=None,
        )
        with (
            mock.patch.object(trust, "_sha256_file", return_value="a" * 64),
            mock.patch.object(trust, "_file_version", return_value="7.6.4.0"),
            mock.patch.object(
                trust,
                "_verify_microsoft_authenticode",
                side_effect=trust.HostTrustFailure("failed", "host_signature_invalid"),
            ),
        ):
            with self.assertRaises(trust.HostTrustFailure) as failure:
                lease._build_identity(trust.POWERSHELL_7_ROLE, path)
        self.assertEqual(failure.exception.reason, "host_signature_invalid")


if __name__ == "__main__":
    unittest.main()
