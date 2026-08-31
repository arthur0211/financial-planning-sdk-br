import inspect
import tempfile
import unittest
from pathlib import Path

from scripts import windows_appcontainer_child_probe as probe


class WindowsAppContainerChildProbeTests(unittest.TestCase):
    def test_request_and_lineage_frames_bind_format_role_and_canonical_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-child-protocol-") as directory:
            root = Path(directory).resolve()
            request_path = root / "request.json"
            request = {
                "appcontainer_sid": "S-1-15-2-1",
                "decoy_canary_sha256": "a" * 64,
                "decoy_handle": "101",
                "format": probe.REQUEST_FORMAT,
                "lan_host": "172.29.60.71",
                "lan_port": 55123,
                "loopback_host": "127.0.0.1",
                "loopback_port": 55124,
                "nonce": "b" * 32,
                "permitted_canary_sha256": "c" * 64,
                "permitted_handle": "102",
                "probe_source": str(root / "probe.py"),
                "protected_root": str(root / "protected"),
                "request_path": str(request_path),
                "runtime_root": str(root / "runtime"),
                "scratch_root": str(root / "scratch"),
                "source_root": str(root / "source"),
            }
            request_path.write_bytes(probe._canonical_json(request))
            self.assertEqual(probe._read_request(request_path), request)

            request["format"] = "finplanbr.windows-appcontainer-child-request.v2"
            request_path.write_bytes(probe._canonical_json(request))
            with self.assertRaisesRegex(probe.ProbeFailure, "request_format_invalid"):
                probe._read_request(request_path)

            lineage_path = root / "child.json"
            lineage = {"format": probe.REPORT_FORMAT, "role": "child"}
            lineage_path.write_bytes(probe._canonical_json(lineage))
            self.assertEqual(probe._wait_for(lineage_path, "child"), lineage)
            with self.assertRaisesRegex(probe.ProbeFailure, "lineage_report_protocol_invalid"):
                probe._wait_for(lineage_path, "grandchild")

    def test_root_process_cannot_touch_credited_external_endpoint_before_preflight(self) -> None:
        root_source = inspect.getsource(probe._run_root)
        network_arm_source = inspect.getsource(probe._run_network_arm)

        self.assertNotIn('request["lan_host"]', root_source)
        self.assertNotIn('request["lan_port"]', root_source)
        self.assertIn('request["loopback_host"]', root_source)
        self.assertIn('request["lan_host"]', network_arm_source)
        self.assertIn('request["lan_port"]', network_arm_source)

    def test_native_helper_orders_preflight_before_bracketed_abba(self) -> None:
        source = (
            Path(__file__).parents[2]
            / "scripts"
            / "windows_appcontainer_helper"
            / "Program.cs"
        ).read_text(encoding="utf-8")
        markers = (
            "PreflightNetworkDifferentialResult preflight = RunNetworkPreflight(",
            "SortedDictionary<string, object?> lanControlBefore =",
            "out rootProcess",
            "FullNetworkDifferentialResult fullNetwork = RunFullNetworkDifferential(",
            "SortedDictionary<string, object?> lanControlAfter =",
        )
        offsets = [source.index(marker) for marker in markers]
        self.assertEqual(offsets, sorted(offsets))


if __name__ == "__main__":
    unittest.main()
