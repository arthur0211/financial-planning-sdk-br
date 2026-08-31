"""Adversarial tests for F0 schema and semantic contract controls."""

from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_contracts", REPO_ROOT / "scripts" / "validate_contracts.py"
)
assert SPEC is not None and SPEC.loader is not None
contracts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contracts)


def load(relative: str):
    return contracts.load_json(REPO_ROOT / relative)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def insert_catalog_entry(text: str, entry: str) -> str:
    marker = contracts.CATALOG_BLOCK_END
    if text.count(marker) != 1:
        raise AssertionError("catalog normative end marker must be unique in fixture")
    return text.replace(marker, entry + "\n\n" + marker, 1)


def approved_probe(root: Path, context):
    fixture = contracts.load_json(root / "tests/contracts/fixtures/approval-probe.test-only.json")
    evidence_path = root / "tests/contracts/fixtures/approval-evidence.test-only.txt"
    fingerprint = {
        "artifact_id": "test-only-approval-evidence",
        "applicability": "applicable",
        "version": "0.0.0",
        "sha256": digest(evidence_path),
    }
    attestation = {
        "bootstrap_result_sha256": context.bootstrap_result_sha256,
        "trust_policy_sha256": context.policy_sha256,
        "signer_key_fingerprint": context.signer_key_fingerprint,
    }
    evidence = {
        "evidence_id": "test-only-evidence",
        "status": "passed",
        "artifact_ref": fingerprint,
        "artifact_path": "tests/contracts/fixtures/approval-evidence.test-only.txt",
        "evaluated_at": fixture["reviewed_at"],
        "evidence_summary": fixture["evidence_summary"],
    }
    card = contracts.load_json(root / "schemas/examples/valid/model-card-research.json")
    card.update(
        {
            "test_only": True,
            "artifact_status": "approved",
            "lifecycle_status": "beta",
            "model_use_status": "approved_for_declared_use",
            "owner": fixture["owner_id"],
            "independent_reviewer": fixture["reviewer_id"],
            "validation_evidence": [evidence],
            "benchmark_protocol": {
                "protocol_id": "test-only-benchmark",
                "status": "completed",
                "preregistered_artifact": fingerprint,
                "preregistered_artifact_path": evidence["artifact_path"],
                "preregistered_at": fixture["reviewed_at"],
                "evidence_summary": fixture["evidence_summary"],
                "comparators": [
                    {
                        "comparator_id": "independent-test-comparator",
                        "comparator_kind": "independent_implementation",
                        "artifact_ref": fingerprint,
                        "artifact_path": evidence["artifact_path"],
                        "evaluated_at": fixture["reviewed_at"],
                        "evidence_summary": fixture["evidence_summary"],
                    }
                ],
            },
            "approved_at": fixture["reviewed_at"],
            "review_expires_at": fixture["review_expires_at"],
            "approval_attestation": attestation,
        }
    )
    governance = contracts.load_json(root / "schemas/examples/valid/governance-envelope-research.json")
    governance.update(
        {
            "test_only": True,
            "artifact_status": "approved",
            "model_use_status": "approved_for_declared_use",
            "policy_status": "not_applicable",
            "data_quality_status": "synthetic_only",
            "data_license_status": "no_external_data",
            "regulatory_use_status": "eligible",
            "governance_reason_codes": [],
            "human_review": {
                "required": True,
                "completed": True,
                "owner_id": fixture["owner_id"],
                "reviewer_id": fixture["reviewer_id"],
                "reviewed_at": fixture["reviewed_at"],
                "review_expires_at": fixture["review_expires_at"],
                "approval_attestation": attestation,
                "evidence": [evidence],
            },
        }
    )
    envelope = contracts.load_json(root / "schemas/examples/invalid/execution-envelope-computed-with-warnings.json")
    envelope.update({"computational_status": "computed", "governance": governance, "diagnostics": []})
    return fixture, card, governance, envelope


class ContractSemanticTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.test_runtime = Path(sys.executable)
        reason_schema = load("schemas/reason-codes.schema.json")
        cls.catalog = reason_schema["x-reason-code-catalog"]

    def test_repository_baseline_passes(self) -> None:
        self.assertEqual(contracts.validate_repository(REPO_ROOT), [])

    def test_model_approval_bypasses_are_all_rejected(self) -> None:
        card = load("schemas/examples/invalid/model-card-approval-bypasses.json")
        findings = {(code, path) for code, path, _ in contracts.model_findings(card)}
        self.assertTrue(
            {
                ("MODEL_APPROVAL_INTEGRITY_FAILED", "/independent_reviewer"),
                ("MODEL_APPROVAL_INTEGRITY_FAILED", "/review_expires_at"),
                ("MODEL_APPROVAL_INTEGRITY_FAILED", "/benchmark_protocol/status"),
                ("MODEL_APPROVAL_INTEGRITY_FAILED", "/approval_attestation"),
            }.issubset(findings)
        )

    def test_approved_governance_rejects_every_blocker_axis(self) -> None:
        envelope = load("schemas/examples/invalid/governance-envelope-approved-blockers.json")
        blocked_paths = {
            path
            for code, path, _ in contracts.governance_findings(envelope)
            if code == "GOVERNANCE_APPROVAL_BLOCKED"
        }
        self.assertEqual(
            blocked_paths,
            {
                "/model_use_status",
                "/policy_status",
                "/data_quality_status",
                "/data_license_status",
                "/regulatory_use_status",
            },
        )

        # Exact R20 bypass: promote only the use status while leaving the
        # artifact draft and the human review incomplete.
        promoted_use_only = load(
            "schemas/examples/valid/governance-envelope-research.json"
        )
        promoted_use_only["model_use_status"] = "approved_for_declared_use"
        approval_findings = {
            (code, path)
            for code, path, _ in contracts.governance_findings(promoted_use_only)
        }
        self.assertTrue(
            {
                ("GOVERNANCE_ARTIFACT_APPROVAL_REVIEW", "/model_use_status"),
                ("GOVERNANCE_ARTIFACT_APPROVAL_REVIEW", "/artifact_status"),
                (
                    "GOVERNANCE_ARTIFACT_APPROVAL_REVIEW",
                    "/human_review/completed",
                ),
            }.issubset(approval_findings),
            approval_findings,
        )
        governance_schema = load("schemas/governance-envelope.schema.json")
        inverse = next(
            branch
            for branch in governance_schema["allOf"]
            if branch.get("if", {})
            .get("properties", {})
            .get("model_use_status", {})
            .get("const")
            == "approved_for_declared_use"
        )
        self.assertEqual(
            inverse["then"]["properties"]["artifact_status"]["const"],
            "approved",
        )
        self.assertEqual(
            inverse["then"]["properties"]["human_review"]["properties"][
                "completed"
            ]["const"],
            True,
        )

    def test_derived_minimum_is_exact_not_a_permitted_floor(self) -> None:
        context = load("schemas/examples/invalid/regulatory-use-context-derived-overstated.json")
        self.assertEqual(contracts.derived_minimum_class(context), "A_RESEARCH_CORE")
        self.assertIn(
            ("REGULATED_USE_CLASS_MISMATCH", "/derived_minimum_deployment_class"),
            {(code, path) for code, path, _ in contracts.regulatory_findings(context)},
        )

        baseline = load("schemas/examples/valid/regulatory-use-context-class-a.json")
        mutations = (
            ({}, "A_RESEARCH_CORE"),
            ({"client_specific": True}, "B_PROFESSIONAL_ASSIST"),
            ({"ranking_enabled": True}, "B_PROFESSIONAL_ASSIST"),
            ({"instrument_scope": "security"}, "B_PROFESSIONAL_ASSIST"),
            ({"compensation_model": "fee_only"}, "B_PROFESSIONAL_ASSIST"),
            ({"recommendation_language_enabled": True}, "C_REGULATED_ADVICE"),
            ({"alternatives_origin": "system_generated"}, "C_REGULATED_ADVICE"),
            ({"client_specific": True, "ranking_enabled": True}, "C_REGULATED_ADVICE"),
            ({"instrument_scope": "security", "client_specific": True}, "C_REGULATED_ADVICE"),
            ({"execution_enabled": True}, "D_EXECUTION"),
        )
        for changed, expected in mutations:
            with self.subTest(changed=changed):
                candidate = copy.deepcopy(baseline)
                candidate.update(changed)
                self.assertEqual(contracts.derived_minimum_class(candidate), expected)

    def test_input_scanner_detects_pii_secret_and_decimal_budget(self) -> None:
        instance = load("schemas/examples/invalid/input-adversarial-sensitive-and-decimal.json")
        findings = contracts.semantic_findings(
            contracts.SCHEMA_IDS["input"], instance, self.catalog
        )
        observed = {(code, path) for code, path, _ in findings}
        self.assertIn(("PII_IN_PUBLIC_ARTIFACT", "/request_id"), observed)
        self.assertIn(("SECRET_IN_INPUT_OR_LOG", "/information_set/observable_ids/0"), observed)
        self.assertIn(("CONTRACT_INPUT_LIMIT_EXCEEDED", "/case/synthetic_decimal"), observed)

    def test_diagnostic_safe_context_is_scanned(self) -> None:
        diagnostic = load("schemas/examples/invalid/diagnostic-pii-context.json")
        findings = contracts.diagnostic_findings(diagnostic, self.catalog)
        self.assertIn(
            ("PII_IN_PUBLIC_ARTIFACT", "/safe_context/subject_id"),
            {(code, path) for code, path, _ in findings},
        )

    def test_size_and_depth_budgets_fail_closed(self) -> None:
        too_deep: object = "leaf"
        for _ in range(contracts.MAX_JSON_DEPTH + 1):
            too_deep = [too_deep]
        depth_codes = {code for code, _, _ in contracts.budget_findings(too_deep)}
        size_codes = {
            code
            for code, _, _ in contracts.budget_findings(
                {}, raw_size=contracts.MAX_INPUT_BYTES + 1
            )
        }
        self.assertIn("CONTRACT_INPUT_LIMIT_EXCEEDED", depth_codes)
        self.assertIn("CONTRACT_INPUT_LIMIT_EXCEEDED", size_codes)

        diagnostic = load("schemas/examples/valid/diagnostic-execution-disabled.json")
        diagnostic["safe_context"] = {
            "rounded_value": "9" * (contracts.MAX_DECIMAL_DIGITS + 1)
        }
        diagnostic_findings = contracts.diagnostic_findings(
            diagnostic, self.catalog, contracts.MAX_INPUT_BYTES + 1
        )
        diagnostic_observed = {(code, path) for code, path, _ in diagnostic_findings}
        self.assertIn(("CONTRACT_INPUT_LIMIT_EXCEEDED", ""), diagnostic_observed)
        self.assertIn(
            ("CONTRACT_INPUT_LIMIT_EXCEEDED", "/safe_context/rounded_value"),
            diagnostic_observed,
        )

        with tempfile.TemporaryDirectory(prefix="finplanbr-input-budget-") as directory:
            oversized = Path(directory) / "oversized.json"
            oversized.write_text(
                json.dumps({"padding": "x" * contracts.MAX_INPUT_BYTES}),
                encoding="utf-8",
            )
            with self.assertRaises(contracts.InputLimitError):
                contracts.load_json(oversized, max_bytes=contracts.MAX_INPUT_BYTES)

            too_deep_path = Path(directory) / "too-deep.json"
            too_deep_path.write_text(
                "[" * (contracts.MAX_JSON_DEPTH + 1)
                + "0"
                + "]" * (contracts.MAX_JSON_DEPTH + 1),
                encoding="utf-8",
            )
            with self.assertRaises(contracts.InputLimitError):
                contracts.load_json(
                    too_deep_path,
                    max_bytes=contracts.MAX_INPUT_BYTES,
                    max_depth=contracts.MAX_JSON_DEPTH,
                )

    def test_manifest_has_no_plain_input_hash_and_supports_bounded_linkability(self) -> None:
        public_manifest = load("schemas/examples/invalid/execution-envelope-computed-with-warnings.json")[
            "run_manifest"
        ]
        private_manifest = load("schemas/examples/valid/run-manifest-private.json")
        self.assertNotIn("input_sha256", public_manifest)
        self.assertEqual(public_manifest["input_reference"], {"strategy": "none"})
        self.assertEqual(private_manifest["input_reference"]["strategy"], "keyed_hmac_sha256")
        self.assertEqual(private_manifest["linkability_scope"], "single_operator")

        private_manifest["input_reference"] = {
            "strategy": "operator_local_id",
            "local_id": "52998224725",
        }
        findings = contracts.manifest_findings(private_manifest)
        self.assertIn(
            ("PII_IN_PUBLIC_ARTIFACT", "/input_reference/local_id"),
            {(code, path) for code, path, _ in findings},
        )

    def test_test_only_probes_never_yield_computed_operational_states(self) -> None:
        computed = load("schemas/examples/invalid/execution-envelope-computed-with-warnings.json")
        self.assertTrue(computed["governance"]["test_only"])
        observed = {(code, path) for code, path, _ in contracts.execution_findings(computed, self.catalog)}
        self.assertIn(("EXECUTION_STATUS_INCOHERENT", "/computational_status"), observed)
        examples = {
            load("schemas/examples/valid/execution-envelope-indeterminate.json")["computational_status"],
            load("schemas/examples/valid/execution-envelope-rejected.json")["computational_status"],
        }
        self.assertEqual(examples, {"indeterminate", "rejected"})
        self.assertEqual(
            self.catalog["NUMERIC_ROUNDING_APPLIED"]["default_status"],
            "computed_with_warnings",
        )

    def test_execution_status_cannot_hide_governance_blocker(self) -> None:
        envelope = load("schemas/examples/invalid/execution-envelope-computed-with-warnings.json")
        envelope["computational_status"] = "computed"
        envelope["governance"]["policy_status"] = "expired"
        findings = contracts.execution_findings(envelope, self.catalog)
        self.assertIn(
            ("EXECUTION_STATUS_INCOHERENT", "/computational_status"),
            {(code, path) for code, path, _ in findings},
        )

    def test_non_applicable_run_fingerprint_must_be_omitted(self) -> None:
        manifest = load("schemas/examples/valid/run-manifest-private.json")
        manifest["policy_pack"] = {
            "artifact_id": "unused-policy",
            "applicability": "not_applicable",
        }
        findings = contracts.manifest_findings(manifest)
        self.assertIn(
            ("RUN_MANIFEST_PRIVACY_INVALID", "/policy_pack/applicability"),
            {(code, path) for code, path, _ in findings},
        )

    def test_timestamp_contract_requires_rfc3339_T_and_timezone(self) -> None:
        invalid = load("schemas/examples/invalid/input-non-rfc3339-date-time.json")
        self.assertIsNone(
            contracts._parse_rfc3339(invalid["information_set"]["known_at"])
        )
        self.assertIsNotNone(contracts._parse_rfc3339("2026-01-15T12:00:00Z"))
        self.assertIsNone(contracts._parse_rfc3339("2026-02-30T12:00:00Z"))
        self.assertIsNone(contracts._parse_rfc3339("2026-01-15T12:00:00-00:00"))
        self.assertIsNone(contracts._parse_iso_date("2026-02-30"))

    def test_any_supplied_authority_context_is_refused_and_cannot_promote_approval(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-approval-r3-") as directory:
            root = Path(directory) / "repo"
            shutil.copytree(REPO_ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache"))
            context = SimpleNamespace(
                bootstrap_result_sha256="1" * 64,
                policy_sha256="2" * 64,
                signer_key_fingerprint="sha256:" + "3" * 64,
            )
            fixture, card, governance, _ = approved_probe(root, context)
            model_findings = {
                (code, path) for code, path, _ in contracts.model_findings(
                    card, context, root, fixture["evaluation_time"]
                )
            }
            governance_findings = {
                (code, path) for code, path, _ in contracts.governance_findings(
                    governance, context, root, fixture["evaluation_time"]
                )
            }
            self.assertIn(("MODEL_APPROVAL_INTEGRITY_FAILED", "/test_only"), model_findings)
            self.assertIn(("GOVERNANCE_ARTIFACT_APPROVAL_REVIEW", "/test_only"), governance_findings)
            self.assertIn(("MODEL_APPROVAL_INTEGRITY_FAILED", "/approval_attestation"), model_findings)
            self.assertIn(("GOVERNANCE_ARTIFACT_APPROVAL_REVIEW", "/human_review"), governance_findings)

    def test_digest_only_bootstrap_result_cannot_authorize_approval(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-trust-v1-rejected-") as directory:
            policy_path = Path(directory) / "legacy-trust.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "format": "financial-planning-sdk-br.release-trust-policy.v1",
                        "issued_at": "2026-08-08T00:00:00Z",
                        "expires_at": "2027-08-08T00:00:00Z",
                        "owner_id": "owner-primary",
                        "reviewer_ids": ["owner-primary", "reviewer-primary"],
                        "sha256": "1" * 64,
                    }
                ),
                encoding="utf-8",
            )
            context, failures = contracts.load_external_trust(
                REPO_ROOT,
                policy_path,
                evaluation_time="2026-08-09T12:00:00Z",
            )
            self.assertIsNone(context)
            self.assertTrue(failures)
            self.assertIn("diagnostic/draft-only", failures[0])

    def test_noncanonical_or_invalid_signed_envelope_is_refused_without_semantic_interpretation(self) -> None:
        missing = REPO_ROOT.parent / "must-not-be-opened-bootstrap-result.json"
        context, failures = contracts.load_external_trust(REPO_ROOT, missing)
        self.assertIsNone(context)
        self.assertEqual(len(failures), 1)
        self.assertIn("diagnostic/draft-only", failures[0])
        self.assertFalse(missing.exists())

    def test_fake_sitecustomize_hashlib_and_forged_ed25519_cannot_make_direct_cli_authoritative(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-contract-fake-crypto-") as directory:
            base = Path(directory)
            attacker = base / "attacker"
            attacker.mkdir()
            marker = base / "SITE_CUSTOMIZE_EXECUTED"
            (attacker / "sitecustomize.py").write_text(
                "import hashlib\n"
                f"open({str(marker)!r},'w',encoding='utf-8').write('executed')\n"
                "class FakeHash:\n"
                "    def digest(self): return b'\\0'*64\n"
                "hashlib.sha512=lambda *args,**kwargs: FakeHash()\n",
                encoding="utf-8",
            )
            forged = base / "forged.json"
            forged.write_text(" {\"format\":\"forged\"}\n", encoding="utf-8")
            environment = dict(os.environ)
            environment.update(PYTHONPATH=str(attacker), PYTHONUSERBASE=str(attacker))
            completed = subprocess.run(
                [str(self.test_runtime), str(REPO_ROOT / "scripts" / "validate_contracts.py"), "--bootstrap-result", str(forged)],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
                timeout=60,
                env=environment,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("unrecognized arguments", completed.stderr)
            self.assertTrue(marker.exists(), "probe must demonstrate that the direct runtime was attacker-controlled")
            self.assertNotIn("passed", completed.stdout.casefold())

    def test_direct_trust_shim_does_not_call_hashlib_or_open_payload_paths(self) -> None:
        original = contracts.hashlib.sha512
        contracts.hashlib.sha512 = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("hashlib must not authenticate trust"))
        try:
            context, failures = contracts.load_external_trust(REPO_ROOT, Path("Z:/nonexistent/noncanonical.json"))
        finally:
            contracts.hashlib.sha512 = original
        self.assertIsNone(context)
        self.assertEqual(len(failures), 1)
        self.assertIn("diagnostic/draft-only", failures[0])

    def test_complete_execution_matrix_uses_axes_and_catalog_defaults(self) -> None:
        warnings = load("schemas/examples/invalid/execution-envelope-computed-with-warnings.json")
        findings = {(code, path) for code, path, _ in contracts.execution_findings(warnings, self.catalog)}
        self.assertIn(("EXECUTION_STATUS_INCOHERENT", "/computational_status"), findings)
        hidden_blocker = copy.deepcopy(warnings)
        hidden_blocker["governance"]["governance_reason_codes"] = ["LEGAL_STATUS_CONTESTED"]
        findings = {(code, path) for code, path, _ in contracts.execution_findings(hidden_blocker, self.catalog)}
        self.assertIn(("EXECUTION_STATUS_INCOHERENT", "/computational_status"), findings)

        false_warning = copy.deepcopy(warnings)
        false_warning["governance"]["artifact_status"] = "approved"
        false_warning["governance"]["model_use_status"] = "approved_for_declared_use"
        false_warning["diagnostics"] = []
        findings = {(code, path) for code, path, _ in contracts.execution_findings(false_warning, self.catalog)}
        self.assertIn(("EXECUTION_STATUS_INCOHERENT", "/computational_status"), findings)

        prescriptive = copy.deepcopy(warnings)
        prescriptive["result"]["recοmmended"] = "synthetic"
        findings = {(code, path) for code, path, _ in contracts.execution_findings(prescriptive, self.catalog)}
        self.assertIn(("DEPLOYMENT_CAPABILITY_FORBIDDEN", "/result/recοmmended"), findings)

    def test_recursive_unicode_and_base64_privacy_scanner(self) -> None:
        encoded_cpf = base64.b64encode(b"529.982.247-25").decode()
        encoded_secret = base64.b64encode(b"Bearer ABCDEFGHIJKLMNOPQRST").decode()
        value = {
            "nested": [
                {"identifier": encoded_cpf},
                {"ＰΑSSWORD=abcdefgh": "synthetic"},
                {"token": encoded_secret},
            ]
        }
        observed = {(code, path) for code, path, _ in contracts.privacy_findings(value)}
        self.assertIn(("PII_IN_PUBLIC_ARTIFACT", "/nested/0/identifier"), observed)
        self.assertIn(("SECRET_IN_INPUT_OR_LOG", "/nested/1/<redacted-key>"), observed)
        self.assertIn(("SECRET_IN_INPUT_OR_LOG", "/nested/2/token"), observed)

    def test_global_parser_rejects_noncanonical_or_unbounded_numbers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finplanbr-parser-r3-") as directory:
            path = Path(directory) / "number.json"
            for literal in ("1e3", "-0", "NaN", "9" * (contracts.MAX_DECIMAL_DIGITS + 1)):
                with self.subTest(literal=literal):
                    path.write_text('{"value":' + literal + '}', encoding="utf-8")
                    with self.assertRaises(contracts.NumericLiteralError):
                        contracts.load_json(path)
        self.assertIsNone(contracts.DECIMAL_RE.fullmatch("-0"))
        self.assertIsNone(contracts.DECIMAL_RE.fullmatch("-0.0"))
        self.assertIsNone(contracts.DECIMAL_RE.fullmatch("1e3"))
        self.assertIsNotNone(contracts.DECIMAL_RE.fullmatch("-0.01"))

    def test_manifest_rejects_raw_hash_zero_hmac_and_linkability_mismatch(self) -> None:
        manifest = load("schemas/examples/valid/run-manifest-private.json")
        manifest["input_reference"] = {"strategy": "operator_local_id", "local_id": "a" * 64}
        observed = {(code, path) for code, path, _ in contracts.manifest_findings(manifest)}
        self.assertIn(("RUN_MANIFEST_PRIVACY_INVALID", "/input_reference/local_id"), observed)

        manifest["input_reference"] = {"strategy": "keyed_hmac_sha256", "key_id": "test-key", "hmac_sha256": "0" * 64}
        observed = {(code, path) for code, path, _ in contracts.manifest_findings(manifest)}
        self.assertIn(("RUN_MANIFEST_PRIVACY_INVALID", "/input_reference/hmac_sha256"), observed)

        manifest["input_reference"] = {"strategy": "none"}
        observed = {(code, path) for code, path, _ in contracts.manifest_findings(manifest)}
        self.assertIn(("RUN_MANIFEST_PRIVACY_INVALID", "/linkability_scope"), observed)

    def test_diagnostic_remediation_is_referentially_bound_to_reason_code(self) -> None:
        diagnostic = load("schemas/examples/valid/diagnostic-execution-disabled.json")
        diagnostic["remediation_id"] = "provide-required-field"
        observed = {(code, path) for code, path, _ in contracts.diagnostic_findings(diagnostic, self.catalog)}
        self.assertIn(("DIAGNOSTIC_CATALOG_MISMATCH", "/remediation_id"), observed)


class CorruptPackTotalityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="finplanbr-contracts-")
        self.named_stream_paths: list[Path] = []
        self.root = Path(self.temp_dir.name) / "repo"
        shutil.copytree(
            REPO_ROOT,
            self.root,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache"),
        )

    def tearDown(self) -> None:
        for stream_path in reversed(self.named_stream_paths):
            try:
                os.remove(os.fspath(stream_path))
            except FileNotFoundError:
                pass
            except OSError:
                # Removing the containing TEMP tree also removes its streams.
                pass
        self.temp_dir.cleanup()

    def create_named_stream(
        self,
        target: Path,
        stream_name: str,
        *,
        kind: str,
    ) -> Path:
        if os.name != "nt":
            self.skipTest("NTFS alternate data stream semantics are Windows-only")
        self.assertRegex(stream_name, r"^[a-z0-9-]+$")
        temp_root = Path(self.temp_dir.name).resolve(strict=True)
        target_resolved = target.resolve(strict=True)
        self.assertTrue(
            target_resolved == temp_root or temp_root in target_resolved.parents,
            f"ADS test target escaped disposable TEMP root: {target_resolved}",
        )
        stream_path = Path(f"{target_resolved}:{stream_name}")
        try:
            stream_path.write_bytes(b"R19 named stream probe\n")
        except OSError as exc:
            self.skipTest(f"named stream creation unavailable on TEMP filesystem: {exc}")
        self.named_stream_paths.append(stream_path)
        try:
            observed = contracts._windows_stream_snapshot(
                target_resolved,
                kind,
                "R19 TEMP ADS capability probe",
            )
        except contracts.InputLimitError as exc:
            self.skipTest(f"Win32 stream enumeration unavailable on TEMP filesystem: {exc}")
        if not any(
            name != contracts.WINDOWS_DEFAULT_DATA_STREAM
            for name, _ in (observed or ())
        ):
            self.skipTest("TEMP filesystem did not expose the created named stream as NTFS ADS")
        return stream_path

    def test_non_object_manifest_accumulates_without_exception(self) -> None:
        manifest_path = self.root / "schemas" / "conformance-manifest.json"
        manifest_path.write_text("[]\n", encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("root must be an object" in failure for failure in failures))
        self.assertTrue(any("schema_files mismatch" in failure for failure in failures))

    def test_schema_mutation_after_snapshot_uses_cached_bytes_and_fails_final_recheck(self) -> None:
        schema_path = self.root / "schemas" / "model-card.schema.json"
        attacker_payload = b'{"$id":"urn:financial-planning-sdk-br:schema:model-card:0.0.0","type":"object"}'
        mutated = False

        def swap_after_snapshot() -> None:
            nonlocal mutated
            schema_path.write_bytes(attacker_payload)
            mutated = True

        failures = contracts.validate_repository(self.root, _after_schema_snapshot=swap_after_snapshot)
        self.assertTrue(mutated)
        self.assertTrue(
            any("contract JSON path drifted after immutable diagnostic snapshot acquisition: model-card.schema.json" in failure for failure in failures),
            failures,
        )
        self.assertFalse(any("object field set must be closed" in failure and "model-card.schema.json" in failure for failure in failures))

    def test_missing_ref_fragment_accumulates_without_exception(self) -> None:
        schema_path = self.root / "schemas" / "run-manifest.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["$ref"] = (
            "urn:financial-planning-sdk-br:schema:common:0.0.0#/$defs/does-not-exist"
        )
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("unresolved local $ref fragment" in failure for failure in failures))
        self.assertTrue(any("validation could not complete" in failure for failure in failures))

    def test_duplicate_case_id_and_path_are_both_reported(self) -> None:
        manifest_path = self.root / "schemas" / "conformance-manifest.json"
        baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = copy.deepcopy(baseline)
        manifest["cases"].append(copy.deepcopy(manifest["cases"][0]))
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("duplicate case_id" in failure for failure in failures))
        self.assertTrue(any("duplicate instance_path" in failure for failure in failures))

        coordinated = copy.deepcopy(baseline)
        removed = next(
            case
            for case in coordinated["cases"]
            if case["case_id"] == "valid-run-manifest-private"
        )
        coordinated["cases"].remove(removed)
        manifest_path.write_text(json.dumps(coordinated), encoding="utf-8")
        (self.root / "schemas" / removed["instance_path"]).unlink()
        failures = contracts.validate_repository(self.root)
        self.assertTrue(
            any(
                "manifest cases differ from embedded 33-case roster" in failure
                and "valid-run-manifest-private" in failure
                for failure in failures
            ),
            failures,
        )

    def test_reason_code_ids_and_exact_metadata_reject_full_mutation_set(self) -> None:
        schema_path = self.root / "schemas" / "reason-codes.schema.json"
        baseline = json.loads(schema_path.read_text(encoding="utf-8"))
        code = "CONTRACT_SCHEMA_UNSUPPORTED"

        field_mutations = (
            ("category", "not-a-category", "category is outside the normative enum"),
            ("default_severity", "critical", "default_severity is outside the normative enum"),
            ("default_status", "computed", "default_status must be an allowed"),
            ("default_status", "approved", "default_status must be an allowed"),
            ("default_status", "unknown", "default_status must be an allowed"),
            ("owner", "", "owner must be a nonempty canonical identifier"),
            ("owner", "Contracts/Team", "owner must be a nonempty canonical identifier"),
            ("remediation_id", "", "remediation_id must be a nonempty canonical identifier"),
            ("remediation_id", "REPAIR_NOW", "remediation_id must be a nonempty canonical identifier"),
        )
        for field, value, expected in field_mutations:
            with self.subTest(field=field, value=value):
                mutated = copy.deepcopy(baseline)
                mutated["x-reason-code-catalog"][code][field] = value
                schema_path.write_text(json.dumps(mutated), encoding="utf-8")
                failures = contracts.validate_repository(self.root)
                self.assertTrue(any(expected in failure for failure in failures), failures)

        for mutation in ("missing", "extra"):
            with self.subTest(exact_fields=mutation):
                mutated = copy.deepcopy(baseline)
                metadata = mutated["x-reason-code-catalog"][code]
                if mutation == "missing":
                    metadata.pop("owner")
                else:
                    metadata["message"] = "free text is not metadata"
                schema_path.write_text(json.dumps(mutated), encoding="utf-8")
                failures = contracts.validate_repository(self.root)
                self.assertTrue(
                    any("incomplete or extra catalog metadata" in failure for failure in failures),
                    failures,
                )

        duplicated = copy.deepcopy(baseline)
        duplicated["enum"].append(code)
        schema_path.write_text(json.dumps(duplicated), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("duplicate IDs" in failure for failure in failures), failures)

        malformed_id = copy.deepcopy(baseline)
        bad_code = "CONTRACT__SCHEMA_UNSUPPORTED_"
        malformed_id["enum"][0] = bad_code
        malformed_id["x-reason-code-catalog"][bad_code] = malformed_id[
            "x-reason-code-catalog"
        ].pop(code)
        schema_path.write_text(json.dumps(malformed_id), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("not canonical closed ASCII" in failure for failure in failures), failures)

        coordinated = copy.deepcopy(baseline)
        removed_code = "AUTHORITY_CONFLICT"
        coordinated["enum"].remove(removed_code)
        coordinated["x-reason-code-catalog"].pop(removed_code)
        schema_path.write_text(json.dumps(coordinated), encoding="utf-8")
        catalog_path = self.root / "docs" / "specification" / "error-catalog.md"
        catalog_text = catalog_path.read_text(encoding="utf-8")
        catalog_path.write_text(
            catalog_text.replace(f"- `{removed_code}`\n", "", 1),
            encoding="utf-8",
        )
        failures = contracts.validate_repository(self.root)
        self.assertTrue(
            any("embedded 62-ID roster" in failure for failure in failures),
            failures,
        )
        self.assertTrue(
            any("embedded canonical digest" in failure for failure in failures),
            failures,
        )

    def test_reason_code_normative_enums_and_shared_remediation_are_closed(self) -> None:
        schema_path = self.root / "schemas" / "reason-codes.schema.json"
        baseline = json.loads(schema_path.read_text(encoding="utf-8"))
        enum_mutations = (
            ("category", "contract", "category enum must exactly match"),
            ("default_severity", "info", "default_severity enum must exactly match"),
            ("default_status", "computed", "default_status enum must be allowed"),
        )
        for field, removed_or_added, expected in enum_mutations:
            with self.subTest(normative_enum=field):
                mutated = copy.deepcopy(baseline)
                values = mutated["$defs"]["catalog_metadata"]["properties"][field]["enum"]
                if removed_or_added in values:
                    values.remove(removed_or_added)
                else:
                    values.append(removed_or_added)
                schema_path.write_text(json.dumps(mutated), encoding="utf-8")
                failures = contracts.validate_repository(self.root)
                self.assertTrue(any(expected in failure for failure in failures), failures)

        undeclared_multiplicity = copy.deepcopy(baseline)
        undeclared_multiplicity["x-reason-code-catalog"]["DATA_SCHEMA_MISMATCH"][
            "remediation_id"
        ] = "replace-data-artifact"
        schema_path.write_text(json.dumps(undeclared_multiplicity), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("shared remediation multiplicity differs" in failure for failure in failures), failures)

        broken_reference = copy.deepcopy(baseline)
        broken_reference["x-shared-remediation-ids"]["replace-data-artifact"].append(
            "MODEL_OUT_OF_SCOPE"
        )
        schema_path.write_text(json.dumps(broken_reference), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("not referentially bound" in failure for failure in failures), failures)

    def test_error_catalog_requires_exact_one_to_one_bullet_multiplicity(self) -> None:
        catalog_path = self.root / "docs" / "specification" / "error-catalog.md"
        baseline = catalog_path.read_text(encoding="utf-8")
        canonical_line = "- `CONTRACT_SCHEMA_UNSUPPORTED`"
        catalog_path.write_text(
            insert_catalog_entry(baseline, canonical_line),
            encoding="utf-8",
        )
        failures = contracts.validate_repository(self.root)
        self.assertTrue(
            any(
                "exact 1:1 bullet multiplicity" in failure
                and "CONTRACT_SCHEMA_UNSUPPORTED" in failure
                and "2" in failure
                for failure in failures
            ),
            failures,
        )

        hidden_forms = (
            ("fenced", f"```text\n{canonical_line}\n```"),
            ("commented", f"<!--\n{canonical_line}\n-->"),
        )
        for label, hidden in hidden_forms:
            with self.subTest(moved_to=label):
                moved = baseline.replace(canonical_line, hidden, 1)
                catalog_path.write_text(moved, encoding="utf-8")
                failures = contracts.validate_repository(self.root)
                self.assertTrue(
                    any(
                        "exact 1:1 bullet multiplicity" in failure
                        and "CONTRACT_SCHEMA_UNSUPPORTED" in failure
                        and "missing=" in failure
                        for failure in failures
                    ),
                    failures,
                )

    def test_error_catalog_rejects_noncanonical_known_id_bullet_candidates(self) -> None:
        catalog_path = self.root / "docs" / "specification" / "error-catalog.md"
        baseline = catalog_path.read_text(encoding="utf-8")
        canonical = "CONTRACT_SCHEMA_UNSUPPORTED"
        mutants = (
            ("asterisk marker", f"* `{canonical}`"),
            ("plus marker", f"+ `{canonical}`"),
            ("indented marker", f"  - `{canonical}`"),
            ("plain token", f"- {canonical}"),
            ("ordered item", f"1. `{canonical}`"),
            ("HTML code", f"- <code>{canonical}</code>"),
            ("lowercase", "- `contract_schema_unsupported`"),
            ("Greek omicron", "- `C\u039fNTRACT_SCHEMA_UNSUPPORTED`"),
            ("bidi Cf", "- `CONTRACT_SCHEMA_\u202eUNSUPPORTED`"),
            (
                "fullwidth",
                "- `\uff23\uff2f\uff2e\uff34\uff32\uff21\uff23\uff34\uff3f\uff33\uff23\uff28\uff25\uff2d\uff21\uff3f\uff35\uff2e\uff33\uff35\uff30\uff30\uff2f\uff32\uff34\uff25\uff24`",
            ),
        )
        for label, mutant in mutants:
            with self.subTest(mutant=label):
                catalog_path.write_text(
                    insert_catalog_entry(baseline, mutant),
                    encoding="utf-8",
                )
                failures = contracts.validate_repository(self.root)
                self.assertTrue(
                    any(
                        "exact 1:1 bullet multiplicity" in failure
                        and "noncanonical_candidates" in failure
                        and canonical in failure
                        for failure in failures
                    ),
                    failures,
                )

    def test_error_catalog_allows_known_ids_in_legitimate_prose(self) -> None:
        catalog_path = self.root / "docs" / "specification" / "error-catalog.md"
        baseline = catalog_path.read_text(encoding="utf-8")
        prose = (
            "- Esta nota compara `DATA_CHECKSUM_MISMATCH` e "
            "`DATA_SIGNATURE_INVALID` em prosa, sem criar entrada normativa."
        )
        catalog_path.write_text(
            insert_catalog_entry(baseline, prose),
            encoding="utf-8",
        )
        self.assertEqual(contracts.validate_repository(self.root), [])

    def test_example_directories_bind_expected_valid(self) -> None:
        manifest_path = self.root / "schemas" / "conformance-manifest.json"
        baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
        mutations = (
            ("examples/valid/", False, "true"),
            ("examples/invalid/", True, "false"),
        )
        for prefix, wrong_value, required_value in mutations:
            with self.subTest(prefix=prefix):
                manifest = copy.deepcopy(baseline)
                case = next(
                    item
                    for item in manifest["cases"]
                    if item["instance_path"].startswith(prefix)
                )
                case["expected_valid"] = wrong_value
                if wrong_value is False:
                    case["expected_keyword"] = "type"
                    case["expected_instance_pointer"] = ""
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                failures = contracts.validate_repository(self.root)
                self.assertTrue(
                    any(
                        f"requires expected_valid={required_value} from its examples directory"
                        in failure
                        for failure in failures
                    ),
                    failures,
                )

    def test_example_inventory_rejects_orphans_and_noncanonical_paths(self) -> None:
        valid_root = self.root / "schemas" / "examples" / "valid"
        (valid_root / "orphan-probe.json").write_text("{}\n", encoding="utf-8")
        nested_root = valid_root / "nested"
        nested_root.mkdir()
        (nested_root / "path-probe.json").write_text("{}\n", encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(
            any(
                "examples full inventory mismatch against manifest" in failure
                and "valid/orphan-probe.json" in failure
                for failure in failures
            ),
            failures,
        )
        self.assertTrue(
            any(
                "nested or out-of-contract examples entry is forbidden" in failure
                and "valid/nested/path-probe.json" in failure
                for failure in failures
            ),
            failures,
        )

    def test_example_inventory_rejects_every_entry_class_outside_contract(self) -> None:
        schemas_root = self.root / "schemas"
        examples_root = self.root / "schemas" / "examples"
        valid_root = examples_root / "valid"
        source = valid_root / "common-identifier.json"
        created_files = (
            valid_root / "unmodeled.txt",
            valid_root / "upper-extension.JSON",
            valid_root / "Uppercase-Name.json",
            valid_root / "common-identifi\u0435r.json",
            examples_root / "rogue.json",
        )
        for path in created_files:
            path.write_bytes(source.read_bytes())
        (valid_root / "empty-nested").mkdir()
        (examples_root / "extra").mkdir()
        (schemas_root / "rogue.txt").write_text("not a contract\n", encoding="utf-8")
        nested_rogue = schemas_root / "nested-rogue"
        nested_rogue.mkdir()
        (nested_rogue / "rogue.json").write_text("{}\n", encoding="utf-8")

        failures = contracts.validate_repository(self.root)
        output = "\n".join(failures)
        for relative in (
            "valid/unmodeled.txt",
            "valid/upper-extension.JSON",
            "valid/Uppercase-Name.json",
            "valid/common-identifi\u0435r.json",
            "valid/empty-nested",
            "extra",
            "rogue.json",
            "rogue.txt",
            "nested-rogue",
            "nested-rogue/rogue.json",
        ):
            self.assertIn(relative, output)
        self.assertIn("canonical ASCII lowercase *.json", output)
        self.assertIn("nested or empty examples directory", output)
        self.assertIn("top-level entry is forbidden", output)
        self.assertIn("Unicode/case aliases", output)
        self.assertIn("examples full inventory mismatch against manifest", output)
        self.assertIn("schemas full inventory mismatch against embedded roster", output)

    def test_example_hardlink_is_rejected_by_nlink(self) -> None:
        target = self.root / "schemas" / "common.schema.json"
        link = self.root / "schemas" / "hardlink-probe.schema.json"
        try:
            os.link(target, link)
        except OSError as exc:
            self.skipTest(f"hardlink creation unavailable: {exc}")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("nlink=1" in failure for failure in failures), failures)

    def test_example_inventory_mutation_after_snapshot_fails_final_recheck(self) -> None:
        late_path = self.root / "schemas" / "late-probe.txt"

        def add_after_snapshot() -> None:
            late_path.write_text("late\n", encoding="utf-8")

        failures = contracts.validate_repository(
            self.root, _after_schema_snapshot=add_after_snapshot
        )
        self.assertTrue(
            any("schemas full inventory drifted after immutable" in failure for failure in failures),
            failures,
        )

    def test_preexisting_named_stream_on_examples_root_is_rejected(self) -> None:
        targets = (
            (self.root, "repository root", "r20-repo-root", "directory"),
            (self.root / "schemas", "schemas root", "r20-schemas-root", "directory"),
            (
                self.root / "schemas" / "common.schema.json",
                "schemas/common.schema.json",
                "r20-schema-file",
                "regular_file",
            ),
        )
        for target, _label, stream_name, kind in targets:
            self.create_named_stream(target, stream_name, kind=kind)
        failures = contracts.validate_repository(self.root)
        output = "\n".join(failures)
        for _target, label, stream_name, _kind in targets:
            self.assertIn(
                f"{label} contains forbidden named or non-default streams",
                output,
            )
            self.assertIn(stream_name, output)

    def test_stream_snapshot_covers_root_directories_entries_and_api_errors(self) -> None:
        examples_root = self.root / "schemas" / "examples"
        snapshot = contracts._snapshot_example_inventory(examples_root)
        actual_entries: set[str] = set()
        for current, directory_names, file_names in os.walk(
            examples_root,
            followlinks=False,
        ):
            current_path = Path(current)
            for name in [*directory_names, *file_names]:
                actual_entries.add(
                    (current_path / name).relative_to(examples_root).as_posix()
                )
        self.assertEqual(set(snapshot.entries), actual_entries)
        self.assertIn("valid", snapshot.entries)
        self.assertIn("invalid", snapshot.entries)

        if os.name != "nt":
            self.assertIsNone(snapshot.root_streams)
            self.assertTrue(
                all(entry.streams is None for entry in snapshot.entries.values())
            )
            return

        self.assertIsNotNone(snapshot.root_streams)
        for relative, entry in snapshot.entries.items():
            with self.subTest(relative=relative):
                self.assertIsNotNone(entry.streams)
                if entry.kind == "regular_file":
                    self.assertEqual(
                        entry.streams,
                        ((contracts.WINDOWS_DEFAULT_DATA_STREAM, entry.size),),
                    )
        with self.assertRaisesRegex(
            contracts.InputLimitError,
            "FindFirstStreamW",
        ):
            contracts._windows_stream_snapshot(
                examples_root / "missing-r19-probe.json",
                "regular_file",
                "missing R19 probe",
            )

    @unittest.skipUnless(os.name == "nt", "NTFS alternate data stream semantics are Windows-only")
    def test_named_stream_inserted_after_snapshot_fails_final_recheck(self) -> None:
        target = (
            self.root
            / "schemas"
            / "examples"
            / "valid"
            / "common-identifier.json"
        )

        def add_stream_after_snapshot() -> None:
            self.create_named_stream(
                target,
                "r19-late",
                kind="regular_file",
            )

        failures = contracts.validate_repository(
            self.root,
            _after_schema_snapshot=add_stream_after_snapshot,
        )
        self.assertTrue(
            any(
                "examples full inventory drifted after immutable diagnostic snapshot acquisition"
                in failure
                for failure in failures
            ),
            failures,
        )

    def test_manifest_instance_path_must_be_canonical(self) -> None:
        manifest_path = self.root / "schemas" / "conformance-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["cases"][0]["instance_path"] = (
            "examples/valid/./regulatory-use-context-class-a.json"
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(
            any(
                "instance_path must be a canonical examples/valid or examples/invalid JSON path"
                in failure
                for failure in failures
            ),
            failures,
        )

    def test_unused_ref_cycle_is_detected(self) -> None:
        schema_path = self.root / "schemas" / "common.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["$defs"]["unused_cycle_a"] = {"$ref": "#/$defs/unused_cycle_b"}
        schema["$defs"]["unused_cycle_b"] = {"$ref": "#/$defs/unused_cycle_a"}
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("$ref cycle detected" in failure for failure in failures))

    def test_schema_id_uri_alias_is_rejected(self) -> None:
        source = self.root / "schemas" / "common.schema.json"
        alias = json.loads(source.read_text(encoding="utf-8"))
        alias["$id"] = "urn:financial-planning-sdk-br:schema:comm%6fn:0.0.0"
        alias_path = self.root / "schemas" / "alias.schema.json"
        alias_path.write_text(json.dumps(alias), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(
            any(
                "alias.schema.json" in failure
                and ("invalid schema" in failure or "embedded roster" in failure)
                for failure in failures
            ),
            failures,
        )
        self.assertTrue(any("embedded roster" in failure for failure in failures), failures)

        alias_path.unlink()
        manifest_path = self.root / "schemas" / "conformance-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        removed_schema = "model-card.schema.json"
        removed_id = contracts.SCHEMA_IDS["model"]
        manifest["schema_files"].remove(removed_schema)
        removed_cases = [
            case for case in manifest["cases"] if case["schema_id"] == removed_id
        ]
        manifest["cases"] = [
            case for case in manifest["cases"] if case["schema_id"] != removed_id
        ]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        (self.root / "schemas" / removed_schema).unlink()
        for case in removed_cases:
            (self.root / "schemas" / case["instance_path"]).unlink()
        failures = contracts.validate_repository(self.root)
        self.assertTrue(
            any("filesystem schema files mismatch against embedded roster" in failure for failure in failures),
            failures,
        )
        self.assertTrue(
            any("manifest cases differ from embedded 33-case roster" in failure for failure in failures),
            failures,
        )

    def test_unicode_prescriptive_property_and_open_object_are_rejected(self) -> None:
        schema_path = self.root / "schemas" / "execution-envelope.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["$defs"] = {
            "adversarial_open_result": {
                "type": "object",
                "properties": {"recοmmended": {"type": "string"}},
            },
            "allOf": {
                "type": "object",
                "properties": {"probe": {"type": "string"}},
            },
            "then": {
                "type": "object",
                "properties": {"probe": {"type": "string"}},
            },
            "object_via_properties": {
                "properties": {"probe": {"type": "string"}},
            },
        }
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        failures = contracts.validate_repository(self.root)
        self.assertTrue(any("forbidden prescriptive property" in failure for failure in failures))
        output = "\n".join(failures)
        for pointer in (
            "/$defs/adversarial_open_result",
            "/$defs/allOf",
            "/$defs/then",
            "/$defs/object_via_properties",
        ):
            self.assertIn(
                f"{pointer}: object field set must be closed",
                output,
            )

    def test_fixture_symlink_is_rejected_without_traceback(self) -> None:
        target = self.root / "schemas" / "examples" / "valid" / "common-identifier.json"
        link = self.root / "schemas" / "examples" / "valid" / "symlink-fixture.json"
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        failures = contracts.validate_repository(self.root)
        output = "\n".join(failures)
        self.assertIn("symlink/junction/reparse", output)
        self.assertNotIn("Traceback", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
