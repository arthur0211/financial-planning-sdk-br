from __future__ import annotations

import contextlib
import hashlib
import importlib
import importlib.util
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from copy import deepcopy
from decimal import Decimal, getcontext
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "scripts" / "validate_math_vectors.py"
VECTOR_ROOT = ROOT / "tests" / "vectors" / "math" / "v1"
HERE = Path(__file__).parent
ORACLE_MANIFEST = HERE / "oracle_bundle_manifest.json"
SPEC = importlib.util.spec_from_file_location("validate_math_vectors", RUNNER_PATH)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)
sys.path.insert(0, str(HERE))
import independent_oracle  # noqa: E402
import property_suite  # noqa: E402
import reference_adapter  # noqa: E402


class MathConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors, errors = runner.load_vectors(VECTOR_ROOT, False)
        if errors: raise AssertionError(errors)
        cls.by_id = {vector["id"]: vector for vector in cls.vectors}
        cls.worker = HERE / "module_worker.py"

    def validate_copy(self, vector_id: str, mutation) -> list[str]:
        vector = deepcopy(self.by_id[vector_id]); mutation(vector)
        return runner.validate_vector(vector, Path("probe.json"), False)

    def command(self, code: str, **limits) -> runner.CommandSut:
        return runner.CommandSut([str(Path(sys.executable).resolve()), "-c", code], **limits)

    def module(self, specification: str = "reference_adapter:compute", root: Path = HERE, **limits) -> runner.ModuleSut:
        return runner.ModuleSut(specification, root, self.worker, **limits)

    def copy_corpus(self, directory: str) -> Path:
        target = Path(directory) / "v1"; shutil.copytree(VECTOR_ROOT, target); return target

    def mutation_bundle(self, directory: str, policy: str = "strict") -> tuple[Path, str, dict]:
        root = Path(directory)
        base = root / "base_adapter.py"; mutant = root / "mutant_adapter.py"; operator = root / "math_mutants.py"
        shutil.copy2(HERE / "reference_adapter.py", base); shutil.copy2(HERE / "reference_adapter.py", mutant); shutil.copy2(HERE / "math_mutants.py", operator)
        executable = Path(sys.executable)
        installed_executable = Path(sys.prefix) / executable.name
        if installed_executable.is_file(): executable = installed_executable
        executable_pin = {"path": str(executable.absolute()), "sha256": runner.sha256_file(executable)}
        manifest = {
            "manifest_format": runner.SUT_MUTANTS_FORMAT,
            "association_statement": "declared_by_manifest_not_verified_ownership",
            "execution_failure_policy": policy,
            "base_artifact": {"path": base.name, "sha256": runner.sha256_file(base)},
            "base_launcher": {"kind": "python_script", "python_executable": executable_pin, "arguments": []},
            "mutants": [{
                "id": "declared-abs", "operator_id": "absolute-value-substitution",
                "operator_artifact": {"path": operator.name, "sha256": runner.sha256_file(operator)},
                "mutant_artifact": {"path": mutant.name, "sha256": runner.sha256_file(mutant)},
                "launcher": {"kind": "python_script", "python_executable": executable_pin, "arguments": ["--mutant", "pv_absolute_cashflow"]},
            }],
        }
        path = root / "mutants.json"; path.write_text(json.dumps(manifest), encoding="utf-8")
        return path, runner.sha256_file(path), manifest

    def test_duplicate_keys_decimal_canonicalization_and_tolerance(self) -> None:
        with self.assertRaisesRegex(runner.ConformanceError, "duplicate JSON key"): runner.load_json_strict('{"id":"one","id":"two"}', "duplicate")
        for invalid in ("1e2", "-0.00", "NaN"):
            with self.assertRaises(runner.ConformanceError): runner.decimal(invalid, "probe")
        self.assertTrue(runner.close_enough("1001.5", "1000", Decimal("0.5"), Decimal("0.001"), "metric"))
        self.assertFalse(runner.close_enough("1001.5001", "1000", Decimal("0.5"), Decimal("0.001"), "metric"))

    def test_units_are_closed_per_field_and_brl_probability_is_rejected(self) -> None:
        errors = self.validate_copy("pv-unit-cashflow", lambda vector: vector["units"].__setitem__("input.cash_flow_amount", "BRL_probability"))
        self.assertTrue(any("exact unit" in error or "not a recognized" in error for error in errors), errors)
        errors = self.validate_copy("pv-unit-cashflow", lambda vector: vector["units"].__setitem__("input.cash_flow_amount", "BRL_at_close"))
        self.assertTrue(any("exact unit" in error for error in errors), errors)

    def test_every_numeric_anti_oracle_has_an_exact_unit(self) -> None:
        for vector in self.vectors:
            anti_numeric = set(runner.numeric_leaf_paths(vector.get("anti_oracles", {}), "anti_oracles"))
            for path in anti_numeric:
                declarations = [unit for pattern, unit in vector["units"].items() if runner.pattern_matches(pattern, path)]
                self.assertEqual(1, len(declarations), (vector["id"], path))
        errors = self.validate_copy("reserve-plan-vs-replan", lambda vector: vector["units"].pop("anti_oracles.planned_reserve_with_look_ahead"))
        self.assertTrue(any("exactly one unit" in error for error in errors), errors)

    def test_domain_validation_is_total_for_missing_fields(self) -> None:
        errors = self.validate_copy("reserve-plan-vs-replan", lambda vector: vector["input"]["plan_information_at_t0"].pop("state_probabilities"))
        self.assertTrue(any("state_probabilities" in error and "missing" in error for error in errors), errors)
        malformed = deepcopy(self.by_id["reserve-plan-vs-replan"]); malformed["input"]["plan_information_at_t0"] = None
        errors = runner.validate_domain_semantics(malformed)
        self.assertIsInstance(errors, list)

    def test_alpha_discount_and_lot_ranges_fail_closed(self) -> None:
        alpha = self.validate_copy("cvar-discrete-enumerable", lambda vector: vector["input"].__setitem__("alpha", "1"))
        discount = self.validate_copy("pv-unit-cashflow", lambda vector: vector["input"].__setitem__("discount_factor", "-0.8"))
        sold = self.validate_copy("tax-lot-simple", lambda vector: vector["input"]["sale"].__setitem__("quantity", "11"))
        self.assertTrue(any("0 < alpha < 1" in error for error in alpha), alpha)
        self.assertTrue(any("greater than zero" in error for error in discount), discount)
        self.assertTrue(any("sold <= lot quantity" in error for error in sold), sold)

    def test_dates_ages_probabilities_accounts_and_decimals_fail_closed(self) -> None:
        reversed_dates = self.validate_copy("pv-unit-cashflow", lambda vector: vector["input"].__setitem__("payment_date", "2025-01-01"))
        age = self.validate_copy("couple-deterministic-mortality", lambda vector: vector["input"].__setitem__("age_a_at_valuation", "131"))
        probability = self.validate_copy("couple-four-states", lambda vector: vector["input"].__setitem__("survival_probability_a", "1.01"))
        account = self.validate_copy("tax-lot-simple", lambda vector: vector["input"].__setitem__("account_id", "../escape"))
        malformed_decimal = self.validate_copy("pv-unit-cashflow", lambda vector: vector["input"].__setitem__("cash_flow_amount", "not-a-decimal"))
        self.assertTrue(any("strictly increasing" in error for error in reversed_dates), reversed_dates)
        self.assertTrue(any("age must be" in error for error in age), age)
        self.assertTrue(any("probability must be" in error for error in probability), probability)
        self.assertTrue(any("invalid account" in error for error in account), account)
        self.assertTrue(any("canonical decimal" in error for error in malformed_decimal), malformed_decimal)

    def test_all_fifteen_spec_cases_map_exactly_eighteen_vectors_plus_three_supplemental(self) -> None:
        manifest = json.loads((VECTOR_ROOT / "manifest.json").read_text(encoding="utf-8"))
        mappings = {row["case_id"]: [binding["vector_id"] for binding in row["vector_bindings"]] for row in manifest["spec_case_mapping"]}
        mapped = {vector_id for vector_ids in mappings.values() for vector_id in vector_ids}
        supplemental = {entry["id"] for entry in manifest["vectors"] if entry["spec_case_id"] is None}
        self.assertEqual({str(index) for index in range(1, 16)}, set(mappings))
        self.assertEqual(21, len(manifest["vectors"]))
        self.assertEqual(18, len(mapped))
        self.assertEqual(runner.SUPPLEMENTAL_IDS, supplemental)
        self.assertEqual(runner.REQUIRED_IDS - runner.SUPPLEMENTAL_IDS, mapped)
        self.assertIn("constant-contribution-closed-form", mappings["5"])
        self.assertIn("couple-deterministic-mortality", mappings["8"])
        self.assertEqual({"tax-lot-no-tax", "tax-lot-simple"}, set(mappings["9"]))
        self.assertIn("contribution-all-at-r", mappings["15"])

    def test_cvar_boundary_tax_counterfactual_and_variable_couple_outputs(self) -> None:
        cvar = self.by_id["cvar-discrete-enumerable"]
        self.assertEqual(["0.50", "0.30", "0.10", "0.10"], [row["probability"] for row in cvar["input"]["scenarios"]])
        self.assertEqual("0.80", cvar["input"]["alpha"]); self.assertEqual("60.00", cvar["expected_output"]["tail_expected_shortfall"])
        taxed, untaxed = self.by_id["tax-lot-simple"], self.by_id["tax-lot-no-tax"]
        self.assertEqual(taxed["input"]["account_id"], untaxed["input"]["account_id"])
        self.assertEqual(taxed["input"]["lot"], untaxed["input"]["lot"]); self.assertEqual(taxed["input"]["sale"], untaxed["input"]["sale"])
        outputs=[]
        for horizon in ("2028-01-01", "2031-01-01", "2033-01-01"):
            req=runner.make_request(self.by_id["couple-deterministic-mortality"]); req["input"]["horizon_date"]=horizon; outputs.append(reference_adapter.compute(req)["output"]["household_state"])
        self.assertEqual(3, len(set(outputs)))

    def test_oracle_registry_and_per_vector_validation_types_match_manifest(self) -> None:
        self.assertEqual(runner.ORACLE_DERIVATION_METHODS, independent_oracle.DERIVATION_METHOD_IDS)
        self.assertEqual([], runner.cross_check_independent_oracle(self.vectors, HERE))
        source = (HERE / "independent_oracle.py").read_text(encoding="utf-8")
        self.assertNotIn("elif vector_id", source)
        self.assertGreaterEqual(len(set(independent_oracle.DERIVATION_METHOD_IDS.values())), 20)
        boundary=runner.make_request(self.by_id["cvar-discrete-enumerable"]); boundary["input"]["alpha"]="0.85"
        first,second=reference_adapter.compute(boundary),independent_oracle.compute(boundary)
        self.assertEqual([],runner.compare_values(first,second,Decimal("1e-40"),Decimal(0),"response"))
        manifest = json.loads((VECTOR_ROOT / "manifest.json").read_text(encoding="utf-8"))
        for entry in manifest["vectors"]:
            self.assertEqual(2, len(entry["validation_methods"]), entry["id"])
            self.assertEqual(list(runner.VALIDATION_METHODS_BY_VECTOR[entry["id"]]), entry["validation_methods"])
            self.assertTrue({method["validation_type"] for method in entry["validation_methods"]} <= runner.VALIDATION_TYPES)

    def test_closed_validation_route_rejects_wrapper_import_repin_and_source_reuse(self) -> None:
        original_digest = runner.sha256_file(ORACLE_MANIFEST)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "conformance"
            shutil.copytree(HERE, root, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            manifest_path = root / ORACLE_MANIFEST.name
            independent_path = root / "independent_oracle.py"
            wrapper = (
                "from reference_adapter import compute\n"
                f"DERIVATION_METHOD_IDS = {runner.ORACLE_DERIVATION_METHODS!r}\n"
            )
            independent_path.write_text(wrapper, encoding="utf-8")
            with self.assertRaisesRegex(runner.ConformanceError, "SHA-256 mismatch"):
                runner.load_validation_route_bundle(manifest_path, None, False)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = next(item for item in manifest["source_sets"]["validation"] if item["path"] == "independent_oracle.py")
            entry["sha256"] = runner.sha256_file(independent_path)
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(runner.ConformanceError, "external SHA-256 pin"):
                runner.load_validation_route_bundle(manifest_path, original_digest, True)
            with self.assertRaisesRegex(runner.ConformanceError, "static boundary|reference_adapter"):
                runner.load_validation_route_bundle(manifest_path, None, False)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "conformance"
            shutil.copytree(HERE, root, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            manifest_path = root / ORACLE_MANIFEST.name
            independent_path = root / "independent_oracle.py"
            independent_path.write_bytes((root / "reference_adapter.py").read_bytes())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = next(item for item in manifest["source_sets"]["validation"] if item["path"] == "independent_oracle.py")
            entry["sha256"] = runner.sha256_file(independent_path)
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(runner.ConformanceError, "reuse identical source bytes"):
                runner.load_validation_route_bundle(manifest_path, None, False)

    def test_validation_routes_execute_from_disjoint_private_roots(self) -> None:
        bundle = runner.load_validation_route_bundle(ORACLE_MANIFEST, None, False)
        prepared = runner.prepare_validation_routes(bundle, (5.0, 1_048_576, 65_536, "forbid"))
        try:
            self.assertNotEqual(prepared.reference_sut.module_root, prepared.validation_sut.module_root)
            self.assertNotEqual(HERE.resolve(), prepared.reference_sut.module_root)
            self.assertNotEqual(HERE.resolve(), prepared.validation_sut.module_root)
            self.assertEqual([], runner.cross_check_validation_routes(self.vectors[:1], prepared.reference_sut, prepared.validation_sut))
            prepared.recheck()
        finally:
            prepared.close()

    def test_validation_response_cache_is_canonical_read_only_and_checks_repeatability(self) -> None:
        class CountingSut(runner.Sut):
            def __init__(self, nondeterministic=False):
                self.calls = 0
                self.nondeterministic = nondeterministic

            def compute(self, request):
                self.calls += 1
                return {"value": str(self.calls) if self.nondeterministic else str(request["a"])}

        requests = [{"b": 2, "a": 1}, {"a": 3}]
        deterministic = CountingSut()
        cache = runner.FrozenValidationSut(deterministic, requests, [{"a": 1, "b": 2}])
        self.assertEqual(3, deterministic.calls)
        self.assertEqual(2, cache.cache_entries)
        self.assertEqual(1, cache.repeatability_checks)
        first = cache.compute({"a": 1, "b": 2})
        first["value"] = "mutated-by-caller"
        self.assertEqual({"value": "1"}, cache.compute({"b": 2, "a": 1}))
        with self.assertRaisesRegex(runner.ConformanceError, "outside the precomputed"):
            cache.compute({"a": 99})
        with self.assertRaisesRegex(runner.ConformanceError, "nondeterministic"):
            runner.FrozenValidationSut(CountingSut(nondeterministic=True), requests, [requests[0]])

    def test_property_coverage_is_exact_by_family_not_a_generic_count(self) -> None:
        evaluation = runner.evaluate_sut(self.module(), self.vectors, True)
        self.assertEqual([], evaluation.all_errors())
        self.assertEqual(property_suite.PROPERTY_FAMILIES | {"civil-date-domain"}, set(evaluation.property_counts))
        self.assertEqual(runner.REQUIRED_IDS, property_suite.PROPERTY_FAMILIES)
        self.assertTrue(all(count >= 2 for count in evaluation.property_counts.values()), evaluation.property_counts)

    def test_portfolio_properties_use_inputs_outside_golden_fixture(self) -> None:
        fixtures = {vector["id"]: vector for vector in self.vectors}
        portfolio_inputs = [req["input"] for family, _, req in property_suite.generated_requests(fixtures) if family == "portfolio-two-asset-convex"]
        self.assertTrue(any(row["variance_a"] == "0.04" and row["variance_b"] == "0.09" and row["covariance_ab"] == "0" for row in portfolio_inputs))
        self.assertNotEqual("0", self.by_id["portfolio-two-asset-convex"]["input"]["covariance_ab"])

    def test_seeded_property_grids_kill_all_six_r4_survivors(self) -> None:
        expected_families = {
            "annuity_ignores_payments_after_two": "finite-annuity-certain",
            "death_at_horizon_is_alive": "couple-deterministic-mortality",
            "tax_loss_creates_credit": "tax-lot-simple",
            "portfolio_clips_weights": "portfolio-two-asset-convex",
            "cvar_ignores_scenarios": "cvar-discrete-enumerable",
            "contribution_uses_frozen_factors": "contribution-all-at-r",
        }
        fixtures = {vector["id"]: vector for vector in self.vectors}
        for mutant, family in expected_families.items():
            _, errors = property_suite.run(lambda request, name=mutant: reference_adapter.compute(request, name), independent_oracle.compute, fixtures)
            self.assertTrue(any(f"property {family}:" in error for error in errors), (mutant, errors))
        self.assertEqual(20260809, property_suite.PROPERTY_GRID_SEED)

    def test_full_response_grid_kills_one_fresh_stale_field_mutant_per_vector_without_crash(self) -> None:
        fixtures = {vector["id"]: vector for vector in self.vectors}

        def mutate_output(output: dict) -> None:
            def mutate(container) -> bool:
                if isinstance(container, dict):
                    for key in sorted(container):
                        value = container[key]
                        if isinstance(value, (dict, list)):
                            if mutate(value):
                                return True
                        elif isinstance(value, bool):
                            container[key] = not value
                            return True
                        elif isinstance(value, str) and property_suite.DECIMAL_TEXT.fullmatch(value):
                            container[key] = format(Decimal(value) + Decimal("1"), "f")
                            return True
                        elif isinstance(value, str):
                            container[key] = value + "_stale"
                            return True
                elif isinstance(container, list):
                    for index, value in enumerate(container):
                        if isinstance(value, (dict, list)):
                            if mutate(value):
                                return True
                        elif isinstance(value, str):
                            container[index] = value + "_stale"
                            return True
                return False

            self.assertTrue(mutate(output), output)

        # Each mutant preserves its golden vector and corrupts only generated
        # requests, matching the fresh external-style R5 survivor pattern.
        for family in sorted(runner.REQUIRED_IDS):
            def stale_compute(req, target=family):
                response = reference_adapter.compute(req)
                if req["id"] == target and req["input"] != fixtures[target]["input"]:
                    mutate_output(response["output"])
                return response

            _, errors = property_suite.run(stale_compute, independent_oracle.compute, fixtures)
            self.assertTrue(any(f"property {family}:" in error and "full-response" in error for error in errors), (family, errors))

    def test_exact_identity_sentinel_kills_shared_four_factor_annuity_bug(self) -> None:
        fixtures = {vector["id"]: vector for vector in self.vectors}

        def shared_bug(req):
            response = reference_adapter.compute(req)
            if req["id"] == "finite-annuity-certain" and len(req["input"]["discount_factors"]) >= 4:
                payment = Decimal(req["input"]["payment_amount"])
                response["output"]["present_value"] = format(
                    payment * sum((Decimal(value) for value in req["input"]["discount_factors"][:3]), Decimal(0)),
                    "f",
                )
            return response

        _, errors = property_suite.run(shared_bug, shared_bug, fixtures)
        self.assertTrue(any("finite-annuity exact-identity sentinel" in error for error in errors), errors)

    def test_spec_mapping_rejects_semantic_swaps_and_duplicate_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_corpus(directory)
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            first, second = manifest["spec_case_mapping"][0], manifest["spec_case_mapping"][1]
            first["vector_bindings"], second["vector_bindings"] = second["vector_bindings"], first["vector_bindings"]
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            _, errors = runner.load_vectors(root, False)
            self.assertTrue(any("semantic binding" in error or "not allowed" in error for error in errors), errors)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_corpus(directory)
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            manifest["spec_case_mapping"][1]["vector_bindings"] = deepcopy(manifest["spec_case_mapping"][0]["vector_bindings"])
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            _, errors = runner.load_vectors(root, False)
            self.assertTrue(any("duplicated across" in error or "semantic binding" in error for error in errors), errors)

    def test_manifest_fails_vector_without_two_declared_validation_methods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_corpus(directory)
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["vectors"][0]["validation_methods"] = manifest["vectors"][0]["validation_methods"][:1]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _, errors = runner.load_vectors(root, False)
        self.assertTrue(any("exactly two methods" in error for error in errors), errors)

    def test_wrong_json_field_types_return_diagnostics_without_traceback(self) -> None:
        probes = (
            ("pv-unit-cashflow", lambda value: value.__setitem__("id", [])),
            ("pv-unit-cashflow", lambda value: value.__setitem__("topic", 7)),
            ("pv-unit-cashflow", lambda value: value["input"].__setitem__("cash_flow_amount", True)),
            ("cvar-discrete-enumerable", lambda value: value["input"].__setitem__("scenarios", "wrong")),
            ("tax-lot-simple", lambda value: value["input"].__setitem__("lot", [])),
            ("two-stage-nonanticipativity", lambda value: value["expected_output"]["implementable_policy"].__setitem__("nonanticipativity_satisfied", "true")),
            ("pv-unit-cashflow", lambda value: value.__setitem__("tolerance", [])),
        )
        for vector_id, mutate in probes:
            value = deepcopy(self.by_id[vector_id]); mutate(value)
            errors = runner.validate_vector(value, Path("wrong-type.json"), False)
            self.assertTrue(errors, vector_id)
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_corpus(directory)
            vector_path = root / "pv-unit-cashflow.json"
            value = json.loads(vector_path.read_text(encoding="utf-8")); value["id"] = []
            vector_path.write_text(json.dumps(value), encoding="utf-8")
            _, errors = runner.load_vectors(root, False)
            self.assertTrue(errors)
        with tempfile.TemporaryDirectory() as directory:
            path, _, manifest = self.mutation_bundle(directory)
            manifest["execution_failure_policy"] = []
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(runner.ConformanceError): runner.load_sut_mutation_manifest(path, runner.sha256_file(path))
            with self.assertRaises(runner.ConformanceError): runner.load_sut_mutation_manifest(path, [])  # type: ignore[arg-type]

    def test_vector_root_symlink_or_junction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "linked-root"
            created = False
            if os.name == "nt":
                completed = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(VECTOR_ROOT)], capture_output=True, check=False)
                created = completed.returncode == 0
            else:
                os.symlink(VECTOR_ROOT, link, target_is_directory=True); created = True
            if not created: self.skipTest("reparse-root creation unavailable")
            try: _, errors = runner.load_vectors(link, False)
            finally:
                if link.exists(): link.rmdir()
        self.assertTrue(any("reparse" in error or "symlink" in error for error in errors), errors)

    def test_reparse_entry_is_rejected_before_recursion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_corpus(directory); target = Path(directory) / "target"; target.mkdir(); (target / "decoy.json").write_text("{}", encoding="utf-8")
            link = root / "junction-entry"; created = False
            if os.name == "nt":
                completed = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False); created = completed.returncode == 0
            else:
                os.symlink(target, link, target_is_directory=True); created = True
            if not created: self.skipTest("reparse-entry creation unavailable")
            try: _, errors = runner.load_vectors(root, False)
            finally:
                if link.exists(): link.rmdir()
        self.assertTrue(any("reparse" in error or "symlink" in error for error in errors), errors)

    def test_corpus_rejects_hardlinked_manifest_vector_and_reparse_ancestor(self) -> None:
        for relative in ("manifest.json", "pv-unit-cashflow.json"):
            with tempfile.TemporaryDirectory() as directory:
                root = self.copy_corpus(directory)
                target = root / relative
                source = Path(directory) / f"source-{relative}"
                shutil.copy2(target, source)
                target.unlink()
                try:
                    os.link(source, target)
                except OSError:
                    self.skipTest("hardlink creation unavailable")
                _, errors = runner.load_vectors(root, False)
            self.assertTrue(any("hardlinked" in error or "nlink" in error for error in errors), (relative, errors))

        with tempfile.TemporaryDirectory() as directory:
            real_parent = Path(directory) / "real"
            real_parent.mkdir()
            self.copy_corpus(str(real_parent))
            linked_parent = Path(directory) / "linked"
            if os.name == "nt":
                created = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(linked_parent), str(real_parent)], capture_output=True).returncode == 0
            else:
                os.symlink(real_parent, linked_parent, target_is_directory=True)
                created = True
            if not created:
                self.skipTest("reparse ancestor creation unavailable")
            try:
                _, errors = runner.load_vectors(linked_parent / "v1", False)
            finally:
                if linked_parent.is_symlink():
                    linked_parent.unlink()
                elif linked_parent.exists():
                    linked_parent.rmdir()
        self.assertTrue(any("ancestor" in error or "reparse" in error or "junction" in error for error in errors), errors)

    def test_manifest_path_traversal_and_recursive_orphans_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root=self.copy_corpus(directory); manifest=json.loads((root/"manifest.json").read_text()); manifest["vectors"][0]["path"]="../escape.json"; (root/"manifest.json").write_text(json.dumps(manifest),encoding="utf-8"); _,errors=runner.load_vectors(root,False)
            self.assertTrue(any("path traversal" in error for error in errors), errors)
        with tempfile.TemporaryDirectory() as directory:
            root=self.copy_corpus(directory); nested=root/"nested"; nested.mkdir(); (nested/"decoy.json").write_text("{}",encoding="utf-8"); _,errors=runner.load_vectors(root,False)
            self.assertTrue(any("unregistered JSON" in error for error in errors), errors)

    def test_module_runs_in_subprocess_without_decimal_context_side_effect(self) -> None:
        original = getcontext().prec
        try:
            getcontext().prec = 37
            response = self.module().compute(runner.make_request(self.by_id["contribution-all-at-r"]))
            self.assertEqual("computed", response["computational_status"])
            self.assertEqual(37, getcontext().prec)
            importlib.reload(reference_adapter)
            self.assertEqual(37, getcontext().prec)
        finally: getcontext().prec = original

    def test_module_hash_seed_is_repeatable_without_isolated_mode_ignoring_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hash_probe.py").write_text(
                "def compute(request):\n return {'hash': str(hash(('alpha','beta','gamma')))}\n",
                encoding="utf-8",
            )
            sut = self.module("hash_probe:compute", root)
            observed = [sut.compute({})["hash"] for _ in range(8)]
        self.assertEqual(1, len(set(observed)), observed)
        self.assertIn("-P", sut.command)
        self.assertIn("-s", sut.command)
        self.assertNotIn("-I", sut.command)

    def test_module_timeout_and_streaming_limits_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/"slow.py").write_text("import time\ndef compute(request):\n time.sleep(1)\n return {}\n",encoding="utf-8")
            with self.assertRaisesRegex(runner.SutTimeoutError,"timed out"): self.module("slow:compute",root,timeout_seconds=0.05).compute({})
            (root/"loud.py").write_text("print('x'*10000)\ndef compute(request): return {}\n",encoding="utf-8")
            with self.assertRaisesRegex(runner.SutNonviableError,"stdout exceeds"): self.module("loud:compute",root,stdout_limit=128).compute({})
        with self.assertRaises(runner.SutTimeoutError): self.command("import time;time.sleep(2)",timeout_seconds=0.05).compute({"large":"x"*2_000_000})
        with self.assertRaisesRegex(runner.SutNonviableError, "stdout exceeds"):
            self.command(
                "import sys,time;sys.stdin.read();sys.stdout.buffer.write(b'x'*129);sys.stdout.flush();time.sleep(30)",
                timeout_seconds=1,
                stdout_limit=128,
            ).compute({})

    def test_command_rejects_nonfinite_or_nonexact_limits(self) -> None:
        for timeout in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaisesRegex(runner.ConformanceError, "finite"):
                self.command("pass", timeout_seconds=timeout)
        with self.assertRaisesRegex(runner.ConformanceError, "exact integers"):
            self.command("pass", stdout_limit=True)

    def test_command_uses_isolated_cwd_environment_and_reports_network_honestly(self) -> None:
        code="import json,os,sys;sys.stdin.read();print(json.dumps({'cwd':os.getcwd(),'home':os.environ.get('HOME')}))"
        response=self.command(code).compute({})
        self.assertNotEqual(ROOT.resolve(),Path(response["cwd"]).resolve()); self.assertEqual(Path(response["cwd"]).resolve(),Path(response["home"]).resolve())
        output=io.StringIO()
        with contextlib.redirect_stdout(output): code=runner.main(["--reference","--skip-properties","--skip-reference-sensitivity"])
        report = output.getvalue()
        self.assertEqual(0,code); self.assertIn("network_isolation=not_enforced",report)
        self.assertIn("Math corpus/reference self-check PASSED", report)
        self.assertIn("sut_conformance_status=not_evaluated", report)
        self.assertIn("reference_adapter_mutation_score not_evaluated", report)
        self.assertNotIn("Math conformance PASSED", report)

    def test_self_check_json_report_has_closed_non_conformance_contract(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = runner.main(["--self-check", "--skip-properties", "--skip-reference-sensitivity", "--output-format", "json"])
        self.assertEqual(0, code)
        report = json.loads(output.getvalue())
        self.assertEqual({
            "report_format", "status", "execution_mode", "sut_conformance_status", "authority", "failure",
            "counts", "oracle_boundary", "isolation", "validation_subject", "declared_validation_types",
        }, set(report))
        self.assertEqual("financial-planning-sdk-br.math-conformance-report.v1", report["report_format"])
        self.assertEqual("self_check_passed", report["status"])
        self.assertEqual("corpus_reference_self_check", report["execution_mode"])
        self.assertEqual("not_evaluated", report["sut_conformance_status"])
        self.assertEqual("technical_validation_only_not_release_authority", report["authority"])
        self.assertIsNone(report["failure"])
        self.assertEqual({
            "vectors", "normative_bindings", "supplemental_vectors", "property_families", "property_checks",
            "reference_fixture_sensitivity", "reference_adapter_mutation", "sut_mutation",
        }, set(report["counts"]))
        self.assertEqual((21, 18, 3), (report["counts"]["vectors"], report["counts"]["normative_bindings"], report["counts"]["supplemental_vectors"]))
        self.assertFalse(report["counts"]["sut_mutation"]["evaluated"])
        self.assertEqual({
            "status", "evidence", "digest_provenance", "digest_authentication", "manifest_sha256",
            "source_set_counts", "validation_cache", "execution",
        }, set(report["oracle_boundary"]))
        self.assertEqual("static_checks_passed", report["oracle_boundary"]["status"])
        self.assertEqual("static_boundary_not_proof", report["oracle_boundary"]["evidence"])
        self.assertEqual("repository_local_untrusted", report["oracle_boundary"]["digest_provenance"])
        self.assertEqual("not_provided", report["oracle_boundary"]["digest_authentication"])
        self.assertEqual({"reference": 2, "validation": 11, "harness": 2}, report["oracle_boundary"]["source_set_counts"])
        self.assertEqual({"entries": 21, "repeatability_checks": 3}, report["oracle_boundary"]["validation_cache"])
        self.assertEqual("validation_precomputed_by_separate_subprocess_disjoint_private_roots", report["oracle_boundary"]["execution"])
        self.assertEqual("best_effort_same_process_group_daemon_escape_possible", report["isolation"]["process_tree_posix"])

    def test_sut_mode_without_externally_pinned_mutation_manifest_fails_before_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "sut-started"
            command = json.dumps([sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).write_text('bad')"])
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = runner.main(["--sut-command", command, "--skip-properties", "--skip-reference-sensitivity"])
            self.assertEqual(2, code)
            self.assertFalse(marker.exists())
            self.assertIn("mutation status cannot be not_evaluated", stderr.getvalue())
            self.assertNotIn("PASSED", stderr.getvalue())

    def test_timeout_kills_process_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/"child-survived.txt"
            child=f"import time,pathlib;time.sleep(1.0);pathlib.Path({str(marker)!r}).write_text('bad')"
            parent=f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child!r}]);time.sleep(5)"
            with self.assertRaises(runner.SutTimeoutError): self.command(parent,timeout_seconds=0.05).compute({})
            time.sleep(1.3)
            self.assertFalse(marker.exists())

    def test_candidate_stderr_is_digest_bound_but_never_published(self) -> None:
        secret = "candidate-private-environment-value"
        candidate = self.command(
            f"import sys;sys.stdin.read();sys.stderr.write({secret!r});raise SystemExit(7)"
        )
        with self.assertRaises(runner.SutCrashError) as captured:
            candidate.compute({})
        message = str(captured.exception)
        self.assertIn(f"stderr_bytes={len(secret.encode())}", message)
        self.assertIn(f"stderr_sha256={hashlib.sha256(secret.encode()).hexdigest()}", message)
        self.assertNotIn(secret, message)

    def test_successful_parent_cannot_leave_child_holding_pipes_or_escape_job(self) -> None:
        def process_exists(process_id: int) -> bool:
            if os.name != "nt":
                try:
                    os.kill(process_id, 0)
                except ProcessLookupError:
                    return False
                except PermissionError:
                    return True
                return True
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.restype = wintypes.HANDLE
            handle = kernel32.OpenProcess(0x00100000, False, process_id)  # SYNCHRONIZE
            if not handle:
                return False
            try:
                return kernel32.WaitForSingleObject(handle, 0) == 0x00000102  # WAIT_TIMEOUT
            finally:
                kernel32.CloseHandle(handle)

        with tempfile.TemporaryDirectory() as directory:
            escaped = Path(directory) / "success-child-escaped.txt"
            child = f"import time,pathlib;time.sleep(2);pathlib.Path({str(escaped)!r}).write_text('escaped')"
            parent = (
                "import json,subprocess,sys;"
                "sys.stdin.read();"
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}]);"
                "print(json.dumps({'pid':child.pid}),flush=True)"
            )
            response = self.command(parent).compute({})
            child_pid = int(response["pid"])
            deadline = time.monotonic() + 5
            while process_exists(child_pid) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(process_exists(child_pid), f"descendant {child_pid} still alive")
            self.assertFalse(escaped.exists())

    @unittest.skipIf(os.name == "nt", "POSIX setsid escape is covered on Ubuntu CI")
    def test_posix_setsid_daemon_escape_is_reproduced_and_claimed_best_effort(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "daemon.pid"
            child = f"import os,time,pathlib;os.setsid();pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()));time.sleep(30)"
            parent = (
                "import json,pathlib,subprocess,sys,time;sys.stdin.read();"
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                "time.sleep(0.2);"
                "print(json.dumps({'vector_id':'probe','computational_status':'computed','output':{'pid':str(child.pid)}}),flush=True)"
            )
            response = self.command(parent).compute({})
            daemon_pid = int(response["output"]["pid"])
            try:
                os.kill(daemon_pid, 0)
            except ProcessLookupError:
                self.fail("setsid descendant was unexpectedly contained by same-process-group best effort")
            finally:
                try:
                    os.kill(daemon_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.assertTrue(pid_file.exists())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = runner.main(["--self-check", "--skip-properties", "--skip-reference-sensitivity"])
        self.assertEqual(0, code)
        self.assertIn("process_tree_posix=best_effort_same_process_group", output.getvalue())
        self.assertIn("daemon_escape=possible", output.getvalue())

    def test_process_tree_termination_never_uses_path_taskkill(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        boundary_source = (ROOT / "scripts" / "bounded_subprocess.py").read_text(encoding="utf-8")
        combined = source + boundary_source
        self.assertNotIn('subprocess.run(["taskkill"', combined)
        self.assertIn("AssignProcessToJobObject", boundary_source)
        self.assertIn("os.killpg", boundary_source)
        self.assertIn("run_bounded", source)

    def test_external_write_is_possible_and_is_reported_honestly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "outside.txt"
            code = f"import json,pathlib,sys;sys.stdin.read();pathlib.Path({str(marker)!r}).write_text('written');print(json.dumps({{}}))"
            self.command(code).compute({})
            self.assertTrue(marker.exists())
        output = io.StringIO()
        with contextlib.redirect_stdout(output): result = runner.main(["--reference", "--skip-properties", "--skip-reference-sensitivity"])
        self.assertEqual(0, result)
        self.assertIn("filesystem_isolation=not_enforced", output.getvalue())

    def test_mutation_manifest_requires_external_digest_before_sut_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/"sut-started"; command=json.dumps([sys.executable,"-c",f"from pathlib import Path;Path({str(marker)!r}).write_text('bad')"])
            path,digest,_=self.mutation_bundle(directory)
            stderr=io.StringIO()
            with contextlib.redirect_stderr(stderr): code=runner.main(["--sut-command",command,"--sut-mutants-manifest",str(path)])
            self.assertEqual(2,code); self.assertFalse(marker.exists()); self.assertIn("supplied together",stderr.getvalue())
            with self.assertRaisesRegex(runner.ConformanceError,"external lowercase SHA-256"): runner.load_sut_mutation_manifest(path,None)
            with self.assertRaisesRegex(runner.ConformanceError,"external SHA-256 pin"): runner.load_sut_mutation_manifest(path,"0"*64)

    def test_mutation_manifest_hashes_base_mutant_operator_and_rechecks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path,digest,manifest=self.mutation_bundle(directory); pinned=runner.load_sut_mutation_manifest(path,digest); self.assertEqual(5,len(pinned.pins)); pinned.recheck()
            self.assertIsInstance(pinned.manifest_snapshot, bytes)
            self.assertEqual(digest, hashlib.sha256(pinned.manifest_snapshot).hexdigest())
            for block_path in (manifest["base_artifact"]["path"],manifest["mutants"][0]["mutant_artifact"]["path"],manifest["mutants"][0]["operator_artifact"]["path"]):
                target=Path(directory)/block_path; original=target.read_bytes(); target.write_bytes(original+b"\n# tamper")
                with self.assertRaisesRegex(runner.ConformanceError,"hash changed"): pinned.recheck()
                target.write_bytes(original)

    def test_mutation_manifest_hash_and_parse_use_the_same_single_handle_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, digest, _ = self.mutation_bundle(directory)
            with mock.patch.object(Path, "read_text", side_effect=AssertionError("manifest path was reopened for parsing")):
                pinned = runner.load_sut_mutation_manifest(path, digest)
        self.assertEqual(digest, hashlib.sha256(pinned.manifest_snapshot).hexdigest())

    def test_mutation_manifest_rejects_hardlinks_and_junction_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, _, _ = self.mutation_bundle(directory)
            source = Path(directory) / "manifest-source.json"
            shutil.copy2(path, source)
            path.unlink()
            try:
                os.link(source, path)
            except OSError:
                self.skipTest("hardlink creation unavailable")
            with self.assertRaisesRegex(runner.ConformanceError, "hardlink|nlink"):
                runner.load_sut_mutation_manifest(path, runner.sha256_file(path))
        with tempfile.TemporaryDirectory() as directory:
            path, _, manifest = self.mutation_bundle(directory)
            target = Path(directory) / manifest["mutants"][0]["mutant_artifact"]["path"]
            hardlink = Path(directory) / "hardlinked-mutant.py"
            try: os.link(target, hardlink)
            except OSError: self.skipTest("hardlink creation unavailable")
            manifest["mutants"][0]["mutant_artifact"] = {"path": hardlink.name, "sha256": runner.sha256_file(hardlink)}
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(runner.ConformanceError, "hardlink|nlink"): runner.load_sut_mutation_manifest(path, runner.sha256_file(path))
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real"; real.mkdir(); path, _, _ = self.mutation_bundle(str(real))
            linked = Path(directory) / "linked"; created = False
            if os.name == "nt":
                created = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(linked), str(real)], capture_output=True).returncode == 0
            else:
                os.symlink(real, linked, target_is_directory=True); created = True
            if not created: self.skipTest("junction creation unavailable")
            try:
                with self.assertRaisesRegex(runner.ConformanceError, "ancestor|reparse|junction"): runner.load_sut_mutation_manifest(linked / path.name, runner.sha256_file(path))
            finally:
                if linked.exists(): linked.rmdir()

    def test_mutation_snapshot_detects_swap_restore_and_executes_declared_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, digest, manifest = self.mutation_bundle(directory)
            pinned = runner.load_sut_mutation_manifest(path, digest)
            prepared = runner.prepare_mutation_run(pinned, (5.0, 1_048_576, 65_536, "forbid"))
            try:
                response = prepared.base_sut.compute(runner.make_request(self.by_id["pv-unit-cashflow"]))
                self.assertEqual("computed", response["computational_status"])
                target = Path(directory) / manifest["mutants"][0]["mutant_artifact"]["path"]
                original = target.read_bytes(); target.write_bytes(b"raise SystemExit(99)\n"); target.write_bytes(original)
                with self.assertRaisesRegex(runner.ConformanceError, "identity/hash changed"): prepared.recheck()
            finally: prepared.close()

    def test_base_not_executed_and_crash_only_mutants_fail_strict_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, _, manifest = self.mutation_bundle(directory)
            base = Path(directory) / manifest["base_artifact"]["path"]
            base.write_text("raise SystemExit(12)\n", encoding="utf-8")
            manifest["base_artifact"]["sha256"] = runner.sha256_file(base)
            path.write_text(json.dumps(manifest), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr): code = runner.main(["--reference", "--sut-mutants-manifest", str(path), "--sut-mutants-manifest-sha256", runner.sha256_file(path), "--skip-properties", "--skip-reference-sensitivity"])
            self.assertEqual(1, code); self.assertIn("sut_mutation_base", stderr.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            path, _, manifest = self.mutation_bundle(directory)
            mutant = Path(directory) / manifest["mutants"][0]["mutant_artifact"]["path"]
            mutant.write_text("raise SystemExit(9)\n", encoding="utf-8")
            manifest["mutants"][0]["mutant_artifact"]["sha256"] = runner.sha256_file(mutant)
            manifest["mutants"][0]["launcher"]["arguments"] = []
            path.write_text(json.dumps(manifest), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr): code = runner.main(["--reference", "--sut-mutants-manifest", str(path), "--sut-mutants-manifest-sha256", runner.sha256_file(path), "--skip-properties", "--skip-reference-sensitivity"])
            self.assertEqual(1, code); self.assertIn("crash cannot satisfy strict score", stderr.getvalue())

    def test_externally_pinned_manifest_reports_semantic_score_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path,digest,_=self.mutation_bundle(directory); output=io.StringIO()
            with contextlib.redirect_stdout(output):
                command=json.dumps([sys.executable,str(HERE/"reference_adapter.py")])
                code=runner.main(["--sut-command",command,"--sut-mutants-manifest",str(path),"--sut-mutants-manifest-sha256",digest,"--oracle-bundle-manifest-sha256",runner.sha256_file(ORACLE_MANIFEST),"--skip-properties","--skip-reference-sensitivity"])
        self.assertEqual(0,code); report=output.getvalue(); self.assertIn("sut_mutation_score 1/1 killed policy=strict",report); self.assertIn("semantic_kill=1",report); self.assertIn("association=declared_not_verified",report)
        self.assertIn("Math SUT conformance PASSED", report)

    def test_mutation_manifest_confines_paths_and_rejects_reparse_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path,_,manifest=self.mutation_bundle(directory); outside=Path(directory).parent/"outside-mutant.py"; outside.write_text("pass",encoding="utf-8")
            try:
                manifest["mutants"][0]["mutant_artifact"]={"path":"../outside-mutant.py","sha256":runner.sha256_file(outside)}; path.write_text(json.dumps(manifest),encoding="utf-8"); digest=runner.sha256_file(path)
                with self.assertRaisesRegex(runner.ConformanceError,"confined"): runner.load_sut_mutation_manifest(path,digest)
            finally: outside.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory() as directory:
            path,_,manifest=self.mutation_bundle(directory); target=Path(directory)/manifest["mutants"][0]["mutant_artifact"]["path"]; link=Path(directory)/"linked-mutant.py"
            try: os.symlink(target,link)
            except OSError: self.skipTest("symlink creation unavailable")
            manifest["mutants"][0]["mutant_artifact"]={"path":link.name,"sha256":runner.sha256_file(target)}; path.write_text(json.dumps(manifest),encoding="utf-8"); digest=runner.sha256_file(path)
            with self.assertRaisesRegex(runner.ConformanceError,"reparse|symlink"): runner.load_sut_mutation_manifest(path,digest)

    def test_mutation_categories_are_separate_and_scoring_policy_is_explicit(self) -> None:
        semantic=runner.evaluate_sut(runner.CommandSut([sys.executable,str(HERE/"reference_adapter.py"),"--mutant","pv_absolute_cashflow"]),self.vectors,False,True)
        self.assertEqual("semantic_kill",semantic.mutation_category())
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); shutil.copy2(HERE/"reference_adapter.py",root/"reference_adapter.py"); shutil.copy2(HERE/"math_mutants.py",root/"math_mutants.py")
            (root/"assertion_mutant.py").write_text("import reference_adapter\ndef compute(request):\n r=reference_adapter.compute(request)\n if request['id']=='portfolio-two-asset-convex' and request['input']['covariance_ab']=='0': r['output']['weight_a']='0'\n return r\n",encoding="utf-8")
            assertion=runner.evaluate_sut(self.module("assertion_mutant:compute",root),self.vectors,True,True)
        self.assertEqual("assertion_kill",assertion.mutation_category())
        crash=runner.evaluate_sut(self.command("raise SystemExit(7)"),self.vectors[:1],False,True)
        timeout=runner.evaluate_sut(self.command("import time;time.sleep(1)",timeout_seconds=0.03),self.vectors[:1],False,True)
        nonviable=runner.evaluate_sut(self.command("print('not-json')"),self.vectors[:1],False,True)
        self.assertEqual("crash",crash.mutation_category()); self.assertEqual("timeout",timeout.mutation_category()); self.assertEqual("nonviable",nonviable.mutation_category())
        results={"semantic_kill":["s"],"assertion_kill":["a"],"crash":["c"],"timeout":["t"],"nonviable":["n"],"survived":[]}
        self.assertIn("2/5",runner.mutation_score_text(results,"strict",True)); self.assertIn("not_evaluated",runner.mutation_score_text(results,"strict",False))

    def test_internal_sensitivity_crash_is_reported_and_fails_global_gate(self) -> None:
        categories = runner.empty_mutation_categories()
        categories["crash"].append("fresh-crash-only")
        stderr = io.StringIO()
        with mock.patch.object(runner, "run_reference_fixture_sensitivity", return_value=categories):
            with contextlib.redirect_stderr(stderr):
                code = runner.main(["--reference", "--skip-properties"])
        self.assertEqual(1, code)
        report = stderr.getvalue()
        self.assertIn("crash cannot satisfy sensitivity gate", report)
        self.assertIn("crash=1", report)
        self.assertNotIn("1/1 killed", report)

    def test_manifest_disclaims_ownership_and_workflow_tracks_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path,digest,_=self.mutation_bundle(directory); pinned=runner.load_sut_mutation_manifest(path,digest); self.assertIsNotNone(pinned)
            self.assertNotIn("ownership",json.loads(path.read_text(encoding="utf-8")))
            self.assertEqual("declared_by_manifest_not_verified_ownership",json.loads(path.read_text(encoding="utf-8"))["association_statement"])
        workflow=(ROOT/".github"/"workflows"/"math-conformance.yml").read_text(encoding="utf-8")
        for trigger in (
            "docs/specification/mathematical-engine.md",
            "scripts/bounded_subprocess.py",
            "scripts/validate_math_vectors.*",
            "tests/conformance/**",
            "tests/vectors/math/**",
        ):
            self.assertIn(trigger, workflow)
        self.assertIn("network_isolation",workflow); self.assertIn("external SHA-256 pin",workflow); self.assertIn("never treated as proven ownership",workflow)


if __name__ == "__main__": unittest.main()
