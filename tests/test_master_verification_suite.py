"""
Master Verification Suite for VITAL IDE Complete Repair
Tests all 10 requirements:
  Test 1: Semantic persistence
  Test 2: Security persistence & fixture protection
  Test 3: Ollama AI structured remediation
  Test 4: Parser regression & delimiter validation
  Test 5: Fix All with multiple errors
  Test 6: Partial Fix All success
  Test 7: Fix All across distinct compiler stages
  Test 8: Source recovery (Undo & Restore Original)
  Test 9: Mandatory IR Optimization
  Test 10: Final Report Gate Blocking
"""

import unittest
import os
import sys
import json
import hashlib

# Ensure root is on path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.working_source_manager import WorkingSourceManager
from web.ai_remediation_engine import AIRemediationEngine, DiagnosticNormalizer, StageValidator
from web.ir_optimizer import IROptimizer
from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker
from web.server import create_app


class TestMasterVerificationSuite(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.test_rel_path = "examples/security_lab/english/sec_auth_account.vital"
        self.abs_path = os.path.join(PROJECT_ROOT, self.test_rel_path)

    # -------------------------------------------------------------------------
    # TEST 1: Semantic Persistence
    # -------------------------------------------------------------------------
    def test_01_semantic_persistence(self):
        """Verify semantic analysis error fix persists to disk and revalidation passes."""
        # Clean any prior working copy
        WorkingSourceManager.restore_original(self.test_rel_path)

        with open(self.abs_path, "r", encoding="utf-8") as f:
            original_code = f.read()

        # Step 1: Run pipeline - Semantic Analysis must fail on undeclared identifier 'acc_status'
        tracker1 = PipelineRunTracker()
        execute_pipeline_with_tracker(original_code, "English", run_ai_security=False, tracker=tracker1, pause_on_error=True)
        td1 = tracker1.to_dict()
        sem_stage1 = next(s for s in td1["stages"] if s["id"] == "semantic_analysis")
        self.assertEqual(sem_stage1["status"], "failed", "Semantic Analysis should fail on original fixture")

        # Step 2: Apply semantic correction
        diags = [{
            "id": "SEM-001",
            "stage_id": "semantic_analysis",
            "stage": "Semantic Analysis",
            "title": "Identifier 'acc_status' referenced before assignment",
            "line": 48,
            "column": 5,
            "code_excerpt": "if acc_status == 1 {",
            "evidence": "acc_status",
            "rule_id": "SEM-UNDECLARED-VAR"
        }]

        fix_res = AIRemediationEngine.generate_stage_remediation(
            stage_id="semantic_analysis",
            source_code=original_code,
            language="English",
            diagnostic=diags[0],
            use_ai=False
        )
        self.assertTrue(fix_res.get("success"), f"Fix generation failed: {fix_res.get('error')}")
        proposed_code = fix_res.get("proposed_source")
        self.assertNotEqual(original_code, proposed_code)

        # Step 3: Persist corrected source to disk via WorkingSourceManager
        save_res = WorkingSourceManager.save_working_copy(
            self.test_rel_path,
            proposed_code,
            label="Fix acc_status reference"
        )
        self.assertTrue(save_res.get("success"))
        self.assertTrue(save_res.get("is_modified"))
        self.assertGreaterEqual(save_res.get("source_revision", 0), 2)

        # Step 4: Verify disk persistence by reading back
        wc = WorkingSourceManager.get_working_copy(self.test_rel_path)
        self.assertEqual(wc.get("working_source"), proposed_code)

        # Step 5: Recompile with persisted working source - Semantic Analysis must now pass!
        tracker2 = PipelineRunTracker()
        execute_pipeline_with_tracker(wc["working_source"], "English", run_ai_security=False, tracker=tracker2, pause_on_error=True)
        td2 = tracker2.to_dict()
        sem_stage2 = next(s for s in td2["stages"] if s["id"] == "semantic_analysis")
        self.assertEqual(sem_stage2["status"], "completed", f"Semantic Analysis should pass after fix: {sem_stage2.get('summary')}")

    # -------------------------------------------------------------------------
    # TEST 2: Security Persistence & Demo Fixture Immutability
    # -------------------------------------------------------------------------
    def test_02_security_persistence_and_demo_immutability(self):
        """Verify original demo fixture in examples/ is NEVER modified by fixes."""
        with open(self.abs_path, "r", encoding="utf-8") as f:
            original_code = f.read()
        orig_hash = hashlib.sha256(original_code.encode("utf-8")).hexdigest()

        # Save an edit to the working copy
        test_edit = original_code + "\n// Temporary test modification\n"
        WorkingSourceManager.save_working_copy(self.test_rel_path, test_edit, label="Security fix test")

        # Verify disk working copy has the edit
        wc = WorkingSourceManager.get_working_copy(self.test_rel_path)
        self.assertTrue(wc.get("is_modified"))
        self.assertEqual(wc.get("working_source"), test_edit)

        # CRITICAL ASSERTION: The original demo fixture file must NOT have changed!
        with open(self.abs_path, "r", encoding="utf-8") as f:
            post_check_code = f.read()
        post_hash = hashlib.sha256(post_check_code.encode("utf-8")).hexdigest()
        self.assertEqual(orig_hash, post_hash, "Original demo fixture was modified on disk! It must remain immutable.")

        # Clean up working copy back to original
        WorkingSourceManager.restore_original(self.test_rel_path)

    # -------------------------------------------------------------------------
    # TEST 3: Ollama AI Remediation Engine
    # -------------------------------------------------------------------------
    def test_03_ollama_remediation_structure_and_validation(self):
        """Verify remediation engine returns structured data with dry-run validation."""
        code = "let x = 10\nlet sum = x + y\nprint(sum)\n"
        diag = {
            "id": "SEM-002",
            "stage_id": "semantic_analysis",
            "stage": "Semantic Analysis",
            "title": "Identifier 'y' referenced before assignment",
            "line": 2,
            "column": 15,
            "code_excerpt": "let sum = x + y",
            "evidence": "y",
            "rule_id": "SEM-UNDECLARED-VAR"
        }

        # Test deterministic / fallback remediation (and AI if available)
        res = AIRemediationEngine.generate_stage_remediation(
            stage_id="semantic_analysis",
            source_code=code,
            language="English",
            diagnostic=diag,
            use_ai=False
        )

        self.assertTrue(res.get("success"), "Remediation generation failed")
        self.assertIn("proposed_source", res)
        self.assertIn("diff", res)
        self.assertIn("explanation", res)
        self.assertIn("root_cause", res)
        self.assertIn("safety", res)

        # Validate that the proposed source actually resolves the error
        val = StageValidator.validate_stage("semantic_analysis", res["proposed_source"], "English")
        self.assertTrue(val.get("passed"), f"Dry run validation failed: {val.get('error')}")

    # -------------------------------------------------------------------------
    # TEST 4: Parser Regression & Delimiter Validation
    # -------------------------------------------------------------------------
    def test_04_parser_regression_and_delimiter_checks(self):
        """Verify grammar-aware delimiter checking handles strings, comments, and nesting."""
        # 1. Clean file sec_auth_account.vital should be 100% balanced
        with open(self.abs_path, "r", encoding="utf-8") as f:
            auth_code = f.read()
        res_auth = DiagnosticNormalizer.analyze_delimiters(auth_code)
        self.assertTrue(res_auth["is_balanced"], f"sec_auth_account should be balanced: {res_auth}")
        self.assertEqual(res_auth["open_braces"], res_auth["close_braces"])

        # 2. String containing braces and comments with braces must NOT corrupt delimiter counts
        code_with_strings = (
            "let msg = \"{This is in string}\"\n"
            "// comment with { and } and (\n"
            "/* block comment with { } */\n"
            "if 1 == 1 {\n"
            "    print(\"Hello {World}\")\n"
            "}\n"
        )
        res_strings = DiagnosticNormalizer.analyze_delimiters(code_with_strings)
        self.assertTrue(res_strings["is_balanced"], f"Delimiter count corrupted by strings/comments: {res_strings}")
        self.assertEqual(res_strings["open_braces"], 1)
        self.assertEqual(res_strings["close_braces"], 1)

        # 3. Code with an actual missing brace must be flagged accurately
        unbalanced_code = "if 1 == 1 {\n    print(\"Unclosed\")\n"
        res_unbal = DiagnosticNormalizer.analyze_delimiters(unbalanced_code)
        self.assertFalse(res_unbal["is_balanced"])
        self.assertEqual(len(res_unbal["unclosed_braces"]), 1)

        # 4. Multilingual programs: check Hindi, Bengali, Telugu, Marathi, Nepali
        for lang_folder in ["bengali", "hindi", "marathi", "nepali", "telugu"]:
            folder = os.path.join(PROJECT_ROOT, "examples", lang_folder)
            for fname in os.listdir(folder):
                if fname.endswith(".vital"):
                    with open(os.path.join(folder, fname), "r", encoding="utf-8") as lf:
                        lcode = lf.read()
                    lres = DiagnosticNormalizer.analyze_delimiters(lcode)
                    self.assertTrue(lres["is_balanced"], f"Delimiter imbalance in {lang_folder}/{fname}: {lres}")

    # -------------------------------------------------------------------------
    # TEST 5: Fix All with Multiple Errors in a Stage
    # -------------------------------------------------------------------------
    def test_05_fix_all_multiple_errors(self):
        """Verify Fix All resolves all safely fixable errors in a stage in one batch operation."""
        # Code with 2 undeclared variables in Semantic stage
        multi_error_code = (
            "let a = 1\n"
            "let sum1 = a + missing_one\n"
            "let sum2 = sum1 + missing_two\n"
            "print(sum2)\n"
        )

        diags = [
            {
                "id": "SEM-001",
                "stage_id": "semantic_analysis",
                "stage": "Semantic Analysis",
                "title": "Identifier 'missing_one' referenced before assignment",
                "line": 2,
                "column": 16,
                "code_excerpt": "let sum1 = a + missing_one",
                "evidence": "missing_one",
                "rule_id": "SEM-UNDECLARED-VAR"
            },
            {
                "id": "SEM-002",
                "stage_id": "semantic_analysis",
                "stage": "Semantic Analysis",
                "title": "Identifier 'missing_two' referenced before assignment",
                "line": 3,
                "column": 18,
                "code_excerpt": "let sum2 = sum1 + missing_two",
                "evidence": "missing_two",
                "rule_id": "SEM-UNDECLARED-VAR"
            }
        ]

        fix_all_res = AIRemediationEngine.generate_fix_all(
            stage_id="semantic_analysis",
            source_code=multi_error_code,
            language="English",
            diagnostics=diags,
            use_ai=False
        )

        self.assertTrue(fix_all_res.get("success"), f"Fix all failed: {fix_all_res.get('error')}")
        self.assertEqual(fix_all_res.get("total_diagnostics"), 2)
        self.assertEqual(fix_all_res.get("resolved_count"), 2)
        self.assertEqual(fix_all_res.get("remaining_count"), 0)
        self.assertTrue(fix_all_res.get("validated"))

        # Verify that the synthesized code compiles cleanly through Semantic Analysis
        val = StageValidator.validate_stage("semantic_analysis", fix_all_res["proposed_source"], "English")
        self.assertTrue(val.get("passed"), f"Synthesized code did not pass semantic validation: {val.get('error')}")

    # -------------------------------------------------------------------------
    # TEST 6: Partial Fix All Success
    # -------------------------------------------------------------------------
    def test_06_partial_fix_all_success(self):
        """Verify that fixable errors are resolved and unfixable errors remain reported."""
        code_mixed = (
            "let a = 1\n"
            "let b = a + fixable_var\n"
            "print(b)\n"
        )

        diags = [
            {
                "id": "SEM-FIXABLE",
                "stage_id": "semantic_analysis",
                "title": "Identifier 'fixable_var' referenced before assignment",
                "line": 2,
                "column": 13,
                "code_excerpt": "let b = a + fixable_var",
                "evidence": "fixable_var",
                "rule_id": "SEM-UNDECLARED-VAR"
            },
            {
                "id": "SEM-UNFIXABLE",
                "stage_id": "semantic_analysis",
                "title": "Custom hardware constraint violation: unresolvable peripheral",
                "line": 3,
                "column": 1,
                "code_excerpt": "print(b)",
                "evidence": "hardware_clock",
                "rule_id": "SEM-HARDWARE-UNKNOWN"
            }
        ]

        res = AIRemediationEngine.generate_fix_all(
            stage_id="semantic_analysis",
            source_code=code_mixed,
            language="English",
            diagnostics=diags,
            use_ai=False
        )

        # Should report partial success
        self.assertGreaterEqual(res.get("resolved_count", 0), 1)
        self.assertEqual(res.get("total_diagnostics"), 2)
        # Unfixable finding must remain reported in unresolved list
        self.assertGreaterEqual(len(res.get("unresolved", [])), 1)
        self.assertEqual(res["unresolved"][0]["id"], "SEM-UNFIXABLE")

    # -------------------------------------------------------------------------
    # TEST 7: Fix All across Distinct Stages Independently
    # -------------------------------------------------------------------------
    def test_07_fix_all_distinct_stages(self):
        """Verify Fix All works independently across Parser, Semantic, and Security stages."""
        # 1. Syntax Analysis / Parser stage Fix All
        syntax_code = "if 1 == 1 {\n    print(\"Hello\")\n"  # missing closing brace
        syntax_diag = [{
            "id": "SEC-PAR-001",
            "stage_id": "syntax_analysis",
            "title": "Unbalanced Block Scope Delimiters",
            "line": 2,
            "column": 1,
            "code_excerpt": "if 1 == 1 {",
            "evidence": "missing '}'",
            "rule_id": "SEC-PAR-001"
        }]
        res_syn = AIRemediationEngine.generate_fix_all(
            stage_id="syntax_analysis",
            source_code=syntax_code,
            language="English",
            diagnostics=syntax_diag,
            use_ai=False
        )
        self.assertTrue(res_syn.get("success"), "Parser Fix All failed")
        val_syn = StageValidator.validate_stage("syntax_analysis", res_syn["proposed_source"], "English")
        self.assertTrue(val_syn.get("passed"), "Corrected parser code failed validation")

        # 2. Semantic Analysis stage Fix All
        sem_code = "let x = y + 1\nprint(x)\n"
        sem_diag = [{
            "id": "SEM-001",
            "stage_id": "semantic_analysis",
            "title": "Identifier 'y' referenced before assignment",
            "line": 1,
            "column": 9,
            "code_excerpt": "let x = y + 1",
            "evidence": "y",
            "rule_id": "SEM-UNDECLARED-VAR"
        }]
        res_sem = AIRemediationEngine.generate_fix_all(
            stage_id="semantic_analysis",
            source_code=sem_code,
            language="English",
            diagnostics=sem_diag,
            use_ai=False
        )
        self.assertTrue(res_sem.get("success"), "Semantic Fix All failed")
        val_sem = StageValidator.validate_stage("semantic_analysis", res_sem["proposed_source"], "English")
        self.assertTrue(val_sem.get("passed"), "Corrected semantic code failed validation")

    # -------------------------------------------------------------------------
    # TEST 8: Source Recovery (Undo Fix & Restore Original)
    # -------------------------------------------------------------------------
    def test_08_source_recovery_undo_and_restore(self):
        """Verify Undo Fix rolls back one step and Restore Original resets to pristine demo."""
        # Start fresh
        WorkingSourceManager.restore_original(self.test_rel_path)
        wc0 = WorkingSourceManager.get_working_copy(self.test_rel_path)
        base_code = wc0["original_source"]

        # Edit 1
        edit1 = base_code + "\n// Edit 1\n"
        WorkingSourceManager.save_working_copy(self.test_rel_path, edit1, label="Step 1")

        # Edit 2
        edit2 = edit1 + "\n// Edit 2\n"
        WorkingSourceManager.save_working_copy(self.test_rel_path, edit2, label="Step 2")

        wc2 = WorkingSourceManager.get_working_copy(self.test_rel_path)
        self.assertEqual(wc2["working_source"], edit2)

        # Undo 1 step -> should revert to edit1
        undo_res = WorkingSourceManager.undo_working_copy(self.test_rel_path)
        self.assertTrue(undo_res.get("success"))
        self.assertEqual(undo_res.get("working_source"), edit1)

        # Restore original -> should revert to base_code
        rest_res = WorkingSourceManager.restore_original(self.test_rel_path)
        self.assertTrue(rest_res.get("success"))
        self.assertEqual(rest_res.get("working_source"), base_code)
        self.assertFalse(rest_res.get("is_modified"))

    # -------------------------------------------------------------------------
    # TEST 9: Mandatory IR Optimization
    # -------------------------------------------------------------------------
    def test_09_mandatory_ir_optimization(self):
        """Verify IR Optimization runs mandatory passes and never skips."""
        # 1. Code with constant folding opportunities
        ir_with_opts = (
            "def main():\n"
            "    x = 10 + 20\n"
            "    y = 5 * 4\n"
            "    z = x + y\n"
            "    print(z)\n"
        )
        res_opt = IROptimizer.optimize(ir_with_opts, use_ai=False)
        self.assertTrue(res_opt.get("success"), "IR Optimization failed")
        self.assertEqual(res_opt.get("status"), "completed")
        self.assertGreater(res_opt.get("transformations_count", 0), 0)
        self.assertIn("Constant Folding", res_opt.get("passes_applied", []))

        # 2. Code that is already optimal
        ir_optimal = (
            "def main():\n"
            "    x = 30\n"
            "    print(x)\n"
        )
        res_opt2 = IROptimizer.optimize(ir_optimal, use_ai=False)
        self.assertTrue(res_opt2.get("success"), "IR Optimization on optimal code failed")
        self.assertEqual(res_opt2.get("status"), "completed")
        self.assertEqual(res_opt2.get("validation_status"), "PASSED")

    # -------------------------------------------------------------------------
    # TEST 10: Final Compilation Report Gate Blocking
    # -------------------------------------------------------------------------
    def test_10_final_report_gate_blocking(self):
        """Verify Final Report endpoint blocks generation if any mandatory stage fails."""
        # 1. Code with error (e.g. semantic error)
        bad_code = "let a = b + 1\nprint(a)\n"
        resp_blocked = self.client.post("/api/pipeline/generate-report", json={
            "code": bad_code,
            "language": "English",
            "run_id": "test-run-blocked"
        })
        self.assertEqual(resp_blocked.status_code, 400, "Report generation should be blocked on failure")
        data_blocked = resp_blocked.get_json()
        self.assertFalse(data_blocked.get("success"))
        self.assertIn("Cannot generate Final Report", data_blocked.get("error", ""))

        # 2. Clean valid code through all mandatory stages
        clean_code = "let x = 10\nlet y = 20\nlet sum = x + y\nprint(sum)\n"
        resp_clean = self.client.post("/api/pipeline/generate-report", json={
            "code": clean_code,
            "language": "English",
            "run_id": "test-run-clean"
        })
        self.assertEqual(resp_clean.status_code, 200, "Report generation should succeed for valid code")
        data_clean = resp_clean.get_json()
        self.assertTrue(data_clean.get("success"))
        self.assertIn("artifacts", data_clean)


if __name__ == "__main__":
    unittest.main()
