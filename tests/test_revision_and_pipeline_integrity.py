# -*- coding: utf-8 -*-
"""
tests/test_revision_and_pipeline_integrity.py — Automated Verification Suite (Tests A through F)

Verifies:
  Test A: Approve & Apply modifies backend, updates editor state, persists revision to disk, and increments revision.
  Test B: Parser regression on later-stage fix invalidates earlier stages to STALE and reruns from start.
  Test C: Invalid patch (indentation/syntax) is rejected and rolls back to previous valid revision.
  Test D: Security correction parameterized SQL passes Parser, semantics, and eliminates SEC-INJ-001.
  Test E: Stale patch (generated for revision N, applied at N+1) is rejected.
  Test F: Pipeline completion requires all 14 mandatory stages on identical revision; Final Report blocked if any stage is stale or failed.
"""

import os
import sys
import unittest
import json
import hashlib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from src.main import Compiler, RULES_FILE
from web.working_source_manager import working_source_manager
from web.ai_remediation_engine import remediation_engine, StageValidator, AIRemediationEngine
from web.security_analyzer import security_coordinator, DeterministicSecurityScanner
from web.pipeline_tracker import (
    PipelineRunTracker,
    execute_pipeline_with_tracker,
    STAGE_DEFINITIONS
)


class TestRevisionAndPipelineIntegrity(unittest.TestCase):
    """Automated Verification Suite covering Tests A through F."""

    @classmethod
    def setUpClass(cls):
        cls.telugu_file = "examples/security_lab/telugu/sec_injection_eval_te.vital"
        cls.compiler = Compiler(RULES_FILE)
        cls.compiler.load_rules()
        cls.scanner = DeterministicSecurityScanner()

    def setUp(self):
        # Ensure working copy is restored to pristine fixture before every test
        working_source_manager.restore_original_source(self.telugu_file)

    def tearDown(self):
        # Restore pristine fixture after every test
        working_source_manager.restore_original_source(self.telugu_file)

    def test_a_approve_and_apply_modifies_backend_and_persists_revision(self):
        """
        Test A: Approve & Apply performs real atomic source modification,
        increments source revision, writes to disk, and updates content hash.
        """
        curr = working_source_manager.get_working_source(self.telugu_file)
        self.assertTrue(curr["success"])
        initial_rev = curr["source_revision"]
        initial_code = curr["code"]

        # Valid safe patch for SQL injection
        safe_patch = initial_code.replace(
            'అనుకో పూర్తి_క్వెరీ = క్వెరీ_ప్రారంభం + ఫిల్టర్',
            'అనుకో పూర్తి_క్వెరీ = "SELECT user_id, email FROM accounts WHERE role = \'user\' AND user_id = ?" // safe'
        )
        self.assertNotEqual(initial_code, safe_patch)

        # Apply through remediation engine (same API called by Approve & Apply)
        res = remediation_engine.apply_and_verify_fix(
            file_path=self.telugu_file,
            proposed_source=safe_patch,
            expected_revision=initial_rev,
            stage_id="security_analysis",
            language="Telugu",
            finding_id="SEC-INJ-001"
        )

        self.assertTrue(res.get("success"), f"Apply fix failed: {res.get('error')}")
        self.assertEqual(res.get("source_revision"), initial_rev + 1)
        self.assertEqual(res.get("status"), "Correction Applied & Saved")

        # Verify disk persistence via working_source_manager
        saved = working_source_manager.get_working_source(self.telugu_file)
        self.assertTrue(saved["has_working_copy"])
        self.assertEqual(saved["source_revision"], initial_rev + 1)
        self.assertEqual(saved["code"], safe_patch)
        self.assertEqual(saved["content_hash"], hashlib.sha256(safe_patch.encode("utf-8")).hexdigest())
        self.assertTrue(saved["is_dirty"])

    def test_b_parser_regression_invalidates_earlier_stages_to_stale_and_reruns(self):
        """
        Test B: Parser regression on later-stage fix invalidates earlier stages to STALE
        and reruns from start without skipping stages.
        """
        curr = working_source_manager.get_working_source(self.telugu_file)
        code = curr["code"]

        # 1. Run pipeline on baseline code (Rev 1)
        tracker = execute_pipeline_with_tracker(code, language_hint="Telugu", pause_on_error=True, run_ai_security=False, source_revision=1)
        self.assertIn(tracker.stages["syntax_analysis"]["status"], ("completed", "passed"))
        self.assertEqual(tracker.stages["syntax_analysis"]["source_revision"], 1)

        # 2. Simulate code change moving to Revision 2
        tracker.invalidate_for_new_revision(current_revision=2)

        # Verify all stages from revision 1 transitioned to STALE
        self.assertEqual(tracker.stages["syntax_analysis"]["status"], "stale")
        self.assertEqual(tracker.stages["source_input"]["status"], "stale")
        self.assertFalse(tracker.is_ready_for_report)

        # 3. Re-run pipeline with Revision 2
        re_run_tracker = execute_pipeline_with_tracker(code, language_hint="Telugu", pause_on_error=True, run_ai_security=False, source_revision=2)
        self.assertEqual(re_run_tracker.stages["syntax_analysis"]["status"], "completed")
        self.assertEqual(re_run_tracker.stages["syntax_analysis"]["source_revision"], 2)

    def test_c_invalid_patch_indentation_rejected_and_rolled_back(self):
        """
        Test C: Invalid patch (indentation/syntax) is rejected and rolls back to previous valid revision.
        """
        curr = working_source_manager.get_working_source(self.telugu_file)
        initial_code = curr["code"]
        initial_rev = curr["source_revision"]

        # Create a patch with an unexpected indent syntax error
        bad_indent_patch = initial_code + "\n        unexpected_indent_statement = 999\n"

        res = remediation_engine.apply_and_verify_fix(
            file_path=self.telugu_file,
            proposed_source=bad_indent_patch,
            expected_revision=initial_rev,
            stage_id="security_analysis",
            language="Telugu",
            finding_id="SEC-INJ-001"
        )

        # Must reject patch
        self.assertFalse(res.get("success"))
        self.assertTrue(res.get("regression_detected"))
        self.assertEqual(res.get("failing_stage"), "syntax_analysis")
        self.assertIn("unexpected indent", res.get("error", "").lower())
        self.assertTrue(res.get("retained_original"))

        # Verify disk working copy was NOT modified
        saved = working_source_manager.get_working_source(self.telugu_file)
        self.assertEqual(saved["source_revision"], initial_rev)
        self.assertEqual(saved["code"], initial_code)

    def test_d_security_correction_parameterized_sql_eliminates_sec_inj_001(self):
        """
        Test D: Security correction parameterized SQL passes Parser, semantics,
        and eliminates SEC-INJ-001 according to independent scanner.
        """
        curr = working_source_manager.get_working_source(self.telugu_file)
        code = curr["code"]

        # Initial baseline scan detects SEC-INJ-001
        initial_findings = self.scanner.scan_multilingual_security(code, "Telugu")
        sql_findings = [f for f in initial_findings if f.id == "SEC-INJ-001" or "SQL" in f.title]
        self.assertGreaterEqual(len(sql_findings), 1, "Expected SEC-INJ-001 in vulnerable fixture")

        # Propose fix for SEC-INJ-001
        fix = security_coordinator.suggest_fix_for_finding(
            source_code=code,
            finding_id="SEC-INJ-001",
            finding_data=sql_findings[0].to_dict(),
            language="Telugu",
            prefer_deterministic=True
        )

        self.assertTrue(fix.get("success"), f"Suggest fix failed: {fix.get('error')}")
        proposed = fix.get("proposed_source")
        self.assertIsNotNone(proposed)
        self.assertNotEqual(code, proposed)

        # 1. Proposed code MUST pass Compiler parser cleanly
        parser_valid = self.compiler.run_parser(proposed)
        self.assertTrue(parser_valid, "Proposed fix failed parser syntax validation")

        # 2. Independent security scanner verifies SEC-INJ-001 is completely eliminated
        new_findings = self.scanner.scan_multilingual_security(proposed, "Telugu")
        remaining_sql = [f for f in new_findings if f.id == "SEC-INJ-001" or "SQL" in f.title]
        self.assertEqual(len(remaining_sql), 0, "SEC-INJ-001 was not resolved by the parameterized fix")

        # 3. Independent repair verification confirms syntax is valid and target resolved
        verif = security_coordinator.verify_repair(
            original_source=code,
            repaired_source=proposed,
            language="Telugu",
            target_finding_id="SEC-INJ-001"
        )
        self.assertTrue(verif.get("syntax_valid"))
        self.assertTrue(any(rf.get("id") == "SEC-INJ-001" or "SQL" in rf.get("title", "") for rf in verif.get("resolved_findings", [])))

    def test_e_stale_patch_rejection(self):
        """
        Test E: Stale patch (generated for revision N, applied at N+1) is rejected.
        """
        curr = working_source_manager.get_working_source(self.telugu_file)
        code = curr["code"]

        # Advance file to revision 2
        v2_code = code + "\n// Revision 2 comment\n"
        save_res = working_source_manager.save_working_source(self.telugu_file, v2_code, expected_revision=1, label="Bump to rev 2")
        self.assertTrue(save_res["success"])
        self.assertEqual(save_res["source_revision"], 2)

        # Attempt to apply a patch that expects revision 1 (stale)
        res = remediation_engine.apply_and_verify_fix(
            file_path=self.telugu_file,
            proposed_source=code + "\n// Stale patch\n",
            expected_revision=1,  # Stale: active revision is 2
            stage_id="syntax_analysis",
            language="Telugu"
        )

        self.assertFalse(res.get("success"))
        self.assertIn("stale patch rejection", res.get("error", "").lower())
        self.assertEqual(res.get("current_revision"), 2)

    def test_f_pipeline_completion_requires_all_14_mandatory_stages_identical_revision(self):
        """
        Test F: Pipeline completion requires all 14 mandatory stages on identical revision;
        Final Report is blocked if any mandatory stage is stale, failed, or skipped.
        """
        tracker = PipelineRunTracker(source_revision=1)

        # 1. Complete stages 1 through 7
        for sid in ["source_input", "lexical_analysis", "syntax_analysis", "ast_construction", "semantic_analysis", "symbol_table", "ir_generation"]:
            tracker.complete_stage(sid, "Passed", source_revision=1)

        # 2. Stage 8 (Optimization) is SKIPPED or NOT completed
        tracker.skip_stage("optimization", "Skipped by test")

        # 3. Complete stages 9 through 13
        for sid in ["code_generation", "code_validation", "security_analysis", "ai_security_analysis", "sandbox_execution"]:
            tracker.complete_stage(sid, "Passed", source_revision=1)

        # Check all prereqs: optimization was skipped, so all_prereqs must be False
        mandatory_prereqs = [s["id"] for s in STAGE_DEFINITIONS if s["id"] != "final_report"]
        all_passed = all(
            tracker.stages.get(sid, {}).get("status") in ("completed", "passed", "warning") and
            tracker.stages.get(sid, {}).get("source_revision") == 1
            for sid in mandatory_prereqs
        )
        self.assertFalse(all_passed, "Prerequisites must fail when optimization is skipped")

        # 4. Now properly pass Stage 8 Optimization on Revision 1
        tracker.complete_stage("optimization", "Validated optimization passes applied", source_revision=1)

        all_passed_now = all(
            tracker.stages.get(sid, {}).get("status") in ("completed", "passed", "warning") and
            tracker.stages.get(sid, {}).get("source_revision") == 1
            for sid in mandatory_prereqs
        )
        self.assertTrue(all_passed_now, "All 13 prerequisites must pass when Optimization is completed on Rev 1")

        # 5. Now simulate one stage becoming STALE (e.g. revision bumped to 2)
        tracker.mark_stage_stale("syntax_analysis", "Stale due to code update")

        all_passed_with_stale = all(
            tracker.stages.get(sid, {}).get("status") in ("completed", "passed", "warning") and
            tracker.stages.get(sid, {}).get("source_revision") == 1
            for sid in mandatory_prereqs
        )
        self.assertFalse(all_passed_with_stale, "Prerequisites must fail when any stage is STALE")


if __name__ == "__main__":
    unittest.main()

