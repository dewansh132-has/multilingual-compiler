# -*- coding: utf-8 -*-
"""
tests/test_output_and_report_gating.py — Comprehensive Test Suite for Bug C Fix.

Verifies:
1. Stage 13 produces program output ONLY when stages 1-12 pass/allowed-warning or override=True.
2. For any failure/block (Stage 3 syntax, Stage 5 semantic, Stage 11 security):
   - Program output in API response is strictly "" (empty).
   - Overall status is never "COMPLETED".
   - Stage 14 is marked "blocked", NEVER "passed".
   - Stage 14 generates "DIAGNOSTIC REPORT (INCOMPLETE — pipeline stopped at Stage N)".
   - Diagnostic report contains first failing stage, line-numbered errors, blocked stages with reasons.
   - "Final Status: COMPLETED" never appears in diagnostic report.
3. Clean canonical programs produce full "VITAL COMPILER PIPELINE EXECUTION & AUDIT REPORT",
   status "COMPLETED", Stage 14 "passed", complete=True.
4. Educational override generates execution output with "[EXECUTED WITH SECURITY OVERRIDE]"
   while keeping stages 11/12 non-passed and report reflecting override.
5. Incomplete artifacts contain only logs for stages that actually completed.
6. Server endpoint /api/pipeline/report rejects incomplete pipelines when allow_incomplete=False.
"""

import os
import sys
import unittest
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.pipeline_tracker import (
    PipelineRunTracker,
    execute_pipeline_with_tracker,
    generate_diagnostic_report,
    check_prerequisites,
    STAGE_ORDER
)
from web.gate_policy import GatePolicy
import web.server as server


CLEAN_CODE = """
let x = 10
let y = 20
let z = x + y
print(z)
"""

SYNTAX_ERROR_CODE = """
let a = 10
let b = 20
if (a > 5) {
    print(a)
// Missing closing brace triggers Stage 3 failure
"""

SEMANTIC_ERROR_CODE = """
let a = 10
let b = undefined_target_var + 5
print(b)
"""


class TestOutputAndReportGating(unittest.TestCase):
    """Verifies that program output and Stage 14 Final Report exist only when stages truly pass."""

    def setUp(self):
        self.demo_b_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "security_lab", "english", "sec_data_config.vital"
        )
        with open(self.demo_b_path, "r", encoding="utf-8") as f:
            self.security_high_code = f.read()

    def test_clean_program_produces_full_report_and_output(self):
        """Clean program passes all 14 stages, producing output and full audit report."""
        tracker = PipelineRunTracker(run_id="run-clean-test")
        execute_pipeline_with_tracker(
            source_code=CLEAN_CODE,
            tracker=tracker,
            run_ai_security=False,
        )
        artifacts = tracker.artifacts or {}

        self.assertTrue(artifacts.get("complete"), "Clean run must have complete=True")
        self.assertFalse(artifacts.get("incomplete"), "Clean run must not have incomplete=True")
        self.assertEqual(artifacts.get("overall_status"), "COMPLETED")
        self.assertIn("30", artifacts.get("output", ""))

        # Stage 14 must be passed
        final_stage = tracker.stages.get("final_report", {})
        self.assertIn(final_stage.get("status"), ("passed", "completed"))

        # Full audit report title
        report = artifacts.get("aggregated_log", "")
        self.assertIn("VITAL COMPILER PIPELINE EXECUTION & AUDIT REPORT", report)
        self.assertIn("Final Status:        COMPLETED", report)
        self.assertNotIn("DIAGNOSTIC REPORT (INCOMPLETE", report)

    def test_syntax_error_halts_at_stage_3_no_output_and_diagnostic_report(self):
        """Stage 3 failure produces no output, Stage 14 is blocked, diagnostic report generated."""
        tracker = PipelineRunTracker(run_id="run-syntax-test")
        execute_pipeline_with_tracker(
            source_code=SYNTAX_ERROR_CODE,
            tracker=tracker,
            run_ai_security=False,
        )
        artifacts = tracker.artifacts or {}

        # Output must be strictly empty
        self.assertEqual(artifacts.get("output"), "", "Output must be strictly empty on syntax failure")
        self.assertFalse(artifacts.get("complete"), "complete must be False on failure")
        self.assertTrue(artifacts.get("incomplete"), "incomplete must be True on failure")
        self.assertNotEqual(artifacts.get("overall_status"), "COMPLETED")
        self.assertIn(artifacts.get("overall_status"), ("FAILED", "INCOMPLETE"))

        # Stage 3 is failed
        self.assertEqual(tracker.stages["syntax_analysis"]["status"], "failed")

        # Downstream stages 4..14 must be BLOCKED
        for sid in STAGE_ORDER[3:]:
            st = tracker.stages.get(sid, {})
            self.assertEqual(
                st.get("status"),
                "blocked",
                f"Stage {sid} should be blocked after Stage 3 syntax failure"
            )

        # Stage 14 must NEVER be passed
        self.assertNotEqual(tracker.stages["final_report"]["status"], "passed")
        self.assertEqual(tracker.stages["final_report"]["status"], "blocked")

        # Report must be diagnostic
        report = artifacts.get("aggregated_log", "")
        self.assertIn("DIAGNOSTIC REPORT (INCOMPLETE — pipeline stopped at Stage 3)", report)
        self.assertNotIn("Final Status: COMPLETED", report)
        self.assertNotIn("VITAL COMPILER PIPELINE EXECUTION & AUDIT REPORT", report)
        self.assertIn("FIRST FAILING STAGE & DIAGNOSTIC ERRORS", report)
        self.assertIn("BLOCKED DOWNSTREAM STAGES", report)
        self.assertIn("Blocked by Stage 3 (Syntax Analysis)", report)

        # Downstream artifacts must NOT be produced
        self.assertEqual(artifacts.get("ir_code"), "")
        self.assertEqual(artifacts.get("symbol_table"), "")

    def test_semantic_error_halts_at_stage_5_no_output_and_diagnostic_report(self):
        """Stage 5 failure produces no output, Stage 14 blocked, diagnostic report generated."""
        tracker = PipelineRunTracker(run_id="run-semantic-test")
        execute_pipeline_with_tracker(
            source_code=SEMANTIC_ERROR_CODE,
            tracker=tracker,
            run_ai_security=False,
        )
        artifacts = tracker.artifacts or {}

        self.assertEqual(artifacts.get("output"), "", "Output must be strictly empty on semantic failure")
        self.assertFalse(artifacts.get("complete"))
        self.assertTrue(artifacts.get("incomplete"))
        self.assertNotEqual(artifacts.get("overall_status"), "COMPLETED")

        # Stage 5 is failed
        self.assertEqual(tracker.stages["semantic_analysis"]["status"], "failed")

        # Downstream stages 6..14 must be BLOCKED
        for sid in STAGE_ORDER[5:]:
            st = tracker.stages.get(sid, {})
            self.assertEqual(
                st.get("status"),
                "blocked",
                f"Stage {sid} should be blocked after Stage 5 semantic failure"
            )

        # Stage 14 must be blocked
        self.assertEqual(tracker.stages["final_report"]["status"], "blocked")

        # Diagnostic report checks
        report = artifacts.get("aggregated_log", "")
        self.assertIn("DIAGNOSTIC REPORT (INCOMPLETE — pipeline stopped at Stage 5)", report)
        self.assertNotIn("Final Status: COMPLETED", report)
        self.assertIn("undefined_target_var", report)

    def test_security_high_blocks_at_stage_11_no_output_and_diagnostic_report(self):
        """Stage 11 blocking finding halts before execution: no output, diagnostic report."""
        tracker = PipelineRunTracker(run_id="run-sec-block-test")
        execute_pipeline_with_tracker(
            source_code=self.security_high_code,
            language_hint="English",
            tracker=tracker,
            run_ai_security=False,
        )
        artifacts = tracker.artifacts or {}

        self.assertEqual(artifacts.get("output"), "", "Output must be strictly empty when blocked by security")
        self.assertFalse(artifacts.get("complete"))
        self.assertTrue(artifacts.get("incomplete"))
        self.assertEqual(artifacts.get("overall_status"), "BLOCKED_BY_SECURITY")

        # Stage 11 failed, Stage 12, 13, 14 blocked
        self.assertEqual(tracker.stages["security_analysis"]["status"], "failed")
        self.assertEqual(tracker.stages["sandbox_execution"]["status"], "blocked")
        self.assertEqual(tracker.stages["final_report"]["status"], "blocked")

        # Diagnostic report checks
        report = artifacts.get("aggregated_log", "")
        self.assertIn("DIAGNOSTIC REPORT (INCOMPLETE — pipeline stopped at Stage 11)", report)
        self.assertNotIn("Final Status: COMPLETED", report)
        self.assertIn("Blocked by Stage 11 (Security Analysis)", report)
        self.assertIn("Standard Output:     (None", report)

    def test_security_override_executes_stage_13_with_warning_banner(self):
        """Security override allows Stage 13 to run and produce output with override banner."""
        tracker = PipelineRunTracker(run_id="run-sec-override-test")
        execute_pipeline_with_tracker(
            source_code=self.security_high_code,
            language_hint="English",
            tracker=tracker,
            run_ai_security=False,
            security_override=True,
        )
        artifacts = tracker.artifacts or {}

        # Output must be generated and contain override banner
        output = artifacts.get("output", "")
        self.assertIn("[EXECUTED WITH SECURITY OVERRIDE]", output)
        self.assertEqual(artifacts.get("overall_status"), "EXECUTED_WITH_OVERRIDE")

        # Stages 11 remains failed
        self.assertEqual(tracker.stages["security_analysis"]["status"], "failed")

        # Final report notes execution with override
        report = artifacts.get("aggregated_log", "")
        self.assertIn("EXECUTED WITH SECURITY OVERRIDE", report)

    def test_server_pipeline_generate_report_rejects_incomplete_runs(self):
        """API endpoint /api/pipeline/generate-report returns 400 when pipeline has unsatisfied prerequisites."""
        client = server.app.test_client()

        # 1. Incomplete run without allow_incomplete -> 400
        resp = client.post("/api/pipeline/generate-report", json={
            "code": SYNTAX_ERROR_CODE,
            "language": "English",
            "run_id": "test-server-reject",
            "allow_incomplete": False
        })
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("Cannot generate Final Report", data.get("error", ""))

        # 2. Incomplete run with allow_incomplete=True -> 200, diagnostic report
        resp_allow = client.post("/api/pipeline/generate-report", json={
            "code": SYNTAX_ERROR_CODE,
            "language": "English",
            "run_id": "test-server-allow",
            "allow_incomplete": True
        })
        self.assertEqual(resp_allow.status_code, 200)
        data_allow = resp_allow.get_json()
        self.assertTrue(data_allow.get("is_incomplete"))
        self.assertFalse(data_allow.get("complete"))
        self.assertIn("DIAGNOSTIC REPORT (INCOMPLETE", data_allow.get("report", ""))


if __name__ == "__main__":
    unittest.main()
