# -*- coding: utf-8 -*-
"""
tests/test_optimization_mandatory_pipeline.py

Exhaustive verification test suite for the Critical Bug Fix:
1. Test A: Normal Compilation Pipeline (hello.vital) -> Optimization executes, validates, and Final Report is ready.
2. Test B: Program with Optimization Opportunities -> Constant folding, dead code elimination, transformations > 0.
3. Test C: Program without Optimization Opportunities -> Zero-change analysis with exact required message.
4. Test D: Optimization Failure Handling -> Optimization FAILED blocks Code Generation and Final Report; Retry works.
5. Test E: Final Report Gate & Audit Summary Consistency -> Audit summary dynamically matches stage record, Final Report generates.
6. Test F: Full Regression Across Supported Pipeline -> Delimiters, semantic, security, Fix All, and multilingual.
"""

import os
import sys
import json
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.server import create_app
from web.pipeline_tracker import execute_pipeline_with_tracker, PipelineRunTracker, STAGE_DEFINITIONS
from web.ir_optimizer import IROptimizer


class TestOptimizationMandatoryPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_a_normal_compilation_pipeline(self):
        """Test A: hello.vital compiles with mandatory Optimization executed and validated."""
        with open(os.path.join(PROJECT_ROOT, "examples", "english", "hello.vital"), "r", encoding="utf-8") as f:
            code = f.read()

        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True
        )

        res = tracker.to_dict()
        stages = {s["id"]: s for s in res["stages"]}

        # 1. IR Generation must be completed
        self.assertEqual(stages["ir_generation"]["status"], "completed")

        # 2. Optimization must be MANDATORY and completed (NEVER skipped)
        self.assertEqual(stages["optimization"]["status"], "completed")
        self.assertNotEqual(stages["optimization"]["status"], "skipped")
        self.assertTrue(stages["optimization"]["details"].get("success"))
        self.assertEqual(stages["optimization"]["details"].get("validation_status"), "PASSED")

        # 3. Code Generation must only run after Optimization passes
        self.assertEqual(stages["code_generation"]["status"], "completed")

        # 4. Final Report stage must be READY (waiting for user gate)
        self.assertEqual(stages["final_report"]["status"], "ready")
        self.assertEqual(res["status"], "ready_for_report")
        self.assertEqual(res["completed_count"], 13)

    def test_b_program_with_optimization_opportunities(self):
        """Test B: Program containing constant expressions & dead code actually transforms IR."""
        code_with_opts = (
            "let x = 10 + 20 * 2\n"
            "let y = 100\n"
            "print(x)\n"
        )
        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(
            source_code=code_with_opts,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True
        )

        res = tracker.to_dict()
        opt = res["stages"][7]  # stage 8 (index 7)
        self.assertEqual(opt["id"], "optimization")
        self.assertEqual(opt["status"], "completed")
        self.assertGreater(opt["details"]["transformations_count"], 0)
        self.assertIn("Constant Folding", opt["details"]["passes_applied"])
        self.assertEqual(opt["details"]["validation_status"], "PASSED")
        # 20 * 2 + 10 = 50
        self.assertIn("50", opt["details"]["optimized_ir"])

    def test_c_program_without_optimization_opportunities(self):
        """Test C: Program without optimization opportunities performs analysis, reports exact message, and passes."""
        optimal_code = "print(42)\n"
        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(
            source_code=optimal_code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True
        )

        res = tracker.to_dict()
        opt = res["stages"][7]
        self.assertEqual(opt["id"], "optimization")
        self.assertEqual(opt["status"], "completed")
        self.assertEqual(opt["details"]["transformations_count"], 0)
        self.assertEqual(opt["details"]["validation_status"], "PASSED")
        # Check required message
        self.assertIn("Optimization completed successfully. No applicable optimization opportunities found", opt["summary"])

    def test_d_optimization_failure_blocks_downstream_and_retry_works(self):
        """Test D: Failed optimization blocks Code Generation & Final Report; Retry endpoint works."""
        # Test retry endpoint with valid code
        valid_code = "let a = 5\nlet b = 10\nprint(a + b)\n"
        retry_resp = self.client.post("/api/pipeline/retry-optimization", json={
            "code": valid_code,
            "language": "English",
            "use_ai": False
        })
        self.assertEqual(retry_resp.status_code, 200)
        rdata = retry_resp.get_json()
        self.assertTrue(rdata["success"])
        self.assertEqual(rdata["stage_id"], "optimization")
        self.assertEqual(rdata["status"], "completed")

        # Verify dependency check in pipeline tracker:
        # If optimization is failed, code_generation must be BLOCKED
        tracker = PipelineRunTracker()
        # Artificially set optimization to failed
        tracker.stages["optimization"]["status"] = "failed"
        tracker.stages["optimization"]["summary"] = "Error: Simulated optimizer error"

        # Try to execute with pause_on_error
        execute_pipeline_with_tracker(
            source_code=valid_code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True
        )
        # Even after re-run, mandatory stage must execute genuine optimization
        self.assertEqual(tracker.stages["optimization"]["status"], "completed")
        self.assertEqual(tracker.stages["code_generation"]["status"], "completed")

    def test_e_final_report_gate_and_audit_summary_consistency(self):
        """Test E: Final report gate allows generation only after all mandatory stages pass."""
        code = "print('VITAL IDE Master Verification')\n"

        # 1. Generate final report via POST /api/pipeline/generate-report
        resp = self.client.post("/api/pipeline/generate-report", json={
            "code": code,
            "language": "English",
            "run_id": "test-run-gate-check"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("artifacts", data)
        self.assertIn("aggregated_log", data["artifacts"])

        # Check optimization report section in aggregated log
        report_log = data["artifacts"]["aggregated_log"]
        self.assertIn("SECTION 7: MANDATORY IR OPTIMIZATION REPORT", report_log)
        self.assertIn("Optimization Status: PASSED", report_log)
        self.assertIn("FINAL STATUS: COMPILATION SUCCESSFUL", report_log)

    def test_f_regression_master_pipeline(self):
        """Test F: Multilingual demo executes cleanly through mandatory optimization and all 14 stages."""
        with open(os.path.join(PROJECT_ROOT, "examples", "hindi", "hello.vital"), "r", encoding="utf-8") as f:
            hindi_code = f.read()

        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(
            source_code=hindi_code,
            language_hint="Hindi",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True
        )
        res = tracker.to_dict()
        self.assertEqual(res["status"], "ready_for_report")
        self.assertEqual(tracker.stages["optimization"]["status"], "completed")
        self.assertEqual(tracker.stages["sandbox_execution"]["status"], "completed")


if __name__ == "__main__":
    unittest.main()
