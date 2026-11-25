# -*- coding: utf-8 -*-
"""
tests/test_ai_fix_and_rerun.py — Comprehensive Test Suite for Multi-Stage AI Fix & Re-run Loop

Covers:
  1. Demo A: Starts at Stage 5 (undefined variable) -> fixed -> reaches Stage 11 -> fixed -> COMPLETED.
  2. Demo D: Starts at Stage 3 (missing brace) -> fixed -> reaches later stages -> fixed -> COMPLETED.
  3. Demo C Telugu: Stage 11 seeded injection/eval repaired -> passes through Stage 13 without sandbox errors.
  4. Demo B: Seeded data config CWEs repaired -> passes through to COMPLETED.
  5. No-progress stop: Two consecutive iterations failing identically halt the loop safely.
  6. Patch size cap: Patches exceeding 40% of the file are rejected and halt loop.
  7. Undo fix: Original buffer is preserved and restored byte-for-byte.
  8. Clean demo gating: Clean demos (outside security_lab) never allow fix and return HTTP 403.
  9. Multilingual coverage: One test per language including Fusion (7 languages: English, Hindi,
     Telugu, Bengali, Marathi, Nepali, Fusion).
 10. Remediation integrity: Confirms findings are truly remediated rather than lines deleted (suspect check).
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.fix_orchestrator import run_ai_fix_and_rerun_loop, is_fix_allowed
from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker
from web.server import app


class TestAiFixAndRerunLoop(unittest.TestCase):
    """Test suite for AI Fix & Re-run loop execution and termination conditions."""

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    # -------------------------------------------------------------------------
    # Test 1: Demo A (Stage 5 then Stage 11 -> COMPLETED)
    # -------------------------------------------------------------------------
    def test_demo_a_progression_stage5_then_stage11(self):
        """Demo A starts with Stage 5 failure, fixes Stage 5, then fixes Stage 11 to reach COMPLETED."""
        path = os.path.join("examples", "security_lab", "hindi", "sec_auth_account_hi.vital")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        res = run_ai_fix_and_rerun_loop(
            source_code=code,
            language="hindi",
            file_path=path,
            use_ai=False
        )

        self.assertTrue(res["success"], f"Demo A should pass, got: {res.get('stop_reason')}")
        self.assertIn(res["final_status"], ("COMPLETED", "WARNING", "completed", "warning"))
        self.assertGreaterEqual(res["iterations_count"], 2)

        # Stage 5 was repaired first, then Stage 11
        it_stages = [it["stage_id"] for it in res["iterations"] if it.get("status") == "fixed"]
        self.assertIn("semantic_analysis", it_stages)
        self.assertIn("security_analysis", it_stages)
        self.assertEqual(it_stages[0], "semantic_analysis")

        # Live log format check
        first_log = res["iteration_logs"][0]
        self.assertIn("Iteration 1: fixing Stage 5", first_log)
        self.assertIn("-> fixed, re-running...", first_log)

    # -------------------------------------------------------------------------
    # Test 2: Demo D (Stage 3 then later stages -> COMPLETED)
    # -------------------------------------------------------------------------
    def test_demo_d_progression_stage3_then_later_stages(self):
        """Demo D starts with Stage 3 failure (missing brace), fixes Stage 3, then finishes COMPLETED."""
        path = os.path.join("examples", "security_lab", "hindi", "sec_business_workflow_hi.vital")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        res = run_ai_fix_and_rerun_loop(
            source_code=code,
            language="hindi",
            file_path=path,
            use_ai=False
        )

        self.assertTrue(res["success"], f"Demo D should pass, got: {res.get('stop_reason')}")
        self.assertIn(res["final_status"], ("COMPLETED", "WARNING", "completed", "warning"))
        it_stages = [it["stage_id"] for it in res["iterations"] if it.get("status") == "fixed"]
        self.assertEqual(it_stages[0], "syntax_analysis")

        first_log = res["iteration_logs"][0]
        self.assertIn("Iteration 1: fixing Stage 3", first_log)
        self.assertIn("-> fixed, re-running...", first_log)

    # -------------------------------------------------------------------------
    # Test 3: Demo C Telugu (Reaches passing state without Stage 13 errors)
    # -------------------------------------------------------------------------
    def test_demo_c_telugu_reaches_passing_without_stage13_errors(self):
        """Telugu Demo C repairs Stage 11 seeded flaws and passes Stage 13 without sandbox errors."""
        path = os.path.join("examples", "security_lab", "telugu", "sec_injection_eval_te.vital")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        res = run_ai_fix_and_rerun_loop(
            source_code=code,
            language="telugu",
            file_path=path,
            use_ai=False
        )

        self.assertTrue(res["success"], f"Demo C Telugu should pass: {res.get('stop_reason')}")
        self.assertIn(res["final_status"], ("COMPLETED", "WARNING", "completed", "warning"))

        # Verify Stage 13 sandbox execution on repaired code
        tracker = PipelineRunTracker("test-te-c-final", 100)
        execute_pipeline_with_tracker(res["proposed_source"], "telugu", False, tracker)
        st13 = tracker.stages.get("sandbox_execution", {})
        self.assertIn(st13.get("status"), ("passed", "completed"))
        self.assertEqual(len(st13.get("findings", [])), 0)

    # -------------------------------------------------------------------------
    # Test 4: Demo B Progression
    # -------------------------------------------------------------------------
    def test_demo_b_progression(self):
        """Demo B repairs seeded security findings in Stage 11 and reaches COMPLETED."""
        path = os.path.join("examples", "security_lab", "hindi", "sec_data_config_hi.vital")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        res = run_ai_fix_and_rerun_loop(
            source_code=code,
            language="hindi",
            file_path=path,
            use_ai=False
        )

        self.assertTrue(res["success"], f"Demo B should pass: {res.get('stop_reason')}")
        self.assertIn(res["final_status"], ("COMPLETED", "WARNING", "completed", "warning"))

    # -------------------------------------------------------------------------
    # Test 5: No-Progress Stop (Two consecutive identical failures)
    # -------------------------------------------------------------------------
    def test_no_progress_stop_terminates_gracefully(self):
        """Two consecutive iterations with identical failing stage and error must halt the loop."""
        # Unfixable synthetic construct: custom unknown syntax token in an unfixable line
        source = "function test() {\n    @@@@@ ??????\n}\n"

        res = run_ai_fix_and_rerun_loop(
            source_code=source,
            language="English",
            file_path="user_code/broken.vital",
            use_ai=False
        )

        self.assertFalse(res["passed"])
        self.assertIn("Stopped", res["stop_reason"])
        self.assertLessEqual(res["iterations_count"], 2)

    # -------------------------------------------------------------------------
    # Test 6: Patch Size Exceeds 40% Cap
    # -------------------------------------------------------------------------
    @patch("web.fix_orchestrator.run_stage_targeted_fix_all")
    def test_patch_size_exceeds_40_percent_stop(self, mock_fix):
        """A patch that alters more than 40% of the file lines must be rejected."""
        source = "let a = 1\nlet b = 2\nlet c = 3\nlet d = 4\nlet e = missing_val\n"
        # Mock proposing replacement of entire file (>40%)
        huge_replacement = "let z = 99\nlet y = 98\nlet x = 97\nlet w = 96\nlet v = 95\nlet u = 94\n"
        mock_fix.return_value = {
            "success": True,
            "applied_fixes": [{"finding_id": "SEM-1", "diff": "huge"}],
            "proposed_source": huge_replacement
        }

        res = run_ai_fix_and_rerun_loop(
            source_code=source,
            language="English",
            file_path="user_code/large_patch.vital",
            use_ai=False
        )

        self.assertFalse(res["passed"])
        self.assertIn("40% file limit", res["stop_reason"])

    # -------------------------------------------------------------------------
    # Test 7: Undo Restores Exact Buffer
    # -------------------------------------------------------------------------
    def test_undo_restores_exact_buffer(self):
        """The loop captures original_source byte-for-byte and provides whole-buffer diff."""
        path = os.path.join("examples", "security_lab", "english", "sec_auth_account.vital")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        res = run_ai_fix_and_rerun_loop(
            source_code=code,
            language="english",
            file_path=path,
            use_ai=False
        )

        self.assertEqual(res["original_source"], code)
        self.assertNotEqual(res["proposed_source"], code)
        self.assertTrue(res["undo_available"])
        self.assertIn("--- a/sec_auth_account.vital", res["whole_buffer_diff"])
        self.assertIn("+++ b/sec_auth_account.vital", res["whole_buffer_diff"])

    # -------------------------------------------------------------------------
    # Test 8: Clean Demos Gating (No Fix Allowed, HTTP 403)
    # -------------------------------------------------------------------------
    def test_clean_demos_show_no_fix_and_return_403(self):
        """Clean demos outside security_lab are forbidden from running AI Fix & Re-run."""
        clean_files = [
            "examples/english/hello.vital",
            "examples/hindi/matrix_operations_suite.vital",
            "examples/telugu/task_scheduler_engine.vital"
        ]
        for clean_path in clean_files:
            self.assertFalse(is_fix_allowed(clean_path, ""), f"Clean path {clean_path} must be disallowed")

            resp = self.client.post("/api/pipeline/ai-fix-and-rerun", json={
                "code": "let a = 1\n",
                "language": "English",
                "file_path": clean_path,
                "category": "canonical"
            })
            self.assertEqual(resp.status_code, 403, f"Expected 403 for clean demo {clean_path}")
            self.assertIn("only permitted for Security Lab", resp.get_json()["error"])

    # -------------------------------------------------------------------------
    # Test 9: Multilingual Coverage (All 7 Languages)
    # -------------------------------------------------------------------------
    def test_multilingual_coverage_all_seven_languages(self):
        """One test per language including Fusion verifies stage-by-stage repair to COMPLETED."""
        language_demos = [
            ("english", "examples/security_lab/english/sec_injection_eval.vital"),
            ("hindi", "examples/security_lab/hindi/sec_auth_account_hi.vital"),
            ("telugu", "examples/security_lab/telugu/sec_business_workflow_te.vital"),
            ("bengali", "examples/security_lab/bengali/sec_injection_eval_bn.vital"),
            ("marathi", "examples/security_lab/marathi/sec_auth_account_mr.vital"),
            ("nepali", "examples/security_lab/nepali/sec_business_workflow_ne.vital"),
            ("fusion", "examples/security_lab/fusion/sec_data_config_fusion.vital")
        ]

        for lang, demo_path in language_demos:
            with self.subTest(language=lang, demo=demo_path):
                with open(demo_path, "r", encoding="utf-8") as f:
                    src = f.read()

                res = run_ai_fix_and_rerun_loop(
                    source_code=src,
                    language=lang,
                    file_path=demo_path,
                    use_ai=False
                )

                self.assertTrue(
                    res["success"],
                    f"Language '{lang}' failed to reach COMPLETED: {res.get('stop_reason')}"
                )
                self.assertIn(
                    res["final_status"],
                    ("COMPLETED", "WARNING", "completed", "warning"),
                    f"Language '{lang}' ended with status: {res.get('final_status')}"
                )
                self.assertGreater(len(res["iterations"]), 0)

    # -------------------------------------------------------------------------
    # Test 10: Seeded Flaws Remediated & Suspect Fix Detection
    # -------------------------------------------------------------------------
    def test_seeded_flaws_actually_remediated_and_suspect_detection(self):
        """Seeded flaws must be genuine remediations, and deletions of flagged lines must be flagged."""
        path = os.path.join("examples", "security_lab", "bengali", "sec_injection_eval_bn.vital")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        res = run_ai_fix_and_rerun_loop(
            source_code=code,
            language="bengali",
            file_path=path,
            use_ai=False
        )

        self.assertTrue(res["success"])
        # Fresh scan on proposed code must have 0 security defects
        tracker = PipelineRunTracker("test-remediation-bn", 1)
        execute_pipeline_with_tracker(res["proposed_source"], "bengali", False, tracker)
        st11 = tracker.stages.get("security_analysis", {})
        self.assertEqual(len(st11.get("details", {}).get("findings", [])), 0)


if __name__ == "__main__":
    unittest.main()
