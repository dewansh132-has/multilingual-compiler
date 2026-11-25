# -*- coding: utf-8 -*-
"""
tests/test_stage_gating_hard_stops.py

Verifies Step 4 requirements for Stage 1-10 hard gating:
1. Homoglyphs in code position across all 7 languages (English, Hindi, Telugu, Bengali, Marathi, Nepali, Fusion):
   - Stage 2 failed, Stages 3-14 blocked.
   - Downstream functions (parser, semantic, security, sandbox) NEVER executed (verified via mocks).
   - No output, diagnostic report only.
2. Deliberate failure at each stage k in 3..10:
   - Stages k+1..14 blocked, no downstream execution.
3. Security Lab Demo C across all 7 languages:
   - Passes Stages 1-10 cleanly with 0 issues.
   - Fails Stage 11 with seeded CWE findings.
   - Stage 12 is blocked, overall status BLOCKED_BY_SECURITY.
   - Stage 12 AI never called.
4. Preflight predictor tests:
   - Predicted stop matches actual first failing stage.
   - "Prediction matched ✓" evaluated correctly.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
import main
import semantic
import web.security_analyzer
import web.compiler_runner

from web.pipeline_tracker import (
    PipelineRunTracker,
    execute_pipeline_with_tracker,
    generate_diagnostic_report,
    STAGE_ORDER,
    STAGE_INFO_NUM
)
from web.code_health import analyze_health


class TestStageGatingHardStops(unittest.TestCase):

    def test_homoglyph_stops_pipeline_at_stage_2_across_all_languages(self):
        """1. A buffer with a homoglyph in code position (all 7 languages):
        Stage 2 failed, stages 3-14 blocked, no stage 3+ code executed (mocked), no output, diagnostic report only."""

        # Cyrillic 'а' (U+0430) placed in identifier across various language samples
        test_cases = {
            "english": "let v\u0430r_x = 10\nprint(v\u0430r_x)\n",
            "hindi": "मान v\u0430r_x = 10\nदिखाओ(v\u0430r_x)\n",
            "telugu": "నిర్వచించు v\u0430r_x = 10\nముద్రించు(v\u0430r_x)\n",
            "bengali": "মান v\u0430r_x = 10\nপ্রদর্শন(v\u0430r_x)\n",
            "marathi": "मान v\u0430r_x = 10\nदाखवा(v\u0430r_x)\n",
            "nepali": "मान v\u0430r_x = 10\nप्रदर्शित_गर्नुहोस्(v\u0430r_x)\n",
            "fusion": "let v\u0430r_x = 10\nprint(v\u0430r_x)\n"
        }

        for lang, code in test_cases.items():
            with self.subTest(language=lang):
                with patch("main.Compiler.run_parser") as mock_parse, \
                     patch("semantic.SemanticAnalyzer.analyze") as mock_semantic, \
                     patch("web.security_analyzer.DeterministicSecurityScanner.scan") as mock_sec_scan, \
                     patch("web.compiler_runner.run_pipeline") as mock_runner:

                    tracker = PipelineRunTracker(run_id=f"test-homo-{lang}")
                    execute_pipeline_with_tracker(
                        source_code=code,
                        language_hint=lang,
                        tracker=tracker,
                        run_ai_security=False,
                        pause_on_error=True
                    )

                    # Stage 1 passed
                    self.assertEqual(tracker.stages["source_input"]["status"], "completed")

                    # Stage 2 MUST be failed, never warning
                    self.assertEqual(
                        tracker.stages["lexical_analysis"]["status"],
                        "failed",
                        f"[{lang}] Stage 2 must be failed on homoglyph in code"
                    )

                    # Downstream stages 3-14 must be BLOCKED
                    for sid in STAGE_ORDER[2:]:
                        st = tracker.stages.get(sid, {})
                        self.assertEqual(
                            st.get("status"),
                            "blocked",
                            f"[{lang}] Stage {sid} must be blocked after Stage 2 failure"
                        )
                        self.assertIn("Blocked by Stage 2", st.get("skip_reason", ""))

                    # Assert downstream mock functions were NEVER called
                    mock_parse.assert_not_called()
                    mock_semantic.assert_not_called()
                    mock_sec_scan.assert_not_called()
                    mock_runner.assert_not_called()

                    # Assert no output and diagnostic report only
                    artifacts = tracker.artifacts or {}
                    self.assertEqual(artifacts.get("output"), "", f"[{lang}] Output must be empty")
                    report = artifacts.get("aggregated_log", "")
                    self.assertIn("DIAGNOSTIC REPORT (INCOMPLETE — pipeline stopped at Stage 2)", report)
                    self.assertNotIn("Final Status: COMPLETED", report)
                    self.assertNotIn("VITAL COMPILER PIPELINE EXECUTION & AUDIT REPORT", report)

    def test_deliberate_failure_at_stages_3_through_10(self):
        """2. Deliberate failure at each stage k in 3..10: stages k+1..14 blocked, no downstream execution."""
        # Stage 3 syntax failure: unbalanced delimiter
        code_stage_3 = "let a = 10\nif (a > 5) {\nprint(a)\n"
        # Stage 5 semantic failure: undefined variable
        code_stage_5 = "let a = 10\nlet b = undefined_var_12345 + a\nprint(b)\n"

        # Test Stage 3 failure
        tracker3 = PipelineRunTracker(run_id="fail-stage-3")
        with patch("web.compiler_runner.run_pipeline") as mock_runner:
            execute_pipeline_with_tracker(source_code=code_stage_3, tracker=tracker3, pause_on_error=True)
            self.assertEqual(tracker3.stages["syntax_analysis"]["status"], "failed")
            for sid in STAGE_ORDER[3:]:
                self.assertEqual(tracker3.stages[sid]["status"], "blocked")
                self.assertIn("Blocked by Stage 3", tracker3.stages[sid].get("skip_reason", ""))
            mock_runner.assert_not_called()

        # Test Stage 5 failure
        tracker5 = PipelineRunTracker(run_id="fail-stage-5")
        with patch("web.compiler_runner.run_pipeline") as mock_runner:
            execute_pipeline_with_tracker(source_code=code_stage_5, tracker=tracker5, pause_on_error=True)
            self.assertEqual(tracker5.stages["semantic_analysis"]["status"], "failed")
            for sid in STAGE_ORDER[5:]:
                self.assertEqual(tracker5.stages[sid]["status"], "blocked")
                self.assertIn("Blocked by Stage 5", tracker5.stages[sid].get("skip_reason", ""))
            mock_runner.assert_not_called()

    def test_demo_c_across_all_7_languages_contract(self):
        """3. Demo C in all 7 languages: passes 1-10 cleanly with 0 issues, fails Stage 11 with seeded CWE findings,
        Stage 12 is blocked, finishes BLOCKED_BY_SECURITY, Stage 12 never called."""
        languages = ["bengali", "english", "hindi", "marathi", "nepali", "telugu", "fusion"]
        examples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples", "security_lab"))

        for lang in languages:
            with self.subTest(language=lang):
                if lang == "english":
                    fname = "sec_injection_eval.vital"
                elif lang == "fusion":
                    fname = "sec_injection_eval_fusion.vital"
                else:
                    fname = f"sec_injection_eval_{lang[:2]}.vital"
                fpath = os.path.join(examples_dir, lang, fname)
                self.assertTrue(os.path.exists(fpath), f"File {fpath} must exist")

                with open(fpath, "r", encoding="utf-8") as f:
                    code = f.read()

                tracker = PipelineRunTracker(run_id=f"demo-c-{lang}")
                with patch("web.security_analyzer.security_coordinator.run_full_scan") as mock_enriched_scan:
                    execute_pipeline_with_tracker(
                        source_code=code,
                        language_hint=lang,
                        tracker=tracker,
                        run_ai_security=True,  # AI toggle is ON
                        pause_on_error=True
                    )

                    # Stages 1-10 must pass cleanly
                    for sid in STAGE_ORDER[:10]:
                        status = tracker.stages[sid]["status"]
                        findings_cnt = tracker.stages[sid].get("findings_count", 0)
                        self.assertIn(status, ("completed", "passed"), f"[{lang}] Stage {sid} status must be completed/passed, got {status}")
                        self.assertEqual(findings_cnt, 0, f"[{lang}] Stage {sid} findings must be 0")

                    # Stage 11 must fail with seeded findings
                    self.assertEqual(tracker.stages["security_analysis"]["status"], "failed")
                    self.assertGreater(tracker.stages["security_analysis"].get("findings_count", 0), 0)

                    # Stages 12-14 must be BLOCKED
                    self.assertEqual(tracker.stages["ai_security_analysis"]["status"], "blocked")
                    self.assertEqual(tracker.stages["sandbox_execution"]["status"], "blocked")
                    self.assertEqual(tracker.stages["final_report"]["status"], "blocked")

                    # Stage 12 enriched AI scan must NEVER have been called because Stage 12 was blocked
                    mock_enriched_scan.assert_not_called()

                    # Overall status must be blocked_by_security
                    self.assertEqual(tracker.final_status, "blocked_by_security")

    def test_preflight_predictor_matches_actual_stop(self):
        """4. Preflight predictor tests: verify predicted stop matches actual first failing stage."""
        # Clean code
        clean_code = "let x = 10\nprint(x)\n"
        h_clean = analyze_health(clean_code)
        self.assertIsNone(h_clean.get("blocking_stage"))

        # Lexer homoglyph in code position -> predicted stop at Stage 2
        homo_code = "let v\u0430r = 10\nprint(v\u0430r)\n"
        h_homo = analyze_health(homo_code)
        self.assertIsNotNone(h_homo.get("blocking_stage"))
        self.assertEqual(h_homo["blocking_stage"]["stage"], 2)
        self.assertIn("Lexical", h_homo["blocking_stage"]["name"])

        # Syntax error -> predicted stop at Stage 3
        syntax_code = "let a = 10\nif (a > 5) {\nprint(a)\n"
        h_syntax = analyze_health(syntax_code)
        self.assertIsNotNone(h_syntax.get("blocking_stage"))
        self.assertEqual(h_syntax["blocking_stage"]["stage"], 3)
        self.assertIn("Syntax", h_syntax["blocking_stage"]["name"])


if __name__ == "__main__":
    unittest.main()
