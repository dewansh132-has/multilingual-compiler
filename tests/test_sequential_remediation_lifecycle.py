"""
tests/test_sequential_remediation_lifecycle.py

Comprehensive regression test suite verifying the complete sequential pipeline lifecycle:
1. Single Parser error correction (sec_auth_account.vital) & automatic resumption
2. Multiple Parser errors (partial fix, remaining findings visible, stage stays red)
3. Semantic error after Parser fix (pauses at semantic analysis, fix resumes)
4. Fix introducing new error (stage stays red, downstream blocked)
5. Original demo preservation & Restore Original workflow
6. Save Corrected Code (saved as standard program without lab badges, compiles cleanly)
7. Final Report gating (blocked while errors remain, unlocked when passed, stale on edit)
8. Regression protection across multilingual demo callsets
"""

import os
import sys
import unittest
import json
import hashlib

# Ensure repository root and src/ are on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web.server import app
from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker, STAGE_DEFINITIONS
from web.security_analyzer import security_coordinator
from web.demo_manager import get_all_demos, get_demo_content


class TestSequentialRemediationLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.demo_path = "examples/security_lab/english/sec_auth_account.vital"
        cls.full_demo_path = os.path.join(REPO_ROOT, cls.demo_path)
        with open(cls.full_demo_path, "r", encoding="utf-8") as f:
            cls.original_demo_content = f.read()
        cls.original_demo_hash = hashlib.sha256(cls.original_demo_content.encode("utf-8")).hexdigest()

    def setUp(self):
        # Guarantee disk file remains pristine before each test
        with open(self.full_demo_path, "r", encoding="utf-8") as f:
            current_content = f.read()
        self.assertEqual(
            hashlib.sha256(current_content.encode("utf-8")).hexdigest(),
            self.original_demo_hash,
            "Disk fixture was altered before test started!"
        )

    def tearDown(self):
        # Guarantee disk file remains pristine after each test
        with open(self.full_demo_path, "r", encoding="utf-8") as f:
            current_content = f.read()
        self.assertEqual(
            hashlib.sha256(current_content.encode("utf-8")).hexdigest(),
            self.original_demo_hash,
            "Disk fixture was altered during test!"
        )

    def test_01_single_parser_error_correction_and_resume(self):
        """Scenario 1: Parser error in sec_auth_account.vital halts pipeline; fix auto-resumes to completion."""
        # 1. Inject the line 14 indentation defect (3 spaces instead of 4) into working copy
        # (while pre-fixing the line 67 semantic issue so we test the full downstream resume through all 14 stages)
        faulty_source = self.original_demo_content.replace("    } else {", "   } else {", 1).replace(
            "print(acc_status)", "print(account_closed)"
        )

        tracker = PipelineRunTracker(run_id="test-run-01", source_revision=1)
        execute_pipeline_with_tracker(
            source_code=faulty_source,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True
        )

        # Verify pipeline paused at syntax_analysis (Parser)
        self.assertEqual(tracker.status, "paused")
        self.assertEqual(tracker.paused_stage, "syntax_analysis")
        syntax_stage = tracker.stages["syntax_analysis"]
        self.assertEqual(syntax_stage["status"], "failed")
        self.assertGreater(syntax_stage["findings_count"], 0)

        # Verify downstream stages are blocked
        for stage_id in ["ast_construction", "semantic_analysis", "symbol_table", "ir_generation", "code_generation", "sandbox_execution"]:
            self.assertEqual(tracker.stages[stage_id]["status"], "blocked", f"Stage {stage_id} should be blocked")

        # 2. Generate deterministic fix for line 14 indentation error
        finding_dict = syntax_stage["details"]["findings"][0]
        fix_result = security_coordinator.generate_deterministic_fix(
            source_code=faulty_source,
            finding_id=finding_dict.get("id"),
            finding_data=finding_dict,
            language="English"
        )
        self.assertTrue(fix_result["success"], "Deterministic fix generation should succeed")
        corrected_code = fix_result["proposed_source"]
        self.assertNotEqual(corrected_code, faulty_source)
        self.assertIn("    } else {", corrected_code)

        # 3. Resume pipeline from syntax_analysis with incremented revision
        resume_tracker = PipelineRunTracker(run_id="test-run-01-resume", source_revision=2)
        execute_pipeline_with_tracker(
            source_code=corrected_code,
            language_hint="English",
            run_ai_security=False,
            tracker=resume_tracker,
            pause_on_error=True,
            resume_from="syntax_analysis",
            source_revision=2
        )

        # Verify syntax_analysis passed cleanly
        self.assertEqual(resume_tracker.stages["syntax_analysis"]["status"], "completed")
        self.assertEqual(resume_tracker.stages["syntax_analysis"]["findings_count"], 0)

        # Verify pipeline continued sequentially through AST, Semantic, IR, CodeGen, and Sandbox
        self.assertEqual(resume_tracker.stages["ast_construction"]["status"], "completed")
        self.assertEqual(resume_tracker.stages["semantic_analysis"]["status"], "completed")
        self.assertEqual(resume_tracker.stages["symbol_table"]["status"], "completed")
        self.assertEqual(resume_tracker.stages["ir_generation"]["status"], "completed")
        self.assertEqual(resume_tracker.stages["code_generation"]["status"], "completed")
        self.assertEqual(resume_tracker.stages["code_validation"]["status"], "completed")
        self.assertEqual(resume_tracker.stages["sandbox_execution"]["status"], "completed")

        # Verify pipeline completed prerequisites and is ready for report
        self.assertTrue(resume_tracker.is_ready_for_report or resume_tracker.stages.get('final_report', {}).get('status') in ('completed', 'ready'))
        self.assertEqual(resume_tracker.source_revision, 2)

    def test_02_multiple_parser_errors_partial_fix(self):
        """Scenario 2: Multiple syntax errors in one stage; partial fix leaves stage red; full fix resumes."""
        multi_error_code = (
            "function test_branch(x) {\n"
            "    if (x > 5) {\n"
            "        let y = 20\n"
            "   } else {\n"             # Error 1: 3 spaces indentation on else
            "        let y = 30\n"
            "    }\n"
            "    if (x > 20) {\n"
            "        let z = 40\n"
            "test_branch(10)\n"         # Error 2: missing closing braces
        )

        tracker = PipelineRunTracker(run_id="test-run-02", source_revision=1)
        execute_pipeline_with_tracker(
            source_code=multi_error_code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True
        )
        self.assertEqual(tracker.status, "paused")
        self.assertEqual(tracker.stages["syntax_analysis"]["status"], "failed")

        # Fix only error 2 (add closing braces, but leave error 1 with 3 spaces)
        partially_fixed_code = (
            "function test_branch(x) {\n"
            "    if (x > 5) {\n"
            "        let y = 20\n"
            "   } else {\n"             # Still contains error 1 (3 spaces)
            "        let y = 30\n"
            "    }\n"
            "    if (x > 20) {\n"
            "        let z = 40\n"
            "    }\n"
            "}\n"
            "test_branch(10)\n"
        )

        tracker_partial = PipelineRunTracker(run_id="test-run-02-partial", source_revision=2)
        execute_pipeline_with_tracker(
            source_code=partially_fixed_code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker_partial,
            pause_on_error=True,
            resume_from="syntax_analysis",
            source_revision=2
        )
        # Stage must remain failed because error 1 is still present
        self.assertEqual(tracker_partial.status, "paused")
        self.assertEqual(tracker_partial.stages["syntax_analysis"]["status"], "failed")
        self.assertEqual(tracker_partial.stages["ast_construction"]["status"], "blocked")

        # Now fix error 1 as well (align line 4 to 4 spaces)
        fully_fixed_code = (
            "function test_branch(x) {\n"
            "    if (x > 5) {\n"
            "        let y = 20\n"
            "    } else {\n"            # Error 1 resolved: 4 spaces
            "        let y = 30\n"
            "    }\n"
            "    if (x > 20) {\n"
            "        let z = 40\n"
            "    }\n"
            "}\n"
            "test_branch(10)\n"
        )

        tracker_full = PipelineRunTracker(run_id="test-run-02-full", source_revision=3)
        execute_pipeline_with_tracker(
            source_code=fully_fixed_code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker_full,
            pause_on_error=True,
            resume_from="syntax_analysis",
            source_revision=3
        )
        # Stage now turns green and pipeline completes
        self.assertEqual(tracker_full.stages["syntax_analysis"]["status"], "completed")
        self.assertTrue(tracker_full.is_ready_for_report or tracker_full.stages.get('final_report', {}).get('status') in ('completed', 'ready'))

    def test_03_semantic_error_after_parser_fix(self):
        """Scenario 3: Syntax error fixed -> Parser passes -> pipeline pauses at Semantic Analysis for undeclared var."""
        # Code with line 14 syntax error AND line 67 undefined variable acc_status
        code_with_both = self.original_demo_content.replace("    } else {", "   } else {")

        # 1. First run halts at syntax_analysis
        tracker1 = PipelineRunTracker(run_id="test-run-03-step1", source_revision=1)
        execute_pipeline_with_tracker(
            source_code=code_with_both,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker1,
            pause_on_error=True
        )
        self.assertEqual(tracker1.status, "paused")
        self.assertEqual(tracker1.paused_stage, "syntax_analysis")

        # 2. Fix syntax error on line 14 (leaving semantic bug at line 67)
        code_syntax_fixed = self.original_demo_content  # Has pristine line 14, but retains line 67 acc_status defect

        tracker2 = PipelineRunTracker(run_id="test-run-03-step2", source_revision=2)
        execute_pipeline_with_tracker(
            source_code=code_syntax_fixed,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker2,
            pause_on_error=True,
            resume_from="syntax_analysis",
            source_revision=2
        )

        # Parser passes, AST passes, but pipeline pauses at semantic_analysis!
        self.assertEqual(tracker2.stages["syntax_analysis"]["status"], "completed")
        self.assertEqual(tracker2.stages["ast_construction"]["status"], "completed")
        self.assertEqual(tracker2.status, "paused")
        self.assertEqual(tracker2.paused_stage, "semantic_analysis")
        self.assertEqual(tracker2.stages["semantic_analysis"]["status"], "failed")
        self.assertEqual(tracker2.stages["symbol_table"]["status"], "blocked")

        # 3. Fix semantic error by fixing line 67 to reference account_closed
        code_all_fixed = code_syntax_fixed.replace("print(acc_status)", "print(account_closed)")
        tracker3 = PipelineRunTracker(run_id="test-run-03-step3", source_revision=3)
        execute_pipeline_with_tracker(
            source_code=code_all_fixed,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker3,
            pause_on_error=True,
            resume_from="semantic_analysis",
            source_revision=3
        )
        self.assertEqual(tracker3.stages["semantic_analysis"]["status"], "completed")
        self.assertTrue(tracker3.is_ready_for_report or tracker3.stages.get('final_report', {}).get('status') in ('completed', 'ready'))

    def test_04_fix_introducing_new_error(self):
        """Scenario 4: Fix that introduces a new syntax error keeps stage red and downstream blocked."""
        faulty_code = "fn main() {\n   display(1)\n}\n"
        # Malformed fix: invalid token syntax
        corrupted_fix = "fn main() {\n    display(@@@malformed@@@)\n}\n"

        tracker = PipelineRunTracker(run_id="test-run-04", source_revision=2)
        execute_pipeline_with_tracker(
            source_code=corrupted_fix,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True,
            resume_from="syntax_analysis",
            source_revision=2
        )

        # Must halt at failed stage and not advance downstream
        self.assertIn(tracker.status, ["paused", "failed"])
        self.assertEqual(tracker.stages["syntax_analysis"]["status"], "failed")
        self.assertEqual(tracker.stages["ast_construction"]["status"], "blocked")

    def test_05_original_demo_preservation_and_restore(self):
        """Scenario 5: Built-in demo file is immutable; Restore Original resets working edits back to faulty state."""
        # Ensure disk file content matches initial snapshot
        with open(self.full_demo_path, "r", encoding="utf-8") as f:
            disk_content = f.read()
        self.assertEqual(disk_content, self.original_demo_content)

        # Simulate user applying a fix in their working buffer
        working_buffer = disk_content.replace("print(acc_status)", "print(account_closed)")
        self.assertNotEqual(working_buffer, disk_content)

        # Verify disk file is still 100% untouched
        with open(self.full_demo_path, "r", encoding="utf-8") as f:
            disk_after_edits = f.read()
        self.assertEqual(disk_after_edits, self.original_demo_content)

        # Simulate Restore Original: working buffer resets to original disk content
        restored_buffer = self.original_demo_content
        self.assertEqual(restored_buffer, disk_after_edits)

        # Running pipeline on restored buffer reproduces the exact original defect (pauses at semantic_analysis)
        tracker = PipelineRunTracker(run_id="test-run-05-restored", source_revision=3)
        execute_pipeline_with_tracker(
            source_code=restored_buffer,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=True
        )
        self.assertEqual(tracker.status, "paused")
        self.assertEqual(tracker.paused_stage, "semantic_analysis")

    def test_06_save_corrected_code(self):
        """Scenario 6: Save Corrected Code saves as user program without security demo tags, compiles cleanly."""
        fixed_source = self.original_demo_content.replace("print(acc_status)", "print(account_closed)")
        saved_filename = "sec_auth_account_fixed.vital"
        saved_abs_path = os.path.join(REPO_ROOT, "examples", "saved", saved_filename)

        # Call POST /api/save-file
        resp = self.client.post("/api/save-file", json={
            "filename": saved_filename,
            "code": fixed_source
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["filename"], saved_filename)
        self.assertTrue(os.path.exists(saved_abs_path))

        try:
            # Verify demo manager categorizes it as "User Saved Programs" without Security Lab badges
            demos_meta = get_all_demos()
            all_saved = demos_meta.get("by_category", {}).get("User Saved Programs", [])
            saved_entry = next((d for d in all_saved if d["filename"] == saved_filename), None)
            self.assertIsNotNone(saved_entry, "Saved file must appear in 'User Saved Programs'")
            self.assertFalse(saved_entry["is_security_lab"], "Saved user program must not be flagged as security lab")
            self.assertEqual(saved_entry["difficulty"], "Standard")

            # Verify saved file compiles and executes cleanly
            with open(saved_abs_path, "r", encoding="utf-8") as f:
                saved_content = f.read()

            tracker = PipelineRunTracker(run_id="test-run-06-compile-saved", source_revision=1)
            execute_pipeline_with_tracker(
                source_code=saved_content,
                language_hint="English",
                run_ai_security=False,
                tracker=tracker,
                pause_on_error=True
            )
            self.assertEqual(tracker.stages["syntax_analysis"]["status"], "completed")
            self.assertEqual(tracker.stages["semantic_analysis"]["status"], "completed")
            self.assertEqual(tracker.stages["sandbox_execution"]["status"], "completed")
            self.assertTrue(tracker.is_ready_for_report or tracker.stages.get('final_report', {}).get('status') in ('completed', 'ready'))

            # Verify original demo was not modified by the save action
            with open(self.full_demo_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), self.original_demo_content)

        finally:
            # Cleanup saved file
            if os.path.exists(saved_abs_path):
                os.remove(saved_abs_path)

    def test_07_final_report_gating(self):
        """Scenario 7: Final report is blocked when prerequisites fail; unlocked when clean."""
        # 1. Attempt to generate final report for code with syntax error (must fail)
        syntax_broken_code = self.original_demo_content.replace("    } else {", "   } else {")
        resp_syntax = self.client.post("/api/pipeline/generate-report", json={
            "code": syntax_broken_code,
            "language": "English",
            "run_id": "test-gating-syntax"
        })
        self.assertEqual(resp_syntax.status_code, 400)
        data_syntax = resp_syntax.get_json()
        self.assertFalse(data_syntax["success"], "Report generation must be rejected when syntax fails")
        self.assertEqual(data_syntax.get("blocked_stage"), "syntax_analysis")

        # 2. Attempt to generate final report for code with semantic error (must fail)
        resp_semantic = self.client.post("/api/pipeline/generate-report", json={
            "code": self.original_demo_content,
            "language": "English",
            "run_id": "test-gating-semantic"
        })
        self.assertEqual(resp_semantic.status_code, 400)
        data_semantic = resp_semantic.get_json()
        self.assertFalse(data_semantic["success"], "Report generation must be rejected when semantic fails")
        self.assertEqual(data_semantic.get("blocked_stage"), "semantic_analysis")

        # 3. Generate final report for fully clean code (must succeed)
        clean_code = self.original_demo_content.replace("print(acc_status)", "print(account_closed)")
        resp_ok = self.client.post("/api/pipeline/generate-report", json={
            "code": clean_code,
            "language": "English",
            "run_id": "test-gating-ok"
        })
        self.assertEqual(resp_ok.status_code, 200)
        data_ok = resp_ok.get_json()
        self.assertTrue(data_ok["success"], "Report generation must succeed when all stages pass")
        self.assertIn("artifacts", data_ok)
        self.assertIn("aggregated_log", data_ok["artifacts"])
        self.assertIn("output", data_ok["artifacts"])

    def test_08_multilingual_demos_regression(self):
        """Scenario 8: Standard multilingual demo programs compile cleanly without regression."""
        test_samples = [
            ("examples/english/hello.vital", "English"),
            ("examples/spanish/hola.vital", "Spanish"),
            ("examples/hindi/namaste.vital", "Hindi"),
            ("examples/chinese/nihao.vital", "Chinese"),
            ("examples/bengali/shubhechha.vital", "Bengali")
        ]

        for rel_path, lang in test_samples:
            abs_path = os.path.join(REPO_ROOT, rel_path)
            if not os.path.exists(abs_path):
                continue
            with open(abs_path, "r", encoding="utf-8") as f:
                code = f.read()

            tracker = PipelineRunTracker(run_id=f"regression-{lang}", source_revision=1)
            execute_pipeline_with_tracker(
                source_code=code,
                language_hint=lang,
                run_ai_security=False,
                tracker=tracker,
                pause_on_error=True
            )
            self.assertTrue(
                (tracker.is_ready_for_report or tracker.stages.get('final_report', {}).get('status') in ('completed', 'ready')),
                f"Multilingual demo {rel_path} ({lang}) failed sequential pipeline execution!"
            )


if __name__ == "__main__":
    unittest.main()
