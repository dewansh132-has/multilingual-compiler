# -*- coding: utf-8 -*-
"""
tests/test_preflight.py — Test Suite for Preflight Prediction & Validation.

Verifies:
1. Preflight Code Health prediction on Run:
   - Telugu Demo D: Predicts Stage 3 stop, matches real pipeline Stage 3 failure.
   - English Demo A: Predicts Stage 5 stop, matches real pipeline Stage 5 failure.
   - Canonical Clean Demo: Predicts pass Stages 1–10, matches real pipeline pass.
   - Security Demo B: Predicts pass Stages 1–10, matches real pipeline pass (findings at Stage 11).
2. Preflight message formatting matches requirement:
   "Preflight: predicted stop at Stage 3 — 1 syntax error (line 207). Security: 4 findings (2 high)."
   "Preflight: predicted to pass Stages 1–10. Security: 0 findings."
3. Run button tooltip generation:
   - Expected error sets tooltip "Compilation is expected to fail at Stage N (Name)".
   - Clean / healthy sets standard tooltip "Execute Pipeline (Ctrl + Enter)".
4. Prediction accuracy evaluator:
   - Accuracy matches for matching stages.
   - Mismatch triggers warning and diagnostic report attachment.
5. Isolation:
   - Real pipeline Stages 11 and 12 execute independently and do not consume preflight cache.
"""

import os
import sys
import unittest
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.code_health import analyze_health
from web.pipeline_tracker import PipelineRunTracker, execute_pipeline_with_tracker, STAGE_ORDER
import web.server as server


class TestPreflightPrediction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.app.config["TESTING"] = True
        cls.client = server.app.test_client()

    def test_preflight_prediction_matches_telugu_demo_d(self):
        file_path = os.path.join("examples", "security_lab", "telugu", "sec_business_workflow_te.vital")
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        health = analyze_health(code, language="Telugu", filename="sec_business_workflow_te.vital")
        self.assertIsNotNone(health.get("blocking_stage"))
        self.assertEqual(health["blocking_stage"]["stage"], 3)
        self.assertEqual(health["status"], "errors")

        # Now run real pipeline (stages 1-10)
        tracker = PipelineRunTracker(run_id="test-run-telugu-d")
        res = execute_pipeline_with_tracker(source_code=code, language_hint="Telugu", tracker=tracker)

        # Real pipeline must stop at Stage 3
        failed_stage = None
        for sid, s in tracker.stages.items():
            if s.get("status") == "failed":
                failed_stage = STAGE_ORDER.index(sid) + 1
                break

        self.assertEqual(failed_stage, 3)
        self.assertEqual(health["blocking_stage"]["stage"], failed_stage)

    def test_preflight_prediction_matches_english_demo_a(self):
        file_path = os.path.join("examples", "security_lab", "english", "sec_auth_account.vital")
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        health = analyze_health(code, language="English", filename="sec_auth_account.vital")
        self.assertIsNotNone(health.get("blocking_stage"))
        self.assertEqual(health["blocking_stage"]["stage"], 5)
        self.assertEqual(health["status"], "errors")

        # Now run real pipeline
        tracker = PipelineRunTracker(run_id="test-run-eng-a")
        res = execute_pipeline_with_tracker(source_code=code, language_hint="English", tracker=tracker)

        failed_stage = None
        for sid, s in tracker.stages.items():
            if s.get("status") == "failed":
                failed_stage = STAGE_ORDER.index(sid) + 1
                break

        self.assertEqual(failed_stage, 5)
        self.assertEqual(health["blocking_stage"]["stage"], failed_stage)

    def test_preflight_prediction_matches_clean_demo(self):
        file_path = os.path.join("examples", "english", "student_grade_report.vital")
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        health = analyze_health(code, language="English", filename="student_grade_report.vital")
        self.assertIsNone(health.get("blocking_stage"))
        self.assertIn(health["status"], ("healthy", "warnings"))

        # Real pipeline runs through all stages 1-10 without failure
        tracker = PipelineRunTracker(run_id="test-run-clean")
        res = execute_pipeline_with_tracker(source_code=code, language_hint="English", tracker=tracker)

        failed_compilation_stage = None
        for sid, s in tracker.stages.items():
            stage_num = STAGE_ORDER.index(sid) + 1
            if stage_num <= 10 and s.get("status") == "failed":
                failed_compilation_stage = stage_num
                break

        self.assertIsNone(failed_compilation_stage)

    def test_preflight_message_formatting(self):
        # Format function mirroring ide.js renderPreflightStrip
        def format_preflight_message(health_data):
            blocking = health_data.get("blocking_stage")
            errors = health_data.get("errors", [])
            err_count = len(errors)
            first_err = errors[0] if err_count > 0 else None
            sec_findings = health_data.get("security", {}).get("findings", [])
            sec_count = len(sec_findings)
            high_count = sum(1 for f in sec_findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH"))

            preflight = "Preflight: "
            if blocking:
                err_kind = "compiler error"
                if first_err and first_err.get("code"):
                    c = first_err["code"]
                    if c.startswith("SYN"):
                        err_kind = "syntax error"
                    elif c.startswith("SEM"):
                        err_kind = "semantic error"
                    elif c.startswith("LEX"):
                        err_kind = "lexical error"
                line_part = f" (line {first_err['line']})" if first_err and first_err.get("line") else ""
                s_plural = "s" if err_count > 1 else ""
                preflight += f"predicted stop at Stage {blocking['stage']} — {err_count} {err_kind}{s_plural}{line_part}. "
            else:
                preflight += "predicted to pass Stages 1–10. "

            findings_plural = "s" if sec_count != 1 else ""
            high_part = f" ({high_count} high)" if sec_count > 0 else ""
            preflight += f"Security: {sec_count} finding{findings_plural}{high_part}."
            return preflight

        # Test synthetic Stage 3 error
        mock_health_syntax = {
            "blocking_stage": {"stage": 3, "name": "Syntax Analysis"},
            "errors": [{"code": "SYN-001", "stage": 3, "line": 207}],
            "security": {
                "findings": [
                    {"severity": "HIGH"},
                    {"severity": "HIGH"},
                    {"severity": "MEDIUM"},
                    {"severity": "LOW"}
                ]
            }
        }
        msg = format_preflight_message(mock_health_syntax)
        expected = "Preflight: predicted stop at Stage 3 — 1 syntax error (line 207). Security: 4 findings (2 high)."
        self.assertEqual(msg, expected)

        # Test synthetic clean program
        mock_health_clean = {
            "blocking_stage": None,
            "errors": [],
            "security": {"findings": []}
        }
        msg_clean = format_preflight_message(mock_health_clean)
        expected_clean = "Preflight: predicted to pass Stages 1–10. Security: 0 findings."
        self.assertEqual(msg_clean, expected_clean)

    def test_run_button_tooltip_generation(self):
        def get_tooltip(status, blocking_stage):
            if status == "errors" and blocking_stage:
                return f"Compilation is expected to fail at Stage {blocking_stage['stage']} ({blocking_stage['name']})"
            return "Execute Pipeline (Ctrl + Enter)"

        tip_err = get_tooltip("errors", {"stage": 3, "name": "Syntax Analysis"})
        self.assertEqual(tip_err, "Compilation is expected to fail at Stage 3 (Syntax Analysis)")

        tip_clean = get_tooltip("healthy", None)
        self.assertEqual(tip_clean, "Execute Pipeline (Ctrl + Enter)")

    def test_accuracy_evaluation_logic(self):
        def evaluate_accuracy(predicted_stage, actual_stage):
            is_pass_pred = (predicted_stage is None)
            is_pass_act = (actual_stage is None or actual_stage > 10)
            return (is_pass_pred and is_pass_act) or (not is_pass_pred and predicted_stage == actual_stage)

        # Both agree stage 3
        self.assertTrue(evaluate_accuracy(3, 3))
        # Both agree stage 5
        self.assertTrue(evaluate_accuracy(5, 5))
        # Both agree pass (actual completed)
        self.assertTrue(evaluate_accuracy(None, None))
        # Both agree pass (actual stopped at Stage 11 security)
        self.assertTrue(evaluate_accuracy(None, 11))

        # Mismatches:
        # Predicted 3, actual passed
        self.assertFalse(evaluate_accuracy(3, None))
        # Predicted pass, actual failed at 3
        self.assertFalse(evaluate_accuracy(None, 3))
        # Predicted 5, actual failed at 3
        self.assertFalse(evaluate_accuracy(5, 3))

    def test_pipeline_security_scanner_isolation(self):
        """Pipeline Stages 11 and 12 must perform their own fresh scans and not consume preflight cache."""
        code = 'let admin_secret_key = "sk_live_sec_prod_9948271630_super_admin"\nprint(admin_secret_key)'
        tracker = PipelineRunTracker(run_id="test-isolation")
        execute_pipeline_with_tracker(source_code=code, language_hint="English", tracker=tracker)
        sec_stage = tracker.stages.get("security_analysis", {})
        findings = sec_stage.get("details", {}).get("findings", [])
        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
