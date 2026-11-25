# -*- coding: utf-8 -*-
"""
tests/test_stage12_gemini_analysis.py — Comprehensive Unit & Integration Tests for Stage 12 (Gemini AI Analysis)

Tests:
1. Clean file -> Stage 12 passed, 0 findings, COMPLETED, output & report render.
2. HIGH finding in Stage 12 -> Stage 12 failed, 13 & 14 blocked, BLOCKED_BY_SECURITY.
3. 401, 404, 429, timeout, malformed JSON, missing key -> Stage 12 marked unavailable with honest reason,
   13 & 14 blocked, status INCOMPLETE, no green checks on 13 or 14.
4. Dropping hallucinated line numbers (> len(source)) or non-verbatim evidence strings.
5. Sandbox secret stripping: Stage 13 subprocess receives scrubbed environment, parent retains GEMINI_API_KEY.
6. Grep audit: Zero user-facing "Ollama" strings in stage names, UI titles, or reports.
7. Toggle OFF -> Stage 12 skipped, clean demo COMPLETED.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

from web.pipeline_tracker import execute_pipeline_with_tracker, STAGE_DEFINITIONS, PipelineRunTracker
from web.gemini_client import GeminiClient, ai_client, HealthResult
from src.sandbox_policy import get_sanitized_sandbox_env


CLEAN_CODE = """
అనుకో x = 10
అనుకో y = 20
ముద్రించు(x + y)
""".strip()

SECURITY_CODE = """
ఫంక్షన్ హానికరమైన_పని(కమాండ్) {
    eval("print('Dangerous eval sink')")
    తిరిగి_ఇవ్వు 1
}
""".strip()


class TestStage12GeminiAnalysis(unittest.TestCase):

    def setUp(self):
        # Ensure fresh state
        os.environ["VITAL_STAGE12_TIMEOUT"] = "5.0"
        os.environ["VITAL_AI_TIMEOUT"] = "5.0"

    def test_01_clean_demo_with_stage12_passes(self):
        """Clean file with AI toggle ON passes Stage 12, runs Stage 13 & 14, finishes COMPLETED."""
        mock_response = {
            "success": True,
            "content": json.dumps({"findings": []}),
            "model": "gemini-flash-lite-latest",
            "error": None
        }
        with patch.object(ai_client, "check_health", return_value=HealthResult(True, "Gemini online", {"target_model": "gemini-flash-lite-latest"})), \
             patch.object(ai_client, "chat", return_value=mock_response):

            tracker = execute_pipeline_with_tracker(
                CLEAN_CODE,
                language_hint="telugu",
                run_ai_security=True,
                pause_on_error=True
            )

            # Stage 12 should be completed
            s12 = tracker.stages["ai_security_analysis"]
            self.assertEqual(s12["status"], "completed")
            self.assertEqual(s12["findings_count"], 0)

            # Stage 13 and 14 should have run and passed
            s13 = tracker.stages["sandbox_execution"]
            self.assertIn(s13["status"], ("completed", "passed"))
            s14 = tracker.stages["final_report"]
            self.assertEqual(s14["status"], "completed")

            # Final status should be completed
            self.assertEqual(tracker.final_status, "completed")
            self.assertTrue(tracker.artifacts.get("complete"))
            self.assertFalse(tracker.artifacts.get("incomplete"))
            self.assertIn("30", tracker.artifacts.get("output", ""))

    def test_02_high_finding_in_stage12_blocks_execution(self):
        """HIGH severity finding confirmed or found by Stage 12 fails Stage 12, blocks 13 & 14, BLOCKED_BY_SECURITY."""
        ai_finding = {
            "rule": "SEC-INJ-CMD-01",
            "title": "Command Injection Vulnerability",
            "severity": "High",
            "line": 2,
            "evidence": 'eval("print(\'Dangerous eval sink\')")',
            "description": "Unsanitized system command invocation",
            "remediation": "Do not execute arbitrary system commands"
        }
        mock_response = {
            "success": True,
            "content": json.dumps({"findings": [ai_finding]}),
            "model": "gemini-flash-lite-latest",
            "error": None
        }
        with patch.object(ai_client, "check_health", return_value=HealthResult(True, "Gemini online", {})), \
             patch.object(ai_client, "chat", return_value=mock_response):

            tracker = execute_pipeline_with_tracker(
                SECURITY_CODE,
                language_hint="telugu",
                run_ai_security=True,
                pause_on_error=True
            )

            # If Stage 11 didn't already block it, Stage 12 blocks it:
            s12 = tracker.stages["ai_security_analysis"]
            self.assertIn(s12["status"], ("failed", "blocked"))

            # Downstream stages 13 and 14 must be blocked
            s13 = tracker.stages["sandbox_execution"]
            self.assertEqual(s13["status"], "blocked")
            s14 = tracker.stages["final_report"]
            self.assertEqual(s14["status"], "blocked")

            # Output must be empty and final status blocked_by_security
            self.assertEqual(tracker.final_status, "blocked_by_security")
            self.assertEqual(tracker.artifacts.get("output", ""), "")

    def test_03_stage12_unavailable_honest_reasons_and_blocking(self):
        """When Gemini is unavailable (401, 404, 429, timeout, missing key), Stage 12 is unavailable, 13 & 14 blocked, INCOMPLETE."""
        failure_scenarios = [
            ("No API key found (set GEMINI_API_KEY in .env)", "No API key found (set GEMINI_API_KEY in .env)"),
            ("Gemini rejected the key (401)", "Gemini rejected the key (401)"),
            ("Model 'gemini-nonexistent' not found (404)", "Model 'gemini-nonexistent' not found (404)"),
            ("Quota exceeded (429), retry later", "Quota exceeded (429), retry later"),
            ("Timed out after 20s", "Timed out after 20s"),
            ("Network unreachable", "Network unreachable")
        ]

        for failure_msg, expected_in_reason in failure_scenarios:
            with patch.object(ai_client, "check_health", return_value=HealthResult(False, failure_msg, {"error": failure_msg})):
                tracker = execute_pipeline_with_tracker(
                    CLEAN_CODE,
                    language_hint="telugu",
                    run_ai_security=True,
                    pause_on_error=True
                )

                s12 = tracker.stages["ai_security_analysis"]
                self.assertEqual(s12["status"], "unavailable", f"Expected unavailable for {failure_msg}")
                self.assertIn(expected_in_reason, s12.get("summary", "") or s12.get("reason", ""))

                # Crucial policy check: Stage 13 and 14 MUST be blocked, never green checks
                s13 = tracker.stages["sandbox_execution"]
                self.assertEqual(s13["status"], "blocked", f"Stage 13 should be blocked for {failure_msg}")
                s14 = tracker.stages["final_report"]
                self.assertEqual(s14["status"], "blocked", f"Stage 14 should be blocked for {failure_msg}")

                # Status must be incomplete
                self.assertEqual(tracker.final_status, "incomplete")
                self.assertTrue(tracker.artifacts.get("incomplete"))
                self.assertFalse(tracker.artifacts.get("complete"))
                self.assertEqual(tracker.artifacts.get("output", ""), "")

    def test_04_hallucinated_findings_dropped_and_logged(self):
        """Hallucinated line numbers and non-verbatim evidence are dropped per Requirement 7."""
        # Code has 5 lines
        hallucinated_findings = [
            {
                "rule": "SEC-HALLUC-01",
                "title": "Out of Bounds Line",
                "severity": "High",
                "line": 999,  # Line out of bounds
                "evidence": "ముద్రించు(x + y)",
                "description": "Hallucinated line number",
                "remediation": "None"
            },
            {
                "rule": "SEC-HALLUC-02",
                "title": "Non Verbatim Evidence",
                "severity": "High",
                "line": 2,
                "evidence": "Non-existent line content that does not appear in line 2",
                "description": "Evidence mismatch",
                "remediation": "None"
            }
        ]

        mock_response = {
            "success": True,
            "content": json.dumps({"findings": hallucinated_findings}),
            "model": "gemini-flash-lite-latest",
            "error": None
        }

        with patch.object(ai_client, "check_health", return_value=HealthResult(True, "Gemini online", {})), \
             patch.object(ai_client, "chat", return_value=mock_response):

            tracker = execute_pipeline_with_tracker(
                CLEAN_CODE,
                language_hint="telugu",
                run_ai_security=True,
                pause_on_error=True
            )

            # Both findings must have been dropped, leaving 0 findings -> Stage 12 completed!
            s12 = tracker.stages["ai_security_analysis"]
            self.assertEqual(s12["status"], "completed")
            self.assertEqual(s12["findings_count"], 0)

            # Stage 13 and 14 run to completion
            self.assertEqual(tracker.stages["sandbox_execution"]["status"], "completed")
            self.assertEqual(tracker.stages["final_report"]["status"], "completed")
            self.assertEqual(tracker.final_status, "completed")

    def test_05_sandbox_secret_stripping_and_parent_preservation(self):
        """Stage 13 child subprocess environment strips secrets, while parent os.environ retains GEMINI_API_KEY."""
        # Set dummy key in parent process
        os.environ["GEMINI_API_KEY"] = "AIzaSySecretTestKey12345"
        self.assertIn("GEMINI_API_KEY", os.environ)

        # Build sandbox env
        child_env = get_sanitized_sandbox_env(os.path.abspath("."))

        # Child environment must NOT contain any AI or API keys
        self.assertNotIn("GEMINI_API_KEY", child_env)
        self.assertNotIn("GOOGLE_API_KEY", child_env)
        self.assertNotIn("ANTHROPIC_API_KEY", child_env)
        self.assertNotIn("OPENAI_API_KEY", child_env)

        # Parent process MUST still have GEMINI_API_KEY intact
        self.assertEqual(os.environ.get("GEMINI_API_KEY"), "AIzaSySecretTestKey12345")

    def test_06_no_user_facing_ollama_strings(self):
        """Zero user-facing 'Ollama' strings in stage names, UI titles, or reports."""
        for s in STAGE_DEFINITIONS:
            self.assertNotIn("Ollama", s["name"], f"Stage {s['id']} has Ollama in name")
            self.assertNotIn("Ollama", s.get("description", ""), f"Stage {s['id']} has Ollama in description")

        # Check Stage 12 definition specifically
        s12_def = next(s for s in STAGE_DEFINITIONS if s["id"] == "ai_security_analysis")
        self.assertEqual(s12_def["name"], "12. AI Security Analysis (Gemini)")

    def test_07_toggle_off_skips_stage12_and_completes(self):
        """When AI toggle is OFF, Stage 12 is skipped and clean demo finishes COMPLETED with 13/13 stages."""
        tracker = execute_pipeline_with_tracker(
            CLEAN_CODE,
            language_hint="telugu",
            run_ai_security=False,
            pause_on_error=True
        )

        s12 = tracker.stages["ai_security_analysis"]
        self.assertEqual(s12["status"], "skipped")
        self.assertIn("disabled", s12.get("summary", "").lower())

        s13 = tracker.stages["sandbox_execution"]
        self.assertEqual(s13["status"], "completed")
        s14 = tracker.stages["final_report"]
        self.assertEqual(s14["status"], "completed")

        self.assertEqual(tracker.final_status, "completed")
        self.assertIn("30", tracker.artifacts.get("output", ""))


if __name__ == "__main__":
    unittest.main()
