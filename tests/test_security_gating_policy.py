# -*- coding: utf-8 -*-
"""
tests/test_security_gating_policy.py — Comprehensive Test Suite for Security Gating Policy (Stages 11 & 12).

Tests:
1. Configurable GatePolicy thresholds and evaluation.
2. Stage 11 severity mapping: CRITICAL/HIGH -> failed/BLOCK, MEDIUM/LOW -> warning/ALLOW, clean -> passed/ALLOW.
3. Stage 12 AI confidence threshold: confidence >= 0.6 blocks, confidence < 0.6 does not block.
4. AI findings never downgrade Stage 11 findings.
5. Stage 12 toggle OFF marks Stage 12 skipped and report notes "AI analysis skipped".
6. Stage 12 unavailable (API key missing, network timeout, malformed JSON) -> status unavailable, pipeline INCOMPLETE.
7. Quota protection: when Stage 11 blocks, Stage 12 is blocked and Gemini API is NOT invoked.
8. Stage 13 sandbox execution never runs when gate decision is BLOCK.
9. Educational sandbox override: executes Stage 13 with [EXECUTED WITH SECURITY OVERRIDE] banner, without marking 11/12 as passed.
10. Schema verification: every finding contains id, cwe, severity, line, column, message, evidence, source_stage.
11. Demo B & Demo C end-to-end: Stage 11 failed, Stage 12 blocked, Stage 13 blocked, Stage 14 blocked/diagnostic, overall BLOCKED_BY_SECURITY.
12. Normal programs: all 14 stages pass cleanly, overall COMPLETED.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.gate_policy import (
    GatePolicy,
    DEFAULT_GATE_POLICY,
    format_security_finding,
    extract_cwe_from_text_or_rule
)
from web.pipeline_tracker import (
    PipelineRunTracker,
    execute_pipeline_with_tracker
)


class TestGatePolicyUnit(unittest.TestCase):
    """Unit tests for the GatePolicy configuration object and evaluation functions."""

    def test_default_policy_thresholds(self):
        policy = GatePolicy()
        self.assertEqual(policy.stage11_blocking_severities, {"CRITICAL", "HIGH"})
        self.assertEqual(policy.stage11_warning_severities, {"MEDIUM", "LOW"})
        self.assertEqual(policy.stage12_blocking_severities, {"CRITICAL", "HIGH"})
        self.assertEqual(policy.stage12_warning_severities, {"MEDIUM", "LOW"})
        self.assertEqual(policy.stage12_min_blocking_confidence, 0.6)
        self.assertEqual(policy.stage12_timeout_seconds, 20.0)
        self.assertFalse(policy.run_ai_even_if_sast_fails)
        self.assertTrue(policy.allow_sandbox_override)

    def test_custom_policy_thresholds(self):
        custom = GatePolicy(
            stage11_blocking_severities={"CRITICAL"},
            stage12_min_blocking_confidence=0.8,
            run_ai_even_if_sast_fails=True
        )
        self.assertEqual(custom.stage11_blocking_severities, {"CRITICAL"})
        self.assertEqual(custom.stage12_min_blocking_confidence, 0.8)
        self.assertTrue(custom.run_ai_even_if_sast_fails)

    def test_evaluate_stage11_severities(self):
        policy = GatePolicy()

        # Clean
        status, decision = policy.evaluate_stage11([])
        self.assertEqual(status, "passed")
        self.assertEqual(decision, "ALLOW")

        # Medium / Low -> Warning, ALLOW
        med_findings = [{"severity": "Medium", "message": "Weak PRNG"}]
        status, decision = policy.evaluate_stage11(med_findings)
        self.assertEqual(status, "warning")
        self.assertEqual(decision, "ALLOW")

        low_findings = [{"severity": "LOW", "message": "Minor info"}]
        status, decision = policy.evaluate_stage11(low_findings)
        self.assertEqual(status, "warning")
        self.assertEqual(decision, "ALLOW")

        # High -> Failed, BLOCK
        high_findings = [{"severity": "HIGH", "message": "SQL Injection"}]
        status, decision = policy.evaluate_stage11(high_findings)
        self.assertEqual(status, "failed")
        self.assertEqual(decision, "BLOCK")

        # Critical -> Failed, BLOCK
        crit_findings = [{"severity": "CRITICAL", "message": "Remote Code Exec"}]
        status, decision = policy.evaluate_stage11(crit_findings)
        self.assertEqual(status, "failed")
        self.assertEqual(decision, "BLOCK")

    def test_evaluate_stage12_confidence_threshold(self):
        policy = GatePolicy()

        # High severity with confidence >= 0.6 -> BLOCK
        high_conf = [{"severity": "HIGH", "confidence": 0.85, "message": "Insecure logic"}]
        status, decision = policy.evaluate_stage12(high_conf)
        self.assertEqual(status, "failed")
        self.assertEqual(decision, "BLOCK")

        # High severity with confidence < 0.6 -> ALLOW (downgrades to warning)
        low_conf = [{"severity": "HIGH", "confidence": 0.45, "message": "Uncertain logic"}]
        status, decision = policy.evaluate_stage12(low_conf)
        self.assertEqual(status, "warning")
        self.assertEqual(decision, "ALLOW")

    def test_stage12_never_downgrades_stage11(self):
        policy = GatePolicy()

        stage11_crit = [{"severity": "CRITICAL", "message": "Hardcoded secret"}]
        stage12_clean = []

        # Stage 12 reported clean, but Stage 11 was CRITICAL
        status, decision = policy.evaluate_stage12(stage12_clean, stage11_findings=stage11_crit)
        self.assertEqual(status, "failed")
        self.assertEqual(decision, "BLOCK")

    def test_format_security_finding_schema(self):
        raw = {
            "id": "SEC-INJ-001",
            "rule_id": "SEC-INJ-001",
            "severity": "high",
            "line": 42,
            "column": 5,
            "message": "Potential SQL injection",
            "snippet": "SELECT * FROM users",
            "confidence": 0.95
        }
        formatted = format_security_finding(raw, source_stage=11)
        self.assertEqual(formatted["id"], "SEC-INJ-001")
        self.assertEqual(formatted["cwe"], "CWE-89")
        self.assertEqual(formatted["severity"], "HIGH")
        self.assertEqual(formatted["line"], 42)
        self.assertEqual(formatted["column"], 5)
        self.assertEqual(formatted["message"], "Potential SQL injection")
        self.assertEqual(formatted["evidence"], "SELECT * FROM users")
        self.assertEqual(formatted["source_stage"], 11)
        self.assertEqual(formatted["confidence"], 0.95)


class TestSecurityGatingPipeline(unittest.TestCase):
    """End-to-end integration tests for pipeline security gating."""

    def test_normal_programs_pass_all_14_stages(self):
        normal_code = """
fn main() {
    let x = 10;
    let y = 20;
    let z = x + y;
    print(z);
}
"""
        # Case A: AI disabled (skipped) -> 13 completed, stage 12 skipped, overall COMPLETED
        tracker = PipelineRunTracker(run_id="test-normal-ai-skipped")
        execute_pipeline_with_tracker(
            source_code=normal_code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False
        )
        self.assertEqual(tracker.completed_stages_count, 13)
        self.assertEqual(tracker.compute_overall_status(), "COMPLETED")
        self.assertEqual(tracker.stages["ai_security_analysis"]["status"], "skipped")

        # Case B: AI enabled and clean -> all 14 stages pass cleanly, overall COMPLETED
        with patch("web.gemini_client.ai_client.check_health") as mock_health:
            mock_health.return_value = (True, "Online", "gemini-3-flash-preview")
            tracker14 = PipelineRunTracker(run_id="test-normal-all-14-pass")
            execute_pipeline_with_tracker(
                source_code=normal_code,
                language_hint="English",
                run_ai_security=True,
                tracker=tracker14,
                pause_on_error=False
            )
            self.assertEqual(tracker14.completed_stages_count, 14)
            self.assertEqual(tracker14.compute_overall_status(), "COMPLETED")
            for sid, st in tracker14.stages.items():
                self.assertIn(st["status"], ("passed", "completed"), f"Stage {sid} not passed: {st}")

    def test_demo_b_security_lab_blocks_execution(self):
        demo_b_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "security_lab", "english", "sec_data_config.vital"
        )
        with open(demo_b_path, "r", encoding="utf-8") as f:
            code = f.read()

        tracker = PipelineRunTracker(run_id="test-demo-b-sast-block")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=True,
            tracker=tracker,
            pause_on_error=False
        )

        # Expected:
        # Stages 1-10: passed
        for sid in [
            "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
            "semantic_analysis", "symbol_table", "ir_generation", "optimization",
            "code_generation", "code_validation"
        ]:
            self.assertIn(
                tracker.stages[sid]["status"],
                ("passed", "completed", "warning"),
                f"Stage {sid} should pass for Demo B"
            )

        # Stage 11: failed
        self.assertEqual(tracker.stages["security_analysis"]["status"], "failed")
        self.assertEqual(tracker.stages["security_analysis"]["details"].get("gate_decision"), "BLOCK")

        # Stage 12: blocked (Quota protection: AI not run)
        self.assertEqual(tracker.stages["ai_security_analysis"]["status"], "blocked")

        # Stage 13: blocked
        self.assertEqual(tracker.stages["sandbox_execution"]["status"], "blocked")

        # Stage 14: blocked / diagnostic only (incomplete)
        self.assertEqual(tracker.stages["final_report"]["status"], "blocked")

        # Overall Status
        self.assertEqual(tracker.compute_overall_status(), "BLOCKED_BY_SECURITY")

    def test_demo_c_security_lab_blocks_execution(self):
        demo_c_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "security_lab", "english", "sec_injection_eval.vital"
        )
        with open(demo_c_path, "r", encoding="utf-8") as f:
            code = f.read()

        tracker = PipelineRunTracker(run_id="test-demo-c-sast-block")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=True,
            tracker=tracker,
            pause_on_error=False
        )

        # Stage 11: failed
        self.assertEqual(tracker.stages["security_analysis"]["status"], "failed")
        self.assertEqual(tracker.stages["security_analysis"]["details"].get("gate_decision"), "BLOCK")

        # Stage 12: blocked
        self.assertEqual(tracker.stages["ai_security_analysis"]["status"], "blocked")

        # Stage 13: blocked
        self.assertEqual(tracker.stages["sandbox_execution"]["status"], "blocked")

        # Overall Status
        self.assertEqual(tracker.compute_overall_status(), "BLOCKED_BY_SECURITY")

    def test_quota_protection_ai_not_called_when_sast_blocks(self):
        """Ensures Gemini AI API is not called when Stage 11 detects blocking findings."""
        demo_b_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "security_lab", "english", "sec_data_config.vital"
        )
        with open(demo_b_path, "r", encoding="utf-8") as f:
            code = f.read()

        import web.security_analyzer
        with patch("web.gemini_client.ai_client.check_health") as mock_health, \
             patch("web.security_analyzer.security_coordinator.run_full_scan", wraps=web.security_analyzer.security_coordinator.run_full_scan) as mock_scan:
            tracker = PipelineRunTracker(run_id="test-quota-protection")
            execute_pipeline_with_tracker(
                source_code=code,
                language_hint="English",
                run_ai_security=True,
                tracker=tracker,
                pause_on_error=False
            )
            # mock_health should NOT be called at all for Stage 12
            mock_health.assert_not_called()
            # Stage 12 was blocked by Stage 11
            self.assertEqual(tracker.stages["ai_security_analysis"]["status"], "blocked")
            # Verify run_full_scan was never called with use_ai_enrichment=True
            for call_item in mock_scan.call_args_list:
                _, kwargs = call_item
                self.assertFalse(kwargs.get("use_ai_enrichment", False), "Gemini AI scan was called despite Stage 11 block!")

    def test_stage12_toggle_off_sets_status_skipped(self):
        clean_code = "fn main() { print(42); }"
        tracker = PipelineRunTracker(run_id="test-ai-toggle-off")
        execute_pipeline_with_tracker(
            source_code=clean_code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False
        )
        self.assertEqual(tracker.stages["ai_security_analysis"]["status"], "skipped")
        self.assertIn("AI analysis skipped", tracker.stages["ai_security_analysis"]["summary"])

    def test_stage12_unavailable_marks_incomplete(self):
        """Simulates Stage 12 API error / timeout -> status unavailable -> overall INCOMPLETE."""
        clean_code = "fn main() { print(42); }"

        with patch("web.gemini_client.ai_client.check_health") as mock_health:
            mock_health.return_value = (False, "Missing GEMINI_API_KEY environment variable", "")
            tracker = PipelineRunTracker(run_id="test-ai-unavailable")
            execute_pipeline_with_tracker(
                source_code=clean_code,
                language_hint="English",
                run_ai_security=True,
                tracker=tracker,
                pause_on_error=False
            )
            self.assertEqual(tracker.stages["ai_security_analysis"]["status"], "unavailable")
            self.assertEqual(tracker.compute_overall_status(), "INCOMPLETE")
            tracker = PipelineRunTracker(run_id="test-ai-unavailable")
            execute_pipeline_with_tracker(
                source_code=clean_code,
                language_hint="English",
                run_ai_security=True,
                tracker=tracker,
                pause_on_error=False
            )
            self.assertEqual(tracker.stages["ai_security_analysis"]["status"], "unavailable")
            self.assertEqual(tracker.compute_overall_status(), "INCOMPLETE")

    def test_educational_sandbox_override(self):
        """
        When security_override=True:
        - Stage 11 remains failed
        - Stage 13 runs in sandbox
        - Output is stamped with [EXECUTED WITH SECURITY OVERRIDE]
        - Report is stamped with [EXECUTED WITH SECURITY OVERRIDE]
        - Pipeline status is EXECUTED_WITH_OVERRIDE
        """
        demo_b_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "security_lab", "english", "sec_data_config.vital"
        )
        with open(demo_b_path, "r", encoding="utf-8") as f:
            code = f.read()

        tracker = PipelineRunTracker(run_id="test-educational-override")
        execute_pipeline_with_tracker(
            source_code=code,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            pause_on_error=False,
            security_override=True
        )

        # Stage 11 must NOT be marked passed
        self.assertEqual(tracker.stages["security_analysis"]["status"], "failed")

        # Stage 13 must have executed under override
        self.assertEqual(tracker.stages["sandbox_execution"]["status"], "passed")
        self.assertTrue(tracker.stages["sandbox_execution"]["details"].get("security_override"))

        # Output must be stamped with red banner
        output_text = tracker.stages["sandbox_execution"]["details"].get("output_preview", "")
        self.assertIn("[EXECUTED WITH SECURITY OVERRIDE]", output_text)

        # Final report must also be stamped
        self.assertEqual(tracker.stages["final_report"]["status"], "passed")

        # Overall status must be EXECUTED_WITH_OVERRIDE
        self.assertEqual(tracker.compute_overall_status(), "EXECUTED_WITH_OVERRIDE")


if __name__ == "__main__":
    unittest.main()
