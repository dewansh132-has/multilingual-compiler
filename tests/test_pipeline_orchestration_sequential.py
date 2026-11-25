# -*- coding: utf-8 -*-
"""
tests/test_pipeline_orchestration_sequential.py

Unit test suite verifying the strict sequential pipeline state machine orchestration:
1. Strict sequential order 1..14 with prerequisite gating.
2. Failure at stage k blocks stages k+1..14 for every k in 1..14.
3. Unavailable stage 12 never yields COMPLETED and blocks stages 13 and 14.
4. Security gate decision: HIGH/CRITICAL findings block stage 13 & 14, yielding BLOCKED_BY_SECURITY.
5. Real file test with examples/security_lab/fusion/sec_auth_account_fusion.vital halting at Stage 5.
"""

import os
import unittest
from typing import Dict, Any

from web.pipeline_tracker import (
    STAGE_ORDER,
    STAGE_INFO,
    STAGE_STATUS_PASSED,
    STAGE_STATUS_WARNING,
    STAGE_STATUS_FAILED,
    STAGE_STATUS_BLOCKED,
    STAGE_STATUS_UNAVAILABLE,
    PipelineRunTracker,
    execute_pipeline_with_tracker,
    security_gate_decision,
    check_prerequisites,
    make_header_message
)

VALID_CODE = 'let x = 10\nprint(x)\n'


class TestPipelineOrchestrationSequential(unittest.TestCase):

    def test_01_failure_at_stage_k_blocks_k_plus_1_to_14_for_all_k(self):
        """
        Verify that for every k from 1 to 14, a failure at stage k
        blocks all subsequent stages k+1..14, sets reason text 'Blocked by Stage k',
        and yields overall status FAILED.
        """
        for k in range(1, 15):
            stage_id = STAGE_ORDER[k - 1]
            b_num, b_name = STAGE_INFO[stage_id]

            def make_failing_override(target_sid):
                def _fail(tracker, ctx):
                    tracker.fail_stage(target_sid, f"Intentional mock failure at Stage {b_num}")
                return _fail

            tracker = PipelineRunTracker()
            execute_pipeline_with_tracker(
                source_code=VALID_CODE,
                language_hint="English",
                run_ai_security=False,
                tracker=tracker,
                stage_overrides={stage_id: make_failing_override(stage_id)}
            )

            # 1. Stages 1..k-1 must be satisfied (passed, completed, warning, or optional clean skip)
            for prev_idx in range(k - 1):
                prev_sid = STAGE_ORDER[prev_idx]
                prev_status = tracker.stages[prev_sid]["status"]
                self.assertIn(
                    prev_status,
                    ("passed", "completed", "warning", "skipped"),
                    f"When stage {k} ({stage_id}) fails, stage {prev_idx+1} ({prev_sid}) must be satisfied, but was {prev_status}"
                )

            # 2. Stage k must be failed
            self.assertEqual(
                tracker.stages[stage_id]["status"],
                "failed",
                f"Stage {k} ({stage_id}) was expected to fail"
            )

            # 3. Stages k+1..14 must be blocked
            for next_idx in range(k, 14):
                next_sid = STAGE_ORDER[next_idx]
                next_st = tracker.stages[next_sid]
                self.assertEqual(
                    next_st["status"],
                    "blocked",
                    f"When stage {k} fails, downstream stage {next_idx+1} ({next_sid}) must be 'blocked', but was {next_st['status']}"
                )
                self.assertIn(
                    f"Blocked by Stage {b_num}",
                    next_st["reason"],
                    f"Blocked stage reason must cite Stage {b_num}, got: {next_st['reason']}"
                )

            # 4. Overall status must be FAILED
            self.assertEqual(tracker.compute_overall_status(), "FAILED")
            self.assertFalse(tracker.to_dict()["success"])

    def test_02_unavailable_stage_12_never_yields_completed(self):
        """
        Verify that an 'unavailable' Stage 12 (AI Security Analysis)
        is NEVER treated as passed, blocks Stage 13 and 14, and overall status is FAILED.
        """
        def stage12_unavailable_override(tracker, ctx):
            tracker.mark_stage_unavailable("ai_security_analysis", "API key missing or quota exceeded")

        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(
            source_code=VALID_CODE,
            language_hint="English",
            run_ai_security=True,
            tracker=tracker,
            stage_overrides={"ai_security_analysis": stage12_unavailable_override}
        )

        st12 = tracker.stages["ai_security_analysis"]
        self.assertEqual(st12["status"], "unavailable")

        # Stages 13 and 14 must be blocked
        st13 = tracker.stages["sandbox_execution"]
        st14 = tracker.stages["final_report"]
        self.assertEqual(st13["status"], "blocked")
        self.assertEqual(st14["status"], "blocked")
        self.assertIn("Blocked by Stage 12", st13["reason"])
        self.assertIn("Blocked by Stage 12", st14["reason"])

        # Overall status must never be COMPLETED (INCOMPLETE per Task 5 policy)
        overall = tracker.compute_overall_status()
        self.assertNotEqual(overall, "COMPLETED")
        self.assertIn(overall, ("INCOMPLETE", "FAILED"))
        self.assertFalse(tracker.to_dict()["success"])

    def test_03_security_gate_decision_blocks_stage_13_on_critical_high(self):
        """
        Verify that Critical or High findings in Stage 11 result in security_gate_decision == 'block',
        which blocks Stage 13 & 14 and sets overall status to BLOCKED_BY_SECURITY.
        """
        def stage11_critical_override(tracker, ctx):
            findings = [
                {
                    "id": "SEC-AUTH-001",
                    "cwe": "CWE-306",
                    "severity": "CRITICAL",
                    "line": 42,
                    "message": "Missing authentication on privileged endpoint"
                }
            ]
            self.assertEqual(security_gate_decision(findings), "block")
            tracker.complete_stage(
                "security_analysis",
                "Critical vulnerability detected",
                details={"findings": findings, "max_severity": "CRITICAL", "gate_decision": "block"},
                findings_count=1
            )

        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(
            source_code=VALID_CODE,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            stage_overrides={"security_analysis": stage11_critical_override}
        )

        # Stage 11 is warning
        self.assertEqual(tracker.stages["security_analysis"]["status"], "warning")

        # Stages 13 and 14 must be blocked
        st13 = tracker.stages["sandbox_execution"]
        st14 = tracker.stages["final_report"]
        self.assertEqual(st13["status"], "blocked")
        self.assertEqual(st14["status"], "blocked")
        self.assertIn("Blocked by Stage 11", st13["reason"])

        # Overall status must be BLOCKED_BY_SECURITY
        overall = tracker.compute_overall_status()
        self.assertEqual(overall, "BLOCKED_BY_SECURITY")

    def test_04_security_gate_decision_allows_stage_13_on_low_findings(self):
        """
        Verify that Low/Medium findings result in security_gate_decision == 'allow',
        allowing Stage 13 & 14 to run and finish with overall status WARNING.
        """
        def stage11_low_override(tracker, ctx):
            findings = [
                {
                    "id": "SEC-INFO-001",
                    "cwe": "CWE-200",
                    "severity": "LOW",
                    "line": 5,
                    "message": "Minor information disclosure"
                }
            ]
            self.assertEqual(security_gate_decision(findings), "allow")
            tracker.complete_stage(
                "security_analysis",
                "Low finding detected",
                details={"findings": findings, "max_severity": "LOW", "gate_decision": "allow"},
                findings_count=1
            )

        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(
            source_code=VALID_CODE,
            language_hint="English",
            run_ai_security=False,
            tracker=tracker,
            stage_overrides={"security_analysis": stage11_low_override}
        )

        # Stage 11 warning is allowed
        self.assertEqual(tracker.stages["security_analysis"]["status"], "warning")
        # Stage 13 and 14 ran and passed
        self.assertIn(tracker.stages["sandbox_execution"]["status"], ("passed", "completed"))
        self.assertIn(tracker.stages["final_report"]["status"], ("passed", "completed"))

        overall = tracker.compute_overall_status()
        self.assertEqual(overall, "WARNING")

    def test_05_real_demo_fusion_auth_stops_at_stage_5(self):
        """
        Reproduce Bug B with examples/security_lab/fusion/sec_auth_account_fusion.vital:
        Contains an undefined variable 'acc_status' at line 157.
        Must fail at Stage 5 (Semantic Analysis) and block Stages 6..14 completely.
        """
        demo_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "examples", "security_lab", "fusion", "sec_auth_account_fusion.vital"
        )
        self.assertTrue(os.path.exists(demo_path), f"Demo file missing: {demo_path}")
        with open(demo_path, "r", encoding="utf-8") as f:
            code = f.read()

        tracker = execute_pipeline_with_tracker(code, "English", run_ai_security=False)

        # Stages 1..4 passed
        self.assertIn(tracker.stages["source_input"]["status"], ("passed", "completed"))
        self.assertIn(tracker.stages["lexical_analysis"]["status"], ("passed", "completed"))
        self.assertIn(tracker.stages["syntax_analysis"]["status"], ("passed", "completed"))
        self.assertIn(tracker.stages["ast_construction"]["status"], ("passed", "completed"))

        # Stage 5 failed
        self.assertEqual(tracker.stages["semantic_analysis"]["status"], "failed")
        self.assertIn("acc_status", tracker.stages["semantic_analysis"]["summary"])

        # Stages 6..14 are ALL blocked
        for sid in STAGE_ORDER[5:]:
            st = tracker.stages[sid]
            self.assertEqual(
                st["status"],
                "blocked",
                f"Stage {sid} must be blocked after semantic failure, but was {st['status']}"
            )
            self.assertIn("Blocked by Stage 5 (Semantic Analysis)", st["reason"])

        # Overall status is FAILED
        self.assertEqual(tracker.compute_overall_status(), "FAILED")

        # Completed count is exactly 4
        self.assertEqual(tracker.count_completed_stages(), 4)

        # Header message precisely describes stop location and blocked count
        self.assertEqual(tracker.header_message, "Stopped at Stage 5 (Semantic Analysis): 1 error. 9 stages blocked.")

    def test_06_stage_result_contains_all_required_fields(self):
        """
        Verify Rule 6: Each stage result includes status, started_at, duration_ms, reason, source_hash, run_id.
        """
        tracker = execute_pipeline_with_tracker(VALID_CODE, "English", run_ai_security=False)
        for sid in STAGE_ORDER:
            st = tracker.stages[sid]
            self.assertIn("status", st)
            self.assertIn("started_at", st)
            self.assertIn("duration_ms", st)
            self.assertIn("reason", st)
            self.assertIn("source_hash", st)
            self.assertIn("run_id", st)
            self.assertEqual(st["run_id"], tracker.run_id)
            self.assertEqual(st["source_hash"], tracker.source_hash)


if __name__ == "__main__":
    unittest.main()
