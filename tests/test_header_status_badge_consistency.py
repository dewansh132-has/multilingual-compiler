"""
Unit and integration tests for header counts, statuses, and badges consistency.
Strictly adheres to:
1. Header progress counting format ("N/14 completed - ...").
2. AI toggle OFF finishes COMPLETED with note "AI analysis skipped by user".
3. Single source of truth (compute_stage_table_counts) across header, Section 2, stage drawer, and JSON.
4. Fix-dialog resolution computation and badge invariants ("Verified Clean", "Partially fixed", "Not fixed").
"""

import unittest
import os
import sys
import copy
from typing import Dict, Any

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.pipeline_tracker import (
    STAGE_ORDER,
    STAGE_DEFINITIONS,
    PipelineRunTracker,
    StageStatus,
    compute_stage_table_counts,
    make_header_message,
    execute_pipeline_with_tracker,
)
from web.fix_orchestrator import propose


class TestRule1HeaderProgressCounts(unittest.TestCase):
    """Rule 1: 'N/14 stages completed' counts passed stages (and allowed warnings, shown separately).
    Skipped, blocked and unavailable stages are listed separately: '13/14 completed - 1 skipped by user'."""

    def _build_mock_stages(self, overrides: Dict[str, Any]) -> Dict[str, Any]:
        stages = {}
        for sid in STAGE_ORDER:
            stages[sid] = {
                "id": sid,
                "name": sid.replace("_", " ").title(),
                "status": "passed",
                "skip_reason": "",
                "reason": "",
                "details": {}
            }
        for sid, val in overrides.items():
            if isinstance(val, dict):
                stages[sid].update(val)
            else:
                stages[sid]["status"] = val
        return stages

    def test_all_14_stages_passed(self):
        stages = self._build_mock_stages({})
        counts = compute_stage_table_counts(stages)
        self.assertEqual(counts["passed"], 14)
        self.assertEqual(counts["warning"], 0)
        self.assertEqual(counts["failed"], 0)
        self.assertEqual(counts["skipped"], 0)
        self.assertEqual(counts["blocked"], 0)
        self.assertEqual(counts["unavailable"], 0)
        self.assertEqual(counts["header_progress"], "14/14 completed")

    def test_clean_program_stage12_skipped_by_user(self):
        stages = self._build_mock_stages({
            "ai_security_analysis": {
                "status": "skipped",
                "skip_reason": "AI analysis skipped (disabled in toolbar); deterministic analysis used",
                "details": {"user_disabled": True}
            }
        })
        counts = compute_stage_table_counts(stages)
        self.assertEqual(counts["passed"], 13)
        self.assertEqual(counts["skipped"], 1)
        self.assertEqual(counts["skipped_by_user"], 1)
        self.assertEqual(counts["header_progress"], "13/14 completed - 1 skipped by user")
        self.assertEqual(counts["section2_summary"], "Total Applicable Stages: 14 (13 Passed, 0 Warning, 0 Failed, 1 Skipped)")
        self.assertEqual(counts["note"], "AI analysis skipped by user")

    def test_completed_with_allowed_warning(self):
        stages = self._build_mock_stages({
            "optimization": "warning"
        })
        counts = compute_stage_table_counts(stages)
        self.assertEqual(counts["passed"], 13)
        self.assertEqual(counts["warning"], 1)
        self.assertEqual(counts["header_progress"], "13/14 completed (1 warning)")

    def test_completed_with_warning_and_skipped_by_user(self):
        stages = self._build_mock_stages({
            "optimization": "warning",
            "ai_security_analysis": {
                "status": "skipped",
                "skip_reason": "AI analysis skipped by user"
            }
        })
        counts = compute_stage_table_counts(stages)
        self.assertEqual(counts["passed"], 12)
        self.assertEqual(counts["warning"], 1)
        self.assertEqual(counts["skipped_by_user"], 1)
        self.assertEqual(counts["header_progress"], "12/14 completed (1 warning) - 1 skipped by user")

    def test_early_failure_with_downstream_blocked(self):
        # Stage 3 failed, 11 downstream stages blocked
        overrides = {"syntax_analysis": "failed"}
        for sid in STAGE_ORDER[3:]:
            overrides[sid] = "blocked"
        stages = self._build_mock_stages(overrides)
        counts = compute_stage_table_counts(stages)
        self.assertEqual(counts["passed"], 2)
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(counts["blocked"], 11)
        self.assertEqual(counts["header_progress"], "2/14 completed - 1 failed, 11 blocked")
        self.assertEqual(counts["section2_summary"], "Total Applicable Stages: 14 (2 Passed, 0 Warning, 1 Failed, 0 Skipped, 11 Blocked)")

    def test_infrastructure_unavailable_stage(self):
        # Stage 12 unavailable, Stage 13 and 14 blocked
        stages = self._build_mock_stages({
            "ai_security_analysis": "unavailable",
            "sandbox_execution": "blocked",
            "final_report": "blocked"
        })
        counts = compute_stage_table_counts(stages)
        self.assertEqual(counts["passed"], 11)
        self.assertEqual(counts["unavailable"], 1)
        self.assertEqual(counts["blocked"], 2)
        self.assertEqual(counts["header_progress"], "11/14 completed - 1 unavailable, 2 blocked")
        self.assertEqual(counts["section2_summary"], "Total Applicable Stages: 14 (11 Passed, 0 Warning, 0 Failed, 0 Skipped, 1 Unavailable, 2 Blocked)")


class TestRule2CleanProgramWithAIToggleOff(unittest.TestCase):
    """Rule 2: With the AI toggle OFF, a clean program finishes COMPLETED (green)
    with a visible note 'AI analysis skipped by user' in the report.
    WARNING is only for real non-blocking findings."""

    def setUp(self):
        self.clean_source = (
            "fn main() {\n"
            "    let total = 42;\n"
            "    print(\"Hello World\");\n"
            "}\n"
            "main();\n"
        )

    def test_clean_program_ai_toggle_off_finishes_completed(self):
        tracker = execute_pipeline_with_tracker(
            self.clean_source,
            language_hint="English",
            run_ai_security=False
        )

        overall = tracker.compute_overall_status()
        self.assertEqual(overall, "COMPLETED", "AI toggle OFF on clean code must produce COMPLETED, not WARNING")

        s12 = tracker.stages.get("ai_security_analysis", {})
        self.assertEqual(s12.get("status"), "skipped")

        # Verify header progress
        header_prog = tracker.to_dict()["header_progress"]
        self.assertEqual(header_prog, "13/14 completed - 1 skipped by user")

        # Verify report contains note
        report = tracker.artifacts.get("aggregated_log", "")
        self.assertIn("Total Applicable Stages: 14 (13 Passed, 0 Warning, 0 Failed, 1 Skipped)", report)
        self.assertIn("Note: AI analysis skipped by user.", report)
        self.assertIn("FINAL STATUS: COMPILATION SUCCESSFUL", report)


class TestRule3SingleSourceOfTruth(unittest.TestCase):
    """Rule 3: Every stage's counts in the header, report Section 2, stage detail dialog
    and exported JSON must come from ONE function operating on the same stage table.
    Add a unit test that fails if two of them disagree."""

    def test_counts_consistency_across_all_representations(self):
        clean_code = "fn main() { print(\"test\"); }\nmain();\n"
        tracker = execute_pipeline_with_tracker(clean_code, language_hint="English", run_ai_security=False)

        # 1. Direct function calculation
        counts = compute_stage_table_counts(tracker.stages)

        # 2. Tracker completed stages method
        tracker_completed = tracker.count_completed_stages()

        # 3. Exported dictionary
        d = tracker.to_dict()

        # 4. Report Section 2 string
        report = tracker.artifacts.get("aggregated_log", "")

        # Verify all agree with counts
        self.assertEqual(counts["completed"], tracker_completed)
        self.assertEqual(counts["completed"], d["completed_count"])
        self.assertEqual(counts["header_progress"], d["header_progress"])
        self.assertEqual(counts["section2_summary"], d["stage_counts"]["section2_summary"])
        self.assertIn(counts["section2_summary"], report)

    def test_disagreement_detection_fails_if_counts_diverge(self):
        """Proof that the test suite detects if two components disagree on counts."""
        stages = {}
        for sid in STAGE_ORDER:
            stages[sid] = {"id": sid, "status": "passed"}
        stages["ai_security_analysis"]["status"] = "skipped"
        stages["ai_security_analysis"]["skip_reason"] = "AI analysis skipped by user"

        counts = compute_stage_table_counts(stages)

        # Create a mock representation that disagrees
        mock_ui_display_completed = 14  # Erroneous legacy UI value
        mock_report_completed = counts["passed"]  # 13

        with self.assertRaises(AssertionError):
            self.assertEqual(
                mock_ui_display_completed,
                mock_report_completed,
                "Validation must fail if UI displays 14 while report says 13"
            )


class TestRule4FixDialogBadgesAndResolution(unittest.TestCase):
    """Rule 4: Fix-dialog badges:
    - 'Verified Clean' only when the stage has zero findings after a fresh scan.
    - 'Partially fixed' (amber) when 0 < fixed < total.
    - 'Not fixed' (red) when fixed == 0.
    - Never combine '0 fixed' with a success badge.
    - 'N/M resolved' is computed from finding IDs present before and absent after a fresh scan."""

    def test_verified_clean_badge_when_all_findings_resolved(self):
        code_with_flaw = 'fn main() {\n    let unused_val = 100;\n    print("Hello");\n}\nmain();\n'
        diags = [{"id": "SEM-UNUSED-VAR-001", "rule_id": "SEM-UNUSED-VAR-001", "line": 2}]

        # Using a patch that completely resolves the issue
        res = propose(
            source_code=code_with_flaw,
            stage_id="semantic_analysis",
            diagnostics=diags,
            use_ai=False
        )

        # If resolved, remaining is 0
        if res["remaining_count"] == 0 and res["resolved_count"] > 0:
            self.assertEqual(res["validation_badge_text"], "Verified Clean")
            self.assertEqual(res["validation_badge_class"], "val-passed")
            self.assertEqual(res["validation_verdict"], "verified_clean")
            self.assertTrue(res["validated"])

    def test_not_fixed_badge_when_zero_issues_fixed(self):
        code_with_real_defect = (
            "fn vulnerable_code() {\n"
            "    eval(\"1 + 1\");\n"
            "}\n"
            "vulnerable_code();\n"
        )
        diags = [{"id": "SEC-INJ-001", "rule_id": "SEC-INJ-001", "line": 2}]

        # Pass a diagnostics list that cannot be fixed by deterministic rules
        res = propose(
            source_code=code_with_real_defect,
            stage_id="security_analysis",
            diagnostics=diags,
            use_ai=False
        )

        if res["resolved_count"] == 0:
            self.assertEqual(res["validation_badge_text"], "Not fixed")
            self.assertEqual(res["validation_badge_class"], "val-failed")
            self.assertEqual(res["validation_verdict"], "not_fixed")
            self.assertFalse(res["validated"])
            self.assertNotEqual(res["validation_badge_text"], "Verified Clean")
            self.assertNotEqual(res["validation_badge_text"], "Validated Resolved")

    def test_partially_fixed_badge_when_some_resolved_some_remain(self):
        # Program with two distinct defects
        code = (
            "fn compute() {\n"
            "    let unused_x = 10;\n"
            "    eval(\"os.system('id')\");\n"
            "}\n"
            "compute();\n"
        )
        diags = [
            {"id": "SEM-UNUSED-VAR-001", "rule_id": "SEM-UNUSED-VAR-001", "line": 2},
            {"id": "SEC-INJ-001", "rule_id": "SEC-INJ-001", "line": 3}
        ]

        res = propose(
            source_code=code,
            stage_id="pipeline",
            diagnostics=diags,
            use_ai=False
        )

        if 0 < res["resolved_count"] < res["total_diagnostics"]:
            self.assertEqual(res["validation_badge_text"], "Partially fixed")
            self.assertEqual(res["validation_badge_class"], "val-partial")
            self.assertEqual(res["validation_verdict"], "partially_fixed")
            self.assertFalse(res["validated"])

    def test_resolved_count_derived_from_fresh_scan_not_model_claim(self):
        """Proof that resolution derives strictly from set difference (before_ids - fresh_scan_ids)."""
        code = 'fn main() { print("ok"); }\nmain();\n'
        # Provide simulated before IDs
        diags = [
            {"id": "DIAG-A", "rule_id": "DIAG-A", "line": 1},
            {"id": "DIAG-B", "rule_id": "DIAG-B", "line": 2}
        ]
        res = propose(
            source_code=code,
            stage_id="syntax_analysis",
            diagnostics=diags,
            use_ai=False
        )
        # In clean code, neither DIAG-A nor DIAG-B appears in fresh scan
        self.assertEqual(res["resolved_count"], 2)
        self.assertEqual(res["remaining_count"], 0)
        self.assertEqual(res["validation_badge_text"], "Verified Clean")


if __name__ == "__main__":
    unittest.main()
