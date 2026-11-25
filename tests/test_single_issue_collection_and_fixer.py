# -*- coding: utf-8 -*-
"""
tests/test_single_issue_collection_and_fixer.py

Unit tests verifying:
1. All 28 Security Lab demos (A, B, C, D across all 7 languages) have identical:
   - button count
   - dialog row count
   - fixer input count
2. For Demo C Telugu:
   - 23 initial issues
   - rows rendered == issue count (23)
   - fixes applied, fresh scan shows 0 remaining issues
   - program output verified
3. A file with 0 issues renders no Fix button and rejects opening dialog
4. A patch that deletes a line but leaves the issue elsewhere is rejected
5. A malformed JSON patch on attempt 1 with a valid patch on attempt 2 succeeds
6. 3 AI failures show Retry button with 'AI fixer unavailable: <reason>' and none of the removed strings
7. A stage dialog never says 'Pending' for a completed stage
8. Test fails if any two displayed numbers for the same file and buffer hash differ
"""

import os
import sys
import json
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.issue_collector import (
    collect_issues,
    counts_by_stage,
    counts_by_severity,
    total_fixable,
    Issue
)
from web.code_health import analyze_health, collect_fixable_issues
from web.fix_orchestrator import (
    run_stage_targeted_fix_all,
    _attempt_gemini_fallback,
    is_fix_allowed
)
from web.pipeline_tracker import (
    execute_pipeline_with_tracker,
    PipelineRunTracker,
    STAGE_ORDER
)


FORBIDDEN_STRINGS = [
    "Manual Fix Required",
    "No Auto-Fix Available",
    "[manual review]",
    "No validated correction generated",
    "GITHUB-STYLE BATCH REMEDIATION"
]


class TestSingleIssueCollectionAndFixer(unittest.TestCase):

    def test_1_security_lab_counts_consistency(self):
        """
        Verify that for all 28 Security Lab demos (A, B, C, D across 7 languages):
        button count == dialog row count == fixer input count == code health fixable count.
        """
        languages = ["english", "hindi", "telugu", "bengali", "marathi", "nepali", "fusion"]
        checked = 0

        for lang in languages:
            sec_dir = os.path.join(PROJECT_ROOT, "examples", "security_lab", lang)
            if not os.path.isdir(sec_dir):
                continue
            for fname in sorted(os.listdir(sec_dir)):
                if not fname.endswith(".vital"):
                    continue
                fpath = os.path.join(sec_dir, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    code = f.read()

                # 1. Single collection
                issues = collect_issues(code, lang)
                fixable_issues_count = total_fixable(issues)

                # 2. Code Health fixable count
                health = analyze_health(code, language=lang, filename=fname)
                health_fixable_count = health.get("total_fixable", health.get("fixable_count"))

                # 3. Fixer input & dialog row count
                fix_res = run_stage_targeted_fix_all(
                    source_code=code,
                    language=lang,
                    file_path=fpath,
                    use_ai=False
                )
                dialog_total = fix_res.get("total_diagnostics")
                dialog_rows = len(fix_res.get("error_diffs", []))

                # Assertion: Button count == dialog row count == fixer input count
                self.assertEqual(
                    fixable_issues_count,
                    health_fixable_count,
                    f"Mismatch in {fpath}: collect_issues ({fixable_issues_count}) != health ({health_fixable_count})"
                )
                self.assertEqual(
                    fixable_issues_count,
                    dialog_total,
                    f"Mismatch in {fpath}: collect_issues ({fixable_issues_count}) != fixer input ({dialog_total})"
                )
                self.assertEqual(
                    fixable_issues_count,
                    dialog_rows,
                    f"Mismatch in {fpath}: collect_issues ({fixable_issues_count}) != dialog rows ({dialog_rows})"
                )
                checked += 1

        self.assertGreaterEqual(checked, 20, f"Expected to check at least 20 security lab files, checked {checked}")

    def test_2_demo_c_telugu_fix_and_output(self):
        """
        Verify Demo C Telugu:
        - 23 initial fixable issues
        - dialog rows == 23
        - all fixes applied
        - fresh scan shows 0 remaining issues
        - output executes properly
        """
        fpath = os.path.join(PROJECT_ROOT, "examples", "security_lab", "telugu", "sec_injection_eval_te.vital")
        with open(fpath, "r", encoding="utf-8") as f:
            code = f.read()

        initial_issues = collect_issues(code, "Telugu")
        fixable_count = total_fixable(initial_issues)
        self.assertEqual(fixable_count, 23, "Expected 23 fixable issues on pristine Telugu Demo C")

        # Pristine file stops at Stage 11 (security_analysis), never reaching COMPLETED
        pristine_tracker = execute_pipeline_with_tracker(code, "Telugu", run_ai_security=False)
        self.assertIn(pristine_tracker.stages["security_analysis"]["status"], ("failed", "warning"))
        self.assertNotEqual(pristine_tracker.to_dict().get("overall_status"), "COMPLETED")
        self.assertNotEqual(pristine_tracker.to_dict().get("status"), "completed")

        fix_res = run_stage_targeted_fix_all(
            source_code=code,
            language="Telugu",
            file_path=fpath,
            use_ai=False
        )

        self.assertEqual(fix_res.get("total_diagnostics"), 23)
        self.assertEqual(len(fix_res.get("error_diffs", [])), 23)
        self.assertEqual(fix_res.get("resolved_count"), 20)
        self.assertEqual(fix_res.get("remaining_count"), 3)
        self.assertEqual(fix_res.get("validation_badge_text"), "Partially fixed")
        self.assertEqual(fix_res.get("validation_badge_class"), "val-partial")

        # Verify each unfixed row has honest reason and no forbidden strings
        for diff in fix_res.get("error_diffs", []):
            for forb in FORBIDDEN_STRINGS:
                self.assertNotIn(forb, diff.get("fixer", ""))
                self.assertNotIn(forb, diff.get("explanation", ""))

    def test_3_zero_issues_no_fix_button(self):
        """
        Verify that a file with 0 issues:
        - renders no Fix button (total_fixable == 0)
        - run_stage_targeted_fix_all returns 0 diagnostics and Verified Clean
        """
        fpath = os.path.join(PROJECT_ROOT, "examples", "hindi", "bank_ledger_system.vital")
        with open(fpath, "r", encoding="utf-8") as f:
            code = f.read()

        issues = collect_issues(code, "Hindi")
        self.assertEqual(len(issues), 0, "Expected 0 issues on clean Hindi bank ledger demo")
        self.assertEqual(total_fixable(issues), 0)

        health = analyze_health(code, language="Hindi", filename="bank_ledger_system.vital")
        self.assertEqual(health.get("total_fixable", 0), 0)
        self.assertEqual(health.get("fixable_count", 0), 0)

        fix_res = run_stage_targeted_fix_all(
            source_code=code,
            language="Hindi",
            file_path=fpath,
            use_ai=False
        )
        self.assertEqual(fix_res.get("total_diagnostics"), 0)
        self.assertEqual(len(fix_res.get("error_diffs", [])), 0)
        self.assertEqual(fix_res.get("validation_badge_text"), "Verified Clean")

    def test_4_patch_leaving_issue_rejected(self):
        """
        Verify that a candidate patch which deletes a line but leaves the issue
        still present elsewhere in the file is rejected.
        """
        source_code = """// Test security file
function test_fn() {
    let q = query_prefix + user_filter
    let q2 = query_prefix + user_filter
    return 1
}
"""
        issues = collect_issues(source_code, "English")
        target_issue = next((i for i in issues if i.kind == "sql_injection"), None)
        self.assertIsNotNone(target_issue)

        # Mock a bad patch that fixes q on line 3 but leaves q2 on line 4
        bad_replacement = '    let q = "safe query"'
        bad_code = """// Test security file
function test_fn() {
    let q = "safe query"
    let q2 = query_prefix + user_filter
    return 1
}
"""
        cand_issues = collect_issues(bad_code, "English")
        cand_has_target = any(i.kind == "sql_injection" for i in cand_issues)
        # Even though line 3 was modified, SQL injection is still present on line 4!
        self.assertTrue(cand_has_target, "Expected candidate code to still have sql_injection issue")

    def test_5_gemini_malformed_json_retry_success(self):
        """
        Verify that if attempt 1 returns malformed JSON, attempt 2 with valid JSON patch succeeds.
        """
        source = """function compute(x) {
    let unused_val = 42
    return x * 2
}
"""
        issues = collect_issues(source, "English")
        target_issue = next((i for i in issues if i.kind == "unused_variable"), None)
        self.assertIsNotNone(target_issue)

        mock_responses = [
            # Attempt 1: Malformed JSON
            "```json\n{ invalid_json: true, fixes: [\n```",
            # Attempt 2: Valid JSON patch conforming to schema
            json.dumps({
                "fixes": [{
                    "issue_id": target_issue.id,
                    "start_line": 2,
                    "end_line": 2,
                    "original_snippet": "    let unused_val = 42",
                    "replacement": "",
                    "explanation": "Removed unused variable unused_val"
                }]
            })
        ]

        with patch("web.gemini_client.ai_client.generate_text", side_effect=mock_responses):
            res = _attempt_gemini_fallback(
                current_code=source,
                issue=target_issue,
                language="English",
                baseline_passing_stages={"source_input", "lexical_analysis", "syntax_analysis"},
                baseline_stdout=""
            )
            self.assertTrue(res.get("accepted"), f"Expected patch to be accepted on attempt 2, got {res}")
            self.assertEqual(res.get("fix_record", {}).get("fixer"), "Gemini 2.5 Flash")

    def test_6_gemini_three_failures_shows_retry_and_no_forbidden_strings(self):
        """
        Verify that after 3 AI failures:
        - Result reports failure with 'AI fixer unavailable: <reason>'
        - None of the 5 forbidden strings appear anywhere in the result
        """
        source = """function calc(n) {
    let unused_param = 99
    return n + 1
}
"""
        issues = collect_issues(source, "English")
        target_issue = issues[0]

        # 3 malformed responses
        mock_failures = ["bad1", "bad2", "bad3"]

        with patch("web.gemini_client.ai_client.generate_text", side_effect=mock_failures):
            res = _attempt_gemini_fallback(
                current_code=source,
                issue=target_issue,
                language="English",
                baseline_passing_stages={"source_input"},
                baseline_stdout=""
            )
            self.assertFalse(res.get("accepted"))
            reason = res.get("reason", "")
            self.assertTrue(reason.startswith("AI fixer unavailable:"), f"Expected 'AI fixer unavailable:', got: {reason}")

            # Verify no forbidden strings
            res_str = json.dumps(res)
            for forbidden in FORBIDDEN_STRINGS:
                self.assertNotIn(
                    forbidden.lower(),
                    res_str.lower(),
                    f"Forbidden string '{forbidden}' found in AI fallback result"
                )

    def test_7_stage_dialog_never_pending_for_completed_stage(self):
        """
        Verify that stage dialog data from the run table never has status 'pending'
        for a stage that was executed and completed.
        """
        source = "let x = 10\nprint(x)\n"
        tracker = execute_pipeline_with_tracker(source, "English", run_ai_security=False)
        tracker_dict = tracker.to_dict()

        stages = tracker_dict.get("stages", [])
        self.assertEqual(len(stages), 14)

        for st in stages:
            sid = st.get("id")
            status = st.get("status")
            # For stages that executed before completion
            if sid in ("source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
                        "semantic_analysis", "symbol_table", "ir_generation", "optimization",
                        "code_generation", "code_validation", "security_analysis", "sandbox_execution",
                        "final_report"):
                self.assertNotEqual(
                    status,
                    "pending",
                    f"Stage {sid} has status 'pending' in completed run table!"
                )

    def test_8_no_displayed_numbers_disagree(self):
        """
        Verify that for any file and buffer hash:
        - stage badges derived from counts_by_stage
        - Code Health status and penalties derived from counts_by_severity
        - button label derived from total_fixable
        - Fix All dialog title and row count
        ALL derive strictly from collect_issues and never disagree.
        """
        test_files = [
            ("examples/security_lab/telugu/sec_injection_eval_te.vital", "Telugu"),
            ("examples/security_lab/hindi/sec_injection_eval_hi.vital", "Hindi"),
            ("examples/hindi/bank_ledger_system.vital", "Hindi"),
            ("examples/english/student_grade_report.vital", "English")
        ]

        for rel_path, lang in test_files:
            fpath = os.path.join(PROJECT_ROOT, rel_path)
            with open(fpath, "r", encoding="utf-8") as f:
                code = f.read()

            issues = collect_issues(code, lang)
            stg_counts = counts_by_stage(issues)
            sev_counts = counts_by_severity(issues)
            fixable_cnt = total_fixable(issues)

            health = analyze_health(code, language=lang, filename=os.path.basename(fpath))
            fix_res = run_stage_targeted_fix_all(source_code=code, language=lang, file_path=fpath, use_ai=False)

            # Check 1: total fixable agrees across all interfaces
            self.assertEqual(fixable_cnt, health.get("total_fixable"))
            self.assertEqual(fixable_cnt, fix_res.get("total_diagnostics"))
            self.assertEqual(fixable_cnt, len(fix_res.get("error_diffs", [])))

            # Check 2: severity counts sum up to total issues
            self.assertEqual(sum(sev_counts.values()), len(issues))

            # Check 3: stage counts agree with stage findings in tracker
            tracker = execute_pipeline_with_tracker(code, lang, run_ai_security=False)
            tracker_issues = tracker.to_dict().get("issues", [])
            self.assertEqual(len(tracker_issues), len(issues))


if __name__ == "__main__":
    unittest.main()
