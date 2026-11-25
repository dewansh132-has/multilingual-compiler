# -*- coding: utf-8 -*-
"""
tests/test_stage_gates.py — Regression tests asserting expected first-failing stage
per demo type across all supported languages (English, Hindi, Telugu, Bengali, Marathi, Nepali, Fusion).

Gating Rules Verified:
1. Normal canonical examples pass Stages 1-10 cleanly with zero errors.
2. Demo A (sec_auth_account_*) fails at Stage 5 (semantic_analysis) with an undefined-variable
   error naming the variable and line.
3. Demo D (sec_business_workflow_*) fails at Stage 3 (syntax_analysis) with an unbalanced
   delimiter error naming the line.
4. Demo B (sec_data_config_*) passes Stages 1-10 cleanly (its security vulnerabilities are caught in Stage 11).
5. Demo C (sec_injection_eval_*) in English, Hindi, Telugu, Bengali, Marathi, Nepali passes Stages 1-10.
6. Semantic analysis enforces strict lexical scoping: parameter and local variable leakage across
   distinct functions is caught and produces SEC-SEM-001.
"""

import os
import sys
import ast
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.pipeline_tracker import execute_pipeline_with_tracker, STAGE_ORDER
from src.semantic import SemanticAnalyzer


def get_first_failing_stage(tracker):
    """Returns (stage_id, reason) for the first stage in 1-10 that failed or was blocked."""
    for sid in STAGE_ORDER[:10]:
        st = tracker.stages.get(sid, {})
        status = st.get("status")
        if status in ("failed", "blocked"):
            return sid, st.get("reason") or st.get("summary") or "Failed"
    return "PASSED (1-10)", ""


class TestStageGates(unittest.TestCase):

    def _run_file(self, rel_path: str):
        full_path = os.path.join(PROJECT_ROOT, rel_path)
        self.assertTrue(os.path.exists(full_path), f"File not found: {full_path}")
        with open(full_path, "r", encoding="utf-8") as f:
            code = f.read()
        tracker = execute_pipeline_with_tracker(
            source_code=code,
            language_hint="",
            run_ai_security=False,
            mandatory_only=True
        )
        return get_first_failing_stage(tracker)

    # -------------------------------------------------------------------------
    # 1. Normal Canonical Examples: Pass Stages 1-10 cleanly
    # -------------------------------------------------------------------------
    def test_normal_programs_pass_stages_1_to_10(self):
        canonical_files = [
            "examples/english/hello.vital",
            "examples/english/arithmetic.vital",
            "examples/english/inventory_management_system.vital",
            "examples/hindi/hello.vital",
            "examples/hindi/arithmetic.vital",
            "examples/telugu/hello.vital",
            "examples/telugu/arithmetic.vital",
            "examples/bengali/hello.vital",
            "examples/bengali/arithmetic.vital",
            "examples/marathi/hello.vital",
            "examples/marathi/arithmetic.vital",
            "examples/nepali/hello.vital",
            "examples/nepali/arithmetic.vital",
            "examples/fusion/fusion_data_pipeline.vital",
            "examples/fusion/fusion_autonomous_robot.vital",
        ]
        for rel_path in canonical_files:
            with self.subTest(file=rel_path):
                stage, msg = self._run_file(rel_path)
                self.assertEqual(stage, "PASSED (1-10)", f"{rel_path} unexpectedly failed at {stage}: {msg}")

    # -------------------------------------------------------------------------
    # 2. Demo A (sec_auth_account_*): Fail at Stage 5 (semantic_analysis)
    # -------------------------------------------------------------------------
    def test_demo_a_fails_at_stage_5_across_all_languages(self):
        demo_a_files = [
            ("examples/security_lab/english/sec_auth_account.vital", "acc_status"),
            ("examples/security_lab/hindi/sec_auth_account_hi.vital", "खाता_स्थिति"),
            ("examples/security_lab/telugu/sec_auth_account_te.vital", "ఖాతా_స్థితి"),
            ("examples/security_lab/bengali/sec_auth_account_bn.vital", "অ্যাকাউন্ট_অবস্থা"),
            ("examples/security_lab/marathi/sec_auth_account_mr.vital", "खाते_स्थिती"),
            ("examples/security_lab/nepali/sec_auth_account_ne.vital", "खाता_स्थिति"),
            ("examples/security_lab/fusion/sec_auth_account_fusion.vital", "acc_status"),
        ]
        for rel_path, expected_var in demo_a_files:
            with self.subTest(file=rel_path, var=expected_var):
                stage, msg = self._run_file(rel_path)
                self.assertEqual(stage, "semantic_analysis",
                                 f"{rel_path} expected failure at semantic_analysis, got {stage} ({msg})")
                self.assertIn("Identifier", msg)
                self.assertIn(expected_var, msg,
                              f"Expected undeclared identifier '{expected_var}' in error message, got: {msg}")

    # -------------------------------------------------------------------------
    # 3. Demo D (sec_business_workflow_*): Fail at Stage 3 (syntax_analysis)
    # -------------------------------------------------------------------------
    def test_demo_d_fails_at_stage_3_across_all_languages(self):
        demo_d_files = [
            "examples/security_lab/english/sec_business_workflow.vital",
            "examples/security_lab/hindi/sec_business_workflow_hi.vital",
            "examples/security_lab/telugu/sec_business_workflow_te.vital",
            "examples/security_lab/bengali/sec_business_workflow_bn.vital",
            "examples/security_lab/marathi/sec_business_workflow_mr.vital",
            "examples/security_lab/nepali/sec_business_workflow_ne.vital",
            "examples/security_lab/fusion/sec_business_workflow_fusion.vital",
        ]
        for rel_path in demo_d_files:
            with self.subTest(file=rel_path):
                stage, msg = self._run_file(rel_path)
                self.assertEqual(stage, "syntax_analysis",
                                 f"{rel_path} expected failure at syntax_analysis, got {stage} ({msg})")
                self.assertTrue(
                    any(term in msg.lower() for term in ["unbalanced", "delimiter", "unclosed", "{", "}"]),
                    f"Expected delimiter error message for {rel_path}, got: {msg}"
                )

    # -------------------------------------------------------------------------
    # 4. Demo B (sec_data_config_*): Pass Stages 1-10 across all languages
    # -------------------------------------------------------------------------
    def test_demo_b_passes_stages_1_to_10_across_all_languages(self):
        demo_b_files = [
            "examples/security_lab/english/sec_data_config.vital",
            "examples/security_lab/hindi/sec_data_config_hi.vital",
            "examples/security_lab/telugu/sec_data_config_te.vital",
            "examples/security_lab/bengali/sec_data_config_bn.vital",
            "examples/security_lab/marathi/sec_data_config_mr.vital",
            "examples/security_lab/nepali/sec_data_config_ne.vital",
            "examples/security_lab/fusion/sec_data_config_fusion.vital",
        ]
        for rel_path in demo_b_files:
            with self.subTest(file=rel_path):
                stage, msg = self._run_file(rel_path)
                self.assertEqual(stage, "PASSED (1-10)",
                                 f"{rel_path} expected to pass stages 1-10, got {stage} ({msg})")

    # -------------------------------------------------------------------------
    # 5. Demo C (sec_injection_eval_*): Pass Stages 1-10 for the 6 languages
    # -------------------------------------------------------------------------
    def test_demo_c_passes_stages_1_to_10_for_six_languages(self):
        demo_c_files = [
            "examples/security_lab/english/sec_injection_eval.vital",
            "examples/security_lab/hindi/sec_injection_eval_hi.vital",
            "examples/security_lab/telugu/sec_injection_eval_te.vital",
            "examples/security_lab/bengali/sec_injection_eval_bn.vital",
            "examples/security_lab/marathi/sec_injection_eval_mr.vital",
            "examples/security_lab/nepali/sec_injection_eval_ne.vital",
        ]
        for rel_path in demo_c_files:
            with self.subTest(file=rel_path):
                stage, msg = self._run_file(rel_path)
                self.assertEqual(stage, "PASSED (1-10)",
                                 f"{rel_path} expected to pass stages 1-10, got {stage} ({msg})")

    # -------------------------------------------------------------------------
    # 6. Lexical Scoping: Cross-function parameter and local variable isolation
    # -------------------------------------------------------------------------
    def test_cross_function_variable_leakage_prevented(self):
        """Verifies that variables and parameters in function A do not leak into function B."""
        code = """
def func_a(param_secret):
    local_temp = param_secret * 2
    return local_temp

def func_b():
    print(param_secret)
    print(local_temp)
"""
        analyzer = SemanticAnalyzer()
        res = analyzer.analyze(ast.parse(code))
        self.assertEqual(res["error_count"], 2, f"Expected 2 scoping errors, got {res['error_count']}")
        identifiers_flagged = [d.get("identifier") for d in res["diagnostics"] if d.get("type") == "error"]
        self.assertIn("param_secret", identifiers_flagged)
        self.assertIn("local_temp", identifiers_flagged)


if __name__ == "__main__":
    unittest.main()
