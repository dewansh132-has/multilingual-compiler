# -*- coding: utf-8 -*-
"""
tests/test_fast_fix_flow.py — High-speed deterministic-first remediation & Stage 12 bypass tests.

Verifies:
1. Fix All on sec_auth_account.vital across English, Hindi, and Telugu finishes under 3.0s total and leaves stages 1-10 green.
2. Applying Fix All twice changes nothing the second time (idempotent).
3. No-op apply returns status 'already_applied'.
4. Stale-revision apply is rejected with 'Source changed since this fix was suggested, regenerating'.
5. Undefined-variable fix never introduces a new semantic error or invents misleading declarations.
6. Pipeline RUN with Stage 12 toggle OFF completes in under 5.0s.
"""

import os
import sys
import time
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ["VITAL_AI_DISABLED"] = "1"

from web.ai_remediation_engine import remediation_engine, AIRemediationEngine
from web.pipeline_tracker import execute_pipeline_with_tracker
from web.working_source_manager import working_source_manager


class TestFastFixFlow(unittest.TestCase):

    def setUp(self):
        os.environ["VITAL_AI_DISABLED"] = "1"
        self.en_path = os.path.join(PROJECT_ROOT, "examples", "security_lab", "english", "sec_auth_account.vital")
        self.hi_path = os.path.join(PROJECT_ROOT, "examples", "security_lab", "hindi", "sec_auth_account_hi.vital")
        self.te_path = os.path.join(PROJECT_ROOT, "examples", "security_lab", "telugu", "sec_auth_account_te.vital")

    def test_fix_all_speed_and_correctness_multilingual(self):
        """
        Fix All on sec_auth_account.vital in English, Hindi, Telugu must finish under
        3 seconds total and leave stages 1-10 green.
        """
        with open(self.en_path, "r", encoding="utf-8") as f:
            en_code = f.read()
        with open(self.hi_path, "r", encoding="utf-8") as f:
            hi_code = f.read()
        with open(self.te_path, "r", encoding="utf-8") as f:
            te_code = f.read()

        t0 = time.time()

        # 1. English Fix All
        res_en = remediation_engine.generate_fix_all(
            source_code=en_code,
            stage_id="semantic_analysis",
            language="English",
            file_path="examples/security_lab/english/sec_auth_account.vital"
        )
        self.assertTrue(res_en.get("success"), f"English Fix All failed: {res_en.get('error')}")
        self.assertIn("proposed_source", res_en)
        self.assertNotIn("let acc_status = 1", res_en["proposed_source"], "Should not invent 'let acc_status = 1'")
        self.assertIn("print(account_closed)", res_en["proposed_source"])

        # 2. Hindi Fix All
        res_hi = remediation_engine.generate_fix_all(
            source_code=hi_code,
            stage_id="semantic_analysis",
            language="Hindi",
            file_path="examples/security_lab/hindi/sec_auth_account_hi.vital"
        )
        self.assertTrue(res_hi.get("success"), f"Hindi Fix All failed: {res_hi.get('error')}")
        self.assertIn("proposed_source", res_hi)

        # 3. Telugu Fix All
        res_te = remediation_engine.generate_fix_all(
            source_code=te_code,
            stage_id="semantic_analysis",
            language="Telugu",
            file_path="examples/security_lab/telugu/sec_auth_account_te.vital"
        )
        self.assertTrue(res_te.get("success"), f"Telugu Fix All failed: {res_te.get('error')}")
        self.assertIn("proposed_source", res_te)

        total_elapsed = time.time() - t0
        print(f"\n[Performance Benchmark] Multilingual Fix All (EN+HI+TE) total time: {total_elapsed:.3f}s")
        self.assertLess(total_elapsed, 3.0, f"Fix All across 3 languages took {total_elapsed:.2f}s (budget: 3.0s)")

        # Verify stages 1-10 are 100% green on all 3 proposed codes
        stage_keys_1_to_10 = [
            "source_input", "lexical_analysis", "syntax_analysis", "ast_construction",
            "semantic_analysis", "symbol_table", "ir_generation", "optimization",
            "code_generation", "code_validation"
        ]

        for lang, proposed in [("English", res_en["proposed_source"]), ("Hindi", res_hi["proposed_source"]), ("Telugu", res_te["proposed_source"])]:
            tracker = execute_pipeline_with_tracker(proposed, lang, run_ai_security=False, pause_on_error=True)
            for sid in stage_keys_1_to_10:
                stage_status = tracker.stages.get(sid, {}).get("status")
                self.assertIn(
                    stage_status,
                    ("completed", "passed", "warning"),
                    f"Stage '{sid}' failed for {lang} with status: {stage_status}"
                )

    def test_fix_all_twice_changes_nothing(self):
        """Applying Fix All twice changes nothing the second time."""
        with open(self.en_path, "r", encoding="utf-8") as f:
            en_code = f.read()

        res1 = remediation_engine.generate_fix_all(
            source_code=en_code,
            stage_id="semantic_analysis",
            language="English"
        )
        self.assertTrue(res1.get("success"))
        code_after_first = res1.get("proposed_source")

        # Run second time on already fixed code
        res2 = remediation_engine.generate_fix_all(
            source_code=code_after_first,
            stage_id="semantic_analysis",
            language="English"
        )
        self.assertTrue(res2.get("success"))
        self.assertEqual(res2.get("status"), "already_applied")
        self.assertEqual(len(res2.get("fixes", [])), 0)
        self.assertEqual(res2.get("proposed_source"), code_after_first)

    def test_noop_apply_returns_already_applied(self):
        """A no-op apply returns 'Already applied' without regression."""
        test_path = "examples/english/arithmetic.vital"
        full_path = os.path.join(PROJECT_ROOT, test_path)
        with open(full_path, "r", encoding="utf-8") as f:
            code = f.read()

        working_source_manager.save_working_source(test_path, code, expected_revision=None, label="Init test")
        curr = working_source_manager.get_working_source(test_path)
        rev = curr.get("source_revision", 1)

        # Apply identical code
        res = remediation_engine.apply_and_verify_fix(
            file_path=test_path,
            proposed_source=code,
            expected_revision=rev,
            language="English"
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("status"), "already_applied")
        self.assertEqual(res.get("message"), "Already applied")

    def test_stale_revision_apply_is_rejected(self):
        """Stale-revision apply is rejected with exact message."""
        test_path = "examples/english/arithmetic.vital"
        full_path = os.path.join(PROJECT_ROOT, test_path)
        with open(full_path, "r", encoding="utf-8") as f:
            code = f.read()

        working_source_manager.save_working_source(test_path, code, expected_revision=None, label="Init test")
        curr = working_source_manager.get_working_source(test_path)
        active_rev = curr.get("source_revision", 1)

        # Provide a stale revision
        stale_rev = active_rev + 999
        res = remediation_engine.apply_and_verify_fix(
            file_path=test_path,
            proposed_source=code + "\nlet extra = 1\n",
            expected_revision=stale_rev,
            language="English"
        )
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "stale_revision")
        self.assertIn("Source changed since this fix was suggested, regenerating", res.get("error", ""))
        self.assertTrue(res.get("regenerate"))

    def test_undefined_variable_fix_correctness(self):
        """
        Undefined-variable fix renames to similar declared variable in scope,
        and never introduces a new semantic error or invents misleading declarations.
        """
        code = (
            "let account_closed = 1\n"
            "print(acc_status)\n"
        )
        finding_data = {
            "id": "SEC-SEM-001-L2-acc_status",
            "rule_id": "SEC-SEM-001",
            "title": "Identifier 'acc_status' referenced before explicit local assignment.",
            "line": 2,
            "evidence": "print(acc_status)"
        }
        res = AIRemediationEngine._fix_undeclared_variable(code, "SEC-SEM-001-L2-acc_status", finding_data, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertIn("print(account_closed)", res.get("proposed_source"))
        self.assertNotIn("let acc_status = 1", res.get("proposed_source"))

        # Case where no similar declared variable exists: must insert declaration before first use with comment
        code2 = (
            "print(totally_unrelated_var)\n"
        )
        finding_data2 = {
            "id": "SEC-SEM-001-L1-totally_unrelated_var",
            "rule_id": "SEC-SEM-001",
            "title": "Identifier 'totally_unrelated_var' referenced before explicit local assignment.",
            "line": 1,
            "evidence": "print(totally_unrelated_var)"
        }
        res2 = AIRemediationEngine._fix_undeclared_variable(code2, "SEC-SEM-001-L1-totally_unrelated_var", finding_data2, "English")
        self.assertIsNotNone(res2)
        self.assertTrue(res2.get("success"))
        self.assertIn("// TODO: verify initial value", res2.get("proposed_source"))
        self.assertIn("let totally_unrelated_var = 0", res2.get("proposed_source"))

    def test_run_with_stage12_off_completes_under_5s(self):
        """RUN with Stage 12 toggle OFF completes in < 5 seconds."""
        arith_path = os.path.join(PROJECT_ROOT, "examples", "english", "arithmetic.vital")
        with open(arith_path, "r", encoding="utf-8") as f:
            code = f.read()

        t0 = time.time()
        tracker = execute_pipeline_with_tracker(code, "English", run_ai_security=False, pause_on_error=False)
        dur = time.time() - t0

        print(f"\n[Performance Benchmark] Pipeline RUN with Stage 12 OFF took: {dur:.3f}s")
        self.assertLess(dur, 5.0, f"RUN took {dur:.2f}s (budget: 5.0s)")
        stage12 = tracker.stages.get("ai_security_analysis", {})
        self.assertEqual(stage12.get("status"), "skipped")


if __name__ == "__main__":
    unittest.main()
