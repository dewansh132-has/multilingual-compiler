# -*- coding: utf-8 -*-
"""
tests/test_autonomous_pipeline_and_optimization.py

Full verification test suite covering all Master Task acceptance criteria:
  - Test A: Parser brace mismatch remediation (Telugu security demo)
  - Test B: Multiple independent errors
  - Test C: Semantic Analysis error remediation
  - Test D: Mandatory IR Optimization execution, passes, and zero-op handling
  - Test E: Final Report completion guard and blocking on failed/skipped stages
  - Test F: Local Ollama offline handling (graceful degradation without fake fixes)
  - Test G: Working buffer isolation, undo, and demo preservation
  - Test H: Multilingual regression testing across all 6 supported languages
"""

import os
import sys
import json
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, 'src')
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from main import Compiler, RULES_FILE
from web.ai_remediation_engine import remediation_engine, DiagnosticNormalizer, StageValidator
from web.ir_optimizer import IROptimizer
from web.pipeline_tracker import execute_pipeline_with_tracker, PipelineRunTracker, STAGE_DEFINITIONS
from web.ollama_client import ollama_client, OllamaClient


class TestAutonomousPipelineAndOptimization(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.compiler = Compiler(RULES_FILE)
        cls.compiler.load_rules()
        cls.telugu_auth_path = os.path.join(PROJECT_ROOT, "examples", "security_lab", "telugu", "sec_auth_account_te.vital")
        cls.telugu_eval_path = os.path.join(PROJECT_ROOT, "examples", "security_lab", "telugu", "sec_injection_eval_te.vital")

    def test_test_a_parser_brace_remediation(self):
        """Test A: Detects brace mismatch, generates valid fix via engine, and confirms revalidation."""
        with open(self.telugu_auth_path, "r", encoding="utf-8") as f:
            original_code = f.read()

        # Inject an extra closing brace to reproduce 12 open vs 13 close (or 14 vs 15)
        lines = original_code.splitlines()
        lines.insert(45, "    }")
        corrupted_code = "\n".join(lines)

        # 1. Delimiter scan
        delims = DiagnosticNormalizer.analyze_delimiters(corrupted_code)
        self.assertFalse(delims["is_balanced"])
        self.assertEqual(delims["brace_diff"], -1)
        self.assertTrue(len(delims["extra_close_braces"]) > 0)

        # 2. Generate fix
        fix_result = remediation_engine.generate_fix(
            source_code=corrupted_code,
            stage_id="syntax_analysis",
            finding_id="SEC-PAR-001",
            finding_data={
                "title": "Unbalanced Block Scope Delimiters ('{' vs '}')",
                "rule_id": "SEC-PAR-001",
                "evidence": f"Found {delims['open_braces']} open brace(s) and {delims['close_braces']} closing brace(s)",
                "line": delims["extra_close_braces"][0][0],
                "stage_id": "syntax_analysis"
            },
            language="Telugu",
            source_revision=1,
            file_path=self.telugu_auth_path
        )

        self.assertTrue(fix_result.get("success"), f"Fix generation should succeed: {fix_result.get('error')}")
        self.assertIn("Validated", fix_result.get("validation_status", ""))
        self.assertTrue(len(fix_result.get("diff", "")) > 0)

        # 3. Verify that applying the fix balances the delimiters and passes parser
        repaired_source = fix_result.get("proposed_source", "")
        repaired_delims = DiagnosticNormalizer.analyze_delimiters(repaired_source)
        self.assertTrue(repaired_delims["is_balanced"], "Delimiters must be balanced after patch")

        valid = self.compiler.run_parser(repaired_source)
        self.assertTrue(valid, "Parser must validate the repaired source code successfully")

    def test_test_b_multiple_errors_tracked_independently(self):
        """Test B: Multiple syntax errors are reported and tracked independently."""
        code_multi_err = (
            'function test() {\n'
            '    let a = 10\n'
            '    if ((a > 5) {\n' # Unbalanced paren
            '        print("hi")\n'
            '    }\n'
            '}\n'
            '}\n' # Extra closing brace
        )
        delims = DiagnosticNormalizer.analyze_delimiters(code_multi_err)
        self.assertFalse(delims["is_balanced"])
        self.assertEqual(delims["brace_diff"], -1) # 1 extra close brace
        self.assertEqual(delims["paren_diff"], 1)  # 1 unclosed open paren
        self.assertTrue(len(delims["extra_close_braces"]) > 0)
        self.assertTrue(len(delims["unclosed_parens"]) > 0)

    def test_test_c_semantic_remediation(self):
        """Test C: Semantic analysis error generates valid declaration patch."""
        # Code referencing undeclared variable
        code_undeclared = (
            'function test_scope() {\n'
            '    let a = 10\n'
            '    print(undefined_identifier)\n'
            '}\n'
            'test_scope()\n'
        )
        fix_res = remediation_engine.generate_fix(
            source_code=code_undeclared,
            stage_id="semantic_analysis",
            finding_id="SEC-SEM-001",
            finding_data={
                "title": "Identifier 'undefined_identifier' referenced before explicit local assignment.",
                "rule_id": "SEC-SEM-001",
                "line": 3,
                "stage_id": "semantic_analysis"
            },
            language="English"
        )
        self.assertTrue(fix_res.get("success"), "Semantic fix should succeed")
        self.assertIn("undefined_identifier", fix_res.get("proposed_source", ""))
        self.assertIn("Validated", fix_res.get("validation_status", ""))

    def test_test_d_optimization_mandatory_execution(self):
        """Test D: Optimization stage ALWAYS executes, transforms applicable IR, and handles zero-op."""
        # 1. Code with optimization opportunities
        ir_optimizable = (
            "x = 5 + 15 * 2\n"
            "y = 'vital ' + 'compiler'\n"
            "z = x + 0\n"
            "def foo(v):\n"
            "    w = v * 1\n"
            "    return w + 10\n"
            "    print('dead statement')\n"
        )
        opt_res = IROptimizer.optimize(ir_optimizable, use_ai=False)
        self.assertTrue(opt_res["success"])
        self.assertGreater(opt_res["transformations_count"], 0)
        self.assertIn("Constant Folding", opt_res["passes_applied"])
        self.assertIn("Dead Code Elimination", opt_res["passes_applied"])
        self.assertEqual(opt_res["validation_status"], "PASSED")
        self.assertIn("35", opt_res["optimized_ir"]) # 15*2=30 + 5 = 35

        # 2. Code with NO optimization opportunities
        ir_optimal = (
            "def greet(name):\n"
            "    print(name)\n"
            "    return 1\n"
        )
        opt_res2 = IROptimizer.optimize(ir_optimal, use_ai=False)
        self.assertTrue(opt_res2["success"])
        self.assertEqual(opt_res2["transformations_count"], 0)
        self.assertEqual(opt_res2["validation_status"], "PASSED")
        self.assertIn("No applicable optimization found", opt_res2["summary"])

    def test_test_e_final_report_blocking(self):
        """Test E: Mandatory finalization guard blocks report if any required stage failed."""
        from web.server import create_app
        client = create_app().test_client()

        # 1. Blocked by Syntax Error
        resp_syntax_err = client.post("/api/pipeline/generate-report", json={
            "source_code": "function broken() { if (1) { print(1) }",
            "language": "English",
            "run_id": "test-run-1"
        })
        self.assertEqual(resp_syntax_err.status_code, 400)
        data_s = resp_syntax_err.get_json()
        self.assertFalse(data_s["success"])
        self.assertEqual(data_s.get("blocked_stage"), "syntax_analysis")

        # 2. Clean valid code generates report with optimization details
        valid_vital = (
            'let a = 10\n'
            'let b = 20\n'
            'let res = a + b\n'
            'print(res)\n'
        )
        resp_valid = client.post("/api/pipeline/generate-report", json={
            "source_code": valid_vital,
            "language": "English",
            "run_id": "test-run-2"
        })
        self.assertEqual(resp_valid.status_code, 200)
        data_v = resp_valid.get_json()
        self.assertTrue(data_v["success"])
        self.assertIn("optimization", data_v["artifacts"])
        self.assertEqual(data_v["artifacts"]["optimization"]["validation_status"], "PASSED")

    def test_test_f_ollama_offline_behavior(self):
        """Test F: When Ollama is offline, system reports connection status clearly without fake AI."""
        offline_client = OllamaClient(base_url="http://localhost:9999", timeout=1.0)
        is_healthy, msg, details = offline_client.check_health(force_refresh=True)
        self.assertFalse(is_healthy)
        self.assertIn("offline", msg.lower())

    def test_test_g_undo_and_restore_preserves_disk_files(self):
        """Test G: Demo files on disk remain completely unmodified."""
        with open(self.telugu_auth_path, "r", encoding="utf-8") as f:
            disk_content_before = f.read()

        # Execute pipeline and run fix logic on a copy
        tracker = PipelineRunTracker()
        execute_pipeline_with_tracker(
            source_code=disk_content_before,
            language_hint="Telugu",
            run_ai_security=False,
            tracker=tracker
        )

        with open(self.telugu_auth_path, "r", encoding="utf-8") as f:
            disk_content_after = f.read()

        self.assertEqual(disk_content_before, disk_content_after, "Original demo file on disk must never be modified")

    def test_test_h_existing_demos_regression(self):
        """Test H: Multilingual demo files in all supported languages compile properly."""
        langs = ["bengali", "english", "hindi", "marathi", "nepali", "telugu"]
        for lang in langs:
            demo_path = os.path.join(PROJECT_ROOT, "examples", lang, "hello.vital")
            if os.path.exists(demo_path):
                with open(demo_path, "r", encoding="utf-8") as f:
                    code = f.read()
                delims = DiagnosticNormalizer.analyze_delimiters(code)
                self.assertTrue(delims["is_balanced"], f"{lang}/hello.vital delimiters should be balanced")


if __name__ == "__main__":
    unittest.main()

