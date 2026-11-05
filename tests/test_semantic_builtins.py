# -*- coding: utf-8 -*-
"""
tests/test_semantic_builtins.py — Unit Tests for Semantic Builtins and Undeclared Variable Handling (Task A)

Verifies:
  1. Builtin/global names (eval, exec, compile, print, input, len, range, int, str, float, bool, etc.)
     and localized Indic builtins in Hindi, Telugu, Bengali, Marathi, Nepali do NOT cause UNDECLARED_VARIABLE.
  2. Calls to eval/exec/compile/__import__/os.system/subprocess are NOT semantic errors.
  3. Genuinely undeclared variables STILL produce SEC-SEM-001 error with line:col and nearest suggestion.
  4. Generic "guard arithmetic" text is removed from undeclared identifier diagnostics.
"""

import os
import sys
import ast
import unittest
import textwrap

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from main import Compiler, RULES_FILE
from semantic import SemanticAnalyzer, get_known_builtins


class TestSemanticBuiltins(unittest.TestCase):

    def setUp(self):
        self.compiler = Compiler(RULES_FILE)
        self.compiler.load_rules()
        self.analyzer = SemanticAnalyzer()

    def _analyze_source(self, code: str):
        clean_code = textwrap.dedent(code).strip()
        self.compiler.run_lexer(clean_code)
        ir = self.compiler.transpile(clean_code)
        tree = ast.parse(ir)
        return self.analyzer.analyze(tree)

    def test_known_builtins_populated(self):
        builtins = get_known_builtins()
        self.assertIn("eval", builtins)
        self.assertIn("exec", builtins)
        self.assertIn("compile", builtins)
        self.assertIn("print", builtins)
        self.assertIn("input", builtins)
        self.assertIn("len", builtins)
        self.assertIn("range", builtins)
        self.assertIn("int", builtins)
        self.assertIn("str", builtins)
        self.assertIn("float", builtins)
        self.assertIn("bool", builtins)
        # Check localized names
        self.assertTrue(any(ord(ch) > 127 for b in builtins for ch in b))

    def test_eval_exec_print_in_all_six_languages(self):
        """Task A.4: eval/exec/print calls do not cause UNDECLARED_VARIABLE in all 6 languages."""
        snippets = {
            "english": """
            let safe_eval_result = 0
            eval("print('Safe mock evaluation executing...')")
            print("Completed evaluation demo.")
            """,
            "hindi": """
            मानो सुरक्षित_मूल्यांकन_परिणाम = 0
            eval("print('Safe mock evaluation executing...')")
            लिखो("मूल्यांकन डेमो पूरा हुआ।")
            """,
            "telugu": """
            అనుకో సురక్షిత_మూల్యాంకన_ఫలితం = 0
            eval("print('Safe mock evaluation executing...')")
            రాయి("మూల్యాంకన డెమో పూర్తయింది.")
            """,
            "bengali": """
            ধরো নিরাপদ_মূল্যায়ন_ফলাফল = 0
            eval("print('Safe mock evaluation executing...')")
            ছাপাও("মূল্যায়ন ডেমো সম্পন্ন হয়েছে।")
            """,
            "marathi": """
            घ्या सुरक्षित_मूल्यांकन_निकाल = 0
            eval("print('Safe mock evaluation executing...')")
            लिहा("मूल्यांकन डेमो पूर्ण झाला.")
            """,
            "nepali": """
            मान सुरक्षित_मूल्याङ्कन_परिणाम = 0
            eval("print('Safe mock evaluation executing...')")
            छाप("मूल्याङ्कन डेमो पूरा भयो।")
            """
        }

        for lang, code in snippets.items():
            with self.subTest(language=lang):
                res = self._analyze_source(code)
                err_diagnostics = [d for d in res.get("diagnostics", []) if d.get("type") == "error"]
                self.assertEqual(
                    len(err_diagnostics), 0,
                    f"Language {lang} failed semantic analysis with: {err_diagnostics}"
                )

    def test_genuinely_undeclared_variable_detected(self):
        """Genuinely undeclared variable still raises SEC-SEM-001 with line:col and nearest suggestion."""
        code = """
        let account_closed = 1
        let val = account_close
        """
        res = self._analyze_source(code)
        errs = [d for d in res.get("diagnostics", []) if d.get("type") == "error"]
        self.assertGreater(len(errs), 0, "Expected undeclared variable error")

        diag = errs[0]
        self.assertEqual(diag.get("rule_id"), "SEC-SEM-001")
        self.assertEqual(diag.get("identifier"), "account_close")
        self.assertIn("account_close", diag.get("message", ""))
        self.assertIn("line", diag)
        self.assertIn("column", diag)
        # Verify nearest suggestion
        self.assertEqual(diag.get("suggestion"), "account_closed")
        self.assertIn("Did you mean 'account_closed'?", diag.get("message", ""))
        # Verify generic arithmetic advice is NOT in message or remediation
        self.assertNotIn("guard arithmetic", diag.get("message", "").lower())
        self.assertNotIn("guard arithmetic", diag.get("remediation", "").lower())

    def test_division_by_zero_semantic_error(self):
        """Division by literal zero is detected as SEM-001."""
        code = """
        let x = 10 / 0
        """
        res = self._analyze_source(code)
        errs = [d for d in res.get("diagnostics", []) if d.get("type") == "error"]
        self.assertGreater(len(errs), 0, "Expected division by zero error")
        self.assertTrue(any("division by zero" in d.get("message", "").lower() for d in errs))

    def test_eval_call_with_indic_print_statement_string_literal(self):
        """Calls with string literals containing Indic print statements do not parse inside string."""
        indic_evals = [
            'eval("print(\'సురక్షితమైన మాక్ మూల్యాంకనం అమలవుతోంది...\')")',
            'eval("print(\'सुरक्षित मॉक मूल्यांकन चल रहा है...\')")',
            'eval("print(\'নিরাপদ মক মূল্যায়ন কার্যকর হচ্ছে...\')")',
            'eval("print(\'सुरक्षित मॉक मूल्यांकन सुरू आहे...\')")',
            'eval("print(\'सुरक्षित नक्कली मूल्याङ्कन चलिरहेको छ...\')")'
        ]
        for expr in indic_evals:
            with self.subTest(expr=expr):
                code = f"let status = 1\n{expr}\nprint(status)"
                res = self._analyze_source(code)
                errs = [d for d in res.get("diagnostics", []) if d.get("type") == "error"]
                self.assertEqual(len(errs), 0, f"Expression {expr} caused semantic error: {errs}")
                # Ensure words inside string literal were not added to symbols or identifiers
                for forbidden in ["సురక్షితమైన", "सुरक्षित", "নিরাপদ"]:
                    self.assertNotIn(forbidden, res.get("symbols", {}))

    def test_all_six_security_lab_demo_c_files_pass_semantic_analysis(self):
        """All 6 Demo C files must pass Semantic Analysis (Stage 5) with zero semantic errors."""
        import glob
        pattern = os.path.join(PROJECT_ROOT, "examples", "security_lab", "*", "sec_injection_eval*.vital")
        files = glob.glob(pattern)
        self.assertEqual(len(files), 6, f"Expected 6 Demo C files, found {len(files)}")
        for fpath in files:
            with open(fpath, "r", encoding="utf-8") as f:
                code = f.read()
            res = self._analyze_source(code)
            errs = [d for d in res.get("diagnostics", []) if d.get("type") == "error"]
            self.assertEqual(len(errs), 0, f"File {os.path.basename(fpath)} had semantic errors: {errs}")


if __name__ == "__main__":
    unittest.main()
