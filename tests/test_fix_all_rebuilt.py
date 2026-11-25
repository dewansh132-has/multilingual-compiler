# -*- coding: utf-8 -*-
"""
tests/test_fix_all_rebuilt.py — Test Suite for Rebuilt Fix All & Deterministic Fixer Registry

Tests cover:
  1. Deterministic fixers for each rule: homoglyph, stop word, delimiter, undefined var,
     unused code, division by zero, NameError, loop timeout, security CWEs.
  2. Three homoglyphs fixed in one pass (3/3).
  3. Homoglyphs in string literals and comments are not touched and not reported.
  4. Stage 13 ZeroDivisionError guarded and re-run succeeds.
  5. Telugu Demo C fixed through to a clean / passing pipeline.
  6. Malformed JSON retry succeeds on attempt 2.
  7. Three AI failures show Retry / Apply-anyway without banned strings ("manual fix", etc.).
  8. Multilingual coverage across all 7 languages (English, Hindi, Telugu, Bengali, Marathi, Nepali, Fusion).
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.deterministic_fixer import (
    DeterministicFixerRegistry,
    is_in_string_or_comment,
    HOMOGLYPH_MAP
)
from web.ai_remediation_engine import (
    AIRemediationEngine,
    FastStageValidator,
    remediation_engine
)
from web.fix_orchestrator import propose, is_fix_allowed, FIX_ENABLED_CATEGORIES
from web.server import app


class TestDeterministicFixerRegistry(unittest.TestCase):
    """Test 1: Verification of every deterministic fixer rule."""

    def test_fix_homoglyph(self):
        # Devanagari danda '।' used as pipe '|' at col 15 (1-based)
        source = "let x = a । b\n"
        finding = {
            "id": "HOMO-1",
            "rule_id": "LEX-HOMOGLYPH",
            "title": "Devanagari Homoglyph: '।' Spoofing Symbol '|'",
            "line": 1,
            "column": 11,
            "flagged_char": "।",
            "ascii_replacement": "|"
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "lexical_analysis", "HOMO-1", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertIn("|", res.get("proposed_source"))
        self.assertNotIn("।", res.get("proposed_source"))

    def test_fix_stop_word_identifier(self):
        # Hindi stop word 'की' used as identifier
        source = "मानो की = 42\nछापो(की)\n"
        finding = {
            "id": "STOP-1",
            "rule_id": "SEM-STOPWORD",
            "title": "Stop word 'की' used as identifier",
            "identifier": "की",
            "line": 1
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "semantic_analysis", "STOP-1", finding, "Hindi")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertIn("की_var", res.get("proposed_source"))

    def test_fix_delimiter_unclosed_brace(self):
        source = "function compute(x) {\n    let y = x + 1\n"
        finding = {
            "id": "SYN-DELIM-1",
            "rule_id": "SYN-DELIM",
            "title": "Delimiter imbalance: unclosed brace",
            "line": 2
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "syntax_analysis", "SYN-DELIM-1", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("proposed_source").rstrip().endswith("}"))

    def test_fix_undefined_variable_levenshtein(self):
        # Typo: count vs cont
        source = "function run() {\n    let count = 10\n    let res = cont * 2\n}\n"
        finding = {
            "id": "UNDEF-1",
            "rule_id": "SEM-UNDECLARED",
            "title": "Identifier 'cont' is not defined",
            "identifier": "cont",
            "line": 3
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "semantic_analysis", "UNDEF-1", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertIn("count * 2", res.get("proposed_source"))

    def test_fix_undefined_variable_declaration(self):
        # New variable without prior declaration in Telugu
        source = "function calc() {\n    ముద్రించు(total_sum)\n}\n"
        finding = {
            "id": "UNDEF-2",
            "rule_id": "SEM-UNDECLARED",
            "title": "Identifier 'total_sum' is not defined",
            "identifier": "total_sum",
            "line": 2
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "semantic_analysis", "UNDEF-2", finding, "Telugu")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertIn("అనుకో total_sum = 0", res.get("proposed_source"))

    def test_fix_division_by_zero(self):
        source = "function calc(n) {\n    let a = n / 0\n    return a\n}\n"
        finding = {
            "id": "DIV-0",
            "rule_id": "SEM-001",
            "title": "Division by zero",
            "line": 2
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "semantic_analysis", "DIV-0", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertIn("/ 1", res.get("proposed_source"))

    def test_fix_unused_and_unreachable_code(self):
        source = "function work() {\n    let unused_x = 99\n    return 1\n    let dead = 2\n}\n"
        finding = {
            "id": "DEAD-1",
            "rule_id": "DEAD-CODE",
            "title": "Unreachable statement following return",
            "line": 4
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "semantic_analysis", "DEAD-1", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertNotIn("let dead = 2", res.get("proposed_source"))

    def test_fix_stage13_zerodivisionerror(self):
        source = "function div(a, b) {\n    let res = a / b\n    return res\n}\n"
        finding = {
            "id": "RUN-DIV",
            "rule_id": "RUN-EXCEPTION",
            "title": "ZeroDivisionError: division by zero",
            "line": 2,
            "evidence": "a / b"
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "sandbox_execution", "RUN-DIV", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertIn("if (b == 0)", res.get("proposed_source"))

    def test_fix_stage13_nameerror(self):
        source = "function compute() {\n    print(missing_var)\n}\n"
        finding = {
            "id": "RUN-NAME",
            "rule_id": "RUN-EXCEPTION",
            "title": "NameError: name 'missing_var' is not defined",
            "line": 2
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "sandbox_execution", "RUN-NAME", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertIn("let missing_var = 0", res.get("proposed_source"))

    def test_fix_stage13_timeout_loop(self):
        source = "function loop() {\n    while (i < 10) {\n        print(i)\n    }\n}\n"
        finding = {
            "id": "RUN-TO",
            "rule_id": "RUN-TIMEOUT",
            "title": "Execution timed out after 3.0s",
            "line": 2
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "sandbox_execution", "RUN-TO", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertIn("i = i + 1", res.get("proposed_source"))

    def test_fix_security_cwe_sql_injection(self):
        source = 'function query(user_id) {\n    let q = "SELECT * FROM users WHERE id = " + user_id\n    return q\n}\n'
        finding = {
            "id": "SEC-SQL",
            "rule_id": "SEC-INJ-001",
            "title": "SQL Injection (CWE-89)",
            "line": 2
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "security_analysis", "SEC-SQL", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertNotIn("+ user_id", res.get("proposed_source"))

    def test_fix_security_cwe_dynamic_eval(self):
        source = 'function eval_code() {\n    eval("print(\'hello safe world\')")\n}\n'
        finding = {
            "id": "SEC-EVAL",
            "rule_id": "SEC-EVAL-003",
            "title": "Dynamic Code Evaluation via eval() (CWE-95)",
            "line": 2
        }
        res = DeterministicFixerRegistry.attempt_fix(source, "security_analysis", "SEC-EVAL", finding, "English")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("success"))
        self.assertNotIn("eval(", res.get("proposed_source"))
        self.assertIn("print('hello safe world')", res.get("proposed_source"))


class TestMultiHomoglyphAndPreservation(unittest.TestCase):
    """Tests 2 & 3: Multi-homoglyph batches and string/comment immunity."""

    def test_three_homoglyphs_fixed_in_one_pass(self):
        # 3 homoglyphs on lines 1, 2, 3
        source = (
            "let a = x । y\n"      # Line 1: । -> |
            "let b = ०\n"          # Line 2: ० -> 0
            "let c = val ः type\n" # Line 3: ः -> :
        )
        diagnostics = [
            {"id": "H1", "rule_id": "LEX-HOMOGLYPH", "title": "Devanagari Homoglyph: '।' Spoofing '|'", "line": 1, "column": 11, "flagged_char": "।"},
            {"id": "H2", "rule_id": "LEX-HOMOGLYPH", "title": "Devanagari Digit '०' Spoofing '0'", "line": 2, "column": 9, "flagged_char": "०"},
            {"id": "H3", "rule_id": "LEX-HOMOGLYPH", "title": "Visarga 'ः' Spoofing ':'", "line": 3, "column": 13, "flagged_char": "ः"}
        ]
        res = propose(
            source_code=source,
            stage_id="lexical_analysis",
            diagnostics=diagnostics,
            language="English",
            use_ai=False
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("resolved_count"), 3)
        self.assertEqual(res.get("remaining_count"), 0)
        self.assertEqual(res.get("validation_badge_text"), "Verified Clean")
        prop = res.get("proposed_source", "")
        self.assertIn("|", prop)
        self.assertIn("0", prop)
        self.assertIn(":", prop)
        self.assertNotIn("।", prop)
        self.assertNotIn("०", prop)
        self.assertNotIn("ः", prop)

    def test_homoglyphs_in_strings_and_comments_preserved(self):
        line_comment = '// This comment contains a danda । and zero ०'
        line_string = 'let msg = "Hello world । zero ०"'
        # col_idx in comment
        self.assertTrue(is_in_string_or_comment(line_comment, 35))
        # col_idx in string literal
        self.assertTrue(is_in_string_or_comment(line_string, 24))

        # Attempting to fix a homoglyph located inside a string literal returns None
        finding = {
            "id": "H-STR",
            "rule_id": "LEX-HOMOGLYPH",
            "title": "Homoglyph inside string",
            "line": 1,
            "column": 25,
            "flagged_char": "।"
        }
        res = DeterministicFixerRegistry.attempt_fix(line_string, "lexical_analysis", "H-STR", finding, "English")
        self.assertIsNone(res)


class TestTeluguDemoCFixAll(unittest.TestCase):
    """Test 5: Telugu Demo C fixed through to clean or allowed-warning pipeline."""

    def test_telugu_demo_c_remediation(self):
        path = "examples/security_lab/telugu/sec_injection_eval_te.vital"
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        # Run Fix All on security_analysis
        res = remediation_engine.generate_fix_all(
            source_code=code,
            stage_id="security_analysis",
            language="Telugu",
            file_path=path,
            use_ai=False
        )
        self.assertTrue(res.get("success"))
        self.assertGreater(res.get("resolved_count", 0), 0)
        prop_code = res.get("proposed_source")
        self.assertIsNotNone(prop_code)
        # Fast Stage Validator 1-10 must pass
        val = FastStageValidator.verify_stages_1_to_10(prop_code, "Telugu")
        self.assertTrue(val.get("passed"))


class TestAIFallbackAndRetryMechanisms(unittest.TestCase):
    """Tests 6 & 7: Gemini AI Fallback, retries, and honest counters without banned strings."""

    @patch("web.ai_remediation_engine._get_disk_cached_fix", return_value=None)
    @patch("web.ai_remediation_engine.ai_client.chat")
    @patch("web.ai_remediation_engine.ai_client.check_health")
    def test_malformed_json_retry_succeeds_on_attempt_2(self, mock_health, mock_chat, mock_cache):
        mock_health.return_value = (True, "Gemini online", {})
        # Attempt 1: malformed JSON, Attempt 2: valid JSON matching strict patch schema
        mock_chat.side_effect = [
            {"success": True, "content": "```json\n{ this is not valid json }\n```"},
            {"success": True, "content": '```json\n{"fixes": [{"finding_id": "ERR-1", "start_line": 2, "end_line": 2, "original_snippet": "    let y = x +", "replacement": "    let y = x + 1", "explanation": "Added missing operand"}]}\n```'}
        ]

        source = "function test(x) {\n    let y = x +\n    return y\n}\n"
        finding = {"id": "ERR-1", "rule_id": "SYN-OPERATOR", "title": "Missing operand", "line": 2}
        res = remediation_engine.generate_fix(
            source_code=source,
            stage_id="syntax_analysis",
            finding_id="ERR-1",
            finding_data=finding,
            language="English",
            use_ai=True
        )
        self.assertEqual(mock_chat.call_count, 2)
        self.assertTrue(res.get("success"))
        self.assertIn("let y = x + 1", res.get("proposed_source", ""))

    @patch("web.ai_remediation_engine._get_disk_cached_fix", return_value=None)
    @patch("web.ai_remediation_engine.ai_client.chat")
    @patch("web.ai_remediation_engine.ai_client.check_health")
    def test_three_ai_failures_return_unverified_without_banned_strings(self, mock_health, mock_chat, mock_cache):
        mock_health.return_value = (True, "Gemini online", {})
        # 3 failed attempts
        mock_chat.return_value = {"success": True, "content": "```json\n{ invalid json completely }\n```"}

        source = "function broken() {\n    let a =\n}\n"
        finding = {"id": "ERR-BROKEN", "rule_id": "SYN-FAIL", "title": "Syntax error", "line": 2}
        res = remediation_engine.generate_fix(
            source_code=source,
            stage_id="syntax_analysis",
            finding_id="ERR-BROKEN",
            finding_data=finding,
            language="English",
            use_ai=True
        )
        # Must fail honestly without banned strings
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "unverified")
        self.assertIn(res.get("validation_verdict"), ("unverified", "invalid"))
        # Check complete absence of banned strings across result
        res_str = str(res).lower()
        self.assertNotIn("manual fix required", res_str)
        self.assertNotIn("no auto-fix available", res_str)
        self.assertNotIn("[manual review]", res_str)


class TestMultilingualCoverage(unittest.TestCase):
    """Test 8: Full coverage across all 7 languages (English, Hindi, Telugu, Bengali, Marathi, Nepali, Fusion)."""

    def test_all_seven_languages_deterministic_undeclared_var(self):
        cases = [
            ("English", "function test() {\n    print(my_var)\n}\n", "let my_var = 0"),
            ("Hindi", "कार्य test() {\n    छापो(my_var)\n}\n", "मानो my_var = 0"),
            ("Telugu", "ఫంక్షన్ test() {\n    ముద్రించు(my_var)\n}\n", "అనుకో my_var = 0"),
            ("Bengali", "ফাংশন test() {\n    ছাপাও(my_var)\n}\n", "ধরো my_var = 0"),
            ("Marathi", "कार्य_करा test() {\n    छापा(my_var)\n}\n", "घ्या my_var = 0"),
            ("Nepali", "कार्य_गर test() {\n    छाप्नुहोस्(my_var)\n}\n", "मानौँ my_var = 0"),
            ("Fusion", "function test() {\n    print(my_var)\n}\n", "let my_var = 0"),
        ]

        for lang, src, expected_decl in cases:
            with self.subTest(language=lang):
                finding = {
                    "id": f"UNDEF-{lang}",
                    "rule_id": "SEM-UNDECLARED",
                    "title": f"Identifier 'my_var' is not defined in {lang}",
                    "identifier": "my_var",
                    "line": 2
                }
                res = DeterministicFixerRegistry.attempt_fix(src, "semantic_analysis", f"UNDEF-{lang}", finding, lang)
                self.assertIsNotNone(res, f"Fixer returned None for {lang}")
                self.assertTrue(res.get("success"))
                self.assertIn(expected_decl, res.get("proposed_source"), f"Expected '{expected_decl}' in {lang} fix")


class TestCategoryGating(unittest.TestCase):
    """Tests fix controls gating: clean demos vs security_lab / user code."""

    def test_clean_demo_fix_disabled(self):
        self.assertFalse(is_fix_allowed("examples/english/hello.vital", "Benchmark: English"))
        self.assertFalse(is_fix_allowed("examples/hindi/matrix_operations_suite.vital", "Benchmark: Hindi"))
        self.assertTrue(is_fix_allowed("examples/security_lab/telugu/sec_injection_eval_te.vital", "Security Lab"))
        self.assertTrue(is_fix_allowed("my_custom_code.vital", "user_code"))
        self.assertTrue(is_fix_allowed("", "user_code"))


if __name__ == "__main__":
    unittest.main()
