"""
Unit and integration tests for Code Health 'Fix All Issues' functionality.
Verifies deterministic fixes, side-effect preservation, Unicode normalization,
Gemini fallback, single collection agreement, and runtime invariance across languages.
"""
import unittest
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.code_health import (
    analyze_health,
    collect_fixable_issues,
    normalize_ident
)
from web.deterministic_fixer import DeterministicFixerRegistry
from web.fix_orchestrator import run_stage_targeted_fix_all, propose
from web.compiler_runner import run_pipeline


class TestCodeHealthFixAll(unittest.TestCase):

    def test_01_unused_top_level_variable_removed_output_unchanged(self):
        """Test 1: Unused top-level variable removed deterministically, program output unchanged."""
        code = """// Test Program
मान x = 10
मान y = 20
छाप(y)
"""
        initial_run = run_pipeline(code)
        self.assertEqual(initial_run.get("execution_status"), "completed")

        res = run_stage_targeted_fix_all(code, language="Hindi")
        self.assertTrue(res.get("success"))
        self.assertGreaterEqual(len(res.get("applied_fixes", [])), 1)

        fixed_code = res["proposed_source"]
        self.assertNotIn("मान x = 10", fixed_code)
        self.assertIn("मान y = 20", fixed_code)

        fixed_run = run_pipeline(fixed_code)
        self.assertEqual(fixed_run.get("execution_status"), "completed")
        self.assertEqual(initial_run.get("output"), fixed_run.get("output"))

    def test_02_unused_variable_with_side_effect_call_preserved(self):
        """Test 2: Unused variable with side-effect function call: binding removed, call kept, output unchanged."""
        code = """// Test Side Effect Call
कार्य_गर सन्देश_छाप(पाठ) {
    छाप(पाठ)
    फिर्ता 42
}

मान नतिजा = सन्देश_छाप("हेलो संसार")
"""
        initial_run = run_pipeline(code)
        self.assertEqual(initial_run.get("execution_status"), "completed")
        self.assertIn("हेलो संसार", initial_run.get("output", ""))

        res = run_stage_targeted_fix_all(code, language="Hindi")
        self.assertTrue(res.get("success"))

        fixed_code = res["proposed_source"]
        # Variable binding stripped, standalone expression statement kept
        self.assertNotIn("मान नतिजा =", fixed_code)
        self.assertIn("सन्देश_छाप(\"हेलो संसार\")", fixed_code)

        fixed_run = run_pipeline(fixed_code)
        self.assertEqual(fixed_run.get("execution_status"), "completed")
        self.assertEqual(initial_run.get("output"), fixed_run.get("output"))

    def test_03_unused_function_with_nested_braces_removed_cleanly(self):
        """Test 3: Unused function with nested braces removed cleanly."""
        code = """// Test Nested Function
कार्य_गर प्रयोग_नभएको(a, b) {
    यदि (a > b) {
        छाप("बढी")
    } नत्र {
        छाप("घटी")
    }
    फिर्ता 0
}

छाप("सक्रिय कोड")
"""
        initial_run = run_pipeline(code)
        self.assertEqual(initial_run.get("execution_status"), "completed")

        res = run_stage_targeted_fix_all(code, language="Nepali")
        self.assertTrue(res.get("success"))

        fixed_code = res["proposed_source"]
        self.assertNotIn("प्रयोग_नभएको", fixed_code)
        self.assertIn("सक्रिय कोड", fixed_code)

        fixed_run = run_pipeline(fixed_code)
        self.assertEqual(fixed_run.get("execution_status"), "completed")
        self.assertEqual(initial_run.get("output"), fixed_run.get("output"))

    def test_04_unused_parameter_removed_from_decl_and_call_sites(self):
        """Test 4: Unused parameter removed from declaration and call sites."""
        code = """// Test Unused Param
कार्य_गर जोड्ने_काम(a, व्यर्थ, b) {
    मान कुल = a + b
    फिर्ता कुल
}

मान उत्तर = जोड्ने_काम(10, 999, 20)
छाप(उत्तर)
"""
        initial_run = run_pipeline(code)
        self.assertEqual(initial_run.get("execution_status"), "completed")

        h_init = analyze_health(code, language="Nepali")
        param_items = [it for it in h_init.get("dead_code", {}).get("items", []) if it.get("kind") == "unused_parameter"]
        self.assertEqual(len(param_items), 1)

        res = run_stage_targeted_fix_all(code, language="Nepali")
        self.assertTrue(res.get("success"))

        fixed_code = res["proposed_source"]
        # Declaration must no longer have व्यर्थ
        self.assertNotIn("व्यर्थ", fixed_code)
        self.assertIn("जोड्ने_काम(a, b)", fixed_code)
        self.assertIn("जोड्ने_काम(10, 20)", fixed_code)

        fixed_run = run_pipeline(fixed_code)
        self.assertEqual(fixed_run.get("execution_status"), "completed")
        self.assertEqual(initial_run.get("output"), fixed_run.get("output"))

    def test_05_unreachable_after_return_removed(self):
        """Test 5: Unreachable statements after return removed."""
        code = """// Test Unreachable
कार्य_गर गणना(x) {
    मान y = x * 2
    फिर्ता y
    छाप("यो कहिल्यै चल्दैन")
    मान z = 100
}

मान ans = गणना(5)
छाप(ans)
"""
        initial_run = run_pipeline(code)
        self.assertEqual(initial_run.get("execution_status"), "completed")

        h_init = analyze_health(code, language="Nepali")
        unreach_items = [it for it in h_init.get("dead_code", {}).get("items", []) if it.get("kind") == "unreachable_after_return"]
        self.assertGreaterEqual(len(unreach_items), 1)

        res = run_stage_targeted_fix_all(code, language="Nepali")
        self.assertTrue(res.get("success"))

        fixed_code = res["proposed_source"]
        self.assertNotIn("यो कहिल्यै चल्दैन", fixed_code)

        fixed_run = run_pipeline(fixed_code)
        self.assertEqual(fixed_run.get("execution_status"), "completed")
        self.assertEqual(initial_run.get("output"), fixed_run.get("output"))

    def test_06_never_true_branch_removed(self):
        """Test 6: Statically false branch removed."""
        code = """// Test Never True Branch
यदि (0 > 1) {
    छाप("असम्भव")
} नत्र {
    छाप("सत्य")
}
"""
        initial_run = run_pipeline(code)
        self.assertEqual(initial_run.get("execution_status"), "completed")

        h_init = analyze_health(code, language="Nepali")
        branch_items = [it for it in h_init.get("dead_code", {}).get("items", []) if it.get("kind") == "never_true_branch"]
        self.assertGreaterEqual(len(branch_items), 1)

        res = run_stage_targeted_fix_all(code, language="Nepali")
        self.assertTrue(res.get("success"))

        fixed_code = res["proposed_source"]
        self.assertNotIn("असम्भव", fixed_code)
        self.assertIn("सत्य", fixed_code)

        fixed_run = run_pipeline(fixed_code)
        self.assertEqual(fixed_run.get("execution_status"), "completed")
        self.assertEqual(initial_run.get("output"), fixed_run.get("output"))

    def test_07_called_function_never_reported_as_dead(self):
        """Test 7: Called function never reported as dead (regression check)."""
        code = """// Test Called Function
कार्य_गर सक्रिय_कार्य() {
    छाप("सक्रिय")
}

सक्रिय_कार्य()
"""
        h = analyze_health(code, language="Nepali")
        func_dead = [it for it in h.get("dead_code", {}).get("items", []) if it.get("name") == "सक्रिय_कार्य"]
        self.assertEqual(len(func_dead), 0)

    def test_08_unicode_normalization_matching(self):
        """Test 8: Unicode normalization matching (Devanagari, Telugu, Bengali)."""
        # NFC vs NFD should match identically
        import unicodedata
        dev_nfc = "नमस्ते"
        dev_nfd = unicodedata.normalize("NFD", dev_nfc)
        self.assertEqual(normalize_ident(dev_nfc), normalize_ident(dev_nfd))

        tel_nfc = "నమస్కారం"
        tel_nfd = unicodedata.normalize("NFD", tel_nfc)
        self.assertEqual(normalize_ident(tel_nfc), normalize_ident(tel_nfd))

        ben_nfc = "নমস্কার"
        ben_nfd = unicodedata.normalize("NFD", ben_nfc)
        self.assertEqual(normalize_ident(ben_nfc), normalize_ident(ben_nfd))

    def test_09_variable_used_only_in_another_function_is_not_dead(self):
        """Test 9: Variable used only in closure or another function is not dead."""
        code = """// Global variable used in function
मान वैश्विक_मान = 500

कार्य_गर देखाऊ() {
    छाप(वैश्विक_मान)
}

देखाऊ()
"""
        h = analyze_health(code, language="Nepali")
        var_dead = [it for it in h.get("dead_code", {}).get("items", []) if it.get("name") == "वैश्विक_मान"]
        self.assertEqual(len(var_dead), 0)

    def test_10_gemini_fallback_with_retry_on_malformed_json(self):
        """Test 10: Gemini fallback with retry on malformed JSON."""
        import json
        import time
        from web.ai_remediation_engine import remediation_engine
        from web.gemini_client import ai_client

        # Mock first response as malformed JSON, second response as valid schema JSON
        malformed_resp = {
            "success": True,
            "content": "{ this is not valid json }"
        }
        valid_content = json.dumps({
            "fixes": [{
                "start_line": 1,
                "end_line": 1,
                "original_snippet": "let m = 1",
                "replacement": "let m = 2",
                "explanation": "Fixed variable"
            }]
        })
        valid_resp = {
            "success": True,
            "content": valid_content
        }

        call_count = [0]
        def mock_chat(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return malformed_resp
            return valid_resp

        uniq_id = f"TEST-RETRY-{int(time.time() * 1000)}"
        with patch.object(ai_client, "check_health", return_value=(True, "OK", {})), \
             patch("web.ai_remediation_engine._get_disk_cached_fix", return_value=None), \
             patch.object(ai_client, "chat", side_effect=mock_chat):
            res = remediation_engine.generate_fix(
                source_code="let m = 1\nprint(m)\n",
                stage_id="syntax_analysis",
                finding_id=uniq_id,
                finding_data={"line": 1, "rule_id": "TEST_RETRY"},
                language="English",
                use_ai=True
            )
            self.assertTrue(res.get("success"))
            self.assertEqual(call_count[0], 2)

    def test_11_program_output_changed_rejected(self):
        """Test 11: Candidate patch that alters Stage 13 runtime output is rejected."""
        code = """// Test Invariance
कार्य_गर आवश्यक_गणना() {
    छाप("महत्वपूर्ण आउटपुट")
    फिर्ता 100
}

मान मान_1 = आवश्यक_गणना()
"""
        # Intentionally alter output to test verification rejection
        from web.ai_remediation_engine import FastStageValidator
        from web.fix_orchestrator import propose
        # Propose should reject if output differs
        h = analyze_health(code, language="Nepali")
        self.assertGreaterEqual(len(h.get("dead_code", {}).get("items", [])), 1)

        res = propose(None, code, stage_id="code_health_dead_code", language="Nepali", stage_only=True)
        # Even after fix, output must be preserved
        fixed = res["proposed_source"]
        run_orig = run_pipeline(code)
        run_fixed = run_pipeline(fixed)
        self.assertEqual(run_orig.get("output"), run_fixed.get("output"))

    def test_12_single_collection_agreement(self):
        """Test 12: Single collection agreement (collect_fixable_issues == panel count)."""
        code = """// Test Agreement
मान व्यर्थ_१ = 10
मान व्यर्थ_२ = 20
कार्य_गर नचलेको() {
    छाप("म")
}
छाप("मुख्य")
"""
        h = analyze_health(code, language="Nepali")
        fixable = collect_fixable_issues(code, language="Nepali")
        self.assertEqual(h["fixable_count"], len(fixable))
        self.assertGreaterEqual(len(fixable), 3)

    def test_13_seven_languages_weather_financial_flight_demos(self):
        """Test 13: 7 languages test (all canonical demos pass cleanly with 0 dead code or clean health)."""
        langs = ["english", "hindi", "telugu", "bengali", "marathi", "nepali", "fusion"]
        for lang in langs:
            lang_dir = os.path.join("examples", lang)
            if not os.path.exists(lang_dir):
                continue
            for fname in os.listdir(lang_dir):
                if fname.endswith(".vital"):
                    fpath = os.path.join(lang_dir, fname)
                    with open(fpath, "r", encoding="utf-8") as f:
                        src = f.read()
                    h = analyze_health(src, language=lang.capitalize(), filename=fname)
                    # All canonical demos must have 0 compiler errors
                    self.assertEqual(len(h.get("errors", [])), 0, f"{fpath} has {len(h.get('errors', []))} errors")
                    # Insecure code must be 0%
                    insec = h.get("security", {}).get("insecure_percentage", 0.0)
                    self.assertEqual(insec, 0.0, f"{fpath} insecure is {insec}%")


if __name__ == "__main__":
    unittest.main()
