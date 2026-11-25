# -*- coding: utf-8 -*-
"""
tests/test_code_health.py — Comprehensive Test Suite for Pre-Run Code Health Analyzer.

Verifies:
1. Normal programs produce status healthy/warnings with insecure_percentage == 0.0.
2. Demo A (sec_auth_account_*) produces error code SEM-* at the expected line.
3. Demo D (sec_business_workflow_*) produces error code SYN-* for unbalanced brace.
4. Demo B (sec_data_config_*) and Demo C (sec_injection_eval_*) produce insecure_percentage > 0 and expected CWEs.
5. Consistency across all 7 supported language folders:
   english, hindi, telugu, bengali, marathi, nepali, fusion.
6. Performance: Analysis of a 500-line program completes in < 300 ms.
7. LRU cache: In-memory cache returns identical result on hit, evicts at maxsize 64.
8. API Endpoint: POST /api/health/analyze returns complete JSON schema.
"""

import os
import sys
import time
import gc
import unittest
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.code_health import (
    analyze_health,
    calculate_health_score,
    calculate_health_grade,
    clear_health_cache,
    _HEALTH_CACHE,
    _CACHE_MAXSIZE
)
import web.server as server


LANGUAGES = ["english", "hindi", "telugu", "bengali", "marathi", "nepali", "fusion"]
EXAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples"))


class TestCodeHealthAnalyzer(unittest.TestCase):
    """Test suite for web/code_health.py."""

    def setUp(self):
        clear_health_cache()

    def _get_demo_path(self, lang: str, prefix: str) -> str:
        demo_dir = os.path.join(EXAMPLES_DIR, "security_lab", lang)
        matches = [f for f in os.listdir(demo_dir) if f.startswith(prefix) and f.endswith(".vital")]
        self.assertTrue(matches, f"No demo found starting with {prefix} in {demo_dir}")
        return os.path.join(demo_dir, matches[0])

    def test_normal_programs_are_healthy_with_zero_insecure(self):
        """Normal canonical programs yield status healthy/warnings with 0% insecure code."""
        canonical_samples = [
            ("let x = 10\nlet y = 20\nlet z = x + y\nprint(z)\n", "English"),
            ("मानो x = 10\nमानो y = 20\nमानो z = x + y\nलिखो(z)\n", "Hindi"),
            ("తీసుకో x = 10\nముద్రించు(x)\n", "Telugu"),
        ]

        for code, lang in canonical_samples:
            res = analyze_health(code, language=lang, filename="canonical.vital")
            self.assertEqual(res["errors"], [], f"Normal program in {lang} should have 0 errors")
            self.assertEqual(res["security"]["insecure_percentage"], 0.0)
            self.assertIn(res["status"], ("healthy", "warnings"))
            self.assertEqual(res["blocking_stage"], None)
            self.assertEqual(len(res["predicted_pipeline"]), 10)
            self.assertTrue(all(p["status"] == "pass" for p in res["predicted_pipeline"]))
            self.assertGreaterEqual(res["score"], 80)
            self.assertIn(res["grade"], ("A", "B"))

    def test_demo_a_semantic_error_across_all_languages(self):
        """Demo A (sec_auth_account_*) yields SEM-* error at the undefined identifier line."""
        for lang in LANGUAGES:
            with self.subTest(language=lang):
                path = self._get_demo_path(lang, "sec_auth_account")
                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()

                res = analyze_health(code, language=lang, filename=path)
                self.assertEqual(res["status"], "errors")
                self.assertIsNotNone(res["blocking_stage"])
                self.assertEqual(res["blocking_stage"]["stage"], 5)
                self.assertEqual(res["blocking_stage"]["name"], "Semantic Analysis")

                # Find semantic error
                sem_errors = [e for e in res["errors"] if e["stage"] == 5 and e["code"].startswith("SEM-")]
                self.assertGreater(len(sem_errors), 0, f"Expected SEM-* error in {lang}")
                first_sem = sem_errors[0]
                self.assertTrue(first_sem["code"].startswith("SEM-"))
                # Undefined variable is at line 157 in english/fusion, and 149 in bengali/hindi/marathi/nepali/telugu
                expected_line = 157 if lang in ("english", "fusion") else 149
                self.assertEqual(first_sem["line"], expected_line)
                self.assertIn("referenced before", first_sem["message"].lower())

    def test_demo_d_syntax_error_across_all_languages(self):
        """Demo D (sec_business_workflow_*) yields SYN-* error for unbalanced delimiter."""
        for lang in LANGUAGES:
            with self.subTest(language=lang):
                path = self._get_demo_path(lang, "sec_business_workflow")
                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()

                res = analyze_health(code, language=lang, filename=path)
                self.assertEqual(res["status"], "errors")
                self.assertIsNotNone(res["blocking_stage"])
                self.assertEqual(res["blocking_stage"]["stage"], 3)
                self.assertEqual(res["blocking_stage"]["name"], "Syntax Analysis")

                syn_errors = [e for e in res["errors"] if e["stage"] == 3 and e["code"].startswith("SYN-")]
                self.assertGreater(len(syn_errors), 0, f"Expected SYN-* delimiter error in {lang}")
                first_syn = syn_errors[0]
                self.assertTrue(first_syn["code"].startswith("SYN-"))
                self.assertIn("unbalanced", first_syn["message"].lower())

    def test_demo_b_security_findings_and_cwes_across_all_languages(self):
        """Demo B (sec_data_config_*) yields insecure_percentage > 0 and expected CWEs."""
        expected_cwes = {"CWE-798", "CWE-22"}
        for lang in LANGUAGES:
            with self.subTest(language=lang):
                path = self._get_demo_path(lang, "sec_data_config")
                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()

                res = analyze_health(code, language=lang, filename=path)
                self.assertEqual(res["errors"], [], f"Demo B should have 0 compiler errors in {lang}")
                self.assertGreater(res["security"]["insecure_percentage"], 0.0)
                self.assertEqual(res["status"], "unsafe")
                self.assertGreater(len(res["security"]["findings"]), 0)
                self.assertGreater(len(res["security"]["insecure_lines"]), 0)

                found_cwes = {f["cwe"] for f in res["security"]["findings"]}
                for exp_cwe in expected_cwes:
                    self.assertIn(exp_cwe, found_cwes, f"Expected {exp_cwe} in {lang} Demo B")

    def test_demo_c_security_findings_and_cwes_across_all_languages(self):
        """Demo C (sec_injection_eval_*) yields insecure_percentage > 0 and expected CWE-94."""
        for lang in LANGUAGES:
            with self.subTest(language=lang):
                path = self._get_demo_path(lang, "sec_injection_eval")
                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()

                res = analyze_health(code, language=lang, filename=path)
                self.assertGreater(res["security"]["insecure_percentage"], 0.0)
                if lang == "fusion":
                    # Fusion Demo C has an unaligned function call 'डेटाबेस_क्वेरी_चलाएं' vs 'execute_database_query',
                    # raising a Stage 5 semantic error and giving status 'errors'.
                    self.assertIn(res["status"], {"unsafe", "errors"})
                else:
                    self.assertEqual(res["status"], "unsafe")

                found_cwes = {f["cwe"] for f in res["security"]["findings"]}
                self.assertIn("CWE-94", found_cwes, f"Expected CWE-94 (Code Injection) in {lang} Demo C")

    def test_performance_under_300ms_for_500_lines(self):
        """Ensures analyzer completes in < 300 ms for a 500-line VITAL program."""
        # Generate 500-line realistic VITAL code
        lines = ["// 500-line Performance Benchmark File"]
        for i in range(1, 100):
            lines.append(f"let var_{i} = {i * 10}")
            lines.append(f"if (var_{i} > 50) {{ print(var_{i}) }}")
            lines.append(f"let temp_{i} = var_{i} + 1")
            lines.append(f"print(temp_{i})")
            lines.append("")
        program_500 = "\n".join(lines)
        self.assertGreaterEqual(len(program_500.splitlines()), 495)

        # Clear cache to measure fresh parsing time
        clear_health_cache()
        gc.collect()

        t0 = time.perf_counter()
        res = analyze_health(program_500, language="English", filename="perf_test.vital")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        self.assertLess(elapsed_ms, 300.0, f"Analysis took {elapsed_ms:.2f} ms (must be < 300 ms)")
        self.assertIn("score", res)
        self.assertGreaterEqual(res["metrics"]["total_lines"], 495)

    def test_dead_code_detection(self):
        """Tests dead code detection: unused variable, parameter, unreachable after return."""
        dead_sample = """
let active_var = 100
let unused_dead_var = 999
print(active_var)

fn test_func(used_param, unused_param) {
    let result = used_param * 2
    return result
    print("this statement is completely unreachable")
}

fn uncalled_dead_func() {
    print("nobody ever calls me")
}
"""
        res = analyze_health(dead_sample, language="English", filename="dead.vital")
        dead_items = res["dead_code"]["items"]
        kinds = {item["kind"] for item in dead_items}

        self.assertIn("unused_variable", kinds)
        self.assertIn("unused_parameter", kinds)
        self.assertIn("unreachable_after_return", kinds)
        self.assertIn("unused_function", kinds)
        self.assertGreater(res["dead_code"]["percentage"], 0.0)

    def test_lru_cache_behavior_and_size_limit(self):
        """Verifies LRU cache stores entries, retrieves instantly, and caps at maxsize 64."""
        code = "let x = 42\nprint(x)\n"
        res1 = analyze_health(code, language="English")

        t0 = time.perf_counter()
        res2 = analyze_health(code, language="English")
        cache_hit_ms = (time.perf_counter() - t0) * 1000.0

        self.assertLess(cache_hit_ms, 5.0, "Cache hit must take < 5 ms")
        self.assertEqual(res1["source_hash"], res2["source_hash"])

        # Populate cache up to and beyond 64 items
        for i in range(70):
            unique_code = f"let var_{i} = {i}\nprint(var_{i})\n"
            analyze_health(unique_code, language="English")

        self.assertLessEqual(len(_HEALTH_CACHE), _CACHE_MAXSIZE)

    def test_api_endpoint_post_health_analyze(self):
        """Verifies POST /api/health/analyze endpoint returns complete JSON schema."""
        client = server.app.test_client()

        # 1. Valid request
        resp = client.post("/api/health/analyze", json={
            "source": "let a = 10\nprint(a)\n",
            "language": "English",
            "filename": "test.vital"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        required_keys = [
            "source_hash", "language", "analyzed_at", "score", "grade",
            "status", "metrics", "errors", "dead_code", "security",
            "blocking_stage", "predicted_pipeline"
        ]
        for key in required_keys:
            self.assertIn(key, data, f"Missing key '{key}' in API response")

        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["score"], 100)
        self.assertEqual(data["grade"], "A")
        self.assertEqual(data["blocking_stage"], None)
        self.assertEqual(len(data["predicted_pipeline"]), 10)

        # 2. Rejects non-JSON
        bad_resp = client.post("/api/health/analyze", data="plain text", content_type="text/plain")
        self.assertEqual(bad_resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
